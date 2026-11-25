// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>
#include <tsra_api.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

#include "algo/ecc/helpers.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "rsa_static_der.hpp"
#include "utils/auto_key.hpp"
#include "utils/rsa_keygen.hpp"
#include "utils/utils.hpp"

class tsra_rsa_unwrap : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// Wraps a pre-generated external RSA PKCS#8 private-key blob.
static tsra_status make_wrapped_rsa_pkcs8_blob(
    tsra_handle wrapping_public_key,
    uint32_t bit_len,
    const RsaAesWrapConfig &wrap_config,
    std::vector<uint8_t> &wrapped_blob
)
{
    const uint8_t *pkcs8_der = nullptr;
    size_t pkcs8_der_len = 0;

    auto err = get_static_rsa_pkcs8_der(bit_len, pkcs8_der, pkcs8_der_len);
    if (err != TSRA_STATUS_SUCCESS)
    {
        wrapped_blob.clear();
        return err;
    }

    std::vector<uint8_t> pkcs8_bytes(pkcs8_der, pkcs8_der + pkcs8_der_len);

    return wrap_plaintext_with_rsa_aes(wrapping_public_key, pkcs8_bytes, wrap_config, wrapped_blob);
}

struct RsaUnwrapProperties
{
    tsra_key_class private_class;
    tsra_key_kind private_kind;
    uint32_t private_bit_len;
    uint8_t private_session = 1;
    uint8_t private_decrypt = 1;

    tsra_key_class public_class;
    tsra_key_kind public_kind;
    uint32_t public_bit_len;
    uint8_t public_session = 1;
    uint8_t public_encrypt = 1;

    std::vector<tsra_key_prop> private_props;
    std::vector<tsra_key_prop> public_props;

    RsaUnwrapProperties(
        uint32_t bit_len,
        tsra_key_kind requested_private_kind = TSRA_KEY_KIND_RSA,
        tsra_key_class requested_private_class = TSRA_KEY_CLASS_PRIVATE,
        tsra_key_kind requested_public_kind = TSRA_KEY_KIND_RSA,
        tsra_key_class requested_public_class = TSRA_KEY_CLASS_PUBLIC
    )
        : private_class(requested_private_class), private_kind(requested_private_kind),
          private_bit_len(bit_len), public_class(requested_public_class),
          public_kind(requested_public_kind), public_bit_len(bit_len)
    {
        private_props = { { TSRA_KEY_PROP_ID_CLASS, &private_class, sizeof(private_class) },
                          { TSRA_KEY_PROP_ID_KIND, &private_kind, sizeof(private_kind) },
                          { TSRA_KEY_PROP_ID_BIT_LEN, &private_bit_len, sizeof(private_bit_len) },
                          { TSRA_KEY_PROP_ID_SESSION, &private_session, sizeof(private_session) },
                          { TSRA_KEY_PROP_ID_DECRYPT, &private_decrypt, sizeof(private_decrypt) } };

        public_props = { { TSRA_KEY_PROP_ID_CLASS, &public_class, sizeof(public_class) },
                         { TSRA_KEY_PROP_ID_KIND, &public_kind, sizeof(public_kind) },
                         { TSRA_KEY_PROP_ID_BIT_LEN, &public_bit_len, sizeof(public_bit_len) },
                         { TSRA_KEY_PROP_ID_SESSION, &public_session, sizeof(public_session) },
                         { TSRA_KEY_PROP_ID_ENCRYPT, &public_encrypt, sizeof(public_encrypt) } };
    }

    tsra_key_prop_list private_prop_list()
    {
        return { private_props.data(), static_cast<uint32_t>(private_props.size()) };
    }

    tsra_key_prop_list public_prop_list()
    {
        return { public_props.data(), static_cast<uint32_t>(public_props.size()) };
    }
};

struct RsaImportContext
{
    RsaImportContext(uint32_t bits, tsra_key_kind kind, bool sign, bool session_key)
        : properties(bits, kind), signing(sign)
    {
        properties.private_session = session_key;
        properties.public_session = session_key;
        properties.private_decrypt = !sign;
        properties.public_encrypt = !sign;
        private_sign = sign;
        public_verify = sign;
        properties.private_props.push_back(
            { TSRA_KEY_PROP_ID_SIGN, &private_sign, sizeof(private_sign) }
        );
        properties.public_props.push_back(
            { TSRA_KEY_PROP_ID_VERIFY, &public_verify, sizeof(public_verify) }
        );
    }
    RsaImportContext(const RsaImportContext &) = delete;
    RsaImportContext &operator=(const RsaImportContext &) = delete;

    RsaUnwrapProperties properties;
    bool signing;
    uint8_t private_sign = 0;
    uint8_t public_verify = 0;
    std::array<uint32_t, 2> storage{};
    auto_key unwrapping_private;
    auto_key unwrapping_public;
    std::vector<uint8_t> wrapped_blob;
    RsaAesUnwrapAlgo algorithm;

    void init(tsra_handle session)
    {
        ASSERT_EQ(
            generate_rsa_unwrapping_keypair(
                session,
                unwrapping_private.get_ptr(),
                unwrapping_public.get_ptr()
            ),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(unwrapping_private.get(), 0u);
        ASSERT_NE(unwrapping_public.get(), 0u);
        ASSERT_EQ(
            make_wrapped_rsa_pkcs8_blob(
                unwrapping_public.get(),
                properties.private_bit_len,
                RsaAesWrapConfig{},
                wrapped_blob
            ),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_FALSE(wrapped_blob.empty());
    }

    UnwrapPairResult import()
    {
        tsra_buffer blob{ wrapped_blob.data(), static_cast<uint32_t>(wrapped_blob.size()) };
        auto private_props = properties.private_prop_list();
        auto public_props = properties.public_prop_list();
        return try_unwrap_pair(
            &algorithm.algo,
            unwrapping_private.get(),
            &blob,
            &private_props,
            &public_props
        );
    }
};

template <typename Check>
static void for_each_rsa_import(PartitionListHandle &part_list, Check check)
{
    for (uint32_t bits : { 2048u, 3072u, 4096u })
    {
        SCOPED_TRACE(bits);
        for (auto kind : { TSRA_KEY_KIND_RSA, TSRA_KEY_KIND_RSA_CRT })
        {
            SCOPED_TRACE(kind);
            for (bool signing : { true, false })
            {
                SCOPED_TRACE(signing);
                for (bool session_key : { true, false })
                {
                    SCOPED_TRACE(session_key);
                    part_list.for_each_session([&](tsra_handle session) {
                        RsaImportContext ctx(bits, kind, signing, session_key);
                        ASSERT_NO_FATAL_FAILURE(ctx.init(session));
                        check(ctx);
                    });
                }
            }
        }
    }
}

static void expect_rsa_import_properties(
    tsra_handle key,
    const RsaImportContext &ctx,
    bool private_half
)
{
    ASSERT_NE(key, 0u);
    tsra_key_class key_class = TSRA_KEY_CLASS_SECRET;
    tsra_key_kind kind = TSRA_KEY_KIND_AES;
    uint32_t bits = 0;
    ASSERT_EQ(get_key_prop(key, TSRA_KEY_PROP_ID_CLASS, key_class), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(get_key_prop(key, TSRA_KEY_PROP_ID_KIND, kind), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(get_key_prop(key, TSRA_KEY_PROP_ID_BIT_LEN, bits), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(key_class, private_half ? TSRA_KEY_CLASS_PRIVATE : TSRA_KEY_CLASS_PUBLIC);
    ASSERT_EQ(kind, private_half ? ctx.properties.private_kind : TSRA_KEY_KIND_RSA);
    ASSERT_EQ(bits, ctx.properties.private_bit_len);
    for (const auto &[id, expected] : {
             std::pair{ TSRA_KEY_PROP_ID_SESSION, ctx.properties.private_session != 0 },
             std::pair{ TSRA_KEY_PROP_ID_LOCAL, false },
             std::pair{ TSRA_KEY_PROP_ID_SENSITIVE, private_half },
             std::pair{ TSRA_KEY_PROP_ID_EXTRACTABLE, true },
             std::pair{ TSRA_KEY_PROP_ID_SIGN, private_half && ctx.signing },
             std::pair{ TSRA_KEY_PROP_ID_VERIFY, !private_half && ctx.signing },
             std::pair{ TSRA_KEY_PROP_ID_DECRYPT, private_half && !ctx.signing },
             std::pair{ TSRA_KEY_PROP_ID_ENCRYPT, !private_half && !ctx.signing },
             std::pair{ TSRA_KEY_PROP_ID_DERIVE, false },
             std::pair{ TSRA_KEY_PROP_ID_WRAP, false },
             std::pair{ TSRA_KEY_PROP_ID_UNWRAP, false },
         })
    {
        SCOPED_TRACE(id);
        uint8_t actual = 0;
        ASSERT_EQ(get_key_prop(key, id, actual), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(actual, static_cast<uint8_t>(expected));
    }
    tsra_ecc_curve curve = TSRA_ECC_CURVE_P256;
    ASSERT_EQ(
        get_key_prop(key, TSRA_KEY_PROP_ID_EC_CURVE, curve),
        TSRA_STATUS_PROPERTY_NOT_PRESENT
    );
}

static void expect_rsa_import_success(RsaImportContext &ctx)
{
    const auto result = ctx.import();
    auto_key private_key;
    auto_key public_key;
    private_key.handle = result.private_key;
    public_key.handle = result.public_key;
    ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
    ASSERT_NO_FATAL_FAILURE(expect_rsa_import_properties(private_key.get(), ctx, true));
    ASSERT_NO_FATAL_FAILURE(expect_rsa_import_properties(public_key.get(), ctx, false));
}

TEST_F(tsra_rsa_unwrap, imported_properties_all_sizes)
{
    for_each_rsa_import(part_list_, [](RsaImportContext &ctx) { expect_rsa_import_success(ctx); });
}

TEST_F(tsra_rsa_unwrap, imported_labels_preserved)
{
    constexpr size_t documented_label_capacity = 128;
    for (auto label : { std::vector<uint8_t>{},
                        std::vector<uint8_t>{ 'r', 's', 'a' },
                        std::vector<uint8_t>(documented_label_capacity - 1, 'x') })
    {
        SCOPED_TRACE(label.size());
        for_each_rsa_import(part_list_, [&](RsaImportContext &ctx) {
            void *label_data =
                label.empty() ? ctx.storage.data() : static_cast<void *>(label.data());
            ctx.properties.private_props.push_back(
                { TSRA_KEY_PROP_ID_LABEL, label_data, static_cast<uint32_t>(label.size()) }
            );
            ctx.properties.public_props.push_back(
                { TSRA_KEY_PROP_ID_LABEL, label_data, static_cast<uint32_t>(label.size()) }
            );
            auto result = ctx.import();
            auto_key private_key;
            auto_key public_key;
            private_key.handle = result.private_key;
            public_key.handle = result.public_key;
            ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
            ASSERT_NO_FATAL_FAILURE(expect_rsa_import_properties(private_key.get(), ctx, true));
            ASSERT_NO_FATAL_FAILURE(expect_rsa_import_properties(public_key.get(), ctx, false));
            for (auto key : { private_key.get(), public_key.get() })
            {
                std::vector<uint8_t> actual(label.size() + sizeof(uint8_t));
                tsra_key_prop property{ TSRA_KEY_PROP_ID_LABEL,
                                        actual.data(),
                                        static_cast<uint32_t>(actual.size()) };
                ASSERT_EQ(tsra_key_get_prop(key, &property), TSRA_STATUS_SUCCESS);
                ASSERT_EQ(property.len, label.size());
                actual.resize(property.len);
                ASSERT_EQ(actual, label);
            }
        });
    }
}

static void expect_rsa_import_failure(RsaImportContext &ctx)
{
    const auto result = ctx.import();
    auto_key private_key;
    auto_key public_key;
    private_key.handle = result.private_key;
    public_key.handle = result.public_key;
    ASSERT_EQ(result.status, TSRA_STATUS_INVALID_KEY_PROPS);
    ASSERT_EQ(private_key.get(), 0u);
    ASSERT_EQ(public_key.get(), 0u);
}

static void expect_rsa_import_flag(
    PartitionListHandle &part_list,
    bool private_half,
    tsra_key_prop_id flag
)
{
    for_each_rsa_import(part_list, [&](RsaImportContext &ctx) {
        uint8_t enabled = 0;
        auto &target = private_half ? ctx.properties.private_props : ctx.properties.public_props;
        target.push_back({ flag, &enabled, sizeof(enabled) });
        ASSERT_NO_FATAL_FAILURE(expect_rsa_import_success(ctx));
        enabled = 1;
        expect_rsa_import_failure(ctx);
    });
}

TEST_F(tsra_rsa_unwrap, private_encrypt_rejected)
{
    expect_rsa_import_flag(part_list_, true, TSRA_KEY_PROP_ID_ENCRYPT);
}

TEST_F(tsra_rsa_unwrap, private_verify_rejected)
{
    expect_rsa_import_flag(part_list_, true, TSRA_KEY_PROP_ID_VERIFY);
}

TEST_F(tsra_rsa_unwrap, private_derive_rejected)
{
    expect_rsa_import_flag(part_list_, true, TSRA_KEY_PROP_ID_DERIVE);
}

TEST_F(tsra_rsa_unwrap, private_wrap_rejected)
{
    expect_rsa_import_flag(part_list_, true, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_rsa_unwrap, private_unwrap_extra_rejected)
{
    expect_rsa_import_flag(part_list_, true, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_rsa_unwrap, public_sign_rejected)
{
    expect_rsa_import_flag(part_list_, false, TSRA_KEY_PROP_ID_SIGN);
}

TEST_F(tsra_rsa_unwrap, public_decrypt_rejected)
{
    expect_rsa_import_flag(part_list_, false, TSRA_KEY_PROP_ID_DECRYPT);
}

TEST_F(tsra_rsa_unwrap, public_derive_rejected)
{
    expect_rsa_import_flag(part_list_, false, TSRA_KEY_PROP_ID_DERIVE);
}

TEST_F(tsra_rsa_unwrap, public_unwrap_rejected)
{
    expect_rsa_import_flag(part_list_, false, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_rsa_unwrap, public_wrap_extra_rejected)
{
    expect_rsa_import_flag(part_list_, false, TSRA_KEY_PROP_ID_WRAP);
}

template <typename Change>
static void expect_rsa_pair_problem(PartitionListHandle &part_list, Change change)
{
    for_each_rsa_import(part_list, [&](RsaImportContext &ctx) {
        ASSERT_NO_FATAL_FAILURE(expect_rsa_import_success(ctx));
        ASSERT_NO_FATAL_FAILURE(change(ctx));
        expect_rsa_import_failure(ctx);
    });
}

TEST_F(tsra_rsa_unwrap, private_usage_missing)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.private_sign = 0;
        ctx.properties.private_decrypt = 0;
    });
}

TEST_F(tsra_rsa_unwrap, public_usage_missing)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.public_verify = 0;
        ctx.properties.public_encrypt = 0;
    });
}

TEST_F(tsra_rsa_unwrap, private_usage_omitted)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        remove_prop_by_id(ctx.properties.private_props, TSRA_KEY_PROP_ID_SIGN);
        remove_prop_by_id(ctx.properties.private_props, TSRA_KEY_PROP_ID_DECRYPT);
    });
}

TEST_F(tsra_rsa_unwrap, public_usage_omitted)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        remove_prop_by_id(ctx.properties.public_props, TSRA_KEY_PROP_ID_VERIFY);
        remove_prop_by_id(ctx.properties.public_props, TSRA_KEY_PROP_ID_ENCRYPT);
    });
}

TEST_F(tsra_rsa_unwrap, private_usage_conflict)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.private_sign = 1;
        ctx.properties.private_decrypt = 1;
    });
}

TEST_F(tsra_rsa_unwrap, public_usage_conflict)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.public_verify = 1;
        ctx.properties.public_encrypt = 1;
    });
}

TEST_F(tsra_rsa_unwrap, usage_pair_mismatch)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.public_verify = !ctx.signing;
        ctx.properties.public_encrypt = ctx.signing;
    });
}

TEST_F(tsra_rsa_unwrap, session_pair_mismatch)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.properties.public_session = !ctx.properties.private_session;
    });
}

TEST_F(tsra_rsa_unwrap, private_class_rejected)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.properties.private_class = TSRA_KEY_CLASS_PUBLIC;
    });
}

TEST_F(tsra_rsa_unwrap, public_class_rejected)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.properties.public_class = TSRA_KEY_CLASS_PRIVATE;
    });
}

TEST_F(tsra_rsa_unwrap, private_kind_rejected)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.properties.private_kind = TSRA_KEY_KIND_ECC;
    });
}

TEST_F(tsra_rsa_unwrap, public_kind_rejected)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.properties.public_kind = TSRA_KEY_KIND_RSA_CRT;
    });
}

TEST_F(tsra_rsa_unwrap, private_curve_rejected)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.storage[0] = TSRA_ECC_CURVE_P256;
        ctx.properties.private_props.push_back(
            { TSRA_KEY_PROP_ID_EC_CURVE, ctx.storage.data(), sizeof(uint32_t) }
        );
    });
}

TEST_F(tsra_rsa_unwrap, public_curve_rejected)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.storage[0] = TSRA_ECC_CURVE_P256;
        ctx.properties.public_props.push_back(
            { TSRA_KEY_PROP_ID_EC_CURVE, ctx.storage.data(), sizeof(uint32_t) }
        );
    });
}

TEST_F(tsra_rsa_unwrap, bit_length_pair_mismatch)
{
    expect_rsa_pair_problem(part_list_, [](RsaImportContext &ctx) {
        ctx.properties.public_bit_len = ctx.properties.private_bit_len == 2048 ? 3072 : 2048;
    });
}

// Unwraps an external RSA PKCS#8 key using caller-selected identity properties.
static UnwrapPairResult unwrap_external_rsa_pair_with_identity_properties(
    tsra_handle session,
    uint32_t bit_len,
    tsra_key_kind private_kind,
    tsra_key_class private_class,
    tsra_key_kind public_kind,
    tsra_key_class public_class
)
{
    UnwrapPairResult result{};

    auto_key wrapping_private_key;
    auto_key wrapping_public_key;

    auto err = generate_rsa_unwrapping_keypair(
        session,
        wrapping_private_key.get_ptr(),
        wrapping_public_key.get_ptr()
    );
    if (err != TSRA_STATUS_SUCCESS)
    {
        result.status = err;
        return result;
    }

    std::vector<uint8_t> wrapped_blob;
    err = make_wrapped_rsa_pkcs8_blob(
        wrapping_public_key.get(),
        bit_len,
        RsaAesWrapConfig{},
        wrapped_blob
    );
    if (err != TSRA_STATUS_SUCCESS)
    {
        result.status = err;
        return result;
    }

    tsra_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                 .len = static_cast<uint32_t>(wrapped_blob.size()) };

    RsaAesUnwrapAlgo unwrap_algo{};
    RsaUnwrapProperties properties(bit_len, private_kind, private_class, public_kind, public_class);

    auto private_prop_list = properties.private_prop_list();
    auto public_prop_list = properties.public_prop_list();

    return try_unwrap_pair(
        &unwrap_algo.algo,
        wrapping_private_key.get(),
        &wrapped_key_buf,
        &private_prop_list,
        &public_prop_list
    );
}

static UnwrapPairResult unwrap_external_rsa_pair(tsra_handle session, uint32_t bit_len)
{
    return unwrap_external_rsa_pair_with_identity_properties(
        session,
        bit_len,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PRIVATE,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PUBLIC
    );
}

static void verify_external_rsa_keypair_unwrap_succeeds(
    PartitionListHandle &part_list,
    uint32_t bit_len
)
{
    part_list.for_each_session([bit_len](tsra_handle session) {
        auto result = unwrap_external_rsa_pair(session, bit_len);

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);
        ASSERT_NE(result.private_key, result.public_key);

        auto_key imported_private_key;
        auto_key imported_public_key;
        imported_private_key.handle = result.private_key;
        imported_public_key.handle = result.public_key;
    });
}

static void verify_unwrapped_external_rsa_properties(
    PartitionListHandle &part_list,
    uint32_t bit_len
)
{
    part_list.for_each_session([bit_len](tsra_handle session) {
        auto result = unwrap_external_rsa_pair(session, bit_len);

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;

        tsra_key_kind private_kind{};
        ASSERT_EQ(
            get_key_prop(private_key.get(), TSRA_KEY_PROP_ID_KIND, private_kind),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(private_kind, TSRA_KEY_KIND_RSA);

        tsra_key_class private_class{};
        ASSERT_EQ(
            get_key_prop(private_key.get(), TSRA_KEY_PROP_ID_CLASS, private_class),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(private_class, TSRA_KEY_CLASS_PRIVATE);

        uint32_t private_bits{};
        ASSERT_EQ(
            get_key_prop(private_key.get(), TSRA_KEY_PROP_ID_BIT_LEN, private_bits),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(private_bits, bit_len);

        tsra_key_kind public_kind{};
        ASSERT_EQ(
            get_key_prop(public_key.get(), TSRA_KEY_PROP_ID_KIND, public_kind),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(public_kind, TSRA_KEY_KIND_RSA);

        tsra_key_class public_class{};
        ASSERT_EQ(
            get_key_prop(public_key.get(), TSRA_KEY_PROP_ID_CLASS, public_class),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(public_class, TSRA_KEY_CLASS_PUBLIC);

        uint32_t public_bits{};
        ASSERT_EQ(
            get_key_prop(public_key.get(), TSRA_KEY_PROP_ID_BIT_LEN, public_bits),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(public_bits, bit_len);
    });
}

static void verify_corrupted_blob_rejected(PartitionListHandle &part_list, uint32_t bit_len)
{
    part_list.for_each_session([bit_len](tsra_handle session) {
        auto_key wrapping_private_key;
        auto_key wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_private_key.get_ptr(),
            wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_rsa_pkcs8_blob(
            wrapping_public_key.get(),
            bit_len,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());

        wrapped_blob[wrapped_blob.size() / 2] ^= 0xA5;

        tsra_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                     .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};
        RsaUnwrapProperties properties(bit_len);
        auto private_prop_list = properties.private_prop_list();
        auto public_prop_list = properties.public_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            wrapping_private_key.get(),
            &wrapped_key_buf,
            &private_prop_list,
            &public_prop_list
        );

        ASSERT_NE(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

static void verify_truncated_blob_rejected(PartitionListHandle &part_list, uint32_t bit_len)
{
    part_list.for_each_session([bit_len](tsra_handle session) {
        auto_key wrapping_private_key;
        auto_key wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_private_key.get_ptr(),
            wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_rsa_pkcs8_blob(
            wrapping_public_key.get(),
            bit_len,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_GT(wrapped_blob.size(), 1u);

        wrapped_blob.pop_back();

        tsra_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                     .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};
        RsaUnwrapProperties properties(bit_len);
        auto private_prop_list = properties.private_prop_list();
        auto public_prop_list = properties.public_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            wrapping_private_key.get(),
            &wrapped_key_buf,
            &private_prop_list,
            &public_prop_list
        );

        ASSERT_NE(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

static void verify_requested_bit_length_mismatch_rejected(
    PartitionListHandle &part_list,
    uint32_t wrapped_bit_len,
    uint32_t requested_bit_len
)
{
    part_list.for_each_session([wrapped_bit_len, requested_bit_len](tsra_handle session) {
        auto_key wrapping_private_key;
        auto_key wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_private_key.get_ptr(),
            wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_rsa_pkcs8_blob(
            wrapping_public_key.get(),
            wrapped_bit_len,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        tsra_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                     .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};
        {
            RsaUnwrapProperties control_properties(wrapped_bit_len);
            auto control_private_props = control_properties.private_prop_list();
            auto control_public_props = control_properties.public_prop_list();
            const auto control = try_unwrap_pair(
                &unwrap_algo.algo,
                wrapping_private_key.get(),
                &wrapped_key_buf,
                &control_private_props,
                &control_public_props
            );
            auto_key private_key;
            auto_key public_key;
            private_key.handle = control.private_key;
            public_key.handle = control.public_key;
            ASSERT_EQ(control.status, TSRA_STATUS_SUCCESS);
            ASSERT_NE(private_key.get(), 0u);
            ASSERT_NE(public_key.get(), 0u);
        }
        RsaUnwrapProperties properties(requested_bit_len);
        auto private_prop_list = properties.private_prop_list();
        auto public_prop_list = properties.public_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            wrapping_private_key.get(),
            &wrapped_key_buf,
            &private_prop_list,
            &public_prop_list
        );

        ASSERT_EQ(result.status, TSRA_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

static void verify_identity_properties_rejected(
    PartitionListHandle &part_list,
    uint32_t bit_len,
    tsra_key_kind private_kind,
    tsra_key_class private_class,
    tsra_key_kind public_kind,
    tsra_key_class public_class
)
{
    part_list.for_each_session([=](tsra_handle session) {
        RsaImportContext ctx(bit_len, TSRA_KEY_KIND_RSA, false, true);
        ASSERT_NO_FATAL_FAILURE(ctx.init(session));
        remove_prop_by_id(ctx.properties.private_props, TSRA_KEY_PROP_ID_SIGN);
        remove_prop_by_id(ctx.properties.public_props, TSRA_KEY_PROP_ID_VERIFY);
        ASSERT_NO_FATAL_FAILURE(expect_rsa_import_success(ctx));
        ctx.properties.private_kind = private_kind;
        ctx.properties.private_class = private_class;
        ctx.properties.public_kind = public_kind;
        ctx.properties.public_class = public_class;
        expect_rsa_import_failure(ctx);
    });
}

static void verify_unwrapped_external_rsa_roundtrip(
    PartitionListHandle &part_list,
    uint32_t bit_len
)
{
    part_list.for_each_session([bit_len](tsra_handle session) {
        auto result = unwrap_external_rsa_pair(session, bit_len);

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;

        const char *plaintext = "RSA unwrap functional roundtrip";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + std::strlen(plaintext));

        tsra_algo rsa_algo{ .id = TSRA_ALGO_ID_RSA_PKCS, .params = nullptr, .len = 0 };

        tsra_buffer plaintext_buf{ .ptr = plaintext_data.data(),
                                   .len = static_cast<uint32_t>(plaintext_data.size()) };

        const uint32_t rsa_output_size = bit_len / 8u;

        std::vector<uint8_t> ciphertext_data(rsa_output_size);
        tsra_buffer ciphertext_buf{ .ptr = ciphertext_data.data(),
                                    .len = static_cast<uint32_t>(ciphertext_data.size()) };

        auto err = tsra_crypt_encrypt(&rsa_algo, public_key.get(), &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(ciphertext_buf.len, rsa_output_size);

        std::vector<uint8_t> decrypted_data(rsa_output_size);
        tsra_buffer decrypted_buf{ .ptr = decrypted_data.data(),
                                   .len = static_cast<uint32_t>(decrypted_data.size()) };

        err = tsra_crypt_decrypt(&rsa_algo, private_key.get(), &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, std::memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));
    });
}

static void verify_wrong_unwrapping_key_rejected(PartitionListHandle &part_list, uint32_t bit_len)
{
    if (part_list.count() < 2u)
    {
        GTEST_SKIP(
        ) << "requires at least two partitions to guarantee distinct wrapping-key contexts";
    }

    auto source_path = part_list.get_path(0);
    auto other_path = part_list.get_path(1);

    auto source_partition = PartitionHandle(source_path);
    auto other_partition = PartitionHandle(other_path);

    std::vector<uint8_t> wrapped_blob;
    auto_key wrong_unwrapping_private_key;

    {
        SessionHandle source_session(source_partition.get());

        auto_key source_wrapping_private_key;
        auto_key source_wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            source_session.get(),
            source_wrapping_private_key.get_ptr(),
            source_wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        err = make_wrapped_rsa_pkcs8_blob(
            source_wrapping_public_key.get(),
            bit_len,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());
    }

    {
        SessionHandle other_session(other_partition.get());

        auto_key wrong_wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            other_session.get(),
            wrong_unwrapping_private_key.get_ptr(),
            wrong_wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    }

    tsra_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                 .len = static_cast<uint32_t>(wrapped_blob.size()) };

    RsaAesUnwrapAlgo unwrap_algo{};
    RsaUnwrapProperties properties(bit_len);
    auto private_prop_list = properties.private_prop_list();
    auto public_prop_list = properties.public_prop_list();

    auto result = try_unwrap_pair(
        &unwrap_algo.algo,
        wrong_unwrapping_private_key.get(),
        &wrapped_key_buf,
        &private_prop_list,
        &public_prop_list
    );

    ASSERT_NE(result.status, TSRA_STATUS_SUCCESS);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies an externally generated 2048-bit RSA key pair can be unwrapped.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_2048_keypair_succeeds)
{
    verify_external_rsa_keypair_unwrap_succeeds(part_list_, 2048u);
}

// Verifies an externally generated 3072-bit RSA key pair can be unwrapped.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_3072_keypair_succeeds)
{
    verify_external_rsa_keypair_unwrap_succeeds(part_list_, 3072u);
}

// Verifies an unwrapped 2048-bit RSA key pair reports expected properties.
TEST_F(tsra_rsa_unwrap, unwrapped_external_rsa_2048_reports_expected_properties)
{
    verify_unwrapped_external_rsa_properties(part_list_, 2048u);
}

// Verifies an unwrapped 3072-bit RSA key pair reports expected properties.
TEST_F(tsra_rsa_unwrap, unwrapped_external_rsa_3072_reports_expected_properties)
{
    verify_unwrapped_external_rsa_properties(part_list_, 3072u);
}

// Verifies 2048-bit RSA unwrap rejects corrupted wrapped key material.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_2048_rejects_corrupted_blob)
{
    verify_corrupted_blob_rejected(part_list_, 2048u);
}

// Verifies 3072-bit RSA unwrap rejects corrupted wrapped key material.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_3072_rejects_corrupted_blob)
{
    verify_corrupted_blob_rejected(part_list_, 3072u);
}

// Verifies 2048-bit RSA unwrap rejects a wrong unwrapping key.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_2048_rejects_wrong_unwrapping_key)
{
    if (api_rev_at_least(1, 1))
    {
        return;
    }
    verify_wrong_unwrapping_key_rejected(part_list_, 2048u);
}

// Verifies 3072-bit RSA unwrap rejects a wrong unwrapping key.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_3072_rejects_wrong_unwrapping_key)
{
    if (api_rev_at_least(1, 1))
    {
        return;
    }
    verify_wrong_unwrapping_key_rejected(part_list_, 3072u);
}

// Verifies 2048-bit RSA unwrap rejects a truncated wrapped blob.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_2048_rejects_truncated_blob)
{
    verify_truncated_blob_rejected(part_list_, 2048u);
}

// Verifies 3072-bit RSA unwrap rejects a truncated wrapped blob.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_3072_rejects_truncated_blob)
{
    verify_truncated_blob_rejected(part_list_, 3072u);
}

// Verifies a wrapped 2048-bit RSA key rejects requested 3072-bit properties.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_2048_rejects_requested_3072_bit_length)
{
    verify_requested_bit_length_mismatch_rejected(part_list_, 2048u, 3072u);
}

// Verifies a wrapped 3072-bit RSA key rejects requested 2048-bit properties.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_3072_rejects_requested_2048_bit_length)
{
    verify_requested_bit_length_mismatch_rejected(part_list_, 3072u, 2048u);
}

// Verifies 2048-bit RSA unwrap rejects private KIND set to ECC.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_2048_rejects_private_kind_not_rsa)
{
    verify_identity_properties_rejected(
        part_list_,
        2048u,
        TSRA_KEY_KIND_ECC,
        TSRA_KEY_CLASS_PRIVATE,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PUBLIC
    );
}

// Verifies 3072-bit RSA unwrap rejects private KIND set to ECC.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_3072_rejects_private_kind_not_rsa)
{
    verify_identity_properties_rejected(
        part_list_,
        3072u,
        TSRA_KEY_KIND_ECC,
        TSRA_KEY_CLASS_PRIVATE,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PUBLIC
    );
}

// Verifies 2048-bit RSA unwrap rejects public KIND set to ECC.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_2048_rejects_public_kind_not_rsa)
{
    verify_identity_properties_rejected(
        part_list_,
        2048u,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PRIVATE,
        TSRA_KEY_KIND_ECC,
        TSRA_KEY_CLASS_PUBLIC
    );
}

// Verifies 3072-bit RSA unwrap rejects public KIND set to ECC.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_3072_rejects_public_kind_not_rsa)
{
    verify_identity_properties_rejected(
        part_list_,
        3072u,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PRIVATE,
        TSRA_KEY_KIND_ECC,
        TSRA_KEY_CLASS_PUBLIC
    );
}

// Verifies 2048-bit RSA unwrap rejects private CLASS set to PUBLIC.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_2048_rejects_private_class_set_to_public)
{
    verify_identity_properties_rejected(
        part_list_,
        2048u,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PUBLIC,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PUBLIC
    );
}

// Verifies 3072-bit RSA unwrap rejects private CLASS set to PUBLIC.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_3072_rejects_private_class_set_to_public)
{
    verify_identity_properties_rejected(
        part_list_,
        3072u,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PUBLIC,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PUBLIC
    );
}

// Verifies 2048-bit RSA unwrap rejects public CLASS set to PRIVATE.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_2048_rejects_public_class_set_to_private)
{
    verify_identity_properties_rejected(
        part_list_,
        2048u,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PRIVATE,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PRIVATE
    );
}

// Verifies 3072-bit RSA unwrap rejects public CLASS set to PRIVATE.
TEST_F(tsra_rsa_unwrap, unwrap_external_rsa_3072_rejects_public_class_set_to_private)
{
    verify_identity_properties_rejected(
        part_list_,
        3072u,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PRIVATE,
        TSRA_KEY_KIND_RSA,
        TSRA_KEY_CLASS_PRIVATE
    );
}

// Verifies an unwrapped 2048-bit RSA key pair supports encrypt/decrypt.
TEST_F(tsra_rsa_unwrap, unwrapped_external_rsa_2048_encrypt_decrypt_roundtrip)
{
    verify_unwrapped_external_rsa_roundtrip(part_list_, 2048u);
}

// Verifies an unwrapped 3072-bit RSA key pair supports encrypt/decrypt.
TEST_F(tsra_rsa_unwrap, unwrapped_external_rsa_3072_encrypt_decrypt_roundtrip)
{
    verify_unwrapped_external_rsa_roundtrip(part_list_, 3072u);
}
