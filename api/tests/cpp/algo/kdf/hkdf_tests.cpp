// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <limits>
#include <string>
#include <tsra_api.h>
#include <utility>
#include <vector>

#include "algo/ecc/helpers.hpp"
#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"
#include "utils/kdf_derive.hpp"
#include "utils/key_props.hpp"
#include "utils/shared_secret.hpp"

// ============================================================
// Test fixture
// ============================================================

class tsra_hkdf : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

static key_props valid_hkdf_aes_props()
{
    key_props props = {};
    props.key_class = TSRA_KEY_CLASS_SECRET;
    props.key_kind = TSRA_KEY_KIND_AES;
    props.key_size_bits = 256;
    props.encrypt = 1;
    props.decrypt = 1;
    return props;
}

struct HkdfOutputCase
{
    tsra_key_kind kind;
    uint32_t bits;
    const char *name;
};

static constexpr HkdfOutputCase HKDF_OUTPUTS[] = {
    { TSRA_KEY_KIND_AES, 128, "AES128" },          { TSRA_KEY_KIND_AES, 192, "AES192" },
    { TSRA_KEY_KIND_AES, 256, "AES256" },          { TSRA_KEY_KIND_HMAC_SHA256, 256, "HMAC256" },
    { TSRA_KEY_KIND_HMAC_SHA384, 384, "HMAC384" }, { TSRA_KEY_KIND_HMAC_SHA512, 512, "HMAC512" },
};

enum class HkdfOutputFamily
{
    All,
    Aes,
    Hmac,
};

struct HkdfAttributeContext
{
    HkdfAttributeContext() = default;
    HkdfAttributeContext(const HkdfAttributeContext &) = delete;
    HkdfAttributeContext &operator=(const HkdfAttributeContext &) = delete;

    tsra_handle session = 0;
    tsra_ecc_curve curve = TSRA_ECC_CURVE_P256;
    auto_key secret;
    auto_key peer_secret;
    key_props props{};
    std::vector<tsra_key_prop> properties;
    tsra_key_prop_list property_list{};
    tsra_algo_hkdf_params params{};
    tsra_algo algo{};
    std::array<uint32_t, 2> storage{};

    void init(
        tsra_handle handle,
        tsra_ecc_curve input_curve,
        const HkdfOutputCase &output,
        bool session_key
    )
    {
        session = handle;
        curve = input_curve;
        ASSERT_NO_FATAL_FAILURE(derive_ecdh_shared_secrets(session, curve, secret, peer_secret));
        ASSERT_NE(secret.get(), 0u);
        ASSERT_NE(peer_secret.get(), 0u);
        const bool aes = output.kind == TSRA_KEY_KIND_AES;
        props.key_class = TSRA_KEY_CLASS_SECRET;
        props.key_kind = output.kind;
        props.key_size_bits = output.bits;
        props.session_key = session_key;
        props.encrypt = aes;
        props.decrypt = aes;
        props.sign = !aes;
        props.verify = !aes;
        property_list = build_key_prop_list(props, properties);
        build_hkdf_algo(params, algo, TSRA_ALGO_ID_HMAC_SHA256, nullptr, nullptr);
    }

    void refresh_properties()
    {
        property_list = { properties.data(), static_cast<uint32_t>(properties.size()) };
    }

    tsra_key_prop *property(tsra_key_prop_id id)
    {
        auto found =
            std::find_if(properties.begin(), properties.end(), [id](const tsra_key_prop &prop) {
                return prop.id == id;
            });
        return found == properties.end() ? nullptr : &*found;
    }

    tsra_status derive(auto_key &key)
    {
        return tsra_key_derive(session, &algo, secret.get(), &property_list, key.get_ptr());
    }
};

template <typename Check>
static void for_each_hkdf_output(
    PartitionListHandle &part_list,
    HkdfOutputFamily family,
    Check check
)
{
    for (const auto &output : HKDF_OUTPUTS)
    {
        if ((family == HkdfOutputFamily::Aes && output.kind != TSRA_KEY_KIND_AES) ||
            (family == HkdfOutputFamily::Hmac && output.kind == TSRA_KEY_KIND_AES))
        {
            continue;
        }
        SCOPED_TRACE(output.name);
        for (const auto &curve : ECC_CURVES)
        {
            SCOPED_TRACE(curve.test_name);
            for (bool session_key : { true, false })
            {
                SCOPED_TRACE(session_key);
                part_list.for_each_session([&](tsra_handle session) {
                    HkdfAttributeContext ctx;
                    ASSERT_NO_FATAL_FAILURE(ctx.init(session, curve.curve, output, session_key));
                    check(ctx);
                });
            }
        }
    }
}

static void expect_hkdf_output_properties(tsra_handle key, const key_props &expected)
{
    ASSERT_NE(key, 0u);
    tsra_key_class key_class = TSRA_KEY_CLASS_PUBLIC;
    tsra_key_kind kind = TSRA_KEY_KIND_ECC;
    uint32_t bits = 0;
    ASSERT_EQ(get_key_prop(key, TSRA_KEY_PROP_ID_CLASS, key_class), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(get_key_prop(key, TSRA_KEY_PROP_ID_KIND, kind), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(get_key_prop(key, TSRA_KEY_PROP_ID_BIT_LEN, bits), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(key_class, TSRA_KEY_CLASS_SECRET);
    ASSERT_EQ(kind, expected.key_kind);
    ASSERT_EQ(bits, expected.key_size_bits);
    for (const auto &[id, value] : {
             std::pair{ TSRA_KEY_PROP_ID_SESSION, expected.session_key },
             std::pair{ TSRA_KEY_PROP_ID_LOCAL, true },
             std::pair{ TSRA_KEY_PROP_ID_SENSITIVE, true },
             std::pair{ TSRA_KEY_PROP_ID_EXTRACTABLE, true },
             std::pair{ TSRA_KEY_PROP_ID_ENCRYPT, expected.encrypt },
             std::pair{ TSRA_KEY_PROP_ID_DECRYPT, expected.decrypt },
             std::pair{ TSRA_KEY_PROP_ID_SIGN, expected.sign },
             std::pair{ TSRA_KEY_PROP_ID_VERIFY, expected.verify },
             std::pair{ TSRA_KEY_PROP_ID_DERIVE, false },
             std::pair{ TSRA_KEY_PROP_ID_WRAP, false },
             std::pair{ TSRA_KEY_PROP_ID_UNWRAP, false },
         })
    {
        SCOPED_TRACE(id);
        uint8_t actual = 0;
        ASSERT_EQ(get_key_prop(key, id, actual), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(actual, static_cast<uint8_t>(value));
    }
    tsra_ecc_curve curve = TSRA_ECC_CURVE_P256;
    ASSERT_EQ(
        get_key_prop(key, TSRA_KEY_PROP_ID_EC_CURVE, curve),
        TSRA_STATUS_PROPERTY_NOT_PRESENT
    );
}

TEST_F(tsra_hkdf, output_properties)
{
    for_each_hkdf_output(part_list_, HkdfOutputFamily::All, [](HkdfAttributeContext &ctx) {
        auto_key key;
        ASSERT_EQ(ctx.derive(key), TSRA_STATUS_SUCCESS);
        expect_hkdf_output_properties(key.get(), ctx.props);
    });
}

TEST_F(tsra_hkdf, output_labels_preserved)
{
    constexpr size_t documented_label_capacity = 128;
    for (auto label : {
             std::vector<uint8_t>{},
             std::vector<uint8_t>{ 'h', 'k', 'd', 'f' },
             std::vector<uint8_t>(documented_label_capacity - 1, 'x'),
         })
    {
        SCOPED_TRACE(label.size());
        for_each_hkdf_output(part_list_, HkdfOutputFamily::All, [&](HkdfAttributeContext &ctx) {
            ctx.properties.push_back({ TSRA_KEY_PROP_ID_LABEL,
                                       label.empty() ? ctx.storage.data()
                                                     : static_cast<void *>(label.data()),
                                       static_cast<uint32_t>(label.size()) });
            ctx.refresh_properties();
            auto_key key;
            ASSERT_EQ(ctx.derive(key), TSRA_STATUS_SUCCESS);
            ASSERT_NO_FATAL_FAILURE(expect_hkdf_output_properties(key.get(), ctx.props));
            std::vector<uint8_t> actual(label.size() + sizeof(uint8_t));
            tsra_key_prop prop{ TSRA_KEY_PROP_ID_LABEL,
                                actual.data(),
                                static_cast<uint32_t>(actual.size()) };
            ASSERT_EQ(tsra_key_get_prop(key.get(), &prop), TSRA_STATUS_SUCCESS);
            ASSERT_EQ(prop.len, label.size());
            actual.resize(prop.len);
            ASSERT_EQ(actual, label);
        });
    }
}

template <typename Change>
static void expect_hkdf_property_rejected(
    PartitionListHandle &part_list,
    HkdfOutputFamily family,
    tsra_status expected,
    Change change
)
{
    for_each_hkdf_output(part_list, family, [&](HkdfAttributeContext &ctx) {
        {
            auto_key control;
            ASSERT_EQ(ctx.derive(control), TSRA_STATUS_SUCCESS);
            ASSERT_NO_FATAL_FAILURE(expect_hkdf_output_properties(control.get(), ctx.props));
        }
        ASSERT_NO_FATAL_FAILURE(change(ctx));
        auto_key rejected;
        ASSERT_EQ(ctx.derive(rejected), expected);
        ASSERT_EQ(rejected.get(), 0u);
    });
}

static void expect_hkdf_forbidden_flag(
    PartitionListHandle &part_list,
    HkdfOutputFamily family,
    tsra_key_prop_id flag
)
{
    expect_hkdf_property_rejected(
        part_list,
        family,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [flag](HkdfAttributeContext &ctx) {
            auto property = ctx.property(flag);
            ASSERT_NE(property, nullptr);
            ASSERT_FALSE(*static_cast<bool *>(property->val));
            *static_cast<bool *>(property->val) = true;
        }
    );
}

TEST_F(tsra_hkdf, attribute_aes_sign_rejected)
{
    expect_hkdf_forbidden_flag(part_list_, HkdfOutputFamily::Aes, TSRA_KEY_PROP_ID_SIGN);
}

TEST_F(tsra_hkdf, attribute_aes_verify_rejected)
{
    expect_hkdf_forbidden_flag(part_list_, HkdfOutputFamily::Aes, TSRA_KEY_PROP_ID_VERIFY);
}

TEST_F(tsra_hkdf, attribute_aes_derive_rejected)
{
    expect_hkdf_forbidden_flag(part_list_, HkdfOutputFamily::Aes, TSRA_KEY_PROP_ID_DERIVE);
}

TEST_F(tsra_hkdf, attribute_aes_wrap_rejected)
{
    expect_hkdf_forbidden_flag(part_list_, HkdfOutputFamily::Aes, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_hkdf, attribute_aes_unwrap_rejected)
{
    expect_hkdf_forbidden_flag(part_list_, HkdfOutputFamily::Aes, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_hkdf, attribute_hmac_encrypt_rejected)
{
    expect_hkdf_forbidden_flag(part_list_, HkdfOutputFamily::Hmac, TSRA_KEY_PROP_ID_ENCRYPT);
}

TEST_F(tsra_hkdf, attribute_hmac_decrypt_rejected)
{
    expect_hkdf_forbidden_flag(part_list_, HkdfOutputFamily::Hmac, TSRA_KEY_PROP_ID_DECRYPT);
}

TEST_F(tsra_hkdf, attribute_hmac_derive_rejected)
{
    expect_hkdf_forbidden_flag(part_list_, HkdfOutputFamily::Hmac, TSRA_KEY_PROP_ID_DERIVE);
}

TEST_F(tsra_hkdf, attribute_hmac_wrap_rejected)
{
    expect_hkdf_forbidden_flag(part_list_, HkdfOutputFamily::Hmac, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_hkdf, attribute_hmac_unwrap_rejected)
{
    expect_hkdf_forbidden_flag(part_list_, HkdfOutputFamily::Hmac, TSRA_KEY_PROP_ID_UNWRAP);
}

static void expect_hkdf_required_usages(PartitionListHandle &part_list, HkdfOutputFamily family)
{
    const auto first =
        family == HkdfOutputFamily::Aes ? TSRA_KEY_PROP_ID_ENCRYPT : TSRA_KEY_PROP_ID_SIGN;
    const auto second =
        family == HkdfOutputFamily::Aes ? TSRA_KEY_PROP_ID_DECRYPT : TSRA_KEY_PROP_ID_VERIFY;
    for (auto absent :
         { std::pair{ true, false }, std::pair{ false, true }, std::pair{ true, true } })
    {
        for (bool omit : { true, false })
        {
            SCOPED_TRACE(omit);
            expect_hkdf_property_rejected(
                part_list,
                family,
                TSRA_STATUS_INVALID_KEY_PROPS,
                [=](HkdfAttributeContext &ctx) {
                    for (auto id : { first, second })
                    {
                        if ((id == first && !absent.first) || (id == second && !absent.second))
                        {
                            continue;
                        }
                        if (omit)
                        {
                            remove_prop_by_id(ctx.properties, id);
                        }
                        else
                        {
                            auto property = ctx.property(id);
                            ASSERT_NE(property, nullptr);
                            *static_cast<bool *>(property->val) = false;
                        }
                    }
                    ctx.refresh_properties();
                }
            );
        }
    }
}

TEST_F(tsra_hkdf, attribute_aes_required_usages)
{
    expect_hkdf_required_usages(part_list_, HkdfOutputFamily::Aes);
}

TEST_F(tsra_hkdf, attribute_hmac_required_usages)
{
    expect_hkdf_required_usages(part_list_, HkdfOutputFamily::Hmac);
}

TEST_F(tsra_hkdf, attribute_output_class_rejected)
{
    for (auto key_class : { TSRA_KEY_CLASS_PRIVATE, TSRA_KEY_CLASS_PUBLIC })
    {
        SCOPED_TRACE(key_class);
        expect_hkdf_property_rejected(
            part_list_,
            HkdfOutputFamily::All,
            TSRA_STATUS_INVALID_KEY_PROPS,
            [key_class](HkdfAttributeContext &ctx) { ctx.props.key_class = key_class; }
        );
    }
}

TEST_F(tsra_hkdf, attribute_output_curve_rejected)
{
    expect_hkdf_property_rejected(
        part_list_,
        HkdfOutputFamily::All,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](HkdfAttributeContext &ctx) {
            ctx.storage[0] = ctx.curve;
            ctx.properties.push_back(
                { TSRA_KEY_PROP_ID_EC_CURVE, ctx.storage.data(), sizeof(uint32_t) }
            );
            ctx.refresh_properties();
        }
    );
}

static void expect_hkdf_missing_property(
    PartitionListHandle &part_list,
    tsra_key_prop_id id,
    tsra_status expected
)
{
    expect_hkdf_property_rejected(
        part_list,
        HkdfOutputFamily::All,
        expected,
        [id](HkdfAttributeContext &ctx) {
            remove_prop_by_id(ctx.properties, id);
            ctx.refresh_properties();
        }
    );
}

TEST_F(tsra_hkdf, attribute_missing_class)
{
    expect_hkdf_missing_property(
        part_list_,
        TSRA_KEY_PROP_ID_CLASS,
        TSRA_STATUS_KEY_CLASS_NOT_SPECIFIED
    );
}

TEST_F(tsra_hkdf, attribute_missing_kind)
{
    expect_hkdf_missing_property(
        part_list_,
        TSRA_KEY_PROP_ID_KIND,
        TSRA_STATUS_KEY_KIND_NOT_SPECIFIED
    );
}

TEST_F(tsra_hkdf, attribute_missing_bits)
{
    expect_hkdf_missing_property(
        part_list_,
        TSRA_KEY_PROP_ID_BIT_LEN,
        TSRA_STATUS_PROPERTY_NOT_PRESENT
    );
}

TEST_F(tsra_hkdf, attribute_invalid_enum)
{
    for (auto id : { TSRA_KEY_PROP_ID_CLASS, TSRA_KEY_PROP_ID_KIND, TSRA_KEY_PROP_ID_EC_CURVE })
    {
        SCOPED_TRACE(id);
        expect_hkdf_property_rejected(
            part_list_,
            HkdfOutputFamily::All,
            TSRA_STATUS_INVALID_ARGUMENT,
            [id](HkdfAttributeContext &ctx) {
                remove_prop_by_id(ctx.properties, id);
                ctx.storage[0] = std::numeric_limits<uint32_t>::max();
                ctx.properties.push_back({ id, ctx.storage.data(), sizeof(uint32_t) });
                ctx.refresh_properties();
            }
        );
    }
}

enum class HkdfEncodingProblem
{
    Null,
    Empty,
    Short,
    Long,
};

static void expect_hkdf_bad_encoding(PartitionListHandle &part_list, HkdfEncodingProblem problem)
{
    for (auto id : {
             TSRA_KEY_PROP_ID_CLASS,
             TSRA_KEY_PROP_ID_KIND,
             TSRA_KEY_PROP_ID_BIT_LEN,
             TSRA_KEY_PROP_ID_EC_CURVE,
             TSRA_KEY_PROP_ID_SESSION,
             TSRA_KEY_PROP_ID_ENCRYPT,
             TSRA_KEY_PROP_ID_DECRYPT,
             TSRA_KEY_PROP_ID_SIGN,
             TSRA_KEY_PROP_ID_VERIFY,
             TSRA_KEY_PROP_ID_DERIVE,
             TSRA_KEY_PROP_ID_WRAP,
             TSRA_KEY_PROP_ID_UNWRAP,
             TSRA_KEY_PROP_ID_LABEL,
         })
    {
        const uint32_t width = id == TSRA_KEY_PROP_ID_CLASS || id == TSRA_KEY_PROP_ID_KIND ||
                                       id == TSRA_KEY_PROP_ID_BIT_LEN ||
                                       id == TSRA_KEY_PROP_ID_EC_CURVE
                                   ? sizeof(uint32_t)
                                   : sizeof(uint8_t);
        if ((id == TSRA_KEY_PROP_ID_LABEL && problem != HkdfEncodingProblem::Null) ||
            (width == sizeof(uint8_t) && problem == HkdfEncodingProblem::Short))
        {
            continue;
        }
        SCOPED_TRACE(id);
        expect_hkdf_property_rejected(
            part_list,
            HkdfOutputFamily::All,
            TSRA_STATUS_INVALID_ARGUMENT,
            [=](HkdfAttributeContext &ctx) {
                remove_prop_by_id(ctx.properties, id);
                tsra_key_prop property{ id, ctx.storage.data(), width };
                switch (problem)
                {
                case HkdfEncodingProblem::Null:
                    property.val = nullptr;
                    break;
                case HkdfEncodingProblem::Empty:
                    property.len = 0;
                    break;
                case HkdfEncodingProblem::Short:
                    property.len = width - 1;
                    break;
                case HkdfEncodingProblem::Long:
                    property.len = width + 1;
                    break;
                }
                ASSERT_LE(property.len, sizeof(ctx.storage));
                ctx.properties.push_back(property);
                ctx.refresh_properties();
            }
        );
    }
}

TEST_F(tsra_hkdf, attribute_null_value)
{
    expect_hkdf_bad_encoding(part_list_, HkdfEncodingProblem::Null);
}

TEST_F(tsra_hkdf, attribute_empty_value)
{
    expect_hkdf_bad_encoding(part_list_, HkdfEncodingProblem::Empty);
}

TEST_F(tsra_hkdf, attribute_short_value)
{
    expect_hkdf_bad_encoding(part_list_, HkdfEncodingProblem::Short);
}

TEST_F(tsra_hkdf, attribute_long_value)
{
    expect_hkdf_bad_encoding(part_list_, HkdfEncodingProblem::Long);
}

TEST_F(tsra_hkdf, attribute_null_array)
{
    expect_hkdf_property_rejected(
        part_list_,
        HkdfOutputFamily::All,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](HkdfAttributeContext &ctx) { ctx.property_list.props = nullptr; }
    );
}

TEST_F(tsra_hkdf, attribute_empty_list)
{
    expect_hkdf_property_rejected(
        part_list_,
        HkdfOutputFamily::All,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](HkdfAttributeContext &ctx) { ctx.property_list.count = 0; }
    );
}

TEST_F(tsra_hkdf, attribute_null_list)
{
    for_each_hkdf_output(part_list_, HkdfOutputFamily::All, [](HkdfAttributeContext &ctx) {
        {
            auto_key control;
            ASSERT_EQ(ctx.derive(control), TSRA_STATUS_SUCCESS);
            ASSERT_NO_FATAL_FAILURE(expect_hkdf_output_properties(control.get(), ctx.props));
        }
        auto_key rejected;
        ASSERT_EQ(
            tsra_key_derive(ctx.session, &ctx.algo, ctx.secret.get(), nullptr, rejected.get_ptr()),
            TSRA_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(rejected.get(), 0u);
    });
}

TEST_F(tsra_hkdf, attribute_device_owned_properties)
{
    for (auto id :
         { TSRA_KEY_PROP_ID_LOCAL, TSRA_KEY_PROP_ID_SENSITIVE, TSRA_KEY_PROP_ID_EXTRACTABLE })
    {
        SCOPED_TRACE(id);
        expect_hkdf_property_rejected(
            part_list_,
            HkdfOutputFamily::All,
            TSRA_STATUS_INVALID_ARGUMENT,
            [id](HkdfAttributeContext &ctx) {
                ctx.properties.push_back({ id, ctx.storage.data(), sizeof(uint8_t) });
                ctx.refresh_properties();
            }
        );
    }
}

enum class HkdfBitsProblem
{
    Zero,
    One,
    Short,
    Long,
    Maximum,
};

TEST_F(tsra_hkdf, attribute_invalid_output_bits)
{
    for (auto problem : { HkdfBitsProblem::Zero,
                          HkdfBitsProblem::One,
                          HkdfBitsProblem::Short,
                          HkdfBitsProblem::Long,
                          HkdfBitsProblem::Maximum })
    {
        SCOPED_TRACE(static_cast<int>(problem));
        for_each_hkdf_output(
            part_list_,
            HkdfOutputFamily::All,
            [problem](HkdfAttributeContext &ctx) {
                {
                    auto_key control;
                    ASSERT_EQ(ctx.derive(control), TSRA_STATUS_SUCCESS);
                    ASSERT_NO_FATAL_FAILURE(expect_hkdf_output_properties(control.get(), ctx.props)
                    );
                }
                switch (problem)
                {
                case HkdfBitsProblem::Zero:
                    ctx.props.key_size_bits = 0;
                    break;
                case HkdfBitsProblem::One:
                    ctx.props.key_size_bits = 1;
                    break;
                case HkdfBitsProblem::Short:
                    --ctx.props.key_size_bits;
                    break;
                case HkdfBitsProblem::Long:
                    ++ctx.props.key_size_bits;
                    break;
                case HkdfBitsProblem::Maximum:
                    ctx.props.key_size_bits = std::numeric_limits<uint32_t>::max();
                    break;
                }
                const auto expected =
                    ctx.props.key_size_bits == 0 || ctx.props.key_kind != TSRA_KEY_KIND_AES
                        ? TSRA_STATUS_INVALID_KEY_PROPS
                        : TSRA_STATUS_INVALID_ARGUMENT;
                auto_key rejected;
                ASSERT_EQ(ctx.derive(rejected), expected);
                ASSERT_EQ(rejected.get(), 0u);
            }
        );
    }
}

static tsra_status hkdf_derive_with_algo(tsra_handle session, tsra_algo *algo, key_props props)
{
    auto_key secret_a;
    auto_key secret_b;
    derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

    std::vector<tsra_key_prop> derived_key_props;
    tsra_key_prop_list derived_key_prop_list = build_key_prop_list(props, derived_key_props);

    auto_key derived_key;

    return tsra_key_derive(
        session,
        algo,
        secret_a.get(),
        &derived_key_prop_list,
        derived_key.get_ptr()
    );
}

static tsra_status hkdf_derive_with_custom_params(
    tsra_handle session,
    tsra_algo_id hmac_algo_id,
    key_props props,
    tsra_buffer *salt,
    tsra_buffer *info
)
{
    auto_key secret_a;
    auto_key secret_b;
    derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

    tsra_algo_hkdf_params hkdf_params{};
    tsra_algo hkdf_algo{};
    build_hkdf_algo(hkdf_params, hkdf_algo, hmac_algo_id, salt, info);

    std::vector<tsra_key_prop> derived_key_props;
    tsra_key_prop_list derived_key_prop_list = build_key_prop_list(props, derived_key_props);

    auto_key derived_key;

    return tsra_key_derive(
        session,
        &hkdf_algo,
        secret_a.get(),
        &derived_key_prop_list,
        derived_key.get_ptr()
    );
}

static void init_test_aes_cbc_pad_algo(tsra_algo &algo, tsra_algo_aes_cbc_params &params)
{
    uint8_t iv[16] = { 0xA5 };
    std::memcpy(params.iv, iv, sizeof(iv));

    algo.id = TSRA_ALGO_ID_AES_CBC_PAD;
    algo.params = &params;
    algo.len = sizeof(params);
}

static void assert_aes_cbc_roundtrip_does_not_recover_plaintext(
    tsra_handle enc_key,
    tsra_handle dec_key,
    const uint8_t *plaintext,
    size_t plaintext_len
)
{
    tsra_algo_aes_cbc_params cbc_params{};
    tsra_algo crypt_algo{};
    init_test_aes_cbc_pad_algo(crypt_algo, cbc_params);

    std::vector<uint8_t> ciphertext;
    ASSERT_EQ(
        TSRA_STATUS_SUCCESS,
        ::single_shot_crypt(
            CryptOperation::Encrypt,
            enc_key,
            &crypt_algo,
            plaintext,
            plaintext_len,
            ciphertext
        )
    );

    init_test_aes_cbc_pad_algo(crypt_algo, cbc_params);

    std::vector<uint8_t> decrypted;
    tsra_status decrypt_status = ::single_shot_crypt(
        CryptOperation::Decrypt,
        dec_key,
        &crypt_algo,
        ciphertext.data(),
        ciphertext.size(),
        decrypted
    );

    // If decryption fails, that is expected for different key material.
    if (decrypt_status != TSRA_STATUS_SUCCESS)
    {
        SUCCEED();
        return;
    }

    // If decryption succeeds, it still must not recover the original plaintext.
    ASSERT_FALSE(
        decrypted.size() == plaintext_len &&
        std::memcmp(decrypted.data(), plaintext, plaintext_len) == 0
    );
}

// ============================================================
// Test cases
// ============================================================

/// Test HKDF derive with various HMAC hash algorithms for P-256 curve
TEST_F(tsra_hkdf, hkdf_matrix_p256)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_hkdf_matrix_for_curve(session, TSRA_ECC_CURVE_P256);
    });
}

/// Test HKDF derive with various HMAC hash algorithms for P-384 curve
TEST_F(tsra_hkdf, hkdf_matrix_p384)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_hkdf_matrix_for_curve(session, TSRA_ECC_CURVE_P384);
    });
}

/// Test HKDF derive with various HMAC hash algorithms for P-521 curve
TEST_F(tsra_hkdf, hkdf_matrix_p521)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_hkdf_matrix_for_curve(session, TSRA_ECC_CURVE_P521);
    });
}

/// Test that deriving an AES-GCM key with HKDF fails with InvalidKeyProps
TEST_F(tsra_hkdf, hkdf_derive_aes_gcm_key_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = {};
        props.key_class = TSRA_KEY_CLASS_SECRET;
        props.key_kind = TSRA_KEY_KIND_AES_GCM;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            TSRA_ALGO_ID_HMAC_SHA256,
            props,
            TSRA_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test that deriving a key with SharedSecret kind fails with InvalidArgument
TEST_F(tsra_hkdf, hkdf_derive_unsupported_key_kind_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = {};
        props.key_class = TSRA_KEY_CLASS_SECRET;
        props.key_kind = TSRA_KEY_KIND_SHARED_SECRET;
        props.key_size_bits = 256;
        props.derive = 1;

        hkdf_derive_fails_common(
            session,
            TSRA_ALGO_ID_HMAC_SHA256,
            props,
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that deriving a key with an invalid HMAC algorithm fails with InvalidArgument
TEST_F(tsra_hkdf, hkdf_derive_invalid_hmac_algo_id_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = {};
        props.key_class = TSRA_KEY_CLASS_SECRET;
        props.key_kind = TSRA_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(session, TSRA_ALGO_ID_SHA256, props, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

/// Test that deriving a key with zero bit length fails with InvalidKeyProps
TEST_F(tsra_hkdf, hkdf_derive_zero_bit_len_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = {};
        props.key_class = TSRA_KEY_CLASS_SECRET;
        props.key_kind = TSRA_KEY_KIND_AES;
        props.key_size_bits = 0;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            TSRA_ALGO_ID_HMAC_SHA256,
            props,
            TSRA_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test that deriving a key with empty salt and info buffers succeeds (since salt and info are
/// optional in HKDF) and produces correct output
TEST_F(tsra_hkdf, hkdf_empty_salt_info_roundtrip)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        // Empty (zero-length) salt and info buffers.
        tsra_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        tsra_buffer info_buf = { .ptr = nullptr, .len = 0 };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "empty salt info";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF accepts non-null salt/info pointers with zero lengths
TEST_F(tsra_hkdf, hkdf_allows_non_null_salt_info_with_zero_len)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt[] = { 0xAA, 0xBB, 0xCC };
        uint8_t info[] = { 0x01, 0x02, 0x03 };

        tsra_buffer salt_buf = { .ptr = salt, .len = 0 };
        tsra_buffer info_buf = { .ptr = info, .len = 0 };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "zero length salt info";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF supports AES-128 output key size
TEST_F(tsra_hkdf, hkdf_supports_aes_128)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt[] = { 0x10, 0x20, 0x30 };
        uint8_t info[] = { 0x40, 0x50, 0x60 };

        tsra_buffer salt_buf = { .ptr = salt, .len = static_cast<uint32_t>(sizeof(salt)) };

        tsra_buffer info_buf = {
            .ptr = info,
            .len = static_cast<uint32_t>(sizeof(info)),
        };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 128, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 128, key_b);

        const char *msg = "hkdf aes 128";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF supports AES-192 output key size
TEST_F(tsra_hkdf, hkdf_supports_aes_192)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt[] = { 0x10, 0x20, 0x30 };
        uint8_t info[] = { 0x40, 0x50, 0x60 };

        tsra_buffer salt_buf = { .ptr = salt, .len = static_cast<uint32_t>(sizeof(salt)) };

        tsra_buffer info_buf = { .ptr = info, .len = static_cast<uint32_t>(sizeof(info)) };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 192, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 192, key_b);

        const char *msg = "hkdf aes 192";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF rejects invalid AES output key size
TEST_F(tsra_hkdf, hkdf_rejects_invalid_aes_key_size)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = {};
        props.key_class = TSRA_KEY_CLASS_SECRET;
        props.key_kind = TSRA_KEY_KIND_AES;
        props.key_size_bits = 129;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            TSRA_ALGO_ID_HMAC_SHA256,
            props,
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that identical HKDF inputs produce compatible derived keys
TEST_F(tsra_hkdf, hkdf_same_inputs_are_deterministic)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt[] = { 0x11, 0x22, 0x33, 0x44 };
        uint8_t info[] = { 0x55, 0x66, 0x77, 0x88 };

        tsra_buffer salt_buf = { .ptr = salt, .len = static_cast<uint32_t>(sizeof(salt)) };

        tsra_buffer info_buf = { .ptr = info, .len = static_cast<uint32_t>(sizeof(info)) };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "same inputs deterministic";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF rejects very small invalid AES output key size
TEST_F(tsra_hkdf, hkdf_rejects_too_small_aes_key_size)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = {};
        props.key_class = TSRA_KEY_CLASS_SECRET;
        props.key_kind = TSRA_KEY_KIND_AES;
        props.key_size_bits = 1;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            TSRA_ALGO_ID_HMAC_SHA256,
            props,
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test empty salt/info roundtrip for P-384
TEST_F(tsra_hkdf, hkdf_empty_salt_info_roundtrip_p384)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P384, secret_a, secret_b);

        tsra_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        tsra_buffer info_buf = { .ptr = nullptr, .len = 0 };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "empty salt info p384";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test empty salt/info roundtrip for P-521
TEST_F(tsra_hkdf, hkdf_empty_salt_info_roundtrip_p521)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P521, secret_a, secret_b);

        tsra_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        tsra_buffer info_buf = { .ptr = nullptr, .len = 0 };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "empty salt info p521";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF accepts large salt/info buffers
TEST_F(tsra_hkdf, hkdf_salt_info_roundtrip)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        std::vector<uint8_t> salt(64, 0xA5);
        std::vector<uint8_t> info(64, 0x5A);

        tsra_buffer salt_buf = { .ptr = salt.data(), .len = static_cast<uint32_t>(salt.size()) };

        tsra_buffer info_buf = { .ptr = info.data(), .len = static_cast<uint32_t>(info.size()) };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "large salt info";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF rejects public output key class
TEST_F(tsra_hkdf, hkdf_rejects_public_output_key_class)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = {};
        props.key_class = TSRA_KEY_CLASS_PUBLIC;
        props.key_kind = TSRA_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            TSRA_ALGO_ID_HMAC_SHA256,
            props,
            TSRA_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test that HKDF supports AES-256 output key size
TEST_F(tsra_hkdf, hkdf_supports_aes_256)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt[] = { 0x10, 0x20, 0x30 };
        uint8_t info[] = { 0x40, 0x50, 0x60 };

        tsra_buffer salt_buf = { .ptr = salt, .len = static_cast<uint32_t>(sizeof(salt)) };

        tsra_buffer info_buf = { .ptr = info, .len = static_cast<uint32_t>(sizeof(info)) };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "hkdf aes 256";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF rejects oversized AES output key size
TEST_F(tsra_hkdf, hkdf_rejects_oversized_aes_key_size)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = {};
        props.key_class = TSRA_KEY_CLASS_SECRET;
        props.key_kind = TSRA_KEY_KIND_AES;
        props.key_size_bits = 1024;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            TSRA_ALGO_ID_HMAC_SHA256,
            props,
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that HKDF rejects AES output key with no usage flags
TEST_F(tsra_hkdf, hkdf_rejects_aes_key_without_usage_flags)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = {};
        props.key_class = TSRA_KEY_CLASS_SECRET;
        props.key_kind = TSRA_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 0;
        props.decrypt = 0;

        hkdf_derive_fails_common(
            session,
            TSRA_ALGO_ID_HMAC_SHA256,
            props,
            TSRA_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test HKDF derive when only salt is provided
TEST_F(tsra_hkdf, hkdf_with_only_salt)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt[] = { 'h', 'k', 'd', 'f', '-', 's', 'a', 'l', 't' };
        tsra_buffer salt_buf = { .ptr = salt, .len = static_cast<uint32_t>(sizeof(salt)) };

        for (uint32_t bits : { 128u, 192u, 256u })
        {
            tsra_algo_hkdf_params hkdf_params{};
            tsra_algo hkdf_algo{};
            build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, nullptr);

            auto_key key_a;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), bits, key_a);

            auto_key key_b;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), bits, key_b);

            std::string msg = "hkdf only salt aes " + std::to_string(bits);
            assert_aes_cbc_roundtrip(
                key_a.get(),
                key_b.get(),
                reinterpret_cast<const uint8_t *>(msg.data()),
                msg.size()
            );
        }
    });
}

/// Test HKDF derive when only info is provided
TEST_F(tsra_hkdf, hkdf_with_only_info)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t info[] = { 'h', 'k', 'd', 'f', '-', 'i', 'n', 'f', 'o' };
        tsra_buffer info_buf = { .ptr = info, .len = static_cast<uint32_t>(sizeof(info)) };

        for (uint32_t bits : { 128u, 192u, 256u })
        {
            tsra_algo_hkdf_params hkdf_params{};
            tsra_algo hkdf_algo{};
            build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, nullptr, &info_buf);

            auto_key key_a;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), bits, key_a);

            auto_key key_b;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), bits, key_b);

            std::string msg = "hkdf only info aes " + std::to_string(bits);
            assert_aes_cbc_roundtrip(
                key_a.get(),
                key_b.get(),
                reinterpret_cast<const uint8_t *>(msg.data()),
                msg.size()
            );
        }
    });
}

/// Test HKDF-derived AES keys with large plaintext
TEST_F(tsra_hkdf, hkdf_large_plaintext_roundtrip)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        tsra_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        tsra_buffer info_buf = { .ptr = nullptr, .len = 0 };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        std::vector<uint8_t> plaintext(32 * 1024, 0x55);

        assert_aes_cbc_roundtrip(key_a.get(), key_b.get(), plaintext.data(), plaintext.size());
    });
}

/// Test HKDF-derived AES keys with empty plaintext
TEST_F(tsra_hkdf, hkdf_empty_plaintext_roundtrip)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        tsra_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        tsra_buffer info_buf = { .ptr = nullptr, .len = 0 };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const uint8_t *plaintext = reinterpret_cast<const uint8_t *>("");

        assert_aes_cbc_roundtrip(key_a.get(), key_b.get(), plaintext, 0);
    });
}

/// Test HKDF-derived AES keys with single-byte plaintext
TEST_F(tsra_hkdf, hkdf_single_byte_plaintext_roundtrip)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        tsra_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        tsra_buffer info_buf = { .ptr = nullptr, .len = 0 };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const uint8_t plaintext[] = { 'A' };

        assert_aes_cbc_roundtrip(key_a.get(), key_b.get(), plaintext, sizeof(plaintext));
    });
}

/// Test deriving multiple AES key sizes using the same HKDF parameters
TEST_F(tsra_hkdf, hkdf_multi_key_size_roundtrip)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        tsra_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        tsra_buffer info_buf = { .ptr = nullptr, .len = 0 };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        for (uint32_t bits : { 128u, 192u, 256u })
        {
            auto_key key_a;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), bits, key_a);

            auto_key key_b;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), bits, key_b);

            const char *msg = "multi key size";
            assert_aes_cbc_roundtrip(
                key_a.get(),
                key_b.get(),
                reinterpret_cast<const uint8_t *>(msg),
                std::strlen(msg)
            );
        }
    });
}

/// Test HKDF with 128-byte salt/info buffers
TEST_F(tsra_hkdf, hkdf_long_salt_info_roundtrip)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        std::vector<uint8_t> salt(128, 0x11);
        std::vector<uint8_t> info(128, 0x22);

        tsra_buffer salt_buf = { .ptr = salt.data(), .len = static_cast<uint32_t>(salt.size()) };

        tsra_buffer info_buf = { .ptr = info.data(), .len = static_cast<uint32_t>(info.size()) };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "long salt info";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF derive rejects a null algorithm pointer.
TEST_F(tsra_hkdf, hkdf_null_algo_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        EXPECT_EQ(
            hkdf_derive_with_algo(session, nullptr, valid_hkdf_aes_props()),
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that HKDF derive rejects null HKDF params.
TEST_F(tsra_hkdf, hkdf_null_algo_params_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        tsra_algo hkdf_algo = {};
        hkdf_algo.id = TSRA_ALGO_ID_HKDF_DERIVE;
        hkdf_algo.params = nullptr;
        hkdf_algo.len = sizeof(tsra_algo_hkdf_params);

        EXPECT_EQ(
            hkdf_derive_with_algo(session, &hkdf_algo, valid_hkdf_aes_props()),
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that HKDF derive rejects zero HKDF params length.
TEST_F(tsra_hkdf, hkdf_zero_algo_params_len_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        uint8_t salt[] = { 0x01, 0x02, 0x03 };
        uint8_t info[] = { 0x04, 0x05, 0x06 };

        tsra_buffer salt_buf = {
            .ptr = salt,
            .len = static_cast<uint32_t>(sizeof(salt)),
        };

        tsra_buffer info_buf = {
            .ptr = info,
            .len = static_cast<uint32_t>(sizeof(info)),
        };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        hkdf_algo.len = 0;

        EXPECT_EQ(
            hkdf_derive_with_algo(session, &hkdf_algo, valid_hkdf_aes_props()),
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that HKDF derive rejects a mismatched HKDF params length.
TEST_F(tsra_hkdf, hkdf_algo_params_len_mismatch_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        uint8_t salt[] = { 0x01, 0x02, 0x03 };
        uint8_t info[] = { 0x04, 0x05, 0x06 };

        tsra_buffer salt_buf = {
            .ptr = salt,
            .len = static_cast<uint32_t>(sizeof(salt)),
        };

        tsra_buffer info_buf = {
            .ptr = info,
            .len = static_cast<uint32_t>(sizeof(info)),
        };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        hkdf_algo.len = sizeof(tsra_algo_hkdf_params) - 1;

        EXPECT_EQ(
            hkdf_derive_with_algo(session, &hkdf_algo, valid_hkdf_aes_props()),
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that HKDF derive rejects a null derived-key output pointer.
TEST_F(tsra_hkdf, hkdf_null_derived_key_output_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt[] = { 0x01, 0x02, 0x03 };
        uint8_t info[] = { 0x04, 0x05, 0x06 };

        tsra_buffer salt_buf = {
            .ptr = salt,
            .len = static_cast<uint32_t>(sizeof(salt)),
        };

        tsra_buffer info_buf = {
            .ptr = info,
            .len = static_cast<uint32_t>(sizeof(info)),
        };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        key_props props = valid_hkdf_aes_props();

        std::vector<tsra_key_prop> derived_key_props;
        tsra_key_prop_list derived_key_prop_list = build_key_prop_list(props, derived_key_props);

        EXPECT_EQ(
            tsra_key_derive(session, &hkdf_algo, secret_a.get(), &derived_key_prop_list, nullptr),
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that HKDF derive rejects a null derived-key property list.
TEST_F(tsra_hkdf, hkdf_null_derived_key_props_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt[] = { 0x01, 0x02, 0x03 };
        uint8_t info[] = { 0x04, 0x05, 0x06 };

        tsra_buffer salt_buf = {
            .ptr = salt,
            .len = static_cast<uint32_t>(sizeof(salt)),
        };

        tsra_buffer info_buf = {
            .ptr = info,
            .len = static_cast<uint32_t>(sizeof(info)),
        };

        tsra_algo_hkdf_params hkdf_params{};
        tsra_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, TSRA_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key derived_key;

        EXPECT_EQ(
            tsra_key_derive(session, &hkdf_algo, secret_a.get(), nullptr, derived_key.get_ptr()),
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that HKDF derive rejects a salt buffer with null pointer and non-zero length.
TEST_F(tsra_hkdf, hkdf_null_salt_with_nonzero_len_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = valid_hkdf_aes_props();

        uint8_t info[] = { 0x04, 0x05, 0x06 };

        tsra_buffer invalid_salt_buf = {
            .ptr = nullptr,
            .len = 1,
        };

        tsra_buffer info_buf = {
            .ptr = info,
            .len = static_cast<uint32_t>(sizeof(info)),
        };

        EXPECT_EQ(
            hkdf_derive_with_custom_params(
                session,
                TSRA_ALGO_ID_HMAC_SHA256,
                props,
                &invalid_salt_buf,
                &info_buf
            ),
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that HKDF derive rejects an info buffer with null pointer and non-zero length.
TEST_F(tsra_hkdf, hkdf_null_info_with_nonzero_len_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        key_props props = valid_hkdf_aes_props();

        uint8_t salt[] = { 0x01, 0x02, 0x03 };

        tsra_buffer salt_buf = {
            .ptr = salt,
            .len = static_cast<uint32_t>(sizeof(salt)),
        };

        tsra_buffer invalid_info_buf = {
            .ptr = nullptr,
            .len = 1,
        };

        EXPECT_EQ(
            hkdf_derive_with_custom_params(
                session,
                TSRA_ALGO_ID_HMAC_SHA256,
                props,
                &salt_buf,
                &invalid_info_buf
            ),
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that changing HKDF salt changes the derived key material.
TEST_F(tsra_hkdf, hkdf_different_salt_produces_non_interoperable_key)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt_a[] = { 's', 'a', 'l', 't', '-', 'a' };
        uint8_t salt_b[] = { 's', 'a', 'l', 't', '-', 'b' };
        uint8_t info[] = { 's', 'a', 'm', 'e', '-', 'i', 'n', 'f', 'o' };

        tsra_buffer salt_a_buf = {
            .ptr = salt_a,
            .len = static_cast<uint32_t>(sizeof(salt_a)),
        };

        tsra_buffer salt_b_buf = {
            .ptr = salt_b,
            .len = static_cast<uint32_t>(sizeof(salt_b)),
        };

        tsra_buffer info_buf = {
            .ptr = info,
            .len = static_cast<uint32_t>(sizeof(info)),
        };

        tsra_algo_hkdf_params hkdf_params_a{};
        tsra_algo hkdf_algo_a{};
        build_hkdf_algo(
            hkdf_params_a,
            hkdf_algo_a,
            TSRA_ALGO_ID_HMAC_SHA256,
            &salt_a_buf,
            &info_buf
        );

        tsra_algo_hkdf_params hkdf_params_b{};
        tsra_algo hkdf_algo_b{};
        build_hkdf_algo(
            hkdf_params_b,
            hkdf_algo_b,
            TSRA_ALGO_ID_HMAC_SHA256,
            &salt_b_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo_a, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo_b, secret_b.get(), 256, key_b);

        const char *msg = "HKDF different salt should not interoperate";

        assert_aes_cbc_roundtrip_does_not_recover_plaintext(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that changing HKDF info changes the derived key material.
TEST_F(tsra_hkdf, hkdf_different_info_produces_non_interoperable_key)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, TSRA_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt[] = { 's', 'a', 'm', 'e', '-', 's', 'a', 'l', 't' };
        uint8_t info_a[] = { 'i', 'n', 'f', 'o', '-', 'a' };
        uint8_t info_b[] = { 'i', 'n', 'f', 'o', '-', 'b' };

        tsra_buffer salt_buf = {
            .ptr = salt,
            .len = static_cast<uint32_t>(sizeof(salt)),
        };

        tsra_buffer info_a_buf = {
            .ptr = info_a,
            .len = static_cast<uint32_t>(sizeof(info_a)),
        };

        tsra_buffer info_b_buf = {
            .ptr = info_b,
            .len = static_cast<uint32_t>(sizeof(info_b)),
        };

        tsra_algo_hkdf_params hkdf_params_a{};
        tsra_algo hkdf_algo_a{};
        build_hkdf_algo(
            hkdf_params_a,
            hkdf_algo_a,
            TSRA_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_a_buf
        );

        tsra_algo_hkdf_params hkdf_params_b{};
        tsra_algo hkdf_algo_b{};
        build_hkdf_algo(
            hkdf_params_b,
            hkdf_algo_b,
            TSRA_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_b_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo_a, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo_b, secret_b.get(), 256, key_b);

        const char *msg = "HKDF different info should not interoperate";

        assert_aes_cbc_roundtrip_does_not_recover_plaintext(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}
