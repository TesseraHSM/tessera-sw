// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <limits>
#include <utility>

#include "handle/part_list_handle.hpp"
#include "helpers.hpp"
#include "utils/key_props.hpp"
#include "utils/shared_secret.hpp"

class tsra_ecdh_derive : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

struct EcdhDeriveContext
{
    EcdhDeriveContext() = default;
    EcdhDeriveContext(const EcdhDeriveContext &) = delete;
    EcdhDeriveContext &operator=(const EcdhDeriveContext &) = delete;

    tsra_handle session = 0;
    auto_key private_key;
    auto_key public_key;
    std::vector<uint8_t> peer_der;
    tsra_buffer peer{};
    tsra_algo_ecdh_params params{};
    tsra_algo algo{};
    key_props secret_props{};
    std::vector<tsra_key_prop> properties;
    tsra_key_prop_list property_list{};
    std::array<uint32_t, 2> property_storage{};

    void init(tsra_handle session_handle, tsra_ecc_curve curve, bool can_derive = true)
    {
        session = session_handle;
        DefaultEccPrivKeyProps private_props;
        DefaultEccPubKeyProps public_props;
        set_ecc_pair_properties(private_props, public_props, curve, can_derive, true);
        auto private_list = private_props.get_prop_list();
        auto public_list = public_props.get_prop_list();
        tsra_algo keygen{ TSRA_ALGO_ID_EC_KEY_PAIR_GEN, nullptr, 0 };
        ASSERT_EQ(
            tsra_key_gen_pair(
                session,
                &keygen,
                &private_list,
                &public_list,
                private_key.get_ptr(),
                public_key.get_ptr()
            ),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(private_key.get(), 0u);
        ASSERT_NE(public_key.get(), 0u);

        tsra_key_prop public_info{ TSRA_KEY_PROP_ID_PUB_KEY_INFO, nullptr, 0 };
        ASSERT_EQ(tsra_key_get_prop(public_key.get(), &public_info), TSRA_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(public_info.len, 0u);
        peer_der.resize(public_info.len);
        public_info.val = peer_der.data();
        ASSERT_EQ(tsra_key_get_prop(public_key.get(), &public_info), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(public_info.len, peer_der.size());
        peer = { peer_der.data(), public_info.len };
        params.pub_key = &peer;
        algo = { TSRA_ALGO_ID_ECDH, &params, sizeof(params) };

        secret_props.key_class = TSRA_KEY_CLASS_SECRET;
        secret_props.key_kind = TSRA_KEY_KIND_SHARED_SECRET;
        secret_props.key_size_bits = get_curve_key_bits(curve);
        secret_props.derive = true;
        property_list = build_key_prop_list(secret_props, properties);
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

    tsra_status derive(auto_key &secret)
    {
        return tsra_key_derive(session, &algo, private_key.get(), &property_list, secret.get_ptr());
    }
};

template <typename Check>
static void for_each_ecdh_curve(PartitionListHandle &part_list, Check check)
{
    for (const auto &curve : ECC_CURVES)
    {
        SCOPED_TRACE(curve.test_name);
        part_list.for_each_session([&](tsra_handle session) {
            EcdhDeriveContext ctx;
            ASSERT_NO_FATAL_FAILURE(ctx.init(session, curve.curve));
            check(ctx, curve.curve);
        });
    }
}

static void expect_ecdh_secret_properties(
    tsra_handle secret,
    tsra_ecc_curve curve,
    bool session_key
)
{
    ASSERT_NE(secret, 0u);
    tsra_key_class key_class = TSRA_KEY_CLASS_PUBLIC;
    tsra_key_kind kind = TSRA_KEY_KIND_ECC;
    uint32_t bits = 0;
    ASSERT_EQ(get_key_prop(secret, TSRA_KEY_PROP_ID_CLASS, key_class), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(get_key_prop(secret, TSRA_KEY_PROP_ID_KIND, kind), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(get_key_prop(secret, TSRA_KEY_PROP_ID_BIT_LEN, bits), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(key_class, TSRA_KEY_CLASS_SECRET);
    ASSERT_EQ(kind, TSRA_KEY_KIND_SHARED_SECRET);
    ASSERT_EQ(bits, get_curve_key_bits(curve));
    for (const auto &[id, expected] : {
             std::pair{ TSRA_KEY_PROP_ID_SESSION, static_cast<uint8_t>(session_key) },
             std::pair{ TSRA_KEY_PROP_ID_LOCAL, uint8_t{ 1 } },
             std::pair{ TSRA_KEY_PROP_ID_SENSITIVE, uint8_t{ 1 } },
             std::pair{ TSRA_KEY_PROP_ID_EXTRACTABLE, uint8_t{ 1 } },
             std::pair{ TSRA_KEY_PROP_ID_DERIVE, uint8_t{ 1 } },
             std::pair{ TSRA_KEY_PROP_ID_ENCRYPT, uint8_t{ 0 } },
             std::pair{ TSRA_KEY_PROP_ID_DECRYPT, uint8_t{ 0 } },
             std::pair{ TSRA_KEY_PROP_ID_SIGN, uint8_t{ 0 } },
             std::pair{ TSRA_KEY_PROP_ID_VERIFY, uint8_t{ 0 } },
             std::pair{ TSRA_KEY_PROP_ID_WRAP, uint8_t{ 0 } },
             std::pair{ TSRA_KEY_PROP_ID_UNWRAP, uint8_t{ 0 } },
         })
    {
        SCOPED_TRACE(id);
        uint8_t value = 0;
        ASSERT_EQ(get_key_prop(secret, id, value), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(value, expected);
    }
    tsra_ecc_curve no_curve = TSRA_ECC_CURVE_P256;
    ASSERT_EQ(
        get_key_prop(secret, TSRA_KEY_PROP_ID_EC_CURVE, no_curve),
        TSRA_STATUS_PROPERTY_NOT_PRESENT
    );
}

TEST_F(tsra_ecdh_derive, session_properties)
{
    for_each_ecdh_curve(part_list_, [](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
        auto_key secret;
        ASSERT_EQ(ctx.derive(secret), TSRA_STATUS_SUCCESS);
        expect_ecdh_secret_properties(secret.get(), curve, true);
    });
}

template <typename Change>
static void expect_ecdh_property_rejected(
    PartitionListHandle &part_list,
    tsra_status expected,
    Change change
)
{
    for_each_ecdh_curve(part_list, [&](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
        {
            auto_key control;
            ASSERT_EQ(ctx.derive(control), TSRA_STATUS_SUCCESS);
            ASSERT_NO_FATAL_FAILURE(expect_ecdh_secret_properties(control.get(), curve, true));
        }
        ASSERT_NO_FATAL_FAILURE(change(ctx, curve));
        auto_key rejected;
        ASSERT_EQ(ctx.derive(rejected), expected);
        ASSERT_EQ(rejected.get(), 0u);
    });
}

static void expect_ecdh_flag_rejected(PartitionListHandle &part_list, tsra_key_prop_id flag)
{
    expect_ecdh_property_rejected(
        part_list,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [flag](EcdhDeriveContext &ctx, tsra_ecc_curve) {
            auto property = ctx.property(flag);
            ASSERT_NE(property, nullptr);
            ASSERT_FALSE(*static_cast<bool *>(property->val));
            *static_cast<bool *>(property->val) = true;
        }
    );
}

TEST_F(tsra_ecdh_derive, wrap_rejected)
{
    expect_ecdh_flag_rejected(part_list_, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_ecdh_derive, unwrap_rejected)
{
    expect_ecdh_flag_rejected(part_list_, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_ecdh_derive, encrypt_rejected)
{
    expect_ecdh_flag_rejected(part_list_, TSRA_KEY_PROP_ID_ENCRYPT);
}

TEST_F(tsra_ecdh_derive, decrypt_rejected)
{
    expect_ecdh_flag_rejected(part_list_, TSRA_KEY_PROP_ID_DECRYPT);
}

TEST_F(tsra_ecdh_derive, sign_rejected)
{
    expect_ecdh_flag_rejected(part_list_, TSRA_KEY_PROP_ID_SIGN);
}

TEST_F(tsra_ecdh_derive, verify_rejected)
{
    expect_ecdh_flag_rejected(part_list_, TSRA_KEY_PROP_ID_VERIFY);
}

TEST_F(tsra_ecdh_derive, persistent_properties)
{
    for_each_ecdh_curve(part_list_, [](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
        ctx.secret_props.session_key = false;
        auto_key secret;
        ASSERT_EQ(ctx.derive(secret), TSRA_STATUS_SUCCESS);
        expect_ecdh_secret_properties(secret.get(), curve, false);
    });
}

TEST_F(tsra_ecdh_derive, labels_preserved)
{
    constexpr size_t documented_label_capacity = 128;
    for (bool session_key : { true, false })
    {
        for (auto label : {
                 std::vector<uint8_t>{},
                 std::vector<uint8_t>{ 'e', 'c', 'd', 'h' },
                 std::vector<uint8_t>(documented_label_capacity - 1, 'x'),
             })
        {
            SCOPED_TRACE(label.size());
            for_each_ecdh_curve(part_list_, [&](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
                uint8_t empty_label = 0;
                ctx.secret_props.session_key = session_key;
                ctx.properties.push_back({
                    TSRA_KEY_PROP_ID_LABEL,
                    label.empty() ? &empty_label : label.data(),
                    static_cast<uint32_t>(label.size()),
                });
                ctx.refresh_properties();
                auto_key secret;
                ASSERT_EQ(ctx.derive(secret), TSRA_STATUS_SUCCESS);
                ASSERT_NO_FATAL_FAILURE(
                    expect_ecdh_secret_properties(secret.get(), curve, session_key)
                );
                std::vector<uint8_t> actual(label.size() + sizeof(uint8_t));
                tsra_key_prop label_prop{
                    TSRA_KEY_PROP_ID_LABEL,
                    actual.data(),
                    static_cast<uint32_t>(actual.size()),
                };
                ASSERT_EQ(tsra_key_get_prop(secret.get(), &label_prop), TSRA_STATUS_SUCCESS);
                ASSERT_EQ(label_prop.len, label.size());
                actual.resize(label_prop.len);
                ASSERT_EQ(actual, label);
            });
        }
    }
}

TEST_F(tsra_ecdh_derive, wrong_class_rejected)
{
    for (auto key_class : { TSRA_KEY_CLASS_PRIVATE, TSRA_KEY_CLASS_PUBLIC })
    {
        SCOPED_TRACE(key_class);
        expect_ecdh_property_rejected(
            part_list_,
            TSRA_STATUS_INVALID_KEY_PROPS,
            [key_class](EcdhDeriveContext &ctx, tsra_ecc_curve) {
                ctx.secret_props.key_class = key_class;
            }
        );
    }
}

TEST_F(tsra_ecdh_derive, wrong_kind_rejected)
{
    for (auto kind : { TSRA_KEY_KIND_ECC, TSRA_KEY_KIND_RSA, TSRA_KEY_KIND_AES })
    {
        SCOPED_TRACE(kind);
        expect_ecdh_property_rejected(
            part_list_,
            TSRA_STATUS_INVALID_KEY_PROPS,
            [kind](EcdhDeriveContext &ctx, tsra_ecc_curve) { ctx.secret_props.key_kind = kind; }
        );
    }
}

TEST_F(tsra_ecdh_derive, missing_derive_rejected)
{
    expect_ecdh_property_rejected(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](EcdhDeriveContext &ctx, tsra_ecc_curve) {
            remove_prop_by_id(ctx.properties, TSRA_KEY_PROP_ID_DERIVE);
            ctx.refresh_properties();
        }
    );
}

TEST_F(tsra_ecdh_derive, derive_false_rejected)
{
    expect_ecdh_property_rejected(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](EcdhDeriveContext &ctx, tsra_ecc_curve) { ctx.secret_props.derive = false; }
    );
}

TEST_F(tsra_ecdh_derive, ecc_curve_rejected)
{
    expect_ecdh_property_rejected(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
            ctx.property_storage[0] = curve;
            ctx.properties.push_back(
                { TSRA_KEY_PROP_ID_EC_CURVE, ctx.property_storage.data(), sizeof(uint32_t) }
            );
            ctx.refresh_properties();
        }
    );
}

TEST_F(tsra_ecdh_derive, invalid_bits_rejected)
{
    for (uint32_t bits : {
             0u,
             1u,
             std::numeric_limits<uint32_t>::max(),
             get_curve_key_bits(TSRA_ECC_CURVE_P256) - 1,
             get_curve_key_bits(TSRA_ECC_CURVE_P256),
             get_curve_key_bits(TSRA_ECC_CURVE_P256) + 1,
             get_curve_key_bits(TSRA_ECC_CURVE_P384) - 1,
             get_curve_key_bits(TSRA_ECC_CURVE_P384),
             get_curve_key_bits(TSRA_ECC_CURVE_P384) + 1,
             get_curve_key_bits(TSRA_ECC_CURVE_P521) - 1,
             get_curve_key_bits(TSRA_ECC_CURVE_P521),
             get_curve_key_bits(TSRA_ECC_CURVE_P521) + 1,
         })
    {
        SCOPED_TRACE(bits);
        for_each_ecdh_curve(part_list_, [bits](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
            if (bits == get_curve_key_bits(curve))
            {
                return;
            }
            {
                auto_key control;
                ASSERT_EQ(ctx.derive(control), TSRA_STATUS_SUCCESS);
                ASSERT_NO_FATAL_FAILURE(expect_ecdh_secret_properties(control.get(), curve, true));
            }
            ctx.secret_props.key_size_bits = bits;
            auto_key rejected;
            ASSERT_EQ(ctx.derive(rejected), TSRA_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(rejected.get(), 0u);
        });
    }
}

static void expect_ecdh_missing_property(
    PartitionListHandle &part_list,
    tsra_key_prop_id id,
    tsra_status expected
)
{
    expect_ecdh_property_rejected(
        part_list,
        expected,
        [id](EcdhDeriveContext &ctx, tsra_ecc_curve) {
            remove_prop_by_id(ctx.properties, id);
            ctx.refresh_properties();
        }
    );
}

TEST_F(tsra_ecdh_derive, missing_class_rejected)
{
    expect_ecdh_missing_property(
        part_list_,
        TSRA_KEY_PROP_ID_CLASS,
        TSRA_STATUS_KEY_CLASS_NOT_SPECIFIED
    );
}

TEST_F(tsra_ecdh_derive, missing_kind_rejected)
{
    expect_ecdh_missing_property(
        part_list_,
        TSRA_KEY_PROP_ID_KIND,
        TSRA_STATUS_KEY_KIND_NOT_SPECIFIED
    );
}

TEST_F(tsra_ecdh_derive, missing_bits_rejected)
{
    expect_ecdh_missing_property(
        part_list_,
        TSRA_KEY_PROP_ID_BIT_LEN,
        TSRA_STATUS_PROPERTY_NOT_PRESENT
    );
}

TEST_F(tsra_ecdh_derive, invalid_enum_rejected)
{
    for (auto id : { TSRA_KEY_PROP_ID_CLASS, TSRA_KEY_PROP_ID_KIND, TSRA_KEY_PROP_ID_EC_CURVE })
    {
        SCOPED_TRACE(id);
        expect_ecdh_property_rejected(
            part_list_,
            TSRA_STATUS_INVALID_ARGUMENT,
            [id](EcdhDeriveContext &ctx, tsra_ecc_curve) {
                remove_prop_by_id(ctx.properties, id);
                ctx.property_storage[0] = std::numeric_limits<uint32_t>::max();
                ctx.properties.push_back({ id, ctx.property_storage.data(), sizeof(uint32_t) });
                ctx.refresh_properties();
            }
        );
    }
}

enum class EcdhEncodingProblem
{
    NullValue,
    EmptyValue,
    ShortValue,
    LongValue,
};

static void expect_ecdh_encoding_rejected(
    PartitionListHandle &part_list,
    EcdhEncodingProblem problem
)
{
    for (auto id : {
             TSRA_KEY_PROP_ID_CLASS,
             TSRA_KEY_PROP_ID_KIND,
             TSRA_KEY_PROP_ID_BIT_LEN,
             TSRA_KEY_PROP_ID_EC_CURVE,
             TSRA_KEY_PROP_ID_SESSION,
             TSRA_KEY_PROP_ID_DERIVE,
             TSRA_KEY_PROP_ID_ENCRYPT,
             TSRA_KEY_PROP_ID_DECRYPT,
             TSRA_KEY_PROP_ID_SIGN,
             TSRA_KEY_PROP_ID_VERIFY,
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
        if ((id == TSRA_KEY_PROP_ID_LABEL && problem != EcdhEncodingProblem::NullValue) ||
            (width == sizeof(uint8_t) && problem == EcdhEncodingProblem::ShortValue))
        {
            continue;
        }
        SCOPED_TRACE(id);
        expect_ecdh_property_rejected(
            part_list,
            TSRA_STATUS_INVALID_ARGUMENT,
            [=](EcdhDeriveContext &ctx, tsra_ecc_curve) {
                remove_prop_by_id(ctx.properties, id);
                tsra_key_prop property{ id, ctx.property_storage.data(), width };
                switch (problem)
                {
                case EcdhEncodingProblem::NullValue:
                    property.val = nullptr;
                    break;
                case EcdhEncodingProblem::EmptyValue:
                    property.len = 0;
                    break;
                case EcdhEncodingProblem::ShortValue:
                    property.len = width - 1;
                    break;
                case EcdhEncodingProblem::LongValue:
                    property.len = width + 1;
                    break;
                }
                ASSERT_LE(property.len, sizeof(ctx.property_storage));
                ctx.properties.push_back(property);
                ctx.refresh_properties();
            }
        );
    }
}

TEST_F(tsra_ecdh_derive, null_property_value_rejected)
{
    expect_ecdh_encoding_rejected(part_list_, EcdhEncodingProblem::NullValue);
}

TEST_F(tsra_ecdh_derive, empty_property_value_rejected)
{
    expect_ecdh_encoding_rejected(part_list_, EcdhEncodingProblem::EmptyValue);
}

TEST_F(tsra_ecdh_derive, short_property_value_rejected)
{
    expect_ecdh_encoding_rejected(part_list_, EcdhEncodingProblem::ShortValue);
}

TEST_F(tsra_ecdh_derive, long_property_value_rejected)
{
    expect_ecdh_encoding_rejected(part_list_, EcdhEncodingProblem::LongValue);
}

TEST_F(tsra_ecdh_derive, null_property_array_rejected)
{
    expect_ecdh_property_rejected(
        part_list_,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](EcdhDeriveContext &ctx, tsra_ecc_curve) { ctx.property_list.props = nullptr; }
    );
}

TEST_F(tsra_ecdh_derive, empty_property_list_rejected)
{
    expect_ecdh_property_rejected(
        part_list_,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](EcdhDeriveContext &ctx, tsra_ecc_curve) { ctx.property_list.count = 0; }
    );
}

TEST_F(tsra_ecdh_derive, device_owned_properties_rejected)
{
    for (auto id :
         { TSRA_KEY_PROP_ID_LOCAL, TSRA_KEY_PROP_ID_SENSITIVE, TSRA_KEY_PROP_ID_EXTRACTABLE })
    {
        SCOPED_TRACE(id);
        expect_ecdh_property_rejected(
            part_list_,
            TSRA_STATUS_INVALID_ARGUMENT,
            [id](EcdhDeriveContext &ctx, tsra_ecc_curve) {
                ctx.properties.push_back({ id, ctx.property_storage.data(), sizeof(uint8_t) });
                ctx.refresh_properties();
            }
        );
    }
}

TEST_F(tsra_ecdh_derive, null_property_list_rejected)
{
    for_each_ecdh_curve(part_list_, [](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
        {
            auto_key control;
            ASSERT_EQ(ctx.derive(control), TSRA_STATUS_SUCCESS);
            ASSERT_NO_FATAL_FAILURE(expect_ecdh_secret_properties(control.get(), curve, true));
        }
        auto_key rejected;
        ASSERT_EQ(
            tsra_key_derive(
                ctx.session,
                &ctx.algo,
                ctx.private_key.get(),
                nullptr,
                rejected.get_ptr()
            ),
            TSRA_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(rejected.get(), 0u);
    });
}

TEST_F(tsra_ecdh_derive, base_without_derive_rejected)
{
    for_each_ecdh_curve(part_list_, [](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
        {
            auto_key control;
            ASSERT_EQ(ctx.derive(control), TSRA_STATUS_SUCCESS);
            ASSERT_NO_FATAL_FAILURE(expect_ecdh_secret_properties(control.get(), curve, true));
        }
        EcdhDeriveContext signing;
        ASSERT_NO_FATAL_FAILURE(signing.init(ctx.session, curve, false));
        auto_key rejected;
        ASSERT_EQ(signing.derive(rejected), TSRA_STATUS_INVALID_KEY);
        ASSERT_EQ(rejected.get(), 0u);
    });
}

TEST_F(tsra_ecdh_derive, public_base_rejected)
{
    for_each_ecdh_curve(part_list_, [](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
        {
            auto_key control;
            ASSERT_EQ(ctx.derive(control), TSRA_STATUS_SUCCESS);
            ASSERT_NO_FATAL_FAILURE(expect_ecdh_secret_properties(control.get(), curve, true));
        }
        auto_key rejected;
        ASSERT_EQ(
            tsra_key_derive(
                ctx.session,
                &ctx.algo,
                ctx.public_key.get(),
                &ctx.property_list,
                rejected.get_ptr()
            ),
            TSRA_STATUS_INVALID_HANDLE
        );
        ASSERT_EQ(rejected.get(), 0u);
    });
}

TEST_F(tsra_ecdh_derive, peer_without_derive_allowed)
{
    for_each_ecdh_curve(part_list_, [](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
        EcdhDeriveContext peer;
        ASSERT_NO_FATAL_FAILURE(peer.init(ctx.session, curve, false));
        uint8_t peer_derive = 1;
        ASSERT_EQ(
            get_key_prop(peer.public_key.get(), TSRA_KEY_PROP_ID_DERIVE, peer_derive),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(peer_derive, 0u);
        ctx.peer = peer.peer;
        auto_key secret;
        ASSERT_EQ(ctx.derive(secret), TSRA_STATUS_SUCCESS);
        expect_ecdh_secret_properties(secret.get(), curve, true);
    });
}

TEST_F(tsra_ecdh_derive, peer_curve_mismatch_rejected)
{
    for (const auto &peer_curve : ECC_CURVES)
    {
        SCOPED_TRACE(peer_curve.test_name);
        for_each_ecdh_curve(part_list_, [&](EcdhDeriveContext &ctx, tsra_ecc_curve curve) {
            if (curve == peer_curve.curve)
            {
                return;
            }
            {
                auto_key control;
                ASSERT_EQ(ctx.derive(control), TSRA_STATUS_SUCCESS);
                ASSERT_NO_FATAL_FAILURE(expect_ecdh_secret_properties(control.get(), curve, true));
            }
            EcdhDeriveContext peer;
            ASSERT_NO_FATAL_FAILURE(peer.init(ctx.session, peer_curve.curve));
            ctx.peer = peer.peer;
            auto_key rejected;
            ASSERT_EQ(ctx.derive(rejected), TSRA_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(rejected.get(), 0u);
        });
    }
}

// Masked-key property rejects a too-small nonzero output buffer.
TEST_F(tsra_ecdh_derive, get_masked_key_rejects_small_buffer)
{
    part_list_.for_each_session([](tsra_handle session) {
        EcdhKeyPairSet key_pairs;
        auto err = key_pairs.generate(session, TSRA_ECC_CURVE_P256);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        auto_key original_secret;
        err = derive_shared_secret_via_ecdh(
            session,
            key_pairs.priv_key_a.handle,
            key_pairs.pub_key_b.handle,
            TSRA_ECC_CURVE_P256,
            original_secret.handle
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(original_secret.get(), 0u);

        std::array<uint8_t, 1> small_buffer{};

        tsra_key_prop masked_prop{};
        masked_prop.id = TSRA_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = small_buffer.data();
        masked_prop.len = static_cast<uint32_t>(small_buffer.size());

        err = tsra_key_get_prop(original_secret.get(), &masked_prop);

        ASSERT_EQ(err, TSRA_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(masked_prop.len, small_buffer.size());
    });
}

// The masked-key property length query is stable across repeated calls.
TEST_F(tsra_ecdh_derive, get_masked_key_length_query_is_stable)
{
    part_list_.for_each_session([](tsra_handle session) {
        EcdhKeyPairSet key_pairs;
        auto err = key_pairs.generate(session, TSRA_ECC_CURVE_P256);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        auto_key original_secret;
        err = derive_shared_secret_via_ecdh(
            session,
            key_pairs.priv_key_a.handle,
            key_pairs.pub_key_b.handle,
            TSRA_ECC_CURVE_P256,
            original_secret.handle
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(original_secret.get(), 0u);

        tsra_key_prop first_query{};
        first_query.id = TSRA_KEY_PROP_ID_MASKED_KEY;
        first_query.val = nullptr;
        first_query.len = 0;

        err = tsra_key_get_prop(original_secret.get(), &first_query);
        ASSERT_EQ(err, TSRA_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(first_query.len, 0u);

        tsra_key_prop second_query{};
        second_query.id = TSRA_KEY_PROP_ID_MASKED_KEY;
        second_query.val = nullptr;
        second_query.len = 0;

        err = tsra_key_get_prop(original_secret.get(), &second_query);
        ASSERT_EQ(err, TSRA_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(second_query.len, first_query.len);
    });
}