// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <tsra_api.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_key.hpp"
#include "utils/shared_secret.hpp"

/// Test fixture for ECC key generation tests across available partition sessions.
class tsra_ecc_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

static void expect_generated_ecc_properties(
    tsra_handle key,
    tsra_ecc_curve curve,
    tsra_key_class key_class,
    bool can_derive,
    bool session_key
)
{
    tsra_key_class actual_class{};
    tsra_key_kind actual_kind{};
    tsra_ecc_curve actual_curve{};
    uint32_t actual_bits = 0;
    ASSERT_EQ(get_key_prop(key, TSRA_KEY_PROP_ID_CLASS, actual_class), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(get_key_prop(key, TSRA_KEY_PROP_ID_KIND, actual_kind), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(get_key_prop(key, TSRA_KEY_PROP_ID_EC_CURVE, actual_curve), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(get_key_prop(key, TSRA_KEY_PROP_ID_BIT_LEN, actual_bits), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(actual_class, key_class);
    ASSERT_EQ(actual_kind, TSRA_KEY_KIND_ECC);
    ASSERT_EQ(actual_curve, curve);
    ASSERT_EQ(actual_bits, get_curve_key_bits(curve));

    const bool is_private = key_class == TSRA_KEY_CLASS_PRIVATE;
    const struct
    {
        tsra_key_prop_id id;
        bool expected;
    } flags[] = {
        { TSRA_KEY_PROP_ID_SESSION, session_key },
        { TSRA_KEY_PROP_ID_LOCAL, true },
        { TSRA_KEY_PROP_ID_SENSITIVE, is_private },
        { TSRA_KEY_PROP_ID_EXTRACTABLE, true },
        { TSRA_KEY_PROP_ID_SIGN, is_private && !can_derive },
        { TSRA_KEY_PROP_ID_VERIFY, !is_private && !can_derive },
        { TSRA_KEY_PROP_ID_DERIVE, can_derive },
        { TSRA_KEY_PROP_ID_ENCRYPT, false },
        { TSRA_KEY_PROP_ID_DECRYPT, false },
        { TSRA_KEY_PROP_ID_WRAP, false },
        { TSRA_KEY_PROP_ID_UNWRAP, false },
    };
    for (const auto &flag : flags)
    {
        SCOPED_TRACE(flag.id);
        uint8_t actual = 0;
        ASSERT_EQ(get_key_prop(key, flag.id, actual), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(actual, static_cast<uint8_t>(flag.expected));
    }
}

/// Verifies that a generated ECC key pair reports the expected key kind and curve properties.
static void run_generated_keypair_has_expected_properties(tsra_handle session, tsra_ecc_curve curve)
{
    auto_key priv_key;
    auto_key pub_key;

    auto err = generate_ecc_keypair(session, curve, true, priv_key.get_ptr(), pub_key.get_ptr());
    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    ASSERT_NE(priv_key.get(), 0u);
    ASSERT_NE(pub_key.get(), 0u);

    ASSERT_NO_FATAL_FAILURE(
        expect_generated_ecc_properties(priv_key.get(), curve, TSRA_KEY_CLASS_PRIVATE, false, true)
    );
    ASSERT_NO_FATAL_FAILURE(
        expect_generated_ecc_properties(pub_key.get(), curve, TSRA_KEY_CLASS_PUBLIC, false, true)
    );
}

/// Verifies that a masked ECC private key can be unmasked into a valid key pair for the given
/// curve.
static void run_unmask_ecc_keypair_for_curve(tsra_handle session, tsra_ecc_curve curve)
{
    auto_key original_priv_key;
    auto_key original_pub_key;

    auto err = generate_ecc_keypair(
        session,
        curve,
        true,
        original_priv_key.get_ptr(),
        original_pub_key.get_ptr()
    );
    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    ASSERT_NE(original_priv_key.get(), 0u);
    ASSERT_NE(original_pub_key.get(), 0u);

    std::vector<uint8_t> masked_key_data;
    err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    ASSERT_FALSE(masked_key_data.empty());

    tsra_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key unmasked_priv_key;
    auto_key unmasked_pub_key;

    err = tsra_key_unmask_pair(
        session,
        TSRA_KEY_KIND_ECC,
        &masked_key_buf,
        unmasked_priv_key.get_ptr(),
        unmasked_pub_key.get_ptr()
    );
    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    ASSERT_NE(unmasked_priv_key.get(), 0u);
    ASSERT_NE(unmasked_pub_key.get(), 0u);

    EccKeySummary private_summary{};
    EccKeySummary public_summary{};

    ASSERT_EQ(read_ecc_key_summary(unmasked_priv_key.get(), private_summary), TSRA_STATUS_SUCCESS);
    ASSERT_EQ(read_ecc_key_summary(unmasked_pub_key.get(), public_summary), TSRA_STATUS_SUCCESS);

    ASSERT_TRUE(is_expected_ecc_curve(private_summary, curve));
    ASSERT_TRUE(is_expected_ecc_curve(public_summary, curve));
}

/// Runs ECC key pair generation with caller-provided private and public key properties.
static tsra_status run_ecc_keygen_with_props(
    tsra_handle session,
    tsra_key_prop_list *priv_prop_list,
    tsra_key_prop_list *pub_prop_list
)
{
    tsra_algo keygen_algo{};
    keygen_algo.id = TSRA_ALGO_ID_EC_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    tsra_handle priv_key_handle = 0;
    tsra_handle pub_key_handle = 0;

    auto err = tsra_key_gen_pair(
        session,
        &keygen_algo,
        priv_prop_list,
        pub_prop_list,
        &priv_key_handle,
        &pub_key_handle
    );

    if (err == TSRA_STATUS_SUCCESS)
    {
        EXPECT_NE(priv_key_handle, 0u);
        EXPECT_NE(pub_key_handle, 0u);
        if (priv_key_handle != 0)
        {
            auto delete_err = tsra_key_delete(priv_key_handle);
            EXPECT_EQ(delete_err, TSRA_STATUS_SUCCESS);
        }

        if (pub_key_handle != 0)
        {
            auto delete_err = tsra_key_delete(pub_key_handle);
            EXPECT_EQ(delete_err, TSRA_STATUS_SUCCESS);
        }
    }
    else
    {
        EXPECT_EQ(priv_key_handle, 0u);
        EXPECT_EQ(pub_key_handle, 0u);
    }

    return err;
}

static void expect_keygen_flag_rejected(
    PartitionListHandle &part_list,
    tsra_key_class key_class,
    bool can_derive,
    tsra_key_prop_id flag
)
{
    for (const auto &curve : ECC_CURVES)
    {
        SCOPED_TRACE(curve.test_name);
        part_list.for_each_session([&](tsra_handle session) {
            DefaultEccPrivKeyProps priv_props;
            DefaultEccPubKeyProps pub_props;
            set_ecc_pair_properties(priv_props, pub_props, curve.curve, can_derive, true);
            uint8_t enabled = 0;
            auto &target = key_class == TSRA_KEY_CLASS_PRIVATE ? priv_props.props : pub_props.props;
            target.push_back({ flag, &enabled, sizeof(enabled) });
            auto private_list = priv_props.get_prop_list();
            auto public_list = pub_props.get_prop_list();

            ASSERT_EQ(
                run_ecc_keygen_with_props(session, &private_list, &public_list),
                TSRA_STATUS_SUCCESS
            );
            enabled = 1;
            ASSERT_EQ(
                run_ecc_keygen_with_props(session, &private_list, &public_list),
                TSRA_STATUS_INVALID_KEY_PROPS
            );
        });
    }
}

TEST_F(tsra_ecc_keygen, private_sign_encrypt_rejected)
{
    expect_keygen_flag_rejected(
        part_list_,
        TSRA_KEY_CLASS_PRIVATE,
        false,
        TSRA_KEY_PROP_ID_ENCRYPT
    );
}

TEST_F(tsra_ecc_keygen, private_derive_encrypt_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, true, TSRA_KEY_PROP_ID_ENCRYPT);
}

TEST_F(tsra_ecc_keygen, private_sign_decrypt_rejected)
{
    expect_keygen_flag_rejected(
        part_list_,
        TSRA_KEY_CLASS_PRIVATE,
        false,
        TSRA_KEY_PROP_ID_DECRYPT
    );
}

TEST_F(tsra_ecc_keygen, private_derive_decrypt_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, true, TSRA_KEY_PROP_ID_DECRYPT);
}

TEST_F(tsra_ecc_keygen, private_sign_wrap_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, false, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_ecc_keygen, private_derive_wrap_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, true, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_ecc_keygen, private_sign_unwrap_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, false, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_ecc_keygen, private_derive_unwrap_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, true, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_ecc_keygen, private_sign_verify_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, false, TSRA_KEY_PROP_ID_VERIFY);
}

TEST_F(tsra_ecc_keygen, private_derive_verify_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, true, TSRA_KEY_PROP_ID_VERIFY);
}

TEST_F(tsra_ecc_keygen, public_verify_encrypt_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, false, TSRA_KEY_PROP_ID_ENCRYPT);
}

TEST_F(tsra_ecc_keygen, public_derive_encrypt_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, true, TSRA_KEY_PROP_ID_ENCRYPT);
}

TEST_F(tsra_ecc_keygen, public_verify_decrypt_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, false, TSRA_KEY_PROP_ID_DECRYPT);
}

TEST_F(tsra_ecc_keygen, public_derive_decrypt_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, true, TSRA_KEY_PROP_ID_DECRYPT);
}

TEST_F(tsra_ecc_keygen, public_verify_wrap_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, false, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_ecc_keygen, public_derive_wrap_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, true, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_ecc_keygen, public_verify_unwrap_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, false, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_ecc_keygen, public_derive_unwrap_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, true, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_ecc_keygen, public_verify_sign_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, false, TSRA_KEY_PROP_ID_SIGN);
}

TEST_F(tsra_ecc_keygen, public_derive_sign_rejected)
{
    expect_keygen_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, true, TSRA_KEY_PROP_ID_SIGN);
}

static void expect_generated_pair_properties(
    PartitionListHandle &part_list,
    bool can_derive,
    bool session_key
)
{
    for (const auto &curve : ECC_CURVES)
    {
        SCOPED_TRACE(curve.test_name);
        part_list.for_each_session([&](tsra_handle session) {
            DefaultEccPrivKeyProps priv_props;
            DefaultEccPubKeyProps pub_props;
            set_ecc_pair_properties(priv_props, pub_props, curve.curve, can_derive, session_key);
            auto private_list = priv_props.get_prop_list();
            auto public_list = pub_props.get_prop_list();
            tsra_algo algo{};
            algo.id = TSRA_ALGO_ID_EC_KEY_PAIR_GEN;
            auto_key private_key;
            auto_key public_key;
            ASSERT_EQ(
                tsra_key_gen_pair(
                    session,
                    &algo,
                    &private_list,
                    &public_list,
                    private_key.get_ptr(),
                    public_key.get_ptr()
                ),
                TSRA_STATUS_SUCCESS
            );
            ASSERT_NO_FATAL_FAILURE(expect_generated_ecc_properties(
                private_key.get(),
                curve.curve,
                TSRA_KEY_CLASS_PRIVATE,
                can_derive,
                session_key
            ));
            ASSERT_NO_FATAL_FAILURE(expect_generated_ecc_properties(
                public_key.get(),
                curve.curve,
                TSRA_KEY_CLASS_PUBLIC,
                can_derive,
                session_key
            ));
        });
    }
}

TEST_F(tsra_ecc_keygen, persistent_sign_properties)
{
    expect_generated_pair_properties(part_list_, false, false);
}

TEST_F(tsra_ecc_keygen, session_derive_properties)
{
    expect_generated_pair_properties(part_list_, true, true);
}

TEST_F(tsra_ecc_keygen, persistent_derive_properties)
{
    expect_generated_pair_properties(part_list_, true, false);
}

enum class EccPropertyProblem
{
    WrongClass,
    WrongKind,
    InvalidClass,
    InvalidKind,
    InvalidCurve,
    MissingClass,
    MissingKind,
    MissingCurve,
    MissingCurveWithBits,
    NoUsage,
    ConflictingUsage,
    IncompatibleUsage,
    SessionCleared,
    SessionSet,
};

static void expect_ecc_property_error(
    PartitionListHandle &part_list,
    EccPropertyProblem problem,
    tsra_status expected
)
{
    for (const auto &curve : ECC_CURVES)
    {
        SCOPED_TRACE(curve.test_name);
        for (bool private_key : { true, false })
        {
            SCOPED_TRACE(private_key ? "Private" : "Public");
            for (bool can_derive : { false, true })
            {
                SCOPED_TRACE(can_derive ? "Derive" : "SignVerify");
                part_list.for_each_session([&](tsra_handle session) {
                    DefaultEccPrivKeyProps priv_props;
                    DefaultEccPubKeyProps pub_props;
                    set_ecc_pair_properties(
                        priv_props,
                        pub_props,
                        curve.curve,
                        can_derive,
                        problem != EccPropertyProblem::SessionSet
                    );
                    auto &target = private_key ? priv_props.props : pub_props.props;
                    uint32_t bits = get_curve_key_bits(curve.curve);
                    if (problem == EccPropertyProblem::MissingCurveWithBits)
                    {
                        target.push_back({ TSRA_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
                    }
                    auto private_list = priv_props.get_prop_list();
                    auto public_list = pub_props.get_prop_list();
                    ASSERT_EQ(
                        run_ecc_keygen_with_props(session, &private_list, &public_list),
                        TSRA_STATUS_SUCCESS
                    );

                    auto &key_class = private_key ? priv_props.key_class : pub_props.key_class;
                    auto &key_kind = private_key ? priv_props.key_kind : pub_props.key_kind;
                    auto &key_curve = private_key ? priv_props.ecc_curve : pub_props.ecc_curve;
                    auto &usage = private_key ? priv_props.can_sign : pub_props.can_verify;
                    auto &derive = private_key ? priv_props.can_derive : pub_props.can_derive;
                    auto &session_key = private_key ? priv_props.is_session : pub_props.is_session;
                    switch (problem)
                    {
                    case EccPropertyProblem::WrongClass:
                        key_class = private_key ? TSRA_KEY_CLASS_PUBLIC : TSRA_KEY_CLASS_PRIVATE;
                        break;
                    case EccPropertyProblem::WrongKind:
                        key_kind = TSRA_KEY_KIND_RSA;
                        break;
                    case EccPropertyProblem::InvalidClass:
                        key_class = 0xFFFFFFFF;
                        break;
                    case EccPropertyProblem::InvalidKind:
                        key_kind = 0xFFFFFFFF;
                        break;
                    case EccPropertyProblem::InvalidCurve:
                        key_curve = 0xFFFFFFFF;
                        break;
                    case EccPropertyProblem::MissingClass:
                        remove_prop_by_id(target, TSRA_KEY_PROP_ID_CLASS);
                        break;
                    case EccPropertyProblem::MissingKind:
                        remove_prop_by_id(target, TSRA_KEY_PROP_ID_KIND);
                        break;
                    case EccPropertyProblem::MissingCurve:
                    case EccPropertyProblem::MissingCurveWithBits:
                        remove_prop_by_id(target, TSRA_KEY_PROP_ID_EC_CURVE);
                        break;
                    case EccPropertyProblem::NoUsage:
                        usage = 0;
                        derive = 0;
                        break;
                    case EccPropertyProblem::ConflictingUsage:
                        usage = 1;
                        derive = 1;
                        break;
                    case EccPropertyProblem::IncompatibleUsage:
                        usage = can_derive;
                        derive = !can_derive;
                        break;
                    case EccPropertyProblem::SessionCleared:
                        session_key = 0;
                        break;
                    case EccPropertyProblem::SessionSet:
                        session_key = 1;
                        break;
                    }
                    private_list = priv_props.get_prop_list();
                    public_list = pub_props.get_prop_list();
                    ASSERT_EQ(
                        run_ecc_keygen_with_props(session, &private_list, &public_list),
                        expected
                    );
                });
            }
        }
    }
}

TEST_F(tsra_ecc_keygen, attribute_rejects_wrong_class)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::WrongClass,
        TSRA_STATUS_INVALID_KEY_PROPS
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_wrong_kind)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::WrongKind,
        TSRA_STATUS_INVALID_KEY_PROPS
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_invalid_class)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::InvalidClass,
        TSRA_STATUS_INVALID_ARGUMENT
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_invalid_kind)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::InvalidKind,
        TSRA_STATUS_INVALID_ARGUMENT
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_invalid_curve)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::InvalidCurve,
        TSRA_STATUS_INVALID_ARGUMENT
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_missing_class)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::MissingClass,
        TSRA_STATUS_KEY_CLASS_NOT_SPECIFIED
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_missing_kind)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::MissingKind,
        TSRA_STATUS_KEY_KIND_NOT_SPECIFIED
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_missing_curve)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::MissingCurve,
        TSRA_STATUS_PROPERTY_NOT_PRESENT
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_missing_curve_with_bits)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::MissingCurveWithBits,
        TSRA_STATUS_INVALID_KEY_PROPS
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_no_usage)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::NoUsage,
        TSRA_STATUS_INVALID_KEY_PROPS
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_conflicting_usage)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::ConflictingUsage,
        TSRA_STATUS_INVALID_KEY_PROPS
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_incompatible_usage)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::IncompatibleUsage,
        TSRA_STATUS_INVALID_KEY_PROPS
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_cleared_session_flag)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::SessionCleared,
        TSRA_STATUS_INVALID_KEY_PROPS
    );
}

TEST_F(tsra_ecc_keygen, attribute_rejects_set_session_flag)
{
    expect_ecc_property_error(
        part_list_,
        EccPropertyProblem::SessionSet,
        TSRA_STATUS_INVALID_KEY_PROPS
    );
}

enum class EccPropertyEncoding
{
    NullValue,
    ZeroLength,
    ShortLength,
    LongLength,
    NullArray,
    EmptyList,
    ReadOnly,
};

static void expect_ecc_encoding_error(PartitionListHandle &part_list, EccPropertyEncoding problem)
{
    for (const auto &curve : ECC_CURVES)
    {
        SCOPED_TRACE(curve.test_name);
        for (bool private_key : { true, false })
        {
            SCOPED_TRACE(private_key ? "Private" : "Public");
            std::vector<tsra_key_prop_id> properties;
            if (problem == EccPropertyEncoding::ReadOnly)
            {
                properties = { TSRA_KEY_PROP_ID_LOCAL,
                               TSRA_KEY_PROP_ID_SENSITIVE,
                               TSRA_KEY_PROP_ID_EXTRACTABLE };
            }
            else if (problem == EccPropertyEncoding::NullArray ||
                     problem == EccPropertyEncoding::EmptyList)
            {
                properties = { TSRA_KEY_PROP_ID_CLASS };
            }
            else
            {
                properties = { TSRA_KEY_PROP_ID_CLASS,
                               TSRA_KEY_PROP_ID_KIND,
                               TSRA_KEY_PROP_ID_EC_CURVE,
                               TSRA_KEY_PROP_ID_BIT_LEN,
                               TSRA_KEY_PROP_ID_SESSION,
                               private_key ? TSRA_KEY_PROP_ID_SIGN : TSRA_KEY_PROP_ID_VERIFY,
                               TSRA_KEY_PROP_ID_DERIVE };
            }
            for (const auto property_id : properties)
            {
                const bool scalar = property_id == TSRA_KEY_PROP_ID_CLASS ||
                                    property_id == TSRA_KEY_PROP_ID_KIND ||
                                    property_id == TSRA_KEY_PROP_ID_EC_CURVE ||
                                    property_id == TSRA_KEY_PROP_ID_BIT_LEN;
                if (!scalar && problem == EccPropertyEncoding::ShortLength)
                {
                    continue;
                }
                SCOPED_TRACE(property_id);
                part_list.for_each_session([&](tsra_handle session) {
                    DefaultEccPrivKeyProps priv_props;
                    DefaultEccPubKeyProps pub_props;
                    set_ecc_pair_properties(priv_props, pub_props, curve.curve, false, true);
                    auto &target = private_key ? priv_props.props : pub_props.props;
                    uint32_t bits = get_curve_key_bits(curve.curve);
                    target.push_back({ TSRA_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
                    alignas(uint32_t) uint8_t value[sizeof(uint32_t) + 1]{};
                    auto property =
                        std::find_if(target.begin(), target.end(), [&](const tsra_key_prop &prop) {
                            return prop.id == property_id;
                        });
                    if (problem != EccPropertyEncoding::ReadOnly)
                    {
                        ASSERT_NE(property, target.end());
                        ASSERT_LE(property->len, sizeof(value));
                        std::memcpy(value, property->val, property->len);
                        property->val = value;
                    }
                    auto private_list = priv_props.get_prop_list();
                    auto public_list = pub_props.get_prop_list();
                    ASSERT_EQ(
                        run_ecc_keygen_with_props(session, &private_list, &public_list),
                        TSRA_STATUS_SUCCESS
                    );

                    uint8_t enabled = 1;
                    switch (problem)
                    {
                    case EccPropertyEncoding::NullValue:
                        property->val = nullptr;
                        break;
                    case EccPropertyEncoding::ZeroLength:
                        property->len = 0;
                        break;
                    case EccPropertyEncoding::ShortLength:
                        --property->len;
                        break;
                    case EccPropertyEncoding::LongLength:
                        ++property->len;
                        break;
                    case EccPropertyEncoding::ReadOnly:
                        target.push_back({ property_id, &enabled, sizeof(enabled) });
                        break;
                    case EccPropertyEncoding::NullArray:
                    case EccPropertyEncoding::EmptyList:
                        break;
                    }
                    private_list = priv_props.get_prop_list();
                    public_list = pub_props.get_prop_list();
                    auto &list = private_key ? private_list : public_list;
                    if (problem == EccPropertyEncoding::NullArray)
                    {
                        list.props = nullptr;
                    }
                    if (problem == EccPropertyEncoding::EmptyList)
                    {
                        list.count = 0;
                    }
                    ASSERT_EQ(
                        run_ecc_keygen_with_props(session, &private_list, &public_list),
                        TSRA_STATUS_INVALID_ARGUMENT
                    );
                });
            }
        }
    }
}

TEST_F(tsra_ecc_keygen, encoding_rejects_null_values)
{
    expect_ecc_encoding_error(part_list_, EccPropertyEncoding::NullValue);
}

TEST_F(tsra_ecc_keygen, encoding_rejects_zero_lengths)
{
    expect_ecc_encoding_error(part_list_, EccPropertyEncoding::ZeroLength);
}

TEST_F(tsra_ecc_keygen, encoding_rejects_short_lengths)
{
    expect_ecc_encoding_error(part_list_, EccPropertyEncoding::ShortLength);
}

TEST_F(tsra_ecc_keygen, encoding_rejects_long_lengths)
{
    expect_ecc_encoding_error(part_list_, EccPropertyEncoding::LongLength);
}

TEST_F(tsra_ecc_keygen, encoding_rejects_null_arrays)
{
    expect_ecc_encoding_error(part_list_, EccPropertyEncoding::NullArray);
}

TEST_F(tsra_ecc_keygen, encoding_rejects_empty_lists)
{
    expect_ecc_encoding_error(part_list_, EccPropertyEncoding::EmptyList);
}

TEST_F(tsra_ecc_keygen, encoding_rejects_read_only_properties)
{
    expect_ecc_encoding_error(part_list_, EccPropertyEncoding::ReadOnly);
}

/// Verifies that a masked ECC key can still be unmasked after the original key pair is deleted.
static void run_unmask_after_original_keys_deleted(tsra_handle session, tsra_ecc_curve curve)
{
    auto_key original_priv_key;
    auto_key original_pub_key;

    auto err = generate_ecc_keypair(
        session,
        curve,
        true,
        original_priv_key.get_ptr(),
        original_pub_key.get_ptr()
    );
    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    ASSERT_NE(original_priv_key.get(), 0u);
    ASSERT_NE(original_pub_key.get(), 0u);

    std::vector<uint8_t> masked_key_data;
    err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    ASSERT_FALSE(masked_key_data.empty());

    auto original_priv_handle = original_priv_key.get();
    auto original_pub_handle = original_pub_key.get();

    err = tsra_key_delete(original_priv_handle);
    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    original_priv_key.release();

    err = tsra_key_delete(original_pub_handle);
    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    original_pub_key.release();

    tsra_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key unmasked_priv_key;
    auto_key unmasked_pub_key;

    err = tsra_key_unmask_pair(
        session,
        TSRA_KEY_KIND_ECC,
        &masked_key_buf,
        unmasked_priv_key.get_ptr(),
        unmasked_pub_key.get_ptr()
    );

    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    ASSERT_NE(unmasked_priv_key.get(), 0u);
    ASSERT_NE(unmasked_pub_key.get(), 0u);
}

/// Verifies that unmasking an ECC key returns new handles distinct from the original key handles.
static void run_unmasked_handles_are_distinct_from_original(
    tsra_handle session,
    tsra_ecc_curve curve
)
{
    auto_key original_priv_key;
    auto_key original_pub_key;

    auto err = generate_ecc_keypair(
        session,
        curve,
        true,
        original_priv_key.get_ptr(),
        original_pub_key.get_ptr()
    );
    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    ASSERT_NE(original_priv_key.get(), 0u);
    ASSERT_NE(original_pub_key.get(), 0u);

    std::vector<uint8_t> masked_key_data;
    err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    ASSERT_FALSE(masked_key_data.empty());

    tsra_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key unmasked_priv_key;
    auto_key unmasked_pub_key;

    err = tsra_key_unmask_pair(
        session,
        TSRA_KEY_KIND_ECC,
        &masked_key_buf,
        unmasked_priv_key.get_ptr(),
        unmasked_pub_key.get_ptr()
    );

    ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
    ASSERT_NE(unmasked_priv_key.get(), 0u);
    ASSERT_NE(unmasked_pub_key.get(), 0u);

    ASSERT_NE(unmasked_priv_key.get(), original_priv_key.get());
    ASSERT_NE(unmasked_pub_key.get(), original_pub_key.get());
}

/// Verifies that ECC key pair generation succeeds for all supported curves.
TEST_F(tsra_ecc_keygen, generate_keypair_all_curves)
{
    for (const auto &test_case : ECC_CURVES)
    {
        SCOPED_TRACE("Testing key generation with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](tsra_handle session) {
            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(
                session,
                test_case.curve,
                true,
                priv_key.get_ptr(),
                pub_key.get_ptr()
            );
            ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
            ASSERT_NE(priv_key.get(), 0);
            ASSERT_NE(pub_key.get(), 0);

            // Explicitly test deletion (auto_key will also delete on scope exit as backup)
            auto delete_priv_err = tsra_key_delete(priv_key.get());
            ASSERT_EQ(delete_priv_err, TSRA_STATUS_SUCCESS);
            priv_key.release();

            auto delete_pub_err = tsra_key_delete(pub_key.get());
            ASSERT_EQ(delete_pub_err, TSRA_STATUS_SUCCESS);
            pub_key.release();
        });
    }
}

/// Verifies that ECC key generation rejects a null algorithm pointer.
TEST_F(tsra_ecc_keygen, null_algorithm)
{
    part_list_.for_each_session([](tsra_handle session) {
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;

        tsra_handle priv_key_handle = 0;
        tsra_handle pub_key_handle = 0;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto err = tsra_key_gen_pair(
            session,
            nullptr,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key generation rejects null private key properties.
TEST_F(tsra_ecc_keygen, null_priv_key_props)
{
    part_list_.for_each_session([](tsra_handle session) {
        tsra_algo keygen_algo{};
        keygen_algo.id = TSRA_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        DefaultEccPubKeyProps pub_props;
        auto pub_prop_list = pub_props.get_prop_list();

        tsra_handle priv_key_handle = 0;
        tsra_handle pub_key_handle = 0;

        auto err = tsra_key_gen_pair(
            session,
            &keygen_algo,
            nullptr,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key generation rejects null public key properties.
TEST_F(tsra_ecc_keygen, null_pub_key_props)
{
    part_list_.for_each_session([](tsra_handle session) {
        tsra_algo keygen_algo{};
        keygen_algo.id = TSRA_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        DefaultEccPrivKeyProps priv_props;
        auto priv_prop_list = priv_props.get_prop_list();

        tsra_handle priv_key_handle = 0;
        tsra_handle pub_key_handle = 0;

        auto err = tsra_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            nullptr,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key generation rejects a null private key output pointer.
TEST_F(tsra_ecc_keygen, null_priv_key_handle_output)
{
    part_list_.for_each_session([](tsra_handle session) {
        tsra_algo keygen_algo{};
        keygen_algo.id = TSRA_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        tsra_handle pub_key_handle = 0;

        auto err = tsra_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            nullptr,
            &pub_key_handle
        );
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key generation rejects a null public key output pointer.
TEST_F(tsra_ecc_keygen, null_pub_key_handle_output)
{
    part_list_.for_each_session([](tsra_handle session) {
        tsra_algo keygen_algo{};
        keygen_algo.id = TSRA_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        tsra_handle priv_key_handle = 0;

        auto err = tsra_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            nullptr
        );
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key generation rejects an invalid session handle.
TEST_F(tsra_ecc_keygen, invalid_session_handle)
{
    tsra_algo keygen_algo{};
    keygen_algo.id = TSRA_ALGO_ID_EC_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    tsra_handle priv_key_handle = 0;
    tsra_handle pub_key_handle = 0;

    auto err = tsra_key_gen_pair(
        0xDEADBEEF,
        &keygen_algo,
        &priv_prop_list,
        &pub_prop_list,
        &priv_key_handle,
        &pub_key_handle
    );
    ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
}

/// Verifies that ECC key generation rejects an unsupported algorithm identifier.
TEST_F(tsra_ecc_keygen, unsupported_algorithm)
{
    part_list_.for_each_session([](tsra_handle session) {
        tsra_algo keygen_algo{};
        keygen_algo.id = static_cast<tsra_algo_id>(0xFFFFFFFF);
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        tsra_handle priv_key_handle = 0;
        tsra_handle pub_key_handle = 0;

        auto err = tsra_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key pair unmasking rejects an unsupported key kind.
TEST_F(tsra_ecc_keygen, unmask_pair_rejects_unsupported_key_kind)
{
    part_list_.for_each_session([](tsra_handle session) {
        std::vector<uint8_t> masked_key_data(16, 0x42);
        tsra_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key priv_key;
        auto_key pub_key;
        auto err = tsra_key_unmask_pair(
            session,
            TSRA_KEY_KIND_AES,
            &masked_key_buf,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_UNSUPPORTED_KEY_KIND);
        ASSERT_EQ(priv_key.get(), 0u);
        ASSERT_EQ(pub_key.get(), 0u);
    });
}

/// Verifies that a generated P-256 ECC key pair has the expected properties.
TEST_F(tsra_ecc_keygen, generated_p256_keypair_has_expected_properties)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_generated_keypair_has_expected_properties(session, TSRA_ECC_CURVE_P256);
    });
}

/// Verifies that a generated P-384 ECC key pair has the expected properties.
TEST_F(tsra_ecc_keygen, generated_p384_keypair_has_expected_properties)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_generated_keypair_has_expected_properties(session, TSRA_ECC_CURVE_P384);
    });
}

/// Verifies that a generated P-521 ECC key pair has the expected properties.
TEST_F(tsra_ecc_keygen, generated_p521_keypair_has_expected_properties)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_generated_keypair_has_expected_properties(session, TSRA_ECC_CURVE_P521);
    });
}

/// Verifies that a masked P-256 ECC private key can be unmasked into a key pair.
TEST_F(tsra_ecc_keygen, unmask_ecc_p256_keypair)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_unmask_ecc_keypair_for_curve(session, TSRA_ECC_CURVE_P256);
    });
}

/// Verifies that a masked P-384 ECC private key can be unmasked into a key pair.
TEST_F(tsra_ecc_keygen, unmask_ecc_p384_keypair)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_unmask_ecc_keypair_for_curve(session, TSRA_ECC_CURVE_P384);
    });
}

/// Verifies that a masked P-521 ECC private key can be unmasked into a key pair.
TEST_F(tsra_ecc_keygen, unmask_ecc_p521_keypair)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_unmask_ecc_keypair_for_curve(session, TSRA_ECC_CURVE_P521);
    });
}

/// Verifies that ECC key pair unmasking rejects corrupted masked key data.
TEST_F(tsra_ecc_keygen, unmask_ecc_rejects_corrupted_data)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key original_priv_key;
        auto_key original_pub_key;

        auto err = generate_ecc_keypair(
            session,
            TSRA_ECC_CURVE_P256,
            true,
            original_priv_key.get_ptr(),
            original_pub_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        std::vector<uint8_t> masked_key_data;
        err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(masked_key_data.empty());

        masked_key_data[masked_key_data.size() / 2] ^= 0x5A;

        tsra_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_priv_key;
        auto_key unmasked_pub_key;

        err = tsra_key_unmask_pair(
            session,
            TSRA_KEY_KIND_ECC,
            &masked_key_buf,
            unmasked_priv_key.get_ptr(),
            unmasked_pub_key.get_ptr()
        );

        ASSERT_EQ(err, TSRA_STATUS_MASKED_KEY_DECODE_FAILED);
        ASSERT_EQ(unmasked_priv_key.get(), 0u);
        ASSERT_EQ(unmasked_pub_key.get(), 0u);
    });
}

/// Verifies that ECC key pair unmasking rejects a null masked key buffer.
TEST_F(tsra_ecc_keygen, unmask_rejects_null_masked_key_buffer)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = tsra_key_unmask_pair(
            session,
            TSRA_KEY_KIND_ECC,
            nullptr,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );

        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(priv_key.get(), 0u);
        ASSERT_EQ(pub_key.get(), 0u);
    });
}

/// Verifies that ECC key pair unmasking rejects a null private key output pointer.
TEST_F(tsra_ecc_keygen, unmask_rejects_null_private_output)
{
    part_list_.for_each_session([](tsra_handle session) {
        std::vector<uint8_t> masked_key_data(16, 0x42);

        tsra_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key pub_key;

        auto err = tsra_key_unmask_pair(
            session,
            TSRA_KEY_KIND_ECC,
            &masked_key_buf,
            nullptr,
            pub_key.get_ptr()
        );

        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(pub_key.get(), 0u);
    });
}

/// Verifies that ECC key pair unmasking rejects a null public key output pointer.
TEST_F(tsra_ecc_keygen, unmask_rejects_null_public_output)
{
    part_list_.for_each_session([](tsra_handle session) {
        std::vector<uint8_t> masked_key_data(16, 0x42);

        tsra_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key priv_key;

        auto err = tsra_key_unmask_pair(
            session,
            TSRA_KEY_KIND_ECC,
            &masked_key_buf,
            priv_key.get_ptr(),
            nullptr
        );

        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(priv_key.get(), 0u);
    });
}

/// Verifies that ECC key pair unmasking rejects an empty masked key buffer.
TEST_F(tsra_ecc_keygen, unmask_rejects_empty_masked_key_buffer)
{
    part_list_.for_each_session([](tsra_handle session) {
        tsra_buffer masked_key_buf{};
        masked_key_buf.ptr = nullptr;
        masked_key_buf.len = 0;

        auto_key priv_key;
        auto_key pub_key;

        auto err = tsra_key_unmask_pair(
            session,
            TSRA_KEY_KIND_ECC,
            &masked_key_buf,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );

        ASSERT_EQ(err, TSRA_STATUS_MASKED_KEY_DECODE_FAILED);
        ASSERT_EQ(priv_key.get(), 0u);
        ASSERT_EQ(pub_key.get(), 0u);
    });
}

/// Verifies that ECC masked key data cannot be unmasked as an RSA key pair.
TEST_F(tsra_ecc_keygen, unmask_rejects_wrong_key_kind_for_real_ecc_masked_key)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key original_priv_key;
        auto_key original_pub_key;

        auto err = generate_ecc_keypair(
            session,
            TSRA_ECC_CURVE_P256,
            true,
            original_priv_key.get_ptr(),
            original_pub_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(original_priv_key.get(), 0u);
        ASSERT_NE(original_pub_key.get(), 0u);

        std::vector<uint8_t> masked_key_data;
        err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(masked_key_data.empty());

        tsra_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_priv_key;
        auto_key unmasked_pub_key;

        err = tsra_key_unmask_pair(
            session,
            TSRA_KEY_KIND_RSA,
            &masked_key_buf,
            unmasked_priv_key.get_ptr(),
            unmasked_pub_key.get_ptr()
        );

        ASSERT_EQ(err, TSRA_STATUS_INTERNAL_ERROR);
        ASSERT_EQ(unmasked_priv_key.get(), 0u);
        ASSERT_EQ(unmasked_pub_key.get(), 0u);
    });
}

/// Verifies that ECC key generation rejects mismatched P-256 private and P-384 public key curves.
TEST_F(tsra_ecc_keygen, keygen_rejects_curve_mismatch_p256_private_p384_public)
{
    part_list_.for_each_session([](tsra_handle session) {
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;

        priv_props.ecc_curve = TSRA_ECC_CURVE_P256;
        pub_props.ecc_curve = TSRA_ECC_CURVE_P384;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto err = run_ecc_keygen_with_props(session, &priv_prop_list, &pub_prop_list);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_KEY_PROPS);
    });
}

/// Verifies that ECC key generation rejects mismatched P-384 private and P-521 public key curves.
TEST_F(tsra_ecc_keygen, keygen_rejects_curve_mismatch_p384_private_p521_public)
{
    part_list_.for_each_session([](tsra_handle session) {
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;

        priv_props.ecc_curve = TSRA_ECC_CURVE_P384;
        pub_props.ecc_curve = TSRA_ECC_CURVE_P521;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto err = run_ecc_keygen_with_props(session, &priv_prop_list, &pub_prop_list);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_KEY_PROPS);
    });
}

/// Verifies that ECC key generation rejects mismatched P-521 private and P-256 public key curves.
TEST_F(tsra_ecc_keygen, keygen_rejects_curve_mismatch_p521_private_p256_public)
{
    part_list_.for_each_session([](tsra_handle session) {
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;

        priv_props.ecc_curve = TSRA_ECC_CURVE_P521;
        pub_props.ecc_curve = TSRA_ECC_CURVE_P256;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto err = run_ecc_keygen_with_props(session, &priv_prop_list, &pub_prop_list);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_KEY_PROPS);
    });
}

/// Verifies that a masked P-256 ECC key can be unmasked after the original key pair is deleted.
TEST_F(tsra_ecc_keygen, unmask_p256_succeeds_after_original_keys_deleted)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_unmask_after_original_keys_deleted(session, TSRA_ECC_CURVE_P256);
    });
}

/// Verifies that a masked P-384 ECC key can be unmasked after the original key pair is deleted.
TEST_F(tsra_ecc_keygen, unmask_p384_succeeds_after_original_keys_deleted)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_unmask_after_original_keys_deleted(session, TSRA_ECC_CURVE_P384);
    });
}

/// Verifies that a masked P-521 ECC key can be unmasked after the original key pair is deleted.
TEST_F(tsra_ecc_keygen, unmask_p521_succeeds_after_original_keys_deleted)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_unmask_after_original_keys_deleted(session, TSRA_ECC_CURVE_P521);
    });
}

/// Verifies that unmasking a P-256 ECC key returns handles distinct from the original handles.
TEST_F(tsra_ecc_keygen, unmask_p256_returns_distinct_handles)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_unmasked_handles_are_distinct_from_original(session, TSRA_ECC_CURVE_P256);
    });
}

/// Verifies that unmasking a P-384 ECC key returns handles distinct from the original handles.
TEST_F(tsra_ecc_keygen, unmask_p384_returns_distinct_handles)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_unmasked_handles_are_distinct_from_original(session, TSRA_ECC_CURVE_P384);
    });
}

/// Verifies that unmasking a P-521 ECC key returns handles distinct from the original handles.
TEST_F(tsra_ecc_keygen, unmask_p521_returns_distinct_handles)
{
    part_list_.for_each_session([](tsra_handle session) {
        run_unmasked_handles_are_distinct_from_original(session, TSRA_ECC_CURVE_P521);
    });
}

/// Verifies that ECC key pair unmasking rejects an invalid session handle.
TEST_F(tsra_ecc_keygen, unmask_pair_rejects_invalid_session_handle)
{
    std::vector<uint8_t> masked_key_data(16, 0x42);

    tsra_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key priv_key;
    auto_key pub_key;

    auto err = tsra_key_unmask_pair(
        0xDEADBEEF,
        TSRA_KEY_KIND_ECC,
        &masked_key_buf,
        priv_key.get_ptr(),
        pub_key.get_ptr()
    );

    ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    ASSERT_EQ(priv_key.get(), 0u);
    ASSERT_EQ(pub_key.get(), 0u);
}