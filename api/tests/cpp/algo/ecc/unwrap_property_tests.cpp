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
#include "utils/rsa_keygen.hpp"

class tsra_ecc_keyunwrap_property : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

static void expect_unwrap_result(UnwrapPairResult result, tsra_status expected)
{
    auto_key private_key;
    auto_key public_key;
    private_key.handle = result.private_key;
    public_key.handle = result.public_key;
    ASSERT_EQ(result.status, expected);
    if (expected == TSRA_STATUS_SUCCESS)
    {
        ASSERT_NE(result.private_key, 0u);
        ASSERT_NE(result.public_key, 0u);
    }
    else
    {
        ASSERT_EQ(result.private_key, 0u);
        ASSERT_EQ(result.public_key, 0u);
    }
}

template <typename Mutate>
static void expect_unwrap_property_failure(
    PartitionListHandle &part_list,
    tsra_status expected,
    Mutate mutate
)
{
    part_list.for_each_session([&](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(ctx.try_unwrap(), TSRA_STATUS_SUCCESS));
        mutate(ctx);
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(ctx.try_unwrap(), expected));
    });
}

// Helper: unwraps a wrapped ECC key pair for the given curve and verifies the
// imported keys preserve the requested properties (CLASS, KIND, EC_CURVE,
// SESSION, SIGN/VERIFY).
static void verify_unwrap_pair_preserves_properties(
    PartitionListHandle &part_list,
    tsra_ecc_curve curve
)
{
    part_list.for_each_session([&](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, curve, ctx),
            TSRA_STATUS_SUCCESS
        );

        ctx.priv_props.ecc_curve = curve;
        ctx.pub_props.ecc_curve = curve;

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);

        auto_key imported_private_key;
        auto_key imported_public_key;
        imported_private_key.handle = result.private_key;
        imported_public_key.handle = result.public_key;

        ASSERT_NE(imported_private_key.get(), 0u);
        ASSERT_NE(imported_public_key.get(), 0u);
        tsra_key_class private_class = TSRA_KEY_CLASS_PUBLIC;
        tsra_key_kind private_kind = TSRA_KEY_KIND_AES;
        tsra_ecc_curve private_curve = TSRA_ECC_CURVE_P256;
        uint8_t private_session = 0;
        uint8_t private_sign = 0;

        ASSERT_EQ(
            get_key_prop(imported_private_key.get(), TSRA_KEY_PROP_ID_CLASS, private_class),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(
            get_key_prop(imported_private_key.get(), TSRA_KEY_PROP_ID_KIND, private_kind),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(
            get_key_prop(imported_private_key.get(), TSRA_KEY_PROP_ID_EC_CURVE, private_curve),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(
            get_key_prop(imported_private_key.get(), TSRA_KEY_PROP_ID_SESSION, private_session),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(
            get_key_prop(imported_private_key.get(), TSRA_KEY_PROP_ID_SIGN, private_sign),
            TSRA_STATUS_SUCCESS
        );

        tsra_key_class public_class = TSRA_KEY_CLASS_PRIVATE;
        tsra_key_kind public_kind = TSRA_KEY_KIND_AES;
        tsra_ecc_curve public_curve = TSRA_ECC_CURVE_P256;
        uint8_t public_session = 0;
        uint8_t public_verify = 0;

        ASSERT_EQ(
            get_key_prop(imported_public_key.get(), TSRA_KEY_PROP_ID_CLASS, public_class),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(
            get_key_prop(imported_public_key.get(), TSRA_KEY_PROP_ID_KIND, public_kind),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(
            get_key_prop(imported_public_key.get(), TSRA_KEY_PROP_ID_EC_CURVE, public_curve),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(
            get_key_prop(imported_public_key.get(), TSRA_KEY_PROP_ID_SESSION, public_session),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(
            get_key_prop(imported_public_key.get(), TSRA_KEY_PROP_ID_VERIFY, public_verify),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(private_class, TSRA_KEY_CLASS_PRIVATE);
        ASSERT_EQ(private_kind, TSRA_KEY_KIND_ECC);
        ASSERT_EQ(private_curve, curve);
        ASSERT_EQ(private_session, ctx.priv_props.is_session);
        ASSERT_EQ(private_sign, ctx.priv_props.can_sign);

        ASSERT_EQ(public_class, TSRA_KEY_CLASS_PUBLIC);
        ASSERT_EQ(public_kind, TSRA_KEY_KIND_ECC);
        ASSERT_EQ(public_curve, curve);
        ASSERT_EQ(public_session, ctx.pub_props.is_session);
        ASSERT_EQ(public_verify, ctx.pub_props.can_verify);
    });
}

// P-256: unwrapped keys preserve all requested properties.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_preserves_properties_p256)
{
    verify_unwrap_pair_preserves_properties(part_list_, TSRA_ECC_CURVE_P256);
}

// P-384: unwrapped keys preserve all requested properties.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_preserves_properties_p384)
{
    verify_unwrap_pair_preserves_properties(part_list_, TSRA_ECC_CURVE_P384);
}

// P-521: unwrapped keys preserve all requested properties.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_preserves_properties_p521)
{
    verify_unwrap_pair_preserves_properties(part_list_, TSRA_ECC_CURVE_P521);
}

// ==================== key_unwrap_pair: Property Argument Validation ====================

// ----- Private/Public Property Argument Validation -----

// Verifies unwrap preserves requested SESSION flag for persistent/token-key imports.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_preserves_session_flag_cleared)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );

        ctx.priv_props.is_session = 0;
        ctx.pub_props.is_session = 0;

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key imported_private_key;
        auto_key imported_public_key;
        imported_private_key.handle = result.private_key;
        imported_public_key.handle = result.public_key;

        uint8_t private_session = 1;
        uint8_t public_session = 1;
        ASSERT_EQ(
            get_key_prop(imported_private_key.get(), TSRA_KEY_PROP_ID_SESSION, private_session),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(
            get_key_prop(imported_public_key.get(), TSRA_KEY_PROP_ID_SESSION, public_session),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(private_session, 0);
        ASSERT_EQ(public_session, 0);
    });
}

// Verifies unwrap rejects malformed or invalid private-key property lists.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_invalid_private_property_list)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(ctx.try_unwrap(), TSRA_STATUS_SUCCESS));

        auto pub_prop_list = ctx.pub_props.get_prop_list();

        tsra_key_prop_list malformed_priv_list{};
        malformed_priv_list.props = nullptr;
        malformed_priv_list.count = 1;

        auto result = try_unwrap_pair(
            &ctx.unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &malformed_priv_list,
            &pub_prop_list
        );
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(result, TSRA_STATUS_INVALID_ARGUMENT));
    });
}

// Verifies unwrap rejects private CLASS set to PUBLIC.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_private_class_set_to_public)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.priv_props.key_class = TSRA_KEY_CLASS_PUBLIC; }
    );
}

// Verifies unwrap rejects private KIND set to non-ECC.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_private_kind_not_ecc)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.priv_props.key_kind = TSRA_KEY_KIND_RSA; }
    );
}

// Verifies unwrap rejects malformed or invalid public-key property lists.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_invalid_public_property_list)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(ctx.try_unwrap(), TSRA_STATUS_SUCCESS));

        auto priv_prop_list = ctx.priv_props.get_prop_list();

        tsra_key_prop_list malformed_pub_list{};
        malformed_pub_list.props = nullptr;
        malformed_pub_list.count = 1;

        auto result = try_unwrap_pair(
            &ctx.unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            &malformed_pub_list
        );
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(result, TSRA_STATUS_INVALID_ARGUMENT));
    });
}

// Verifies unwrap rejects public CLASS set to PRIVATE.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_public_class_set_to_private)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.pub_props.key_class = TSRA_KEY_CLASS_PRIVATE; }
    );
}

// Verifies unwrap rejects public KIND set to non-ECC.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_public_kind_not_ecc)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.pub_props.key_kind = TSRA_KEY_KIND_RSA; }
    );
}

// Verifies private VERIFY is rejected while the valid SIGN capability remains set.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_private_verify_flag)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) {
            ctx.priv_props.props.push_back({ TSRA_KEY_PROP_ID_VERIFY,
                                             &ctx.priv_props.can_sign,
                                             sizeof(ctx.priv_props.can_sign) });
        }
    );
}

// Verifies public SIGN is rejected while the valid VERIFY capability remains set.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_public_sign_flag)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) {
            ctx.pub_props.props.push_back({ TSRA_KEY_PROP_ID_SIGN,
                                            &ctx.pub_props.can_verify,
                                            sizeof(ctx.pub_props.can_verify) });
        }
    );
}

// Verifies unwrap allows duplicate property IDs in the private property list.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_allows_duplicate_private_property_id)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );

        ctx.priv_props.props.push_back({ TSRA_KEY_PROP_ID_EC_CURVE,
                                         &ctx.priv_props.ecc_curve,
                                         sizeof(ctx.priv_props.ecc_curve) });

        auto result = ctx.try_unwrap();

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;
    });
}

// Verifies unwrap rejects conflicting property values in public property list.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_conflicting_public_property_value)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(ctx.try_unwrap(), TSRA_STATUS_SUCCESS));

        uint8_t conflicting_verify = 0;
        ctx.pub_props.props.push_back(
            { TSRA_KEY_PROP_ID_VERIFY, &conflicting_verify, sizeof(conflicting_verify) }
        );

        ASSERT_NO_FATAL_FAILURE(
            expect_unwrap_result(ctx.try_unwrap(), TSRA_STATUS_INVALID_KEY_PROPS)
        );
    });
}

// Verifies unwrap rejects private property with null value and non-zero length.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_private_property_null_value_nonzero_len)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](UnwrapPairContext &ctx) { ctx.priv_props.props.front().val = nullptr; }
    );
}

// Verifies unwrap rejects public property with null value and non-zero length.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_public_property_null_value_nonzero_len)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](UnwrapPairContext &ctx) { ctx.pub_props.props.front().val = nullptr; }
    );
}

// Verifies unwrap rejects property length mismatches in unwrap lists.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_property_length_mismatch)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](UnwrapPairContext &ctx) {
            ctx.priv_props.props.front().len = sizeof(ctx.priv_props.key_class) - 1;
        }
    );
}

// Verifies omissions from a session SIGN/VERIFY pair return the specific property error.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_private_missing_required_properties_table)
{
    const struct
    {
        tsra_key_prop_id id;
        tsra_status expected;
    } cases[] = {
        { TSRA_KEY_PROP_ID_CLASS, TSRA_STATUS_KEY_CLASS_NOT_SPECIFIED },
        { TSRA_KEY_PROP_ID_KIND, TSRA_STATUS_KEY_KIND_NOT_SPECIFIED },
        { TSRA_KEY_PROP_ID_EC_CURVE, TSRA_STATUS_PROPERTY_NOT_PRESENT },
        { TSRA_KEY_PROP_ID_SESSION, TSRA_STATUS_INVALID_KEY_PROPS },
        { TSRA_KEY_PROP_ID_SIGN, TSRA_STATUS_INVALID_KEY_PROPS },
    };
    for (const auto &test_case : cases)
    {
        SCOPED_TRACE(test_case.id);
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_property_failure(
            part_list_,
            test_case.expected,
            [&](UnwrapPairContext &ctx) { remove_prop_by_id(ctx.priv_props.props, test_case.id); }
        ));
    }
}

// Verifies omissions from a session SIGN/VERIFY pair return the specific property error.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_public_missing_required_properties_table)
{
    const struct
    {
        tsra_key_prop_id id;
        tsra_status expected;
    } cases[] = {
        { TSRA_KEY_PROP_ID_CLASS, TSRA_STATUS_KEY_CLASS_NOT_SPECIFIED },
        { TSRA_KEY_PROP_ID_KIND, TSRA_STATUS_KEY_KIND_NOT_SPECIFIED },
        { TSRA_KEY_PROP_ID_EC_CURVE, TSRA_STATUS_PROPERTY_NOT_PRESENT },
        { TSRA_KEY_PROP_ID_SESSION, TSRA_STATUS_INVALID_KEY_PROPS },
        { TSRA_KEY_PROP_ID_VERIFY, TSRA_STATUS_INVALID_KEY_PROPS },
    };
    for (const auto &test_case : cases)
    {
        SCOPED_TRACE(test_case.id);
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_property_failure(
            part_list_,
            test_case.expected,
            [&](UnwrapPairContext &ctx) { remove_prop_by_id(ctx.pub_props.props, test_case.id); }
        ));
    }
}

// Verifies unwrap rejects curve mismatch between private/public properties.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_curve_mismatch_between_priv_pub)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.pub_props.ecc_curve = TSRA_ECC_CURVE_P384; }
    );
}

// Verifies unwrap rejects session mismatch between private/public properties.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_session_mismatch_between_priv_pub)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.pub_props.is_session = 0; }
    );
}

// Verifies unwrap allows duplicate property IDs in the public property list.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_allows_duplicate_public_property_id)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );

        ctx.pub_props.props.push_back(
            { TSRA_KEY_PROP_ID_EC_CURVE, &ctx.pub_props.ecc_curve, sizeof(ctx.pub_props.ecc_curve) }
        );

        auto result = ctx.try_unwrap();

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;
    });
}

// Verifies unwrap rejects requested EC_CURVE that does not match the wrapped ECC key.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_requested_curve_mismatch_with_wrapped_key)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );

        ctx.priv_props.ecc_curve = TSRA_ECC_CURVE_P384;
        ctx.pub_props.ecc_curve = TSRA_ECC_CURVE_P384;

        auto result = ctx.try_unwrap();
        ASSERT_NE(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects invalid private EC_CURVE enum value.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_invalid_private_curve_value)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](UnwrapPairContext &ctx) { ctx.priv_props.ecc_curve = static_cast<tsra_ecc_curve>(0x7F); }
    );
}

// Verifies unwrap rejects invalid public EC_CURVE enum value.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_invalid_public_curve_value)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](UnwrapPairContext &ctx) { ctx.pub_props.ecc_curve = static_cast<tsra_ecc_curve>(0x7F); }
    );
}

// Verifies unwrap rejects public property length mismatch.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_public_property_length_mismatch)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](UnwrapPairContext &ctx) {
            ctx.pub_props.props.front().len = sizeof(ctx.pub_props.key_class) - 1;
        }
    );
}

// Verifies unwrap rejects private property with valid value pointer but zero length.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_private_property_zero_length)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](UnwrapPairContext &ctx) { ctx.priv_props.props.front().len = 0; }
    );
}

// Verifies unwrap rejects public property with valid value pointer but zero length.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_public_property_zero_length)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_ARGUMENT,
        [](UnwrapPairContext &ctx) { ctx.pub_props.props.front().len = 0; }
    );
}

// Verifies unwrap rejects private key when SIGN capability is explicitly disabled.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_private_sign_disabled)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.priv_props.can_sign = 0; }
    );
}

// Verifies unwrap rejects public key when VERIFY capability is explicitly disabled.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_public_verify_disabled)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.pub_props.can_verify = 0; }
    );
}

// Verifies unwrap rejects private key with no usage flags.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_private_no_usage_flags)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) {
            remove_prop_by_id(ctx.priv_props.props, TSRA_KEY_PROP_ID_SIGN);
        }
    );
}

// Verifies unwrap rejects public key with no usage flags.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_public_no_usage_flags)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) {
            remove_prop_by_id(ctx.pub_props.props, TSRA_KEY_PROP_ID_VERIFY);
        }
    );
}

// Verifies unwrap rejects private key with both SIGN and DERIVE usage flags.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_private_sign_and_derive)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.priv_props.can_derive = 1; }
    );
}

// Verifies unwrap rejects public key with both VERIFY and DERIVE usage flags.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_public_verify_and_derive)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.pub_props.can_derive = 1; }
    );
}

// Verifies unwrap rejects DERIVE-only private key paired with VERIFY public key.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_derive_private_verify_public)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) {
            ctx.priv_props.can_sign = 0;
            ctx.priv_props.can_derive = 1;
        }
    );
}

// Verifies unwrap rejects SIGN private key paired with DERIVE-only public key.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_sign_private_derive_public)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) {
            ctx.pub_props.can_verify = 0;
            ctx.pub_props.can_derive = 1;
        }
    );
}

// Verifies unwrap rejects session mismatch when private is persistent and public is session.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_reverse_session_mismatch_between_priv_pub)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.priv_props.is_session = 0; }
    );
}

// Verifies unwrap rejects curve mismatch when private curve differs from public curve.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_reverse_curve_mismatch_between_priv_pub)
{
    expect_unwrap_property_failure(
        part_list_,
        TSRA_STATUS_INVALID_KEY_PROPS,
        [](UnwrapPairContext &ctx) { ctx.priv_props.ecc_curve = TSRA_ECC_CURVE_P384; }
    );
}

// Verifies unwrap treats a non-zero private SESSION value as true.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_allows_nonzero_private_session_value)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );

        ctx.priv_props.is_session = 2;
        ctx.pub_props.is_session = 1;

        auto result = ctx.try_unwrap();

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;

        uint8_t private_session = 0;
        ASSERT_EQ(
            get_key_prop(private_key.get(), TSRA_KEY_PROP_ID_SESSION, private_session),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(private_session, 0);
    });
}

// Verifies unwrap treats a non-zero public SESSION value as true.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_allows_nonzero_public_session_value)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );

        ctx.priv_props.is_session = 1;
        ctx.pub_props.is_session = 2;

        auto result = ctx.try_unwrap();

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;

        uint8_t public_session = 0;
        ASSERT_EQ(
            get_key_prop(public_key.get(), TSRA_KEY_PROP_ID_SESSION, public_session),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(public_session, 0);
    });
}

// Verifies unwrap treats a non-zero private SIGN value as true.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_allows_nonzero_private_sign_value)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );

        ctx.priv_props.can_sign = 2;

        auto result = ctx.try_unwrap();

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;

        uint8_t private_sign = 0;
        ASSERT_EQ(
            get_key_prop(private_key.get(), TSRA_KEY_PROP_ID_SIGN, private_sign),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(private_sign, 0);
    });
}

// Verifies unwrap treats a non-zero public VERIFY value as true.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_allows_nonzero_public_verify_value)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );

        ctx.pub_props.can_verify = 2;

        auto result = ctx.try_unwrap();

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;

        uint8_t public_verify = 0;
        ASSERT_EQ(
            get_key_prop(public_key.get(), TSRA_KEY_PROP_ID_VERIFY, public_verify),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(public_verify, 0);
    });
}

// Verifies unwrap ignores unknown private property IDs.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_ignores_unknown_private_property_id)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );

        uint8_t value = 1;
        ctx.priv_props.props.push_back(
            { static_cast<tsra_key_prop_id>(0x7FFF), &value, sizeof(value) }
        );

        auto result = ctx.try_unwrap();

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;
    });
}

// Verifies unwrap ignores unknown public property IDs.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_ignores_unknown_public_property_id)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );

        uint8_t value = 1;
        ctx.pub_props.props.push_back(
            { static_cast<tsra_key_prop_id>(0x7FFF), &value, sizeof(value) }
        );

        auto result = ctx.try_unwrap();

        ASSERT_EQ(result.status, TSRA_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;
    });
}

static void expect_unwrap_flag_rejected(
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
            UnwrapPairContext ctx;
            ASSERT_EQ(
                UnwrapPairContext::create_with_wrapped_blob(session, curve.curve, ctx),
                TSRA_STATUS_SUCCESS
            );
            set_ecc_pair_properties(ctx.priv_props, ctx.pub_props, curve.curve, can_derive, true);
            uint8_t enabled = 0;
            auto &target =
                key_class == TSRA_KEY_CLASS_PRIVATE ? ctx.priv_props.props : ctx.pub_props.props;
            target.push_back({ flag, &enabled, sizeof(enabled) });
            ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(ctx.try_unwrap(), TSRA_STATUS_SUCCESS));

            enabled = 1;
            ASSERT_NO_FATAL_FAILURE(
                expect_unwrap_result(ctx.try_unwrap(), TSRA_STATUS_INVALID_KEY_PROPS)
            );
        });
    }
}

TEST_F(tsra_ecc_keyunwrap_property, private_sign_encrypt_rejected)
{
    expect_unwrap_flag_rejected(
        part_list_,
        TSRA_KEY_CLASS_PRIVATE,
        false,
        TSRA_KEY_PROP_ID_ENCRYPT
    );
}

TEST_F(tsra_ecc_keyunwrap_property, private_derive_encrypt_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, true, TSRA_KEY_PROP_ID_ENCRYPT);
}

TEST_F(tsra_ecc_keyunwrap_property, private_sign_decrypt_rejected)
{
    expect_unwrap_flag_rejected(
        part_list_,
        TSRA_KEY_CLASS_PRIVATE,
        false,
        TSRA_KEY_PROP_ID_DECRYPT
    );
}

TEST_F(tsra_ecc_keyunwrap_property, private_derive_decrypt_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, true, TSRA_KEY_PROP_ID_DECRYPT);
}

TEST_F(tsra_ecc_keyunwrap_property, private_sign_wrap_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, false, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_ecc_keyunwrap_property, private_derive_wrap_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, true, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_ecc_keyunwrap_property, private_sign_unwrap_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, false, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_ecc_keyunwrap_property, private_derive_unwrap_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, true, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_ecc_keyunwrap_property, private_sign_verify_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, false, TSRA_KEY_PROP_ID_VERIFY);
}

TEST_F(tsra_ecc_keyunwrap_property, private_derive_verify_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PRIVATE, true, TSRA_KEY_PROP_ID_VERIFY);
}

TEST_F(tsra_ecc_keyunwrap_property, public_verify_encrypt_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, false, TSRA_KEY_PROP_ID_ENCRYPT);
}

TEST_F(tsra_ecc_keyunwrap_property, public_derive_encrypt_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, true, TSRA_KEY_PROP_ID_ENCRYPT);
}

TEST_F(tsra_ecc_keyunwrap_property, public_verify_decrypt_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, false, TSRA_KEY_PROP_ID_DECRYPT);
}

TEST_F(tsra_ecc_keyunwrap_property, public_derive_decrypt_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, true, TSRA_KEY_PROP_ID_DECRYPT);
}

TEST_F(tsra_ecc_keyunwrap_property, public_verify_wrap_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, false, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_ecc_keyunwrap_property, public_derive_wrap_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, true, TSRA_KEY_PROP_ID_WRAP);
}

TEST_F(tsra_ecc_keyunwrap_property, public_verify_unwrap_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, false, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_ecc_keyunwrap_property, public_derive_unwrap_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, true, TSRA_KEY_PROP_ID_UNWRAP);
}

TEST_F(tsra_ecc_keyunwrap_property, public_verify_sign_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, false, TSRA_KEY_PROP_ID_SIGN);
}

TEST_F(tsra_ecc_keyunwrap_property, public_derive_sign_rejected)
{
    expect_unwrap_flag_rejected(part_list_, TSRA_KEY_CLASS_PUBLIC, true, TSRA_KEY_PROP_ID_SIGN);
}

// Verifies unwrap rejects an empty private property list while using a valid wrapped ECC blob.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_empty_private_property_list)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(ctx.try_unwrap(), TSRA_STATUS_SUCCESS));

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        priv_prop_list.count = 0;

        auto result = try_unwrap_pair(
            &ctx.unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );

        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(result, TSRA_STATUS_INVALID_ARGUMENT));
    });
}

// Verifies unwrap rejects an empty public property list while using a valid wrapped ECC blob.
TEST_F(tsra_ecc_keyunwrap_property, unwrap_pair_rejects_empty_public_property_list)
{
    part_list_.for_each_session([](tsra_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, TSRA_ECC_CURVE_P256, ctx),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(ctx.try_unwrap(), TSRA_STATUS_SUCCESS));

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        pub_prop_list.count = 0;

        auto result = try_unwrap_pair(
            &ctx.unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );

        ASSERT_NO_FATAL_FAILURE(expect_unwrap_result(result, TSRA_STATUS_INVALID_ARGUMENT));
    });
}