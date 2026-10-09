// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstring>
#include <gtest/gtest.h>
#include <tsra_api.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_key.hpp"
#include "utils/rsa_keygen.hpp"

class tsra_rsa_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// Verifies RSA 2048 key pair generation succeeds and keys can be deleted.
TEST_F(tsra_rsa_keygen, generate_rsa_2048_keypair)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
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

// Verifies generated RSA keys report the expected key kind and class properties.
TEST_F(tsra_rsa_keygen, get_key_properties)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        tsra_key_kind kind{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_KIND, .val = &kind, .len = sizeof(kind) };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(kind, TSRA_KEY_KIND_RSA);

        tsra_key_class key_class{};
        prop.id = TSRA_KEY_PROP_ID_CLASS;
        prop.val = &key_class;
        prop.len = sizeof(key_class);

        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(key_class, TSRA_KEY_CLASS_PRIVATE);
    });
}

// Verifies key property retrieval rejects a null output buffer.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_invalid_output_buffer)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        tsra_key_kind kind{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_KIND, .val = nullptr, .len = sizeof(kind) };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies EC curve property is not present on RSA private keys.
TEST_F(tsra_rsa_keygen, get_key_prop_ec_curve_not_present)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        tsra_ecc_curve curve{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve) };

        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_PROPERTY_NOT_PRESENT);
    });
}

// Verifies requesting an unsupported property returns the expected error.
TEST_F(tsra_rsa_keygen, get_key_prop_unknown_property_fails)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        uint32_t value{};
        tsra_key_prop prop{ .id = static_cast<tsra_key_prop_id>(0xFFFFFFFF),
                            .val = &value,
                            .len = sizeof(value) };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_UNSUPPORTED_PROPERTY);
    });
}

// Verifies generated RSA keys report the expected kind and public/private class.
TEST_F(tsra_rsa_keygen, generated_rsa_keys_report_expected_kind_and_class)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        tsra_key_kind pub_kind{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_KIND,
                            .val = &pub_kind,
                            .len = sizeof(pub_kind) };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(pub_kind, TSRA_KEY_KIND_RSA);

        tsra_key_kind priv_kind{};
        prop.id = TSRA_KEY_PROP_ID_KIND;
        prop.val = &priv_kind;
        prop.len = sizeof(priv_kind);

        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(priv_kind, TSRA_KEY_KIND_RSA);

        tsra_key_class pub_class{};
        prop.id = TSRA_KEY_PROP_ID_CLASS;
        prop.val = &pub_class;
        prop.len = sizeof(pub_class);

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(pub_class, TSRA_KEY_CLASS_PUBLIC);

        tsra_key_class priv_class{};
        prop.id = TSRA_KEY_PROP_ID_CLASS;
        prop.val = &priv_class;
        prop.len = sizeof(priv_class);

        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(priv_class, TSRA_KEY_CLASS_PRIVATE);
    });
}

// Verifies key property retrieval rejects a null property descriptor.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_null_property_pointer)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        err = tsra_key_get_prop(pub_key.get(), nullptr);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies key property retrieval rejects an invalid key handle.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_invalid_key_handle)
{
    part_list_.for_each_session([](tsra_handle /*session*/) {
        tsra_key_kind kind{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_KIND, .val = &kind, .len = sizeof(kind) };

        auto err = tsra_key_get_prop(static_cast<tsra_handle>(0), &prop);

        ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    });
}

// Verifies EC curve property is not present on RSA public keys.
TEST_F(tsra_rsa_keygen, get_key_prop_ec_curve_not_present_on_public_key)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        tsra_ecc_curve curve{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve) };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_PROPERTY_NOT_PRESENT);
    });
}

// Verifies failed property retrieval does not modify the caller's output buffer.
TEST_F(tsra_rsa_keygen, get_key_prop_does_not_modify_output_on_failure)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        tsra_ecc_curve curve = TSRA_ECC_CURVE_P256;
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve) };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_PROPERTY_NOT_PRESENT);
        ASSERT_EQ(curve, TSRA_ECC_CURVE_P256);
    });
}

// Verifies key kind property rejects an undersized output buffer.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_small_kind_buffer)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        uint8_t small_buffer{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_KIND,
                            .val = &small_buffer,
                            .len = sizeof(small_buffer) };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_BUFFER_TOO_SMALL);
    });
}

// Verifies key class property rejects an undersized output buffer.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_small_class_buffer)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        uint8_t small_buffer{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_CLASS,
                            .val = &small_buffer,
                            .len = sizeof(small_buffer) };

        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_BUFFER_TOO_SMALL);
    });
}

// Verifies key property retrieval rejects a zero-length output buffer.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_zero_length_buffer)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        tsra_key_kind kind{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_KIND, .val = &kind, .len = 0 };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_BUFFER_TOO_SMALL);
    });
}

// Verifies generated RSA unwrapping keys have the expected key attribute flags.
TEST_F(tsra_rsa_keygen, generate_unwrapping_key_flags)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        bool value{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_LOCAL, .val = &value, .len = sizeof(value) };

        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_TRUE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_SESSION;
        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = false;
        prop.id = TSRA_KEY_PROP_ID_SENSITIVE;
        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_TRUE(value);

        value = false;
        prop.id = TSRA_KEY_PROP_ID_EXTRACTABLE;
        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_TRUE(value);

        value = false;
        prop.id = TSRA_KEY_PROP_ID_LOCAL;
        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_TRUE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_SESSION;
        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_SENSITIVE;
        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = false;
        prop.id = TSRA_KEY_PROP_ID_EXTRACTABLE;
        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_TRUE(value);
    });
}

// Verifies generated RSA private keys expose only the expected capabilities.
TEST_F(tsra_rsa_keygen, generate_unwrapping_private_key_capability)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        bool value{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_UNWRAP, .val = &value, .len = sizeof(value) };

        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_TRUE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_SIGN;
        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_VERIFY;
        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_ENCRYPT;
        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_DECRYPT;
        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_WRAP;
        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_DERIVE;
        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);
    });
}

// Verifies generated RSA public keys expose only the expected capabilities.
TEST_F(tsra_rsa_keygen, generate_unwrapping_public_key_capability)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        bool value{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_WRAP, .val = &value, .len = sizeof(value) };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_TRUE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_SIGN;
        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_VERIFY;
        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_ENCRYPT;
        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_DECRYPT;
        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_UNWRAP;
        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);

        value = true;
        prop.id = TSRA_KEY_PROP_ID_DERIVE;
        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_FALSE(value);
    });
}

// Verifies both generated RSA keys report a 2048-bit length.
TEST_F(tsra_rsa_keygen, generated_keypair_reports_2048_bit_length)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        uint32_t priv_bits{};
        tsra_key_prop priv_prop{ .id = TSRA_KEY_PROP_ID_BIT_LEN,
                                 .val = &priv_bits,
                                 .len = sizeof(priv_bits) };

        err = tsra_key_get_prop(priv_key.get(), &priv_prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(priv_bits, 2048u);

        uint32_t pub_bits{};
        tsra_key_prop pub_prop{ .id = TSRA_KEY_PROP_ID_BIT_LEN,
                                .val = &pub_bits,
                                .len = sizeof(pub_bits) };

        err = tsra_key_get_prop(pub_key.get(), &pub_prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(pub_bits, 2048u);
    });
}

// Verifies BIT_LEN rejects a buffer smaller than uint32_t.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_small_bit_len_buffer)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        uint8_t small_buffer{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_BIT_LEN,
                            .val = &small_buffer,
                            .len = sizeof(small_buffer) };

        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_BUFFER_TOO_SMALL);
    });
}

// Verifies BIT_LEN rejects a zero-length output buffer.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_zero_length_bit_len_buffer)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        uint32_t bits{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = 0 };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_BUFFER_TOO_SMALL);
    });
}

// Verifies BIT_LEN rejects a null output pointer.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_null_bit_len_output_buffer)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_BIT_LEN,
                            .val = nullptr,
                            .len = sizeof(uint32_t) };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies failed BIT_LEN reads do not modify the caller's output value.
TEST_F(tsra_rsa_keygen, get_key_prop_bit_len_does_not_modify_output_on_failure)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        uint32_t bits = 0xA5A5A5A5;
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = 0 };

        err = tsra_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(bits, 0xA5A5A5A5u);
    });
}

// Verifies unknown property reads do not modify the caller's output value.
TEST_F(tsra_rsa_keygen, get_key_prop_unknown_property_does_not_modify_output)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        uint32_t value = 0xDEADBEEF;
        tsra_key_prop prop{ .id = static_cast<tsra_key_prop_id>(0xFFFFFFFF),
                            .val = &value,
                            .len = sizeof(value) };

        err = tsra_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_UNSUPPORTED_PROPERTY);
        ASSERT_EQ(value, 0xDEADBEEFu);
    });
}

// Verifies multiple RSA keypairs can be generated in the same session.
TEST_F(tsra_rsa_keygen, generate_multiple_rsa_keypairs_in_same_session)
{
    part_list_.for_each_session([](tsra_handle session) {
        for (int i = 0; i < 3; ++i)
        {
            SCOPED_TRACE(::testing::Message() << "RSA keygen iteration " << i);
            auto_key priv_key;
            auto_key pub_key;

            auto err =
                generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
            ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
            ASSERT_NE(priv_key.get(), 0);
            ASSERT_NE(pub_key.get(), 0);
            ASSERT_NE(priv_key.get(), pub_key.get());
        }
    });
}

// Verifies key handles are unique across separate RSA keygen calls.
TEST_F(tsra_rsa_keygen, generated_keypair_handles_are_unique_across_keygen_calls)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key first_priv_key;
        auto_key first_pub_key;
        auto_key second_priv_key;
        auto_key second_pub_key;

        auto err = generate_rsa_unwrapping_keypair(
            session,
            first_priv_key.get_ptr(),
            first_pub_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        err = generate_rsa_unwrapping_keypair(
            session,
            second_priv_key.get_ptr(),
            second_pub_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        ASSERT_NE(first_priv_key.get(), 0);
        ASSERT_NE(first_pub_key.get(), 0);
        ASSERT_NE(second_priv_key.get(), 0);
        ASSERT_NE(second_pub_key.get(), 0);

        ASSERT_NE(first_priv_key.get(), first_pub_key.get());
        ASSERT_NE(second_priv_key.get(), second_pub_key.get());
        ASSERT_NE(first_priv_key.get(), second_priv_key.get());
        ASSERT_NE(first_pub_key.get(), second_pub_key.get());
    });
}

// Verifies a deleted RSA private key handle can no longer be queried.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_deleted_private_key_handle)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);

        tsra_handle deleted_key = priv_key.get();

        err = tsra_key_delete(deleted_key);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        priv_key.release();

        tsra_key_kind kind{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_KIND, .val = &kind, .len = sizeof(kind) };

        err = tsra_key_get_prop(deleted_key, &prop);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    });
}

// Verifies a deleted RSA public key handle can no longer be queried.
TEST_F(tsra_rsa_keygen, get_key_prop_rejects_deleted_public_key_handle)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(pub_key.get(), 0);

        tsra_handle deleted_key = pub_key.get();

        err = tsra_key_delete(deleted_key);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        pub_key.release();

        tsra_key_kind kind{};
        tsra_key_prop prop{ .id = TSRA_KEY_PROP_ID_KIND, .val = &kind, .len = sizeof(kind) };

        err = tsra_key_get_prop(deleted_key, &prop);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    });
}

// Verifies deleting the same RSA key handle twice does not report success twice.
TEST_F(tsra_rsa_keygen, delete_rsa_key_twice_fails_second_delete)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);

        tsra_handle deleted_key = priv_key.get();

        err = tsra_key_delete(deleted_key);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        priv_key.release();

        err = tsra_key_delete(deleted_key);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    });
}

// Verifies RSA keygen rejects a null private-key output pointer.
TEST_F(tsra_rsa_keygen, generate_rsa_keypair_rejects_null_private_key_output)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key pub_key;

        auto err = generate_rsa_unwrapping_keypair(session, nullptr, pub_key.get_ptr());

        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(pub_key.get(), 0);
    });
}

// Verifies RSA keygen rejects a null public-key output pointer.
TEST_F(tsra_rsa_keygen, generate_rsa_keypair_rejects_null_public_key_output)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto_key priv_key;

        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), nullptr);

        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(priv_key.get(), 0);
    });
}

// Verifies RSA keygen rejects both output pointers being null.
TEST_F(tsra_rsa_keygen, generate_rsa_keypair_rejects_null_output_pointers)
{
    part_list_.for_each_session([](tsra_handle session) {
        auto err = generate_rsa_unwrapping_keypair(session, nullptr, nullptr);

        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies RSA keygen rejects an invalid session handle.
TEST_F(tsra_rsa_keygen, generate_rsa_keypair_rejects_invalid_session_handle)
{
    auto_key priv_key;
    auto_key pub_key;

    auto err = generate_rsa_unwrapping_keypair(
        static_cast<tsra_handle>(0),
        priv_key.get_ptr(),
        pub_key.get_ptr()
    );

    ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    ASSERT_EQ(priv_key.get(), 0);
    ASSERT_EQ(pub_key.get(), 0);
}
