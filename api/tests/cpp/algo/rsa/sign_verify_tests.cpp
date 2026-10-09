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
#include "rsa_static_der.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/auto_key.hpp"
#include "utils/key_import.hpp"
#include "utils/key_props.hpp"
#include "utils/rsa_keygen.hpp"

class tsra_rsa_sign_verify : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function to setup wrapping and imported key pairs
    void setup_keys(
        tsra_handle session,
        auto_key &wrapping_priv_key,
        auto_key &wrapping_pub_key,
        auto_key &imported_priv_key,
        auto_key &imported_pub_key
    )
    {
        // Generate wrapping key pair
        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Import test key pair
        key_props import_props = {
            .key_kind = TSRA_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(imported_priv_key.get(), 0);
        ASSERT_NE(imported_pub_key.get(), 0);
    }

    // Helper function to perform single-shot sign/verify test
    void test_single_shot_sign_verify(
        tsra_handle priv_key,
        tsra_handle pub_key,
        tsra_algo &sign_algo,
        const std::vector<uint8_t> &data_to_sign
    )
    {
        tsra_buffer data_buf = { .ptr = const_cast<uint8_t *>(data_to_sign.data()),
                                 .len = static_cast<uint32_t>(data_to_sign.size()) };

        std::vector<uint8_t> signature_data(256);
        tsra_buffer sig_buf = { .ptr = signature_data.data(),
                                .len = static_cast<uint32_t>(signature_data.size()) };

        // Sign
        auto sign_err = tsra_crypt_sign(&sign_algo, priv_key, &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, TSRA_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);
        ASSERT_LE(sig_buf.len, 256);

        // Verify
        tsra_buffer verify_sig_buf = { .ptr = signature_data.data(), .len = sig_buf.len };
        auto verify_err = tsra_crypt_verify(&sign_algo, pub_key, &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, TSRA_STATUS_SUCCESS);

        // Verify fails with modified data
        std::vector<uint8_t> modified_data = data_to_sign;
        modified_data[0] ^= 0xFF;
        tsra_buffer modified_buf = { .ptr = modified_data.data(),
                                     .len = static_cast<uint32_t>(modified_data.size()) };
        auto verify_fail_err =
            tsra_crypt_verify(&sign_algo, pub_key, &modified_buf, &verify_sig_buf);
        ASSERT_NE(verify_fail_err, TSRA_STATUS_SUCCESS);
    }

    // Helper function to perform streaming sign/verify test
    void test_streaming_sign_verify(
        tsra_handle priv_key,
        tsra_handle pub_key,
        tsra_algo &sign_algo,
        const std::vector<const char *> &data_chunks
    )
    {
        // Streaming sign
        auto_ctx sign_ctx;
        ASSERT_EQ(
            tsra_crypt_sign_init(&sign_algo, priv_key, sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        for (const char *chunk : data_chunks)
        {
            tsra_buffer buf = { .ptr = (uint8_t *)chunk, .len = (uint32_t)strlen(chunk) };
            ASSERT_EQ(tsra_crypt_sign_update(sign_ctx, &buf), TSRA_STATUS_SUCCESS);
        }

        std::vector<uint8_t> signature_data(256);
        tsra_buffer sig_buf = { .ptr = signature_data.data(), .len = 256 };
        ASSERT_EQ(tsra_crypt_sign_finish(sign_ctx, &sig_buf), TSRA_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        // Streaming verify
        auto_ctx verify_ctx;
        ASSERT_EQ(
            tsra_crypt_verify_init(&sign_algo, pub_key, verify_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        for (const char *chunk : data_chunks)
        {
            tsra_buffer buf = { .ptr = (uint8_t *)chunk, .len = (uint32_t)strlen(chunk) };
            ASSERT_EQ(tsra_crypt_verify_update(verify_ctx, &buf), TSRA_STATUS_SUCCESS);
        }

        tsra_buffer verify_sig_buf = { .ptr = signature_data.data(), .len = sig_buf.len };
        ASSERT_EQ(tsra_crypt_verify_finish(verify_ctx, &verify_sig_buf), TSRA_STATUS_SUCCESS);

        // Verify fails with modified data
        auto_ctx verify_fail_ctx;
        ASSERT_EQ(
            tsra_crypt_verify_init(&sign_algo, pub_key, verify_fail_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        std::vector<const char *> modified_chunks = data_chunks;
        modified_chunks[0] = "Modified ";

        for (const char *chunk : modified_chunks)
        {
            tsra_buffer buf = { .ptr = (uint8_t *)chunk, .len = (uint32_t)strlen(chunk) };
            ASSERT_EQ(tsra_crypt_verify_update(verify_fail_ctx, &buf), TSRA_STATUS_SUCCESS);
        }

        ASSERT_NE(tsra_crypt_verify_finish(verify_fail_ctx, &verify_sig_buf), TSRA_STATUS_SUCCESS);
    }

    // Sets up imported RSA keys using the static PKCS#8 DER vector for the requested key size.
    void setup_keys_for_size(
        tsra_handle session,
        uint32_t key_size_bits,
        auto_key &wrapping_priv_key,
        auto_key &wrapping_pub_key,
        auto_key &imported_priv_key,
        auto_key &imported_pub_key
    )
    {
        ASSERT_EQ(
            generate_rsa_unwrapping_keypair(
                session,
                wrapping_priv_key.get_ptr(),
                wrapping_pub_key.get_ptr()
            ),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        const uint8_t *der_ptr = nullptr;
        size_t der_len = 0;

        ASSERT_EQ(get_static_rsa_pkcs8_der(key_size_bits, der_ptr, der_len), TSRA_STATUS_SUCCESS);
        ASSERT_NE(der_ptr, nullptr);
        ASSERT_GT(der_len, 0);

        std::vector<uint8_t> private_key_der(der_ptr, der_ptr + der_len);

        key_props import_props = {
            .key_kind = TSRA_KEY_KIND_RSA,
            .key_size_bits = key_size_bits,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };

        ASSERT_EQ(
            import_keypair(
                wrapping_pub_key.get(),
                wrapping_priv_key.get(),
                private_key_der,
                import_props,
                imported_priv_key.get_ptr(),
                imported_pub_key.get_ptr()
            ),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(imported_priv_key.get(), 0);
        ASSERT_NE(imported_pub_key.get(), 0);
    }

    void assert_pkcs_sha256_sign_verify_for_key_size(
        tsra_handle private_key,
        tsra_handle public_key,
        uint32_t key_size_bits
    )
    {
        std::vector<uint8_t> data = { 'r', 's', 'a', '-', 'k', 'e', 'y', '-', 's', 'i', 'z', 'e' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(key_size_bits / 8);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(tsra_crypt_sign(&algo, private_key, &data_buf, &sig_buf), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(sig_buf.len, key_size_bits / 8);

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(
            tsra_crypt_verify(&algo, public_key, &data_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );
    }

    void assert_pss_sha256_sign_verify_for_key_size(
        tsra_handle private_key,
        tsra_handle public_key,
        uint32_t key_size_bits
    )
    {
        std::vector<uint8_t> data = { 'r', 's', 'a', '-', 'p', 's', 's', '-',
                                      'k', 'e', 'y', '-', 's', 'i', 'z', 'e' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 32,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = &params,
            .len = sizeof(params),
        };

        std::vector<uint8_t> signature(key_size_bits / 8);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(tsra_crypt_sign(&algo, private_key, &data_buf, &sig_buf), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(sig_buf.len, key_size_bits / 8);

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(
            tsra_crypt_verify(&algo, public_key, &data_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );
    }
};

// Unified test data structure for RSA tests (both single-shot and streaming)
struct RsaTestParams
{
    tsra_algo_id algo_id;
    const char *test_name;
    tsra_algo_rsa_pkcs_pss_params *pss_params; // nullptr for PKCS#1
};

// RSA PKCS#1 Single-Shot Sign/Verify Tests (Raw Message)
TEST_F(tsra_rsa_sign_verify, sign_verify_pkcs_all_hash_algorithms)
{
    std::vector<RsaTestParams> test_cases = {
        { TSRA_ALGO_ID_RSA_PKCS_SHA1, "SHA1", nullptr },
        { TSRA_ALGO_ID_RSA_PKCS_SHA256, "SHA256", nullptr },
        { TSRA_ALGO_ID_RSA_PKCS_SHA384, "SHA384", nullptr },
        { TSRA_ALGO_ID_RSA_PKCS_SHA512, "SHA512", nullptr },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing PKCS#1 with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](tsra_handle session) {
            auto_key wrapping_priv_key, wrapping_pub_key;
            auto_key imported_priv_key, imported_pub_key;
            setup_keys(
                session,
                wrapping_priv_key,
                wrapping_pub_key,
                imported_priv_key,
                imported_pub_key
            );

            std::string test_data =
                std::string("Test RSA PKCS#1 v1.5 ") + test_case.test_name + " signing";
            std::vector<uint8_t> data_to_sign(test_data.begin(), test_data.end());

            tsra_algo sign_algo = {
                .id = test_case.algo_id,
                .params = test_case.pss_params,
                .len = test_case.pss_params
                           ? static_cast<uint32_t>(sizeof(tsra_algo_rsa_pkcs_pss_params))
                           : 0
            };

            test_single_shot_sign_verify(
                imported_priv_key.get(),
                imported_pub_key.get(),
                sign_algo,
                data_to_sign
            );

            ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
            ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
        });
    }
}

// RSA PSS Single-Shot Sign/Verify Tests (Raw Message)
TEST_F(tsra_rsa_sign_verify, sign_verify_pss_all_hash_algorithms)
{
    tsra_algo_rsa_pkcs_pss_params pss_params_sha1 = { .hash_algo_id = TSRA_ALGO_ID_SHA1,
                                                      .mgf_id = TSRA_MGF1_ID_SHA1,
                                                      .salt_len = 20 };

    tsra_algo_rsa_pkcs_pss_params pss_params_sha256 = { .hash_algo_id = TSRA_ALGO_ID_SHA256,
                                                        .mgf_id = TSRA_MGF1_ID_SHA256,
                                                        .salt_len = 32 };

    tsra_algo_rsa_pkcs_pss_params pss_params_sha384 = { .hash_algo_id = TSRA_ALGO_ID_SHA384,
                                                        .mgf_id = TSRA_MGF1_ID_SHA384,
                                                        .salt_len = 48 };

    tsra_algo_rsa_pkcs_pss_params pss_params_sha512 = { .hash_algo_id = TSRA_ALGO_ID_SHA512,
                                                        .mgf_id = TSRA_MGF1_ID_SHA512,
                                                        .salt_len = 64 };

    std::vector<RsaTestParams> test_cases = {
        { TSRA_ALGO_ID_RSA_PKCS_PSS_SHA1, "SHA1", &pss_params_sha1 },
        { TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256, "SHA256", &pss_params_sha256 },
        { TSRA_ALGO_ID_RSA_PKCS_PSS_SHA384, "SHA384", &pss_params_sha384 },
        { TSRA_ALGO_ID_RSA_PKCS_PSS_SHA512, "SHA512", &pss_params_sha512 },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing PSS with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](tsra_handle session) {
            auto_key wrapping_priv_key, wrapping_pub_key;
            auto_key imported_priv_key, imported_pub_key;
            setup_keys(
                session,
                wrapping_priv_key,
                wrapping_pub_key,
                imported_priv_key,
                imported_pub_key
            );

            std::string test_data = std::string("Test RSA PSS ") + test_case.test_name + " signing";
            std::vector<uint8_t> data_to_sign(test_data.begin(), test_data.end());

            tsra_algo sign_algo = { .id = test_case.algo_id,
                                    .params = test_case.pss_params,
                                    .len = sizeof(tsra_algo_rsa_pkcs_pss_params) };

            test_single_shot_sign_verify(
                imported_priv_key.get(),
                imported_pub_key.get(),
                sign_algo,
                data_to_sign
            );

            ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
            ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
        });
    }
}

// RSA PSS Pre-hashed Sign/Verify Tests (Pre-hashed Message)
TEST_F(tsra_rsa_sign_verify, sign_verify_pss_prehashed_all_hash_algorithms)
{
    tsra_algo_rsa_pkcs_pss_params pss_params_sha1 = { .hash_algo_id = TSRA_ALGO_ID_SHA1,
                                                      .mgf_id = TSRA_MGF1_ID_SHA1,
                                                      .salt_len = 20 };

    tsra_algo_rsa_pkcs_pss_params pss_params_sha256 = { .hash_algo_id = TSRA_ALGO_ID_SHA256,
                                                        .mgf_id = TSRA_MGF1_ID_SHA256,
                                                        .salt_len = 32 };

    tsra_algo_rsa_pkcs_pss_params pss_params_sha384 = { .hash_algo_id = TSRA_ALGO_ID_SHA384,
                                                        .mgf_id = TSRA_MGF1_ID_SHA384,
                                                        .salt_len = 48 };

    tsra_algo_rsa_pkcs_pss_params pss_params_sha512 = { .hash_algo_id = TSRA_ALGO_ID_SHA512,
                                                        .mgf_id = TSRA_MGF1_ID_SHA512,
                                                        .salt_len = 64 };

    struct PrehashedTestParams
    {
        const char *test_name;
        tsra_algo_rsa_pkcs_pss_params *pss_params;
        size_t hash_size;
        uint8_t fill_byte;
    };

    std::vector<PrehashedTestParams> test_cases = {
        { "SHA1", &pss_params_sha1, 20, 0x9A },
        { "SHA256", &pss_params_sha256, 32, 0xAB },
        { "SHA384", &pss_params_sha384, 48, 0xCD },
        { "SHA512", &pss_params_sha512, 64, 0xEF },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing PSS pre-hashed with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](tsra_handle session) {
            auto_key wrapping_priv_key, wrapping_pub_key;
            auto_key imported_priv_key, imported_pub_key;
            setup_keys(
                session,
                wrapping_priv_key,
                wrapping_pub_key,
                imported_priv_key,
                imported_pub_key
            );

            std::vector<uint8_t> hashed_data(test_case.hash_size, test_case.fill_byte);

            tsra_algo sign_algo = { .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
                                    .params = test_case.pss_params,
                                    .len = sizeof(tsra_algo_rsa_pkcs_pss_params) };

            test_single_shot_sign_verify(
                imported_priv_key.get(),
                imported_pub_key.get(),
                sign_algo,
                hashed_data
            );

            ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
            ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
        });
    }
}

// RSA PKCS#1 Streaming Sign/Verify Tests (Raw Message)
TEST_F(tsra_rsa_sign_verify, streaming_sign_verify_pkcs_all_hash_algorithms)
{
    std::vector<RsaTestParams> test_cases = {
        { TSRA_ALGO_ID_RSA_PKCS_SHA1, "SHA1", nullptr },
        { TSRA_ALGO_ID_RSA_PKCS_SHA256, "SHA256", nullptr },
        { TSRA_ALGO_ID_RSA_PKCS_SHA384, "SHA384", nullptr },
        { TSRA_ALGO_ID_RSA_PKCS_SHA512, "SHA512", nullptr },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing PKCS#1 streaming with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](tsra_handle session) {
            auto_key wrapping_priv_key, wrapping_pub_key;
            auto_key imported_priv_key, imported_pub_key;
            setup_keys(
                session,
                wrapping_priv_key,
                wrapping_pub_key,
                imported_priv_key,
                imported_pub_key
            );

            tsra_algo sign_algo = {
                .id = test_case.algo_id,
                .params = test_case.pss_params,
                .len = test_case.pss_params
                           ? static_cast<uint32_t>(sizeof(tsra_algo_rsa_pkcs_pss_params))
                           : 0
            };

            std::vector<const char *> chunks = { "Part1 ", "Part2 ", "Part3" };
            test_streaming_sign_verify(
                imported_priv_key.get(),
                imported_pub_key.get(),
                sign_algo,
                chunks
            );

            ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
            ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
        });
    }
}

// RSA PSS Streaming Sign/Verify Tests
TEST_F(tsra_rsa_sign_verify, streaming_sign_verify_pss_all_hash_algorithms)
{
    tsra_algo_rsa_pkcs_pss_params pss_params_sha1 = { .hash_algo_id = TSRA_ALGO_ID_SHA1,
                                                      .mgf_id = TSRA_MGF1_ID_SHA1,
                                                      .salt_len = 20 };

    tsra_algo_rsa_pkcs_pss_params pss_params_sha256 = { .hash_algo_id = TSRA_ALGO_ID_SHA256,
                                                        .mgf_id = TSRA_MGF1_ID_SHA256,
                                                        .salt_len = 32 };

    tsra_algo_rsa_pkcs_pss_params pss_params_sha384 = { .hash_algo_id = TSRA_ALGO_ID_SHA384,
                                                        .mgf_id = TSRA_MGF1_ID_SHA384,
                                                        .salt_len = 48 };

    tsra_algo_rsa_pkcs_pss_params pss_params_sha512 = { .hash_algo_id = TSRA_ALGO_ID_SHA512,
                                                        .mgf_id = TSRA_MGF1_ID_SHA512,
                                                        .salt_len = 64 };

    std::vector<RsaTestParams> test_cases = {
        { TSRA_ALGO_ID_RSA_PKCS_PSS_SHA1, "SHA1", &pss_params_sha1 },
        { TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256, "SHA256", &pss_params_sha256 },
        { TSRA_ALGO_ID_RSA_PKCS_PSS_SHA384, "SHA384", &pss_params_sha384 },
        { TSRA_ALGO_ID_RSA_PKCS_PSS_SHA512, "SHA512", &pss_params_sha512 },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing PSS streaming with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](tsra_handle session) {
            auto_key wrapping_priv_key, wrapping_pub_key;
            auto_key imported_priv_key, imported_pub_key;
            setup_keys(
                session,
                wrapping_priv_key,
                wrapping_pub_key,
                imported_priv_key,
                imported_pub_key
            );

            tsra_algo sign_algo = { .id = test_case.algo_id,
                                    .params = test_case.pss_params,
                                    .len = sizeof(tsra_algo_rsa_pkcs_pss_params) };

            std::vector<const char *> chunks = { "Streaming ", "PSS ", test_case.test_name };
            test_streaming_sign_verify(
                imported_priv_key.get(),
                imported_pub_key.get(),
                sign_algo,
                chunks
            );

            ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
            ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
        });
    }
}

// RSA single-shot verify rejects a tampered signature.
TEST_F(tsra_rsa_sign_verify, verify_rejects_tampered_signature)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'r', 's', 'a', ' ', 't', 'a', 'm', 'p', 'e', 'r' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_GT(sig_buf.len, 0);
        signature[0] ^= 0x01;

        tsra_buffer tampered_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_NE(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &data_buf, &tampered_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA single-shot verify rejects a truncated signature.
TEST_F(tsra_rsa_sign_verify, verify_rejects_truncated_signature)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'r', 's', 'a', ' ', 't', 'r', 'u', 'n', 'c' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_GT(sig_buf.len, 1);

        tsra_buffer truncated_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len - 1,
        };

        ASSERT_NE(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &data_buf, &truncated_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA single-shot sign rejects a signature output buffer that is too small.
TEST_F(tsra_rsa_sign_verify, sign_rejects_small_signature_buffer)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 's', 'm', 'a', 'l', 'l', ' ', 'b', 'u', 'f' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(1);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA sign rejects using a public key handle.
TEST_F(tsra_rsa_sign_verify, sign_rejects_public_key_handle)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'w', 'r', 'o', 'n', 'g', ' ', 'k', 'e', 'y' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_pub_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS verify rejects mismatched PSS parameters.
TEST_F(tsra_rsa_sign_verify, verify_rejects_mismatched_pss_params)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'p', 's', 's', ' ', 'm', 'i', 's', 'm', 'a', 't', 'c', 'h' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params sign_params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 32,
        };

        tsra_algo_rsa_pkcs_pss_params verify_params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 20,
        };

        tsra_algo sign_algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = &sign_params,
            .len = sizeof(sign_params),
        };

        tsra_algo verify_algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = &verify_params,
            .len = sizeof(verify_params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_NE(
            tsra_crypt_verify(&verify_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS pre-hashed signing rejects a digest length that does not match the selected hash.
TEST_F(tsra_rsa_sign_verify, pss_prehashed_rejects_wrong_digest_length)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo_rsa_pkcs_pss_params pss_params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 32,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
            .params = &pss_params,
            .len = sizeof(pss_params),
        };

        // SHA256 pre-hashed input should be 32 bytes. Use 31 bytes to force rejection.
        std::vector<uint8_t> bad_digest(31, 0xAB);
        tsra_buffer digest_buf = {
            .ptr = bad_digest.data(),
            .len = static_cast<uint32_t>(bad_digest.size()),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &digest_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming sign finish rejects a signature output buffer that is too small.
TEST_F(tsra_rsa_sign_verify, streaming_sign_finish_rejects_small_signature_buffer)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        auto_ctx sign_ctx;
        ASSERT_EQ(
            tsra_crypt_sign_init(&algo, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        const char *chunk = "streaming small signature buffer";
        tsra_buffer chunk_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(chunk)),
            .len = static_cast<uint32_t>(strlen(chunk)),
        };

        ASSERT_EQ(tsra_crypt_sign_update(sign_ctx, &chunk_buf), TSRA_STATUS_SUCCESS);

        std::vector<uint8_t> signature(1);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(tsra_crypt_sign_finish(sign_ctx, &sig_buf), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming verify rejects a tampered signature.
TEST_F(tsra_rsa_sign_verify, streaming_verify_rejects_tampered_signature)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        const char *chunk1 = "streaming ";
        const char *chunk2 = "verify ";
        const char *chunk3 = "tampered signature";

        auto_ctx sign_ctx;
        ASSERT_EQ(
            tsra_crypt_sign_init(&algo, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        for (const char *chunk : { chunk1, chunk2, chunk3 })
        {
            tsra_buffer chunk_buf = {
                .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(chunk)),
                .len = static_cast<uint32_t>(strlen(chunk)),
            };

            ASSERT_EQ(tsra_crypt_sign_update(sign_ctx, &chunk_buf), TSRA_STATUS_SUCCESS);
        }

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(tsra_crypt_sign_finish(sign_ctx, &sig_buf), TSRA_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        signature[sig_buf.len - 1] ^= 0x01;

        auto_ctx verify_ctx;
        ASSERT_EQ(
            tsra_crypt_verify_init(&algo, imported_pub_key.get(), verify_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        for (const char *chunk : { chunk1, chunk2, chunk3 })
        {
            tsra_buffer chunk_buf = {
                .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(chunk)),
                .len = static_cast<uint32_t>(strlen(chunk)),
            };

            ASSERT_EQ(tsra_crypt_verify_update(verify_ctx, &chunk_buf), TSRA_STATUS_SUCCESS);
        }

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_NE(tsra_crypt_verify_finish(verify_ctx, &verify_sig_buf), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA verify rejects a signature when using a different public key.
TEST_F(tsra_rsa_sign_verify, verify_rejects_signature_with_wrong_public_key)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'm', 'i', 's', 'm', 'a', 't', 'c', 'h' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        auto_key other_priv_key, other_pub_key;
        ASSERT_EQ(
            generate_rsa_unwrapping_keypair(
                session,
                other_priv_key.get_ptr(),
                other_pub_key.get_ptr()
            ),
            TSRA_STATUS_SUCCESS
        );

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_NE(
            tsra_crypt_verify(&algo, other_pub_key.get(), &data_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA verify rejects PKCS#1 signature when verified as PSS.
TEST_F(tsra_rsa_sign_verify, verify_rejects_pkcs_signature_with_pss_algo)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'p', 'a', 'd', 'd', 'i', 'n', 'g' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo sign_algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        tsra_algo_rsa_pkcs_pss_params pss_params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 32,
        };

        tsra_algo verify_algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = &pss_params,
            .len = sizeof(pss_params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_NE(
            tsra_crypt_verify(&verify_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA verify rejects PSS signature when verified as PKCS#1.
TEST_F(tsra_rsa_sign_verify, verify_rejects_pss_signature_with_pkcs_algo)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'p', 'a', 'd', 'd', 'i', 'n', 'g' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params pss_params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 32,
        };

        tsra_algo sign_algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = &pss_params,
            .len = sizeof(pss_params),
        };

        tsra_algo verify_algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_NE(
            tsra_crypt_verify(&verify_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PKCS#1 signatures are deterministic for the same key, algorithm, and input.
TEST_F(tsra_rsa_sign_verify, pkcs_signature_is_deterministic)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'd', 'e', 't', 'e', 'r', 'm', 'i',
                                      'n', 'i', 's', 't', 'i', 'c' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> sig1(256);
        tsra_buffer sig_buf1 = {
            .ptr = sig1.data(),
            .len = static_cast<uint32_t>(sig1.size()),
        };

        std::vector<uint8_t> sig2(256);
        tsra_buffer sig_buf2 = {
            .ptr = sig2.data(),
            .len = static_cast<uint32_t>(sig2.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf1),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf2),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(sig_buf1.len, sig_buf2.len);
        ASSERT_EQ(0, std::memcmp(sig1.data(), sig2.data(), sig_buf1.len));

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS signatures are non-deterministic for the same key, algorithm, and input.
TEST_F(tsra_rsa_sign_verify, pss_signature_is_non_deterministic)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'n', 'o', 'n', 'd', 'e', 't', 'e', 'r',
                                      'm', 'i', 'n', 'i', 's', 't', 'i', 'c' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params pss_params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 32,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = &pss_params,
            .len = sizeof(pss_params),
        };

        std::vector<uint8_t> first_sig(256);
        tsra_buffer first_sig_buf = {
            .ptr = first_sig.data(),
            .len = static_cast<uint32_t>(first_sig.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &first_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        bool saw_difference = false;

        for (int i = 0; i < 5; ++i)
        {
            std::vector<uint8_t> next_sig(256);
            tsra_buffer next_sig_buf = {
                .ptr = next_sig.data(),
                .len = static_cast<uint32_t>(next_sig.size()),
            };

            ASSERT_EQ(
                tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &next_sig_buf),
                TSRA_STATUS_SUCCESS
            );

            if (next_sig_buf.len != first_sig_buf.len ||
                std::memcmp(first_sig.data(), next_sig.data(), first_sig_buf.len) != 0)
            {
                saw_difference = true;
                break;
            }
        }

        ASSERT_TRUE(saw_difference);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA verify rejects an empty signature buffer.
TEST_F(tsra_rsa_sign_verify, verify_rejects_empty_signature)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'e', 'm', 'p', 't', 'y' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        uint8_t dummy = 0;
        tsra_buffer empty_sig_buf = {
            .ptr = &dummy,
            .len = 0,
        };

        ASSERT_NE(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &data_buf, &empty_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA verify rejects a signature longer than the RSA modulus size.
TEST_F(tsra_rsa_sign_verify, verify_rejects_oversized_signature)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'o', 'v', 'e', 'r', 's', 'i', 'z', 'e' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        signature.resize(sig_buf.len + 10, 0x00);

        tsra_buffer oversized_sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &data_buf, &oversized_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA verify rejects all-zero and all-0xFF signatures.
TEST_F(tsra_rsa_sign_verify, verify_rejects_all_zero_and_all_ff_signatures)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'b', 'a', 'd', ' ', 's', 'i', 'g' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> all_zero_sig(256, 0x00);
        tsra_buffer all_zero_sig_buf = {
            .ptr = all_zero_sig.data(),
            .len = static_cast<uint32_t>(all_zero_sig.size()),
        };

        std::vector<uint8_t> all_ff_sig(256, 0xFF);
        tsra_buffer all_ff_sig_buf = {
            .ptr = all_ff_sig.data(),
            .len = static_cast<uint32_t>(all_ff_sig.size()),
        };

        ASSERT_NE(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &data_buf, &all_zero_sig_buf),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &data_buf, &all_ff_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA verify succeeds repeatedly with the same key, algorithm, input, and signature.
TEST_F(tsra_rsa_sign_verify, verify_repeatability)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'r', 'e', 'p', 'e', 'a', 't' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        for (int i = 0; i < 3; ++i)
        {
            tsra_buffer verify_sig_buf = {
                .ptr = signature.data(),
                .len = sig_buf.len,
            };

            ASSERT_EQ(
                tsra_crypt_verify(&algo, imported_pub_key.get(), &data_buf, &verify_sig_buf),
                TSRA_STATUS_SUCCESS
            );
        }

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS supports zero salt length.
TEST_F(tsra_rsa_sign_verify, pss_zero_salt_len_sign_verify)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> digest(32, 0xAB);
        tsra_buffer digest_buf = {
            .ptr = digest.data(),
            .len = static_cast<uint32_t>(digest.size()),
        };

        tsra_algo_rsa_pkcs_pss_params pss_params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 0,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
            .params = &pss_params,
            .len = sizeof(pss_params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &digest_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &digest_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS supports the maximum valid salt length for RSA-2048/SHA256.
// emLen - hLen - 2 = 256 - 32 - 2 = 222.
TEST_F(tsra_rsa_sign_verify, pss_max_salt_len_sign_verify)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> digest(32, 0xAB);
        tsra_buffer digest_buf = {
            .ptr = digest.data(),
            .len = static_cast<uint32_t>(digest.size()),
        };

        tsra_algo_rsa_pkcs_pss_params pss_params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 222,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
            .params = &pss_params,
            .len = sizeof(pss_params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &digest_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &digest_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS signing rejects a salt length larger than allowed for RSA-2048/SHA256.
TEST_F(tsra_rsa_sign_verify, pss_rejects_salt_len_too_large)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> digest(32, 0xAB);
        tsra_buffer digest_buf = {
            .ptr = digest.data(),
            .len = static_cast<uint32_t>(digest.size()),
        };

        tsra_algo_rsa_pkcs_pss_params pss_params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 300,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
            .params = &pss_params,
            .len = sizeof(pss_params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &digest_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming sign context rejects update and finish after finish.
TEST_F(tsra_rsa_sign_verify, streaming_sign_update_and_finish_after_finish_fail)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        auto_ctx sign_ctx;
        ASSERT_EQ(
            tsra_crypt_sign_init(&algo, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        const char *data = "test data";
        tsra_buffer data_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(data)),
            .len = static_cast<uint32_t>(strlen(data)),
        };

        ASSERT_EQ(tsra_crypt_sign_update(sign_ctx, &data_buf), TSRA_STATUS_SUCCESS);

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(tsra_crypt_sign_finish(sign_ctx, &sig_buf), TSRA_STATUS_SUCCESS);

        ASSERT_NE(tsra_crypt_sign_update(sign_ctx, &data_buf), TSRA_STATUS_SUCCESS);

        sig_buf.len = static_cast<uint32_t>(signature.size());
        ASSERT_NE(tsra_crypt_sign_finish(sign_ctx, &sig_buf), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming verify context rejects update and finish after finish.
TEST_F(tsra_rsa_sign_verify, streaming_verify_update_and_finish_after_finish_fail)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        const char *data = "test data";
        tsra_buffer data_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(data)),
            .len = static_cast<uint32_t>(strlen(data)),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        auto_ctx verify_ctx;
        ASSERT_EQ(
            tsra_crypt_verify_init(&algo, imported_pub_key.get(), verify_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_crypt_verify_update(verify_ctx, &data_buf), TSRA_STATUS_SUCCESS);

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(tsra_crypt_verify_finish(verify_ctx, &verify_sig_buf), TSRA_STATUS_SUCCESS);

        ASSERT_NE(tsra_crypt_verify_update(verify_ctx, &data_buf), TSRA_STATUS_SUCCESS);
        ASSERT_NE(tsra_crypt_verify_finish(verify_ctx, &verify_sig_buf), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PKCS#1 streaming signature matches one-shot signature for the same message.
TEST_F(tsra_rsa_sign_verify, pkcs_streaming_signature_matches_one_shot)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        const char *message = "hello world";
        tsra_buffer message_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(message)),
            .len = static_cast<uint32_t>(strlen(message)),
        };

        std::vector<uint8_t> one_shot_sig(256);
        tsra_buffer one_shot_sig_buf = {
            .ptr = one_shot_sig.data(),
            .len = static_cast<uint32_t>(one_shot_sig.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &message_buf, &one_shot_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        auto_ctx sign_ctx;
        ASSERT_EQ(
            tsra_crypt_sign_init(&algo, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        const char *chunk1 = "hello ";
        const char *chunk2 = "world";

        tsra_buffer chunk1_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(chunk1)),
            .len = static_cast<uint32_t>(strlen(chunk1)),
        };

        tsra_buffer chunk2_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(chunk2)),
            .len = static_cast<uint32_t>(strlen(chunk2)),
        };

        ASSERT_EQ(tsra_crypt_sign_update(sign_ctx, &chunk1_buf), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_crypt_sign_update(sign_ctx, &chunk2_buf), TSRA_STATUS_SUCCESS);

        std::vector<uint8_t> streaming_sig(256);
        tsra_buffer streaming_sig_buf = {
            .ptr = streaming_sig.data(),
            .len = static_cast<uint32_t>(streaming_sig.size()),
        };

        ASSERT_EQ(tsra_crypt_sign_finish(sign_ctx, &streaming_sig_buf), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(one_shot_sig_buf.len, streaming_sig_buf.len);
        ASSERT_EQ(0, std::memcmp(one_shot_sig.data(), streaming_sig.data(), one_shot_sig_buf.len));

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming empty input signs and verifies successfully.
TEST_F(tsra_rsa_sign_verify, streaming_empty_input_sign_verify)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        auto_ctx sign_ctx;
        ASSERT_EQ(
            tsra_crypt_sign_init(&algo, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(tsra_crypt_sign_finish(sign_ctx, &sig_buf), TSRA_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        auto_ctx verify_ctx;
        ASSERT_EQ(
            tsra_crypt_verify_init(&algo, imported_pub_key.get(), verify_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(tsra_crypt_verify_finish(verify_ctx, &verify_sig_buf), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming empty chunk update behaves like empty input.
TEST_F(tsra_rsa_sign_verify, streaming_empty_chunk_update_sign_verify)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        auto_ctx sign_ctx;
        ASSERT_EQ(
            tsra_crypt_sign_init(&algo, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        uint8_t dummy = 0;
        tsra_buffer empty_buf = {
            .ptr = &dummy,
            .len = 0,
        };

        ASSERT_EQ(tsra_crypt_sign_update(sign_ctx, &empty_buf), TSRA_STATUS_SUCCESS);

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(tsra_crypt_sign_finish(sign_ctx, &sig_buf), TSRA_STATUS_SUCCESS);

        auto_ctx verify_ctx;
        ASSERT_EQ(
            tsra_crypt_verify_init(&algo, imported_pub_key.get(), verify_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_crypt_verify_update(verify_ctx, &empty_buf), TSRA_STATUS_SUCCESS);

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(tsra_crypt_verify_finish(verify_ctx, &verify_sig_buf), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA hash-sign streaming supports large multi-chunk input.
TEST_F(tsra_rsa_sign_verify, streaming_large_multi_chunk_input_sign_verify)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> chunk1(4096, 0x11);
        std::vector<uint8_t> chunk2(4096, 0x22);
        std::vector<uint8_t> chunk3(4096, 0x33);

        std::vector<tsra_buffer> chunks = {
            { .ptr = chunk1.data(), .len = static_cast<uint32_t>(chunk1.size()) },
            { .ptr = chunk2.data(), .len = static_cast<uint32_t>(chunk2.size()) },
            { .ptr = chunk3.data(), .len = static_cast<uint32_t>(chunk3.size()) },
        };

        auto_ctx sign_ctx;
        ASSERT_EQ(
            tsra_crypt_sign_init(&algo, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        for (auto &chunk : chunks)
        {
            ASSERT_EQ(tsra_crypt_sign_update(sign_ctx, &chunk), TSRA_STATUS_SUCCESS);
        }

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(tsra_crypt_sign_finish(sign_ctx, &sig_buf), TSRA_STATUS_SUCCESS);

        auto_ctx verify_ctx;
        ASSERT_EQ(
            tsra_crypt_verify_init(&algo, imported_pub_key.get(), verify_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        for (auto &chunk : chunks)
        {
            ASSERT_EQ(tsra_crypt_verify_update(verify_ctx, &chunk), TSRA_STATUS_SUCCESS);
        }

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(tsra_crypt_verify_finish(verify_ctx, &verify_sig_buf), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA one-shot verify rejects a signature when verify uses a different hash algorithm.
TEST_F(tsra_rsa_sign_verify, verify_rejects_wrong_hash_algorithm)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'h', 'e', 'l', 'l', 'o' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo sign_algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        tsra_algo verify_algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA384,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&sign_algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_NE(
            tsra_crypt_verify(&verify_algo, imported_pub_key.get(), &data_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA one-shot signing and verifying an empty message succeeds.
TEST_F(tsra_rsa_sign_verify, sign_verify_empty_message_one_shot)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        uint8_t dummy = 0;
        tsra_buffer empty_data_buf = {
            .ptr = &dummy,
            .len = 0,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &empty_data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &empty_data_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// ---------------------------------------------------------------------------
// NULL POINTER TESTS
// ---------------------------------------------------------------------------

// RSA single-shot sign rejects a null algorithm pointer.
TEST_F(tsra_rsa_sign_verify, sign_rejects_null_algo)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'n', 'u', 'l', 'l' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(nullptr, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA single-shot sign rejects a null input data buffer.
TEST_F(tsra_rsa_sign_verify, sign_rejects_null_data_buffer)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), nullptr, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA single-shot sign rejects a null signature output buffer.
TEST_F(tsra_rsa_sign_verify, sign_rejects_null_signature_buffer)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'n', 'u', 'l', 'l' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, nullptr),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA single-shot verify rejects a null algorithm pointer.
TEST_F(tsra_rsa_sign_verify, verify_rejects_null_algo)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'n', 'u', 'l', 'l' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        uint8_t dummy_signature = 0;
        tsra_buffer sig_buf = {
            .ptr = &dummy_signature,
            .len = 1,
        };

        ASSERT_NE(
            tsra_crypt_verify(nullptr, imported_pub_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA single-shot verify rejects a null input data buffer.
TEST_F(tsra_rsa_sign_verify, verify_rejects_null_data_buffer)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        uint8_t dummy_signature = 0;
        tsra_buffer sig_buf = {
            .ptr = &dummy_signature,
            .len = 1,
        };

        ASSERT_NE(
            tsra_crypt_verify(&algo, imported_pub_key.get(), nullptr, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA single-shot verify rejects a null signature buffer.
TEST_F(tsra_rsa_sign_verify, verify_rejects_null_signature_buffer)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'n', 'u', 'l', 'l' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        ASSERT_NE(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &data_buf, nullptr),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming sign initialization rejects a null algorithm pointer.
TEST_F(tsra_rsa_sign_verify, streaming_sign_init_rejects_null_algo)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        auto_ctx sign_ctx;
        ASSERT_NE(
            tsra_crypt_sign_init(nullptr, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming verify initialization rejects a null algorithm pointer.
TEST_F(tsra_rsa_sign_verify, streaming_verify_init_rejects_null_algo)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        auto_ctx verify_ctx;
        ASSERT_NE(
            tsra_crypt_verify_init(nullptr, imported_pub_key.get(), verify_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming sign update rejects a null input buffer.
TEST_F(tsra_rsa_sign_verify, streaming_sign_update_rejects_null_buffer)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        auto_ctx sign_ctx;
        ASSERT_EQ(
            tsra_crypt_sign_init(&algo, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(tsra_crypt_sign_update(sign_ctx, nullptr), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming verify update rejects a null input buffer.
TEST_F(tsra_rsa_sign_verify, streaming_verify_update_rejects_null_buffer)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        auto_ctx verify_ctx;
        ASSERT_EQ(
            tsra_crypt_verify_init(&algo, imported_pub_key.get(), verify_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(tsra_crypt_verify_update(verify_ctx, nullptr), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming sign finish rejects a null signature output buffer.
TEST_F(tsra_rsa_sign_verify, streaming_sign_finish_rejects_null_signature_buffer)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        auto_ctx sign_ctx;
        ASSERT_EQ(
            tsra_crypt_sign_init(&algo, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(tsra_crypt_sign_finish(sign_ctx, nullptr), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming verify finish rejects a null signature buffer.
TEST_F(tsra_rsa_sign_verify, streaming_verify_finish_rejects_null_signature_buffer)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        auto_ctx verify_ctx;
        ASSERT_EQ(
            tsra_crypt_verify_init(&algo, imported_pub_key.get(), verify_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(tsra_crypt_verify_finish(verify_ctx, nullptr), TSRA_STATUS_SUCCESS);

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// ---------------------------------------------------------------------------
// INVALID HANDLE TESTS
// ---------------------------------------------------------------------------

// RSA single-shot sign rejects a zero private-key handle.
TEST_F(tsra_rsa_sign_verify, sign_rejects_zero_key_handle)
{
    std::vector<uint8_t> data = { 'b', 'a', 'd', '-', 'h', 'a', 'n', 'd', 'l', 'e' };
    tsra_buffer data_buf = {
        .ptr = data.data(),
        .len = static_cast<uint32_t>(data.size()),
    };

    tsra_algo algo = {
        .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
        .params = nullptr,
        .len = 0,
    };

    std::vector<uint8_t> signature(256);
    tsra_buffer sig_buf = {
        .ptr = signature.data(),
        .len = static_cast<uint32_t>(signature.size()),
    };

    ASSERT_NE(tsra_crypt_sign(&algo, 0, &data_buf, &sig_buf), TSRA_STATUS_SUCCESS);
}

// RSA single-shot verify rejects a zero public-key handle.
TEST_F(tsra_rsa_sign_verify, verify_rejects_zero_key_handle)
{
    std::vector<uint8_t> data = { 'b', 'a', 'd', '-', 'h', 'a', 'n', 'd', 'l', 'e' };
    tsra_buffer data_buf = {
        .ptr = data.data(),
        .len = static_cast<uint32_t>(data.size()),
    };

    tsra_algo algo = {
        .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
        .params = nullptr,
        .len = 0,
    };

    uint8_t dummy_signature = 0;
    tsra_buffer sig_buf = {
        .ptr = &dummy_signature,
        .len = 1,
    };

    ASSERT_NE(tsra_crypt_verify(&algo, 0, &data_buf, &sig_buf), TSRA_STATUS_SUCCESS);
}

// RSA streaming sign initialization rejects a zero private-key handle.
TEST_F(tsra_rsa_sign_verify, streaming_sign_init_rejects_zero_key_handle)
{
    tsra_algo algo = {
        .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
        .params = nullptr,
        .len = 0,
    };

    auto_ctx sign_ctx;
    ASSERT_NE(tsra_crypt_sign_init(&algo, 0, sign_ctx.get_ptr()), TSRA_STATUS_SUCCESS);
}

// RSA streaming verify initialization rejects a zero public-key handle.
TEST_F(tsra_rsa_sign_verify, streaming_verify_init_rejects_zero_key_handle)
{
    tsra_algo algo = {
        .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
        .params = nullptr,
        .len = 0,
    };

    auto_ctx verify_ctx;
    ASSERT_NE(tsra_crypt_verify_init(&algo, 0, verify_ctx.get_ptr()), TSRA_STATUS_SUCCESS);
}

// RSA single-shot sign rejects a deleted private-key handle.
TEST_F(tsra_rsa_sign_verify, sign_rejects_deleted_private_key_handle)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        const tsra_handle stale_private_key = imported_priv_key.release();
        ASSERT_EQ(tsra_key_delete(stale_private_key), TSRA_STATUS_SUCCESS);

        std::vector<uint8_t> data = { 's', 't', 'a', 'l', 'e' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, stale_private_key, &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA single-shot verify rejects a deleted public-key handle.
TEST_F(tsra_rsa_sign_verify, verify_rejects_deleted_public_key_handle)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 's', 't', 'a', 'l', 'e' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        const tsra_handle stale_public_key = imported_pub_key.release();
        ASSERT_EQ(tsra_key_delete(stale_public_key), TSRA_STATUS_SUCCESS);

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_NE(
            tsra_crypt_verify(&algo, stale_public_key, &data_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// ---------------------------------------------------------------------------
// UNSUPPORTED ALGORITHM ID TESTS
// ---------------------------------------------------------------------------

// RSA single-shot sign rejects an unsupported algorithm identifier.
TEST_F(tsra_rsa_sign_verify, sign_rejects_unsupported_algorithm_id)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'b', 'a', 'd', '-', 'a', 'l', 'g', 'o' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = static_cast<tsra_algo_id>(0x7fffffff),
            .params = nullptr,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA single-shot verify rejects an unsupported algorithm identifier.
TEST_F(tsra_rsa_sign_verify, verify_rejects_unsupported_algorithm_id)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'b', 'a', 'd', '-', 'a', 'l', 'g', 'o' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = static_cast<tsra_algo_id>(0x7fffffff),
            .params = nullptr,
            .len = 0,
        };

        uint8_t dummy_signature = 0;
        tsra_buffer sig_buf = {
            .ptr = &dummy_signature,
            .len = 1,
        };

        ASSERT_NE(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA streaming sign and verify initialization reject an unsupported algorithm identifier.
TEST_F(tsra_rsa_sign_verify, streaming_init_rejects_unsupported_algorithm_id)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        tsra_algo algo = {
            .id = static_cast<tsra_algo_id>(0x7fffffff),
            .params = nullptr,
            .len = 0,
        };

        auto_ctx sign_ctx;
        auto_ctx verify_ctx;

        ASSERT_NE(
            tsra_crypt_sign_init(&algo, imported_priv_key.get(), sign_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(
            tsra_crypt_verify_init(&algo, imported_pub_key.get(), verify_ctx.get_ptr()),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PKCS#1 combined algorithms ignore unused parameter data.
TEST_F(tsra_rsa_sign_verify, pkcs_sign_verify_ignores_unused_algo_params)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;

        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'u', 'n', 'u', 's', 'e', 'd', ' ',
                                      'p', 'a', 'r', 'a', 'm', 's' };

        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        uint8_t unused_param = 0xAB;

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
            .params = &unused_param,
            .len = 1,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(sig_buf.len, 256);

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &data_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}
// ---------------------------------------------------------------------------
// ALGORITHM LENGTH MISMATCH TESTS
// ---------------------------------------------------------------------------

// RSA PSS signing rejects an algorithm parameter length of zero.
TEST_F(tsra_rsa_sign_verify, pss_sign_rejects_zero_algo_len)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'l', 'e', 'n' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 32,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = &params,
            .len = 0,
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS signing rejects an algorithm parameter length smaller than the PSS structure.
TEST_F(tsra_rsa_sign_verify, pss_sign_rejects_short_algo_len)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'l', 'e', 'n' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 32,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = &params,
            .len = static_cast<uint32_t>(sizeof(params) - 1),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS signing rejects an algorithm parameter length larger than the PSS structure.
TEST_F(tsra_rsa_sign_verify, pss_sign_rejects_oversized_algo_len)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'l', 'e', 'n' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 32,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = &params,
            .len = static_cast<uint32_t>(sizeof(params) + 1),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS signing rejects null parameters paired with a nonzero parameter length.
TEST_F(tsra_rsa_sign_verify, pss_sign_rejects_null_params_with_nonzero_len)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'l', 'e', 'n' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = nullptr,
            .len = sizeof(tsra_algo_rsa_pkcs_pss_params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// ---------------------------------------------------------------------------
// MALFORMED PSS PARAMETER STRUCTURE TESTS
// ---------------------------------------------------------------------------

// RSA PSS signing rejects an unsupported hash algorithm identifier.
TEST_F(tsra_rsa_sign_verify, pss_sign_rejects_invalid_hash_algorithm)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'b', 'a', 'd', '-', 'h', 'a', 's', 'h' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params params = {
            .hash_algo_id = static_cast<tsra_algo_id>(0x7fffffff),
            .mgf_id = TSRA_MGF1_ID_SHA256,
            .salt_len = 32,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
            .params = &params,
            .len = sizeof(params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS signing rejects an unsupported mask-generation function identifier.
TEST_F(tsra_rsa_sign_verify, pss_sign_rejects_invalid_mgf_id)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'b', 'a', 'd', '-', 'm', 'g', 'f' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = static_cast<tsra_mgf1_id>(0x7fffffff),
            .salt_len = 32,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
            .params = &params,
            .len = sizeof(params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS signing rejects a zero-initialized parameter structure.
TEST_F(tsra_rsa_sign_verify, pss_sign_rejects_zero_initialized_params)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'z', 'e', 'r', 'o' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params params = {};

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
            .params = &params,
            .len = sizeof(params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS signing rejects parameters whose hash does not match the combined algorithm ID.
TEST_F(tsra_rsa_sign_verify, pss_combined_algo_rejects_mismatched_hash_param)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;
        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> data = { 'm', 'i', 's', 'm', 'a', 't', 'c', 'h' };
        tsra_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        tsra_algo_rsa_pkcs_pss_params params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA384,
            .mgf_id = TSRA_MGF1_ID_SHA384,
            .salt_len = 48,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256,
            .params = &params,
            .len = sizeof(params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_NE(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &data_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA PSS supports different message-hash and MGF1-hash algorithms.
TEST_F(tsra_rsa_sign_verify, pss_sign_verify_supports_hash_and_mgf_mismatch)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;

        setup_keys(
            session,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        std::vector<uint8_t> digest(32, 0xAB);
        tsra_buffer digest_buf = {
            .ptr = digest.data(),
            .len = static_cast<uint32_t>(digest.size()),
        };

        tsra_algo_rsa_pkcs_pss_params params = {
            .hash_algo_id = TSRA_ALGO_ID_SHA256,
            .mgf_id = TSRA_MGF1_ID_SHA384,
            .salt_len = 32,
        };

        tsra_algo algo = {
            .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
            .params = &params,
            .len = sizeof(params),
        };

        std::vector<uint8_t> signature(256);
        tsra_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            tsra_crypt_sign(&algo, imported_priv_key.get(), &digest_buf, &sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(sig_buf.len, 256);

        tsra_buffer verify_sig_buf = {
            .ptr = signature.data(),
            .len = sig_buf.len,
        };

        ASSERT_EQ(
            tsra_crypt_verify(&algo, imported_pub_key.get(), &digest_buf, &verify_sig_buf),
            TSRA_STATUS_SUCCESS
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// ---------------------------------------------------------------------------
// RSA-3072 AND RSA-4096 TESTS
// ---------------------------------------------------------------------------

// RSA-3072 PKCS#1 v1.5 with SHA-256 signs and verifies successfully.
TEST_F(tsra_rsa_sign_verify, rsa_3072_pkcs_sha256_sign_verify)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;

        setup_keys_for_size(
            session,
            3072,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        assert_pkcs_sha256_sign_verify_for_key_size(
            imported_priv_key.get(),
            imported_pub_key.get(),
            3072
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA-3072 PSS with SHA-256 signs and verifies successfully.
TEST_F(tsra_rsa_sign_verify, rsa_3072_pss_sha256_sign_verify)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;

        setup_keys_for_size(
            session,
            3072,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        assert_pss_sha256_sign_verify_for_key_size(
            imported_priv_key.get(),
            imported_pub_key.get(),
            3072
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA-4096 PKCS#1 v1.5 with SHA-256 signs and verifies successfully.
TEST_F(tsra_rsa_sign_verify, rsa_4096_pkcs_sha256_sign_verify)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;

        setup_keys_for_size(
            session,
            4096,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        assert_pkcs_sha256_sign_verify_for_key_size(
            imported_priv_key.get(),
            imported_pub_key.get(),
            4096
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}

// RSA-4096 PSS with SHA-256 signs and verifies successfully.
TEST_F(tsra_rsa_sign_verify, rsa_4096_pss_sha256_sign_verify)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto_key wrapping_priv_key, wrapping_pub_key;
        auto_key imported_priv_key, imported_pub_key;

        setup_keys_for_size(
            session,
            4096,
            wrapping_priv_key,
            wrapping_pub_key,
            imported_priv_key,
            imported_pub_key
        );

        assert_pss_sha256_sign_verify_for_key_size(
            imported_priv_key.get(),
            imported_pub_key.get(),
            4096
        );

        ASSERT_EQ(tsra_key_delete(imported_priv_key.release()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(tsra_key_delete(imported_pub_key.release()), TSRA_STATUS_SUCCESS);
    });
}
