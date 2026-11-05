// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstring>
#include <gtest/gtest.h>
#include <tsra_api.h>
#include <vector>

#include "handle/key_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_ctx.hpp"

// AES-CFB is only supported on extended (session-ex) sessions.
class tsra_aes_cfb : public ::testing::Test
{
  protected:
    static constexpr size_t AES_BLOCK_SIZE = 16;

    PartitionListHandle part_list_ = PartitionListHandle{};

    static std::vector<uint8_t> test_iv()
    {
        return make_incrementing_bytes(AES_BLOCK_SIZE);
    }

    static void init_algo(
        tsra_algo &algo,
        tsra_algo_aes_cfb_params &params,
        const std::vector<uint8_t> &iv
    )
    {
        std::memcpy(params.iv, iv.data(), AES_BLOCK_SIZE);
        algo.id = TSRA_ALGO_ID_AES_CFB;
        algo.params = &params;
        algo.len = sizeof(params);
    }

    static std::vector<uint8_t> params_iv(const tsra_algo_aes_cfb_params &params)
    {
        return std::vector<uint8_t>(params.iv, params.iv + AES_BLOCK_SIZE);
    }
};

#if SESSION_EX_TESTS

TEST_F(tsra_aes_cfb, single_shot_matches_reference)
{
    part_list_.for_each_session([&](tsra_handle session) {
        for (const auto &key_size : aes_key_sizes())
        {
            auto key = generate_aes_key(session, key_size.bits);
            for (size_t len : { 1, 15, 16, 17, 31, 32, 33, 100, 255, 2 * 1024 + 37 })
            {
                SCOPED_TRACE(std::string(key_size.test_name) + " len " + std::to_string(len));
                auto plaintext = make_incrementing_bytes(len);
                std::vector<uint8_t> expected, expected_iv;
                aes_feedback_reference_encrypt(
                    AesFeedbackMode::Cfb,
                    key.get(),
                    test_iv().data(),
                    plaintext,
                    expected,
                    expected_iv
                );

                tsra_algo_aes_cfb_params params{};
                tsra_algo algo{};
                init_algo(algo, params, test_iv());
                std::vector<uint8_t> ciphertext;
                ASSERT_EQ(
                    single_shot_crypt(
                        CryptOperation::Encrypt,
                        key.get(),
                        &algo,
                        plaintext.data(),
                        plaintext.size(),
                        ciphertext
                    ),
                    TSRA_STATUS_SUCCESS
                );
                ASSERT_EQ(ciphertext, expected);
                ASSERT_EQ(params_iv(params), expected_iv);

                init_algo(algo, params, test_iv());
                std::vector<uint8_t> decrypted;
                ASSERT_EQ(
                    single_shot_crypt(
                        CryptOperation::Decrypt,
                        key.get(),
                        &algo,
                        ciphertext.data(),
                        ciphertext.size(),
                        decrypted
                    ),
                    TSRA_STATUS_SUCCESS
                );
                ASSERT_EQ(decrypted, plaintext);
                ASSERT_EQ(params_iv(params), expected_iv);
            }
        }
    });
}

TEST_F(tsra_aes_cfb, streaming_matches_single_shot)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 256);
        auto plaintext = make_incrementing_bytes(1100);

        tsra_algo_aes_cfb_params params{};
        tsra_algo algo{};
        init_algo(algo, params, test_iv());
        std::vector<uint8_t> expected;
        ASSERT_EQ(
            single_shot_crypt(
                CryptOperation::Encrypt,
                key.get(),
                &algo,
                plaintext.data(),
                plaintext.size(),
                expected
            ),
            TSRA_STATUS_SUCCESS
        );
        auto expected_iv = params_iv(params);

        for (size_t chunk : { 1, 7, 16, 33, 1024, 2000 })
        {
            SCOPED_TRACE("chunk " + std::to_string(chunk));
            init_algo(algo, params, test_iv());
            std::vector<uint8_t> ciphertext;
            ASSERT_EQ(
                streaming_crypt(
                    CryptOperation::Encrypt,
                    key.get(),
                    &algo,
                    plaintext.data(),
                    plaintext.size(),
                    chunk,
                    ciphertext
                ),
                TSRA_STATUS_SUCCESS
            );
            ASSERT_EQ(ciphertext, expected);
            ASSERT_EQ(params_iv(params), expected_iv);

            init_algo(algo, params, test_iv());
            std::vector<uint8_t> decrypted;
            ASSERT_EQ(
                streaming_crypt(
                    CryptOperation::Decrypt,
                    key.get(),
                    &algo,
                    ciphertext.data(),
                    ciphertext.size(),
                    chunk,
                    decrypted
                ),
                TSRA_STATUS_SUCCESS
            );
            ASSERT_EQ(decrypted, plaintext);
            ASSERT_EQ(params_iv(params), expected_iv);
        }
    });
}

TEST_F(tsra_aes_cfb, params_iv_chains_block_aligned_calls)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 128);
        auto plaintext = make_incrementing_bytes(77);

        tsra_algo_aes_cfb_params params{};
        tsra_algo algo{};
        init_algo(algo, params, test_iv());
        std::vector<uint8_t> expected;
        ASSERT_EQ(
            single_shot_crypt(
                CryptOperation::Encrypt,
                key.get(),
                &algo,
                plaintext.data(),
                plaintext.size(),
                expected
            ),
            TSRA_STATUS_SUCCESS
        );

        // Reuse the same params; the IV-out of each call continues the message.
        init_algo(algo, params, test_iv());
        std::vector<uint8_t> chained, part;
        for (auto [offset, len] : { std::pair<size_t, size_t>{ 0, 32 }, { 32, 16 }, { 48, 29 } })
        {
            ASSERT_EQ(
                single_shot_crypt(
                    CryptOperation::Encrypt,
                    key.get(),
                    &algo,
                    plaintext.data() + offset,
                    len,
                    part
                ),
                TSRA_STATUS_SUCCESS
            );
            chained.insert(chained.end(), part.begin(), part.end());
        }
        ASSERT_EQ(chained, expected);
    });
}

TEST_F(tsra_aes_cfb, empty_input_produces_empty_output)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 128);
        uint8_t dummy = 0;

        tsra_algo_aes_cfb_params params{};
        tsra_algo algo{};
        init_algo(algo, params, test_iv());
        std::vector<uint8_t> out;
        ASSERT_EQ(
            single_shot_crypt(CryptOperation::Encrypt, key.get(), &algo, &dummy, 0, out),
            TSRA_STATUS_SUCCESS
        );
        ASSERT_TRUE(out.empty());
        ASSERT_EQ(params_iv(params), test_iv());
    });
}

TEST_F(tsra_aes_cfb, rejects_invalid_params)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 128);
        uint8_t data[AES_BLOCK_SIZE] = { 0 };
        tsra_buffer input{ data, sizeof(data) };
        tsra_buffer output{ nullptr, 0 };

        tsra_algo_aes_cfb_params params{};
        tsra_algo null_params{ TSRA_ALGO_ID_AES_CFB, nullptr, sizeof(params) };
        ASSERT_NE(
            tsra_crypt_encrypt(&null_params, key.get(), &input, &output),
            TSRA_STATUS_SUCCESS
        );

        tsra_algo bad_len{ TSRA_ALGO_ID_AES_CFB, &params, sizeof(params) - 1 };
        ASSERT_NE(tsra_crypt_encrypt(&bad_len, key.get(), &input, &output), TSRA_STATUS_SUCCESS);

        auto_ctx ctx;
        ASSERT_NE(tsra_crypt_decrypt_init(&bad_len, key.get(), ctx.get_ptr()), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(ctx.get(), 0u);
    });
}

TEST_F(tsra_aes_cfb, buffer_too_small_reports_required_len)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 128);
        auto plaintext = make_incrementing_bytes(33);
        std::vector<uint8_t> out(32);
        tsra_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        tsra_buffer output{ out.data(), static_cast<uint32_t>(out.size()) };

        tsra_algo_aes_cfb_params params{};
        tsra_algo algo{};
        init_algo(algo, params, test_iv());
        ASSERT_EQ(
            tsra_crypt_encrypt(&algo, key.get(), &input, &output),
            TSRA_STATUS_BUFFER_TOO_SMALL
        );
        ASSERT_EQ(output.len, 33u);
        ASSERT_EQ(params_iv(params), test_iv());
    });
}

TEST_F(tsra_aes_cfb, context_unusable_after_finish)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 128);
        auto plaintext = make_incrementing_bytes(20);
        std::vector<uint8_t> out(32);

        tsra_algo_aes_cfb_params params{};
        tsra_algo algo{};
        init_algo(algo, params, test_iv());

        auto_ctx enc;
        ASSERT_EQ(tsra_crypt_encrypt_init(&algo, key.get(), enc.get_ptr()), TSRA_STATUS_SUCCESS);
        tsra_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        tsra_buffer output{ out.data(), static_cast<uint32_t>(out.size()) };
        ASSERT_EQ(tsra_crypt_encrypt_update(enc.get(), &input, &output), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(output.len, 16u);
        output = { out.data(), static_cast<uint32_t>(out.size()) };
        ASSERT_EQ(tsra_crypt_encrypt_finish(enc.get(), &output), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(output.len, 4u);
        assert_encrypt_ctx_finished(enc.get());

        init_algo(algo, params, test_iv());
        auto_ctx dec;
        ASSERT_EQ(tsra_crypt_decrypt_init(&algo, key.get(), dec.get_ptr()), TSRA_STATUS_SUCCESS);
        output = { out.data(), static_cast<uint32_t>(out.size()) };
        ASSERT_EQ(tsra_crypt_decrypt_finish(dec.get(), &output), TSRA_STATUS_SUCCESS);
        assert_decrypt_ctx_finished(dec.get());
    });
}

#else

TEST_F(tsra_aes_cfb, unsupported_without_session_ex)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 128);
        uint8_t data[AES_BLOCK_SIZE] = { 0 };
        std::vector<uint8_t> out(AES_BLOCK_SIZE);
        tsra_buffer input{ data, sizeof(data) };
        tsra_buffer output{ out.data(), static_cast<uint32_t>(out.size()) };

        tsra_algo_aes_cfb_params params{};
        tsra_algo algo{};
        init_algo(algo, params, test_iv());
        ASSERT_EQ(
            tsra_crypt_encrypt(&algo, key.get(), &input, &output),
            TSRA_STATUS_UNSUPPORTED_ALGORITHM
        );
        ASSERT_EQ(
            tsra_crypt_decrypt(&algo, key.get(), &input, &output),
            TSRA_STATUS_UNSUPPORTED_ALGORITHM
        );

        auto_ctx ctx;
        ASSERT_EQ(
            tsra_crypt_encrypt_init(&algo, key.get(), ctx.get_ptr()),
            TSRA_STATUS_UNSUPPORTED_ALGORITHM
        );
        ASSERT_EQ(ctx.get(), 0u);
        ASSERT_EQ(
            tsra_crypt_decrypt_init(&algo, key.get(), ctx.get_ptr()),
            TSRA_STATUS_UNSUPPORTED_ALGORITHM
        );
        ASSERT_EQ(ctx.get(), 0u);
    });
}

#endif
