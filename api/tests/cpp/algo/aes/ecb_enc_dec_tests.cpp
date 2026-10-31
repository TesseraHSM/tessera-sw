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

// AES-ECB is only supported on extended (session-ex) sessions.
class tsra_aes_ecb : public ::testing::Test
{
  protected:
    static constexpr size_t AES_BLOCK_SIZE = 16;

    PartitionListHandle part_list_ = PartitionListHandle{};

    static tsra_algo ecb_algo()
    {
        return tsra_algo{ TSRA_ALGO_ID_AES_ECB, nullptr, 0 };
    }
};

#if SESSION_EX_TESTS

TEST_F(tsra_aes_ecb, single_shot_matches_cbc_reference)
{
    part_list_.for_each_session([&](tsra_handle session) {
        for (const auto &key_size : aes_key_sizes())
        {
            auto key = generate_aes_key(session, key_size.bits);
            for (size_t len : { 16, 32, 160, 2 * 1024 + 48 })
            {
                SCOPED_TRACE(std::string(key_size.test_name) + " len " + std::to_string(len));
                auto plaintext = make_incrementing_bytes(len);

                // CBC with a zero IV over a single block is the AES forward cipher.
                std::vector<uint8_t> expected;
                for (size_t offset = 0; offset < len; offset += AES_BLOCK_SIZE)
                {
                    tsra_algo_aes_cbc_params cbc_params{};
                    tsra_algo cbc{ TSRA_ALGO_ID_AES_CBC, &cbc_params, sizeof(cbc_params) };
                    std::vector<uint8_t> block;
                    ASSERT_EQ(
                        single_shot_crypt(
                            CryptOperation::Encrypt,
                            key.get(),
                            &cbc,
                            plaintext.data() + offset,
                            AES_BLOCK_SIZE,
                            block
                        ),
                        TSRA_STATUS_SUCCESS
                    );
                    expected.insert(expected.end(), block.begin(), block.end());
                }

                auto algo = ecb_algo();
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
            }
        }
    });
}

TEST_F(tsra_aes_ecb, streaming_matches_single_shot)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 256);
        auto plaintext = make_incrementing_bytes(1104);
        auto algo = ecb_algo();
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

        for (size_t chunk : { 1, 7, 16, 33, 1024, 2000 })
        {
            SCOPED_TRACE("chunk " + std::to_string(chunk));
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
        }
    });
}

TEST_F(tsra_aes_ecb, rejects_invalid_lengths)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 128);
        auto algo = ecb_algo();
        uint8_t dummy = 0;
        std::vector<uint8_t> out;
        ASSERT_EQ(
            single_shot_crypt(CryptOperation::Encrypt, key.get(), &algo, &dummy, 0, out),
            TSRA_STATUS_INVALID_ARGUMENT
        );
        for (size_t len : { 1, 15, 17, 33 })
        {
            SCOPED_TRACE("len " + std::to_string(len));
            auto data = make_incrementing_bytes(len);
            ASSERT_EQ(
                single_shot_crypt(CryptOperation::Encrypt, key.get(), &algo, data.data(), len, out),
                TSRA_STATUS_INVALID_ARGUMENT
            );
            ASSERT_EQ(
                single_shot_crypt(CryptOperation::Decrypt, key.get(), &algo, data.data(), len, out),
                TSRA_STATUS_INVALID_ARGUMENT
            );
            ASSERT_EQ(
                streaming_crypt(
                    CryptOperation::Encrypt,
                    key.get(),
                    &algo,
                    data.data(),
                    len,
                    7,
                    out
                ),
                TSRA_STATUS_INVALID_ARGUMENT
            );
        }
    });
}

TEST_F(tsra_aes_ecb, rejects_params)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 128);
        uint8_t data[AES_BLOCK_SIZE] = { 0 };
        tsra_buffer input{ data, sizeof(data) };
        tsra_buffer output{ nullptr, 0 };

        tsra_algo_aes_cbc_params params{};
        tsra_algo with_params{ TSRA_ALGO_ID_AES_ECB, &params, sizeof(params) };
        ASSERT_EQ(
            tsra_crypt_encrypt(&with_params, key.get(), &input, &output),
            TSRA_STATUS_INVALID_ARGUMENT
        );

        auto_ctx ctx;
        ASSERT_EQ(
            tsra_crypt_encrypt_init(&with_params, key.get(), ctx.get_ptr()),
            TSRA_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(ctx.get(), 0u);
    });
}

TEST_F(tsra_aes_ecb, context_unusable_after_finish)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 128);
        auto plaintext = make_incrementing_bytes(AES_BLOCK_SIZE);
        std::vector<uint8_t> out(AES_BLOCK_SIZE);
        auto algo = ecb_algo();

        auto_ctx enc;
        ASSERT_EQ(tsra_crypt_encrypt_init(&algo, key.get(), enc.get_ptr()), TSRA_STATUS_SUCCESS);
        tsra_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        tsra_buffer output{ out.data(), static_cast<uint32_t>(out.size()) };
        ASSERT_EQ(tsra_crypt_encrypt_update(enc.get(), &input, &output), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(output.len, AES_BLOCK_SIZE);
        output = { out.data(), static_cast<uint32_t>(out.size()) };
        ASSERT_EQ(tsra_crypt_encrypt_finish(enc.get(), &output), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(output.len, 0u);
        assert_encrypt_ctx_finished(enc.get());

        auto_ctx dec;
        ASSERT_EQ(tsra_crypt_decrypt_init(&algo, key.get(), dec.get_ptr()), TSRA_STATUS_SUCCESS);
        output = { out.data(), static_cast<uint32_t>(out.size()) };
        ASSERT_EQ(tsra_crypt_decrypt_finish(dec.get(), &output), TSRA_STATUS_SUCCESS);
        assert_decrypt_ctx_finished(dec.get());
    });
}

#else

TEST_F(tsra_aes_ecb, unsupported_without_session_ex)
{
    part_list_.for_each_session([&](tsra_handle session) {
        auto key = generate_aes_key(session, 128);
        uint8_t data[AES_BLOCK_SIZE] = { 0 };
        std::vector<uint8_t> out(AES_BLOCK_SIZE);
        tsra_buffer input{ data, sizeof(data) };
        tsra_buffer output{ out.data(), static_cast<uint32_t>(out.size()) };
        auto algo = ecb_algo();

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
