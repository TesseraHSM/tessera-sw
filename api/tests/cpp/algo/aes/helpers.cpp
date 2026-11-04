// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "helpers.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/rsa_keygen.hpp"
#include <algorithm>
#include <gtest/gtest.h>
#include <string>

namespace
{
KeyHandle generate_aes_key_of_kind(
    tsra_handle session,
    tsra_algo_id keygen_algo_id,
    tsra_key_kind key_kind,
    uint32_t bits
)
{
    tsra_algo keygen_algo{};
    keygen_algo.id = keygen_algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    key_gen_props props;
    props.key_kind = key_kind;
    props.key_class = TSRA_KEY_CLASS_SECRET;
    props.bits = bits;
    props.is_session = true;
    props.can_encrypt = true;
    props.can_decrypt = true;

    return KeyHandle(session, &keygen_algo, props);
}
} // namespace

tsra_status crypt_call(
    CryptOperation operation,
    tsra_algo *algo,
    tsra_handle key_handle,
    tsra_buffer *input,
    tsra_buffer *output
)
{
    if (operation == CryptOperation::Encrypt)
    {
        return tsra_crypt_encrypt(algo, key_handle, input, output);
    }
    return tsra_crypt_decrypt(algo, key_handle, input, output);
}

tsra_status crypt_init_call(
    CryptOperation operation,
    tsra_algo *algo,
    tsra_handle key_handle,
    tsra_handle *ctx
)
{
    if (operation == CryptOperation::Encrypt)
    {
        return tsra_crypt_encrypt_init(algo, key_handle, ctx);
    }
    return tsra_crypt_decrypt_init(algo, key_handle, ctx);
}

tsra_status crypt_update_call(
    CryptOperation operation,
    tsra_handle ctx,
    tsra_buffer *input,
    tsra_buffer *output
)
{
    if (operation == CryptOperation::Encrypt)
    {
        return tsra_crypt_encrypt_update(ctx, input, output);
    }
    return tsra_crypt_decrypt_update(ctx, input, output);
}

tsra_status crypt_finish_call(CryptOperation operation, tsra_handle ctx, tsra_buffer *output)
{
    if (operation == CryptOperation::Encrypt)
    {
        return tsra_crypt_encrypt_finish(ctx, output);
    }
    return tsra_crypt_decrypt_finish(ctx, output);
}

tsra_status single_shot_status_with_sizing(
    CryptOperation operation,
    tsra_algo *algo,
    tsra_handle key_handle,
    tsra_buffer *input
)
{
    tsra_buffer output{ nullptr, 0 };
    auto err = crypt_call(operation, algo, key_handle, input, &output);
    if (err == TSRA_STATUS_BUFFER_TOO_SMALL)
    {
        std::vector<uint8_t> candidate(output.len);
        output.ptr = candidate.data();
        err = crypt_call(operation, algo, key_handle, input, &output);
    }
    return err;
}

tsra_status streaming_update_status_with_sizing(
    CryptOperation operation,
    tsra_handle ctx,
    tsra_buffer *input
)
{
    tsra_buffer output{ nullptr, 0 };
    auto err = crypt_update_call(operation, ctx, input, &output);
    if (err == TSRA_STATUS_BUFFER_TOO_SMALL)
    {
        std::vector<uint8_t> out_buf(output.len);
        output.ptr = out_buf.data();
        err = crypt_update_call(operation, ctx, input, &output);
    }
    return err;
}

tsra_status streaming_finish_status_with_sizing(CryptOperation operation, tsra_handle ctx)
{
    tsra_buffer output{ nullptr, 0 };
    auto err = crypt_finish_call(operation, ctx, &output);
    if (err == TSRA_STATUS_BUFFER_TOO_SMALL)
    {
        std::vector<uint8_t> out_buf(output.len);
        output.ptr = out_buf.data();
        err = crypt_finish_call(operation, ctx, &output);
    }
    return err;
}

tsra_status single_shot_crypt(
    CryptOperation operation,
    tsra_handle key_handle,
    tsra_algo *algo,
    const uint8_t *input_data,
    size_t input_len,
    std::vector<uint8_t> &output_data
)
{
    output_data.clear();

    tsra_buffer input{ const_cast<uint8_t *>(input_data), static_cast<uint32_t>(input_len) };
    tsra_buffer output{ nullptr, 0 };
    auto err = crypt_call(operation, algo, key_handle, &input, &output);
    if (err == TSRA_STATUS_SUCCESS)
    {
        if (output.len != 0)
        {
            return TSRA_STATUS_INTERNAL_ERROR;
        }

        return TSRA_STATUS_SUCCESS;
    }

    if (err != TSRA_STATUS_BUFFER_TOO_SMALL)
    {
        return err;
    }

    output_data.resize(output.len);
    output.ptr = output_data.data();
    err = crypt_call(operation, algo, key_handle, &input, &output);
    if (err != TSRA_STATUS_SUCCESS)
    {
        return err;
    }

    output_data.resize(output.len);
    return TSRA_STATUS_SUCCESS;
}

tsra_status streaming_crypt(
    CryptOperation operation,
    tsra_handle key_handle,
    tsra_algo *algo,
    const uint8_t *input_data,
    size_t input_len,
    size_t chunk_size,
    std::vector<uint8_t> &output
)
{
    output.clear();

    if (chunk_size == 0)
    {
        return TSRA_STATUS_INVALID_ARGUMENT;
    }

    auto_ctx ctx;
    auto err = crypt_init_call(operation, algo, key_handle, ctx.get_ptr());
    if (err != TSRA_STATUS_SUCCESS)
    {
        return err;
    }
    if (ctx.get() == 0)
    {
        return TSRA_STATUS_INTERNAL_ERROR;
    }

    size_t offset = 0;

    while (offset < input_len)
    {
        size_t current_chunk = std::min(chunk_size, input_len - offset);
        tsra_buffer input{ const_cast<uint8_t *>(input_data + offset),
                           static_cast<uint32_t>(current_chunk) };
        tsra_buffer out_buf{ nullptr, 0 };

        err = crypt_update_call(operation, ctx.get(), &input, &out_buf);
        if (err == TSRA_STATUS_BUFFER_TOO_SMALL)
        {
            if (out_buf.len == 0)
            {
                return TSRA_STATUS_INTERNAL_ERROR;
            }
            size_t current_pos = output.size();
            output.resize(current_pos + out_buf.len);
            out_buf.ptr = output.data() + current_pos;

            err = crypt_update_call(operation, ctx.get(), &input, &out_buf);
            if (err != TSRA_STATUS_SUCCESS)
            {
                return err;
            }
            output.resize(current_pos + out_buf.len);
        }
        else if (err == TSRA_STATUS_SUCCESS)
        {
        }
        else
        {
            return err;
        }

        offset += current_chunk;
    }

    tsra_buffer final_out{ nullptr, 0 };
    err = crypt_finish_call(operation, ctx.get(), &final_out);

    if (err == TSRA_STATUS_BUFFER_TOO_SMALL)
    {
        if (final_out.len == 0)
        {
            return TSRA_STATUS_INTERNAL_ERROR;
        }
        size_t current_pos = output.size();
        output.resize(current_pos + final_out.len);
        final_out.ptr = output.data() + current_pos;
        err = crypt_finish_call(operation, ctx.get(), &final_out);
        if (err != TSRA_STATUS_SUCCESS)
        {
            return err;
        }
        output.resize(current_pos + final_out.len);
    }
    else
    {
        if (err != TSRA_STATUS_SUCCESS)
        {
            return err;
        }
    }

    return TSRA_STATUS_SUCCESS;
}

std::vector<uint8_t> make_incrementing_bytes(size_t len)
{
    std::vector<uint8_t> bytes(len);
    for (size_t i = 0; i < len; ++i)
    {
        bytes[i] = static_cast<uint8_t>(i & 0xFF);
    }

    return bytes;
}

const std::vector<AesKeyTestParams> &aes_key_sizes()
{
    static const std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    return key_sizes;
}

const std::vector<size_t> &padding_sweep_plaintext_sizes()
{
    static const std::vector<size_t> sizes = [] {
        std::vector<size_t> values;
        for (size_t value = 0; value <= 32; ++value)
        {
            values.push_back(value);
        }
        values.push_back(63);
        values.push_back(64);
        values.push_back(65);
        values.push_back(127);
        values.push_back(128);
        values.push_back(129);
        return values;
    }();

    return sizes;
}

const std::vector<size_t> &padding_sweep_chunk_sizes()
{
    static const std::vector<size_t> sizes = { 1, 2, 3, 5, 7, 8, 15, 16, 17, 31, 32, 33, 64, 256 };

    return sizes;
}

void run_single_shot_key_size(
    PartitionListHandle &part_list,
    tsra_algo_id algo_id,
    const std::vector<DataSizeTestParams> &data_sizes,
    uint8_t plaintext_fill,
    const std::function<void(tsra_handle, tsra_algo_id, const uint8_t *, size_t, size_t)>
        &roundtrip_runner,
    const std::function<KeyHandle(tsra_handle, uint32_t)> &key_generator
)
{
    for (const auto &key_param : aes_key_sizes())
    {
        for (const auto &data_param : data_sizes)
        {
            SCOPED_TRACE(std::string(key_param.test_name) + " " + data_param.test_name);

            part_list.for_each_session([&](tsra_handle session) {
                auto key = key_generator(session, key_param.bits);

                std::vector<uint8_t> plaintext(data_param.data_size, plaintext_fill);
                size_t expected_ciphertext_len = (algo_id == TSRA_ALGO_ID_AES_CBC_PAD)
                                                     ? data_param.expected_output_size_with_pad
                                                     : data_param.expected_output_size_no_pad;

                roundtrip_runner(
                    key.get(),
                    algo_id,
                    plaintext.data(),
                    plaintext.size(),
                    expected_ciphertext_len
                );
            });
        }
    }
}

void run_streaming_case_list(
    PartitionListHandle &part_list,
    tsra_algo_id algo_id,
    const std::function<void(tsra_handle, tsra_algo_id, const uint8_t *, size_t, size_t, size_t)>
        &roundtrip_runner,
    const std::vector<StreamingRoundtripCase> &test_cases,
    const std::function<KeyHandle(tsra_handle, uint32_t)> &key_generator
)
{
    for (const auto &key_param : aes_key_sizes())
    {
        for (const auto &test_case : test_cases)
        {
            SCOPED_TRACE(std::string(key_param.test_name) + " " + test_case.test_name);

            part_list.for_each_session([&](tsra_handle session) {
                auto key = key_generator(session, key_param.bits);

                std::vector<uint8_t> plaintext(test_case.plaintext_len, test_case.plaintext_fill);

                roundtrip_runner(
                    key.get(),
                    algo_id,
                    plaintext.data(),
                    plaintext.size(),
                    test_case.chunk_size,
                    test_case.expected_ciphertext_len
                );
            });
        }
    }
}

KeyHandle generate_aes_key(tsra_handle session, uint32_t bits)
{
    return generate_aes_key_of_kind(session, TSRA_ALGO_ID_AES_KEY_GEN, TSRA_KEY_KIND_AES, bits);
}

KeyHandle generate_aes_gcm_key(tsra_handle session, uint32_t bits)
{
    return generate_aes_key_of_kind(session, TSRA_ALGO_ID_AES_KEY_GEN, TSRA_KEY_KIND_AES_GCM, bits);
}

KeyHandle generate_aes_xts_key(tsra_handle session, uint32_t bits)
{
    return generate_aes_key_of_kind(
        session,
        TSRA_ALGO_ID_AES_XTS_KEY_GEN,
        TSRA_KEY_KIND_AES_XTS,
        bits
    );
}

void assert_encrypt_ctx_finished(tsra_handle ctx)
{
    // finish on a finished context must return INVALID_CONTEXT_STATE
    tsra_buffer finish_buf{ nullptr, 0 };
    ASSERT_EQ(
        crypt_finish_call(CryptOperation::Encrypt, ctx, &finish_buf),
        TSRA_STATUS_INVALID_CONTEXT_STATE
    );

    // update on a finished context must return INVALID_CONTEXT_STATE
    uint8_t dummy[16] = { 0 };
    tsra_buffer input{ dummy, sizeof(dummy) };
    tsra_buffer output{ nullptr, 0 };
    ASSERT_EQ(
        crypt_update_call(CryptOperation::Encrypt, ctx, &input, &output),
        TSRA_STATUS_INVALID_CONTEXT_STATE
    );
}

void assert_decrypt_ctx_finished(tsra_handle ctx)
{
    // finish on a finished context must return INVALID_CONTEXT_STATE
    tsra_buffer finish_buf{ nullptr, 0 };
    ASSERT_EQ(
        crypt_finish_call(CryptOperation::Decrypt, ctx, &finish_buf),
        TSRA_STATUS_INVALID_CONTEXT_STATE
    );

    // update on a finished context must return INVALID_CONTEXT_STATE
    uint8_t dummy[16] = { 0 };
    tsra_buffer input{ dummy, sizeof(dummy) };
    tsra_buffer output{ nullptr, 0 };
    ASSERT_EQ(
        crypt_update_call(CryptOperation::Decrypt, ctx, &input, &output),
        TSRA_STATUS_INVALID_CONTEXT_STATE
    );
}

std::vector<uint8_t> aes_ecb_block(tsra_handle key_handle, const uint8_t *block)
{
    tsra_algo algo{ TSRA_ALGO_ID_AES_ECB, nullptr, 0 };
    std::vector<uint8_t> out;
    auto err = single_shot_crypt(CryptOperation::Encrypt, key_handle, &algo, block, 16, out);
    EXPECT_EQ(err, TSRA_STATUS_SUCCESS);
    EXPECT_EQ(out.size(), 16u);
    out.resize(16);
    return out;
}

void aes_feedback_reference_encrypt(
    AesFeedbackMode mode,
    tsra_handle key_handle,
    const uint8_t *iv,
    const std::vector<uint8_t> &plaintext,
    std::vector<uint8_t> &ciphertext,
    std::vector<uint8_t> &iv_out
)
{
    std::vector<uint8_t> reg(iv, iv + 16);
    ciphertext.clear();
    for (size_t offset = 0; offset < plaintext.size(); offset += 16)
    {
        size_t len = std::min<size_t>(16, plaintext.size() - offset);
        auto keystream = aes_ecb_block(key_handle, reg.data());
        std::vector<uint8_t> out(len);
        for (size_t i = 0; i < len; ++i)
        {
            out[i] = plaintext[offset + i] ^ keystream[i];
        }
        switch (mode)
        {
        case AesFeedbackMode::Cfb:
            if (len == 16)
            {
                reg = out;
            }
            break;
        case AesFeedbackMode::Ofb:
            reg = keystream;
            break;
        case AesFeedbackMode::Ctr:
            // 128-bit big-endian increment with wrap-around.
            for (size_t i = 16; i-- > 0;)
            {
                if (++reg[i] != 0)
                {
                    break;
                }
            }
            break;
        }
        ciphertext.insert(ciphertext.end(), out.begin(), out.end());
    }
    iv_out = reg;
}
