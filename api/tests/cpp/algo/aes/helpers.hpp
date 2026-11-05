// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "handle/key_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"
#include <functional>
#include <tsra_api.h>
#include <vector>

enum class CryptOperation
{
    Encrypt,
    Decrypt,
};

struct AesKeyTestParams
{
    uint32_t bits;
    const char *test_name;
};

struct DataSizeTestParams
{
    size_t data_size;
    size_t expected_output_size_no_pad;
    size_t expected_output_size_with_pad;
    const char *test_name;
};

struct StreamingRoundtripCase
{
    size_t plaintext_len;
    size_t chunk_size;
    size_t expected_ciphertext_len;
    uint8_t plaintext_fill;
    const char *test_name;
};

tsra_status crypt_call(
    CryptOperation operation,
    tsra_algo *algo,
    tsra_handle key_handle,
    tsra_buffer *input,
    tsra_buffer *output
);

tsra_status crypt_init_call(
    CryptOperation operation,
    tsra_algo *algo,
    tsra_handle key_handle,
    tsra_handle *ctx
);

tsra_status crypt_update_call(
    CryptOperation operation,
    tsra_handle ctx,
    tsra_buffer *input,
    tsra_buffer *output
);

tsra_status crypt_finish_call(CryptOperation operation, tsra_handle ctx, tsra_buffer *output);

tsra_status single_shot_status_with_sizing(
    CryptOperation operation,
    tsra_algo *algo,
    tsra_handle key_handle,
    tsra_buffer *input
);

tsra_status streaming_update_status_with_sizing(
    CryptOperation operation,
    tsra_handle ctx,
    tsra_buffer *input
);

tsra_status streaming_finish_status_with_sizing(CryptOperation operation, tsra_handle ctx);

tsra_status single_shot_crypt(
    CryptOperation operation,
    tsra_handle key_handle,
    tsra_algo *algo,
    const uint8_t *input_data,
    size_t input_len,
    std::vector<uint8_t> &output
);

tsra_status streaming_crypt(
    CryptOperation operation,
    tsra_handle key_handle,
    tsra_algo *algo,
    const uint8_t *input_data,
    size_t input_len,
    size_t chunk_size,
    std::vector<uint8_t> &output
);

// Builds deterministic incrementing bytes: 0x00, 0x01, 0x02, ...
std::vector<uint8_t> make_incrementing_bytes(size_t len);

const std::vector<AesKeyTestParams> &aes_key_sizes();

const std::vector<size_t> &padding_sweep_plaintext_sizes();

const std::vector<size_t> &padding_sweep_chunk_sizes();

void run_single_shot_key_size(
    PartitionListHandle &part_list,
    tsra_algo_id algo_id,
    const std::vector<DataSizeTestParams> &data_sizes,
    uint8_t plaintext_fill,
    const std::function<void(tsra_handle, tsra_algo_id, const uint8_t *, size_t, size_t)>
        &roundtrip_runner,
    const std::function<KeyHandle(tsra_handle, uint32_t)> &key_generator
);

void run_streaming_case_list(
    PartitionListHandle &part_list,
    tsra_algo_id algo_id,
    const std::function<void(tsra_handle, tsra_algo_id, const uint8_t *, size_t, size_t, size_t)>
        &roundtrip_runner,
    const std::vector<StreamingRoundtripCase> &test_cases,
    const std::function<KeyHandle(tsra_handle, uint32_t)> &key_generator
);

// Generate an AES key for testing.
KeyHandle generate_aes_key(tsra_handle session, uint32_t bits);
KeyHandle generate_aes_gcm_key(tsra_handle session, uint32_t bits);
KeyHandle generate_aes_xts_key(tsra_handle session, uint32_t bits);

// ==================== Context Lifecycle Assertion Helpers ====================
//
// After a successful finish, the context handle is still alive (can be freed),
// but update/finish must return TSRA_STATUS_INVALID_CONTEXT_STATE.

/// Asserts that update and finish on a finished encrypt context both return
/// TSRA_STATUS_INVALID_CONTEXT_STATE.
void assert_encrypt_ctx_finished(tsra_handle ctx);

/// Asserts that update and finish on a finished decrypt context both return
/// TSRA_STATUS_INVALID_CONTEXT_STATE.
void assert_decrypt_ctx_finished(tsra_handle ctx);

// ==================== AES Feedback Mode Reference Helpers ====================
//
// Generated keys never leave the HSM, so CFB/OFB/CTR known-answer checks use
// the HSM's own AES-ECB (the AES forward cipher) to build reference output
// from the NIST SP 800-38A definitions.

enum class AesFeedbackMode
{
    Cfb,
    Ofb,
    Ctr,
};

/// Encrypts a single 16-byte block with AES-ECB under `key_handle`.
std::vector<uint8_t> aes_ecb_block(tsra_handle key_handle, const uint8_t *block);

/// Builds the reference encryption of `plaintext` and the expected IV-out.
void aes_feedback_reference_encrypt(
    AesFeedbackMode mode,
    tsra_handle key_handle,
    const uint8_t *iv,
    const std::vector<uint8_t> &plaintext,
    std::vector<uint8_t> &ciphertext,
    std::vector<uint8_t> &iv_out
);
