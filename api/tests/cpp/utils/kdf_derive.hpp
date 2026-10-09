// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <gtest/gtest.h>
#include <tsra_api.h>
#include <vector>

#include "algo/aes/helpers.hpp"
#include "utils/auto_key.hpp"
#include "utils/key_props.hpp"
#include "utils/shared_secret.hpp"

const char *get_hmac_algo_name(tsra_algo_id hmac_algo_id);

static const std::vector<tsra_algo_id> &supported_hkdf_hash_algos()
{
    static const std::vector<tsra_algo_id> algos = {
        TSRA_ALGO_ID_HMAC_SHA1,
        TSRA_ALGO_ID_HMAC_SHA256,
        TSRA_ALGO_ID_HMAC_SHA384,
        TSRA_ALGO_ID_HMAC_SHA512,
    };
    return algos;
}

// Builds an tsra_algo for HKDF with the given HMAC algo ID and optional salt/info.
void build_hkdf_algo(
    tsra_algo_hkdf_params &hkdf_params,
    tsra_algo &hkdf_algo,
    tsra_algo_id hmac_algo_id,
    tsra_buffer *salt,
    tsra_buffer *info
);

void derive_ecdh_shared_secrets(
    tsra_handle session,
    tsra_ecc_curve curve,
    auto_key &shared_secret_a,
    auto_key &shared_secret_b
);

void derive_aes_key_from_shared_secret(
    tsra_handle session,
    tsra_algo *hkdf_algo,
    tsra_handle shared_secret,
    uint32_t bits,
    auto_key &out_key
);

void assert_aes_cbc_roundtrip(
    tsra_handle enc_key,
    tsra_handle dec_key,
    const uint8_t *plaintext,
    size_t plaintext_len
);

void run_hkdf_matrix_for_curve(tsra_handle session, tsra_ecc_curve curve);

void hkdf_derive_fails_common(
    tsra_handle session,
    tsra_algo_id hmac_algo_id,
    key_props &props,
    tsra_status expected_status
);

// Builds an tsra_algo for SP 800-108 Counter Mode KBKDF with the given HMAC algo ID and
// optional label/context. At least one of label/context must be present at derive time.
void build_kbkdf_counter_algo(
    tsra_algo_kbkdf_counter_params &kbkdf_params,
    tsra_algo &kbkdf_algo,
    tsra_algo_id hmac_algo_id,
    tsra_buffer *label,
    tsra_buffer *context
);

void run_kbkdf_counter_matrix_for_curve(tsra_handle session, tsra_ecc_curve curve);

void kbkdf_derive_fails_common(
    tsra_handle session,
    tsra_algo_id hmac_algo_id,
    key_props &props,
    tsra_status expected_status
);
