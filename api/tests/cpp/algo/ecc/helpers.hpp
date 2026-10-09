// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <tsra_api.h>
#include <vector>

#include "utils/auto_key.hpp"

// Dummy private-key property set used by key-gen and key-unwrap negative tests.
struct DefaultEccPrivKeyProps
{
    uint32_t key_class = TSRA_KEY_CLASS_PRIVATE;
    uint32_t key_kind = TSRA_KEY_KIND_ECC;
    uint32_t ecc_curve = TSRA_ECC_CURVE_P256;
    uint8_t is_session = 1;
    uint8_t can_sign = 1;

    std::vector<tsra_key_prop> props;

    DefaultEccPrivKeyProps();
    tsra_key_prop_list get_prop_list();
};

// Dummy public-key property set used by key-gen and key-unwrap negative tests.
struct DefaultEccPubKeyProps
{
    uint32_t key_class = TSRA_KEY_CLASS_PUBLIC;
    uint32_t key_kind = TSRA_KEY_KIND_ECC;
    uint32_t ecc_curve = TSRA_ECC_CURVE_P256;
    uint8_t is_session = 1;
    uint8_t can_verify = 1;

    std::vector<tsra_key_prop> props;

    DefaultEccPubKeyProps();
    tsra_key_prop_list get_prop_list();
};

// Generates an ECC key pair with standard SIGN/VERIFY capability properties.
tsra_status generate_ecc_keypair(
    tsra_handle session,
    tsra_ecc_curve curve,
    bool session_key,
    tsra_handle *priv_key_handle,
    tsra_handle *pub_key_handle
);

// RSA-AES wrap configuration used to generate wrapped ECC PKCS#8 payloads.
struct RsaAesWrapConfig
{
    tsra_algo_id hash_algo = TSRA_ALGO_ID_SHA256;
    tsra_mgf1_id mgf1_hash_algo = TSRA_MGF1_ID_SHA256;
    const tsra_buffer *label = nullptr;
    uint32_t aes_key_bits = 256;
};

// Builds a wrapped ECC PKCS#8 blob for key_unwrap_pair tests.
tsra_status make_wrapped_ecc_pkcs8_blob(
    tsra_handle wrapping_pub_key,
    tsra_ecc_curve curve,
    const RsaAesWrapConfig &wrap_config,
    std::vector<uint8_t> &wrapped_blob
);

// Removes all properties matching prop_id from a mutable property vector.
void remove_prop_by_id(std::vector<tsra_key_prop> &props, tsra_key_prop_id prop_id);

template <typename T> tsra_status get_key_prop(tsra_handle key, tsra_key_prop_id prop_id, T &value)
{
    tsra_key_prop prop{};
    prop.id = prop_id;
    prop.val = &value;
    prop.len = sizeof(T);
    return tsra_key_get_prop(key, &prop);
}

struct EccKeySummary
{
    tsra_key_kind kind = TSRA_KEY_KIND_AES;
    tsra_ecc_curve curve = TSRA_ECC_CURVE_P256;
};

// Reads common key identity fields used by ECC parity assertions.
tsra_status read_ecc_key_summary(tsra_handle key, EccKeySummary &summary);
bool is_expected_ecc_curve(const EccKeySummary &summary, tsra_ecc_curve expected_curve);

// Reads TSRA_KEY_PROP_ID_MASKED_KEY using probe-then-fetch buffering.
tsra_status get_masked_key_blob(tsra_handle private_key, std::vector<uint8_t> &masked_key_data);
// Generates a valid ECC masked blob suitable for unmask tests.
tsra_status make_valid_masked_ecc_blob(
    tsra_handle session,
    tsra_ecc_curve curve,
    std::vector<uint8_t> &masked_key_data
);

// Common mutable inputs for negative/shape key_unwrap_pair argument tests.
struct RsaAesUnwrapPairInputs
{
    explicit RsaAesUnwrapPairInputs(uint8_t wrapped_blob_byte);

    uint8_t wrapped_blob_byte;
    tsra_buffer wrapped_key_buf{};
    tsra_algo_rsa_pkcs_oaep_params oaep_params{};
    tsra_algo_rsa_aes_key_wrap_params unwrap_params{};
    tsra_algo unwrap_algo{};
};

// Helper wrapper for constructing a valid RSA-AES unwrap algorithm descriptor.
struct RsaAesUnwrapAlgo
{
    explicit RsaAesUnwrapAlgo(const RsaAesWrapConfig &wrap_config = RsaAesWrapConfig{});

    tsra_algo_rsa_pkcs_oaep_params oaep_params{};
    tsra_algo_rsa_aes_key_wrap_params unwrap_params{};
    tsra_algo algo{};
};

struct UnmaskPairResult
{
    tsra_status status = TSRA_STATUS_SUCCESS;
    tsra_handle private_key = 0;
    tsra_handle public_key = 0;
};

UnmaskPairResult try_unmask_pair(
    tsra_handle session,
    tsra_key_kind key_kind,
    tsra_buffer *masked_key
);

struct UnwrapPairResult
{
    tsra_status status = TSRA_STATUS_SUCCESS;
    tsra_handle private_key = 0;
    tsra_handle public_key = 0;
};

UnwrapPairResult try_unwrap_pair(
    tsra_algo *algo,
    tsra_handle unwrapping_key,
    tsra_buffer *wrapped_key,
    tsra_key_prop_list *priv_props,
    tsra_key_prop_list *pub_props
);

struct EcdsaRoundtripResult
{
    tsra_status status = TSRA_STATUS_SUCCESS;
    const char *step = "success";
    const char *detail = "";
};

// Runs sign+verify checks and returns step diagnostics on failure.
EcdsaRoundtripResult run_ecdsa_sign_verify_roundtrip(
    tsra_handle private_key,
    tsra_handle public_key,
    const std::vector<uint8_t> &message
);

// Signs a message with ECDSA-SHA256 using a probe-then-materialize pattern.
tsra_status ecdsa_sign_sha256(
    tsra_handle private_key,
    const std::vector<uint8_t> &message,
    std::vector<uint8_t> &signature
);

// Verifies a message/signature pair with ECDSA-SHA256.
tsra_status ecdsa_verify_sha256(
    tsra_handle public_key,
    const std::vector<uint8_t> &message,
    const std::vector<uint8_t> &signature
);

// Wraps/imports an ECC pair with explicit wrap and unwrap RSA-AES configs.
tsra_status unwrap_wrapped_ecc_pair_with_configs(
    tsra_handle session,
    tsra_ecc_curve curve,
    const RsaAesWrapConfig &wrap_config,
    const RsaAesWrapConfig &unwrap_config,
    UnwrapPairResult &unwrap_result
);

// RSA-AES wraps arbitrary plaintext bytes using caller-selected transport params.
tsra_status wrap_plaintext_with_rsa_aes(
    tsra_handle wrapping_pub_key,
    const std::vector<uint8_t> &plaintext,
    const RsaAesWrapConfig &wrap_config,
    std::vector<uint8_t> &wrapped_blob
);

// Builds deterministic payload bytes for negative unwrap-content tests.
std::vector<uint8_t> make_deterministic_payload(uint8_t seed, uint8_t step, size_t len);

// Pre-built context for key_unwrap_pair tests.
// Generates an RSA unwrapping keypair and optionally wraps a real ECC PKCS#8 blob,
// giving tests mutable access to algo, wrapped buffer, and property lists.
struct UnwrapPairContext
{
    auto_key rsa_priv_key;
    auto_key rsa_pub_key;

    std::vector<uint8_t> wrapped_blob;
    tsra_buffer wrapped_key_buf{};

    RsaAesUnwrapAlgo unwrap_algo;

    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;

    // Creates context with RSA keypair only (no wrapped blob).
    // Tests that use RsaAesUnwrapPairInputs for fake blobs should use this.
    static tsra_status create(tsra_handle session, UnwrapPairContext &ctx);

    // Creates context with RSA keypair and a real wrapped ECC PKCS#8 blob.
    static tsra_status create_with_wrapped_blob(
        tsra_handle session,
        tsra_ecc_curve curve,
        UnwrapPairContext &ctx
    );

    // Creates context with RSA keypair and a real wrapped ECC PKCS#8 blob
    // using explicit wrap configuration.
    static tsra_status create_with_wrapped_blob(
        tsra_handle session,
        tsra_ecc_curve curve,
        const RsaAesWrapConfig &wrap_config,
        UnwrapPairContext &ctx
    );

    // Calls try_unwrap_pair with this context's current state.
    UnwrapPairResult try_unwrap();

    // Calls try_unwrap_pair with an overridden algo pointer (e.g. nullptr).
    UnwrapPairResult try_unwrap_with_algo(tsra_algo *algo);

    // Calls try_unwrap_pair with an overridden unwrapping key handle.
    UnwrapPairResult try_unwrap_with_key(tsra_handle key);

    // Calls try_unwrap_pair with overridden algo and wrapped-key buffer pointers.
    UnwrapPairResult try_unwrap_with(tsra_algo *algo, tsra_buffer *wrapped_key);

    // Calls try_unwrap_pair using the algo and wrapped buffer from RsaAesUnwrapPairInputs.
    UnwrapPairResult try_unwrap_inputs(RsaAesUnwrapPairInputs &inputs);

    // Calls tsra_key_unwrap_pair directly, allowing null output-handle pointers.
    tsra_status raw_unwrap(
        RsaAesUnwrapPairInputs &inputs,
        tsra_handle *priv_out,
        tsra_handle *pub_out
    );
};

// Calls try_unwrap_pair with a fake blob and the given handle, no session needed.
UnwrapPairResult try_unwrap_with_invalid_handle(tsra_handle key_handle);
