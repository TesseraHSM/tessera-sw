// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "utils/auto_key.hpp"
#include "utils/shared_secret.hpp"
#include <cstring>
#include <tsra_api.h>
#include <vector>

// Helper function to get expected HMAC key size in bits from HMAC key kind.
inline uint32_t get_hmac_key_bits(tsra_key_kind hmac_key_kind)
{
    switch (hmac_key_kind)
    {
    case TSRA_KEY_KIND_HMAC_SHA256:
        return 256;
    case TSRA_KEY_KIND_HMAC_SHA384:
        return 384;
    case TSRA_KEY_KIND_HMAC_SHA512:
        return 512;
    default:
        return 256;
    }
}

inline tsra_status derive_hmac_key_via_ecdh_hkdf(
    tsra_handle session_handle,
    tsra_handle server_priv_key,
    tsra_handle client_pub_key,
    tsra_key_kind hmac_key_kind,
    tsra_handle &hmac_key_handle,
    tsra_ecc_curve curve,
    tsra_handle *base_secret_handle = nullptr
)
{
    tsra_status err;

    // Step 1: Derive shared secret via ECDH using common helper
    auto_key temp_base_secret;
    err = derive_shared_secret_via_ecdh(
        session_handle,
        server_priv_key,
        client_pub_key,
        curve,
        temp_base_secret.handle
    );
    if (err != TSRA_STATUS_SUCCESS)
    {
        return err;
    }

    // Step 2: Use HKDF to derive HMAC key from base secret
    const char *salt = "test-salt-hmac-key";
    const char *info = "test-info-hmac-key";

    tsra_buffer salt_buf = { .ptr = (uint8_t *)salt, .len = static_cast<uint32_t>(strlen(salt)) };
    tsra_buffer info_buf = { .ptr = (uint8_t *)info, .len = static_cast<uint32_t>(strlen(info)) };

    tsra_algo_hkdf_params hkdf_params = { .hmac_algo_id = TSRA_ALGO_ID_HMAC_SHA256,
                                          .salt = &salt_buf,
                                          .info = &info_buf };

    tsra_algo hkdf_algo = { .id = TSRA_ALGO_ID_HKDF_DERIVE,
                            .params = &hkdf_params,
                            .len = sizeof(hkdf_params) };

    bool hmac_sign_prop = true;
    bool hmac_verify_prop = true;
    tsra_key_class hmac_key_class = TSRA_KEY_CLASS_SECRET;
    tsra_key_kind hmac_kind = hmac_key_kind;
    // For HMAC keys, the API expects the bit-length to match the digest size
    uint32_t hmac_key_bits = get_hmac_key_bits(hmac_key_kind);

    std::vector<tsra_key_prop> hmac_key_props;
    hmac_key_props.push_back(
        { .id = TSRA_KEY_PROP_ID_CLASS, .val = &hmac_key_class, .len = sizeof(hmac_key_class) }
    );
    hmac_key_props.push_back(
        { .id = TSRA_KEY_PROP_ID_KIND, .val = &hmac_kind, .len = sizeof(hmac_kind) }
    );
    hmac_key_props.push_back(
        { .id = TSRA_KEY_PROP_ID_BIT_LEN, .val = &hmac_key_bits, .len = sizeof(hmac_key_bits) }
    );
    hmac_key_props.push_back(
        { .id = TSRA_KEY_PROP_ID_SIGN, .val = &hmac_sign_prop, .len = sizeof(hmac_sign_prop) }
    );
    hmac_key_props.push_back(
        { .id = TSRA_KEY_PROP_ID_VERIFY, .val = &hmac_verify_prop, .len = sizeof(hmac_verify_prop) }
    );

    tsra_key_prop_list hmac_key_prop_list = { .props = hmac_key_props.data(),
                                              .count =
                                                  static_cast<uint32_t>(hmac_key_props.size()) };

    err = tsra_key_derive(
        session_handle,
        &hkdf_algo,
        temp_base_secret.get(),
        &hmac_key_prop_list,
        &hmac_key_handle
    );

    // If caller wants to keep the base secret, transfer ownership
    if (base_secret_handle != nullptr && err == TSRA_STATUS_SUCCESS)
    {
        *base_secret_handle = temp_base_secret.handle;
        temp_base_secret.handle = 0; // Release ownership so auto_key won't delete it
    }
    // Otherwise, temp_base_secret will be automatically deleted by auto_key destructor

    return err;
}

// Helper function to generate EC key pairs and derive HMAC key
inline tsra_status generate_ecdh_keys_and_derive_hmac(
    tsra_handle session_handle,
    tsra_key_kind hmac_key_type,
    EcdhKeyPairSet &key_pairs,
    tsra_handle &hmac_key_handle,
    tsra_ecc_curve curve
)
{
    // Generate two EC key pairs using common helper
    tsra_status err = key_pairs.generate(session_handle, curve);
    if (err != TSRA_STATUS_SUCCESS)
        return err;

    // Derive HMAC key using party A as server, party B as client
    err = derive_hmac_key_via_ecdh_hkdf(
        session_handle,
        key_pairs.priv_key_a.handle,
        key_pairs.pub_key_b.handle,
        hmac_key_type,
        hmac_key_handle,
        curve
    );

    return err;
}