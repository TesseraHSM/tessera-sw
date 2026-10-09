// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "auto_key.hpp"
#include <tsra_api.h>
#include <vector>

// Helper function to get key size in bits from EC curve
uint32_t get_curve_key_bits(tsra_ecc_curve curve);

// Helper function to generate an EC key pair for derivation operations
tsra_status generate_ec_key_pair_for_derive(
    tsra_handle session_handle,
    tsra_handle &pub_key_handle,
    tsra_handle &priv_key_handle,
    tsra_ecc_curve curve
);

// Helper function to derive a shared secret key via ECDH
// Returns the shared secret key handle via out_shared_secret_handle
tsra_status derive_shared_secret_via_ecdh(
    tsra_handle session_handle,
    tsra_handle priv_key_handle,
    tsra_handle peer_pub_key_handle,
    tsra_ecc_curve curve,
    tsra_handle &out_shared_secret_handle
);

// Helper struct to manage ECDH key pairs with automatic cleanup
struct EcdhKeyPairSet
{
    auto_key pub_key_a;
    auto_key priv_key_a;
    auto_key pub_key_b;
    auto_key priv_key_b;

    // Generate two EC key pairs for ECDH operations
    tsra_status generate(tsra_handle session_handle, tsra_ecc_curve curve)
    {
        tsra_status err = generate_ec_key_pair_for_derive(
            session_handle,
            pub_key_a.handle,
            priv_key_a.handle,
            curve
        );
        if (err != TSRA_STATUS_SUCCESS)
        {
            return err;
        }

        return generate_ec_key_pair_for_derive(
            session_handle,
            pub_key_b.handle,
            priv_key_b.handle,
            curve
        );
    }
};