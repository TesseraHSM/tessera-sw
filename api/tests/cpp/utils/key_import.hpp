// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "key_props.hpp"
#include <tsra_api.h>
#include <vector>

/// Helper function to import a key pair (RSA or ECC) using RSA-AES key wrapping
tsra_status import_keypair(
    tsra_handle wrapping_pub_key,
    tsra_handle wrapping_priv_key,
    const std::vector<uint8_t> &key_der,
    key_props props,
    tsra_handle *imported_priv_key,
    tsra_handle *imported_pub_key
);

/// Helper to RSA-AES wrap an arbitrary plaintext buffer for later unwrap/import.
tsra_status rsa_aes_wrap_bytes(
    tsra_handle wrapping_pub_key,
    const std::vector<uint8_t> &plaintext,
    uint32_t aes_key_bits,
    std::vector<uint8_t> &wrapped_out
);