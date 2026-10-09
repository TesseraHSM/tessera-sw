// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <tsra_api.h>

/// Helper function to generate RSA unwrapping key pair for testing
tsra_status generate_rsa_unwrapping_keypair(
    tsra_handle session,
    tsra_handle *priv_key_handle,
    tsra_handle *pub_key_handle
);