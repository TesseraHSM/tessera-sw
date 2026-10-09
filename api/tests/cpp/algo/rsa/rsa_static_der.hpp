// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstddef>
#include <cstdint>
#include <tsra_api.h>

// Returns the pre-generated test-only RSA PKCS#8 DER blob for the requested bit length
// Currently supports 2048, 3072, or 4096-bit RSA keys.
tsra_status get_static_rsa_pkcs8_der(uint32_t bit_len, const uint8_t *&der_ptr, size_t &der_len);