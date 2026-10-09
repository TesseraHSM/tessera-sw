// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstddef>
#include <cstdint>
#include <tsra_api.h>

// Returns a pointer and length for a precomputed PKCS#8 DER blob matching
// the given ECC curve.  Returns TSRA_STATUS_SUCCESS on success, or
// TSRA_STATUS_INVALID_ARGUMENT for unrecognised curves.
tsra_status get_static_ecc_pkcs8_der(
    tsra_ecc_curve curve,
    const uint8_t *&der_ptr,
    size_t &der_len
);
