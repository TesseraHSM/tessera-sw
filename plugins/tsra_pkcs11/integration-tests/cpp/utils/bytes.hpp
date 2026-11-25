// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// Little-endian integers in byte vectors, for tests that build or read the
/// module's binary formats (store records, the SDK's AES-XTS container).

#include <climits>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "tsra_pkcs11_compat.h"

/// Append `v` to `out` little-endian in `n` bytes.
inline void put_le(std::vector<CK_BYTE> &out, uint64_t v, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        out.push_back(static_cast<CK_BYTE>(v >> (i * CHAR_BIT)));
    }
}

/// The `n` bytes of `in` at `at` as a little-endian value, as put_le writes it.
inline uint64_t get_le(const std::vector<CK_BYTE> &in, size_t at, size_t n)
{
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++)
    {
        v |= static_cast<uint64_t>(in[at + i]) << (i * CHAR_BIT);
    }
    return v;
}
