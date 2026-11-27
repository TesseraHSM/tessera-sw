// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Zero `n` bytes at `p` through a volatile pointer, so the store is not elided
 * as a dead write when the memory is freed or leaves scope right after. The
 * module links no libcrypto outside tsra_pkcs11_hsm.c, so OPENSSL_cleanse is
 * not available; header-static so the store TUs and their unit harnesses need
 * no other TU. NULL-safe.
 */
static inline void tsra_pkcs11_wipe(void *p, size_t n)
{
    if (p == NULL)
    {
        return;
    }
    volatile unsigned char *v = (volatile unsigned char *)p;
    for (size_t i = 0; i < n; i++)
    {
        v[i] = 0;
    }
}

/*
 * Whether the `n` bytes at `a` and `b` are equal, in a time that depends on
 * `n` alone: the XOR of each byte pair is OR-accumulated with no early exit,
 * so comparing a secret value (an HMAC tag) does not tell where it first
 * differs. CRYPTO_memcmp is out of reach for the reason given above. The
 * volatile reads keep the compiler from adding an exit of its own. A NULL
 * range of non-zero length is equal to nothing.
 */
static inline bool tsra_pkcs11_equal_ct(const void *a, const void *b, size_t n)
{
    if ((n > 0) && ((a == NULL) || (b == NULL)))
    {
        return false;
    }
    const volatile unsigned char *x = (const volatile unsigned char *)a;
    const volatile unsigned char *y = (const volatile unsigned char *)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++)
    {
        diff |= (unsigned char)(x[i] ^ y[i]);
    }
    return diff == 0;
}

#ifdef __cplusplus
}
#endif
