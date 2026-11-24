// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

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

#ifdef __cplusplus
}
#endif
