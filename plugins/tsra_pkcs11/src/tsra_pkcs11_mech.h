// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * The mechanism table C_GetMechanismList and C_GetMechanismInfo report: the
 * implemented mechanisms only, each with the flags of the entry points that
 * run it. Device-free, so tests/mech_table_test.c checks it against the
 * dispatch arms (tsra_pkcs11_digest_mech_len, tsra_pkcs11_cipher_mech_find,
 * tsra_pkcs11_sign_mech_find, tsra_pkcs11_keygen_check_template,
 * tsra_pkcs11_ec_keygen_check) in both directions.
 */

/* One row. Key sizes are in bytes for AES and in bits for EC (as PKCS#11
 * counts them); 0 where a mechanism takes no key. */
typedef struct
{
    CK_MECHANISM_TYPE type;
    CK_ULONG min_key;
    CK_ULONG max_key;
    CK_FLAGS flags;
} tsra_pkcs11_mech_t;

/* Rows in tsra_pkcs11_mechs; a piece that implements a mechanism appends its
 * row and raises this (checked at compile time). */
#define TSRA_PKCS11_MECH_COUNT 16

extern const tsra_pkcs11_mech_t tsra_pkcs11_mechs[];

/* The row for `type`, or NULL if the module does not implement it. */
const tsra_pkcs11_mech_t *tsra_pkcs11_mech_find(CK_MECHANISM_TYPE type);

#ifdef __cplusplus
}
#endif
