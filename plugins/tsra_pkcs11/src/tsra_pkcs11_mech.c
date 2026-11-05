// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * The mechanism table (see tsra_pkcs11_mech.h). The device has no general RSA
 * key generation (CKM_RSA_PKCS_KEY_PAIR_GEN hands out its one unwrapping key
 * pair), no AES-ECB or CTR, no non-NIST curves and no SHA-3; the other
 * mechanisms it does have join the table with the piece that implements their
 * entry points.
 */

#include "tsra_pkcs11_mech.h"
#include "tsra_pkcs11_ec_template.h"
#include "tsra_pkcs11_template.h"

#include <stddef.h>

/* The entry-point flags some entry point implements, the only ones a row may
 * carry besides the EC capability flags of an EC row. The piece that
 * implements another entry point (C_DeriveKey, ...) adds its flag here with its
 * rows. */
#define P11_IMPLEMENTED_FLAGS                                                                      \
    (CKF_ENCRYPT | CKF_DECRYPT | CKF_DIGEST | CKF_SIGN | CKF_VERIFY | CKF_GENERATE |               \
     CKF_GENERATE_KEY_PAIR | CKF_UNWRAP)

/* X(type, min_key, max_key, flags), one per implemented mechanism. */
#define P11_MECHS(X)                                                                               \
    X(CKM_SHA_1, 0, 0, CKF_DIGEST)                                                                 \
    X(CKM_SHA256, 0, 0, CKF_DIGEST)                                                                \
    X(CKM_SHA384, 0, 0, CKF_DIGEST)                                                                \
    X(CKM_SHA512, 0, 0, CKF_DIGEST)                                                                \
    X(CKM_AES_KEY_GEN, AES128_KEY_BYTES, AES256_KEY_BYTES, CKF_GENERATE)                           \
    X(CKM_AES_XTS_KEY_GEN, AES_XTS_KEY_BYTES, AES_XTS_KEY_BYTES, CKF_GENERATE)                     \
    X(CKM_AES_CBC, AES128_KEY_BYTES, AES256_KEY_BYTES, CKF_ENCRYPT | CKF_DECRYPT)                  \
    X(CKM_AES_CBC_PAD, AES128_KEY_BYTES, AES256_KEY_BYTES, CKF_ENCRYPT | CKF_DECRYPT)              \
    X(CKM_AES_GCM, AES256_KEY_BYTES, AES256_KEY_BYTES, CKF_ENCRYPT | CKF_DECRYPT)                  \
    X(CKM_AES_XTS, AES_XTS_KEY_BYTES, AES_XTS_KEY_BYTES, CKF_ENCRYPT | CKF_DECRYPT)                \
    X(CKM_EC_KEY_PAIR_GEN, EC_MIN_KEY_BITS, EC_MAX_KEY_BITS, CKF_GENERATE_KEY_PAIR | EC_MECH_FLAGS \
    )                                                                                              \
    X(CKM_ECDSA, EC_MIN_KEY_BITS, EC_MAX_KEY_BITS, CKF_SIGN | CKF_VERIFY | EC_MECH_FLAGS)          \
    X(CKM_ECDSA_SHA1, EC_MIN_KEY_BITS, EC_MAX_KEY_BITS, CKF_SIGN | CKF_VERIFY | EC_MECH_FLAGS)     \
    X(CKM_ECDSA_SHA256, EC_MIN_KEY_BITS, EC_MAX_KEY_BITS, CKF_SIGN | CKF_VERIFY | EC_MECH_FLAGS)   \
    X(CKM_ECDSA_SHA384, EC_MIN_KEY_BITS, EC_MAX_KEY_BITS, CKF_SIGN | CKF_VERIFY | EC_MECH_FLAGS)   \
    X(CKM_ECDSA_SHA512, EC_MIN_KEY_BITS, EC_MAX_KEY_BITS, CKF_SIGN | CKF_VERIFY | EC_MECH_FLAGS)   \
    X(CKM_RSA_PKCS_KEY_PAIR_GEN, RSA_UNWRAP_KEY_BITS, RSA_UNWRAP_KEY_BITS, CKF_GENERATE_KEY_PAIR)  \
    X(CKM_RSA_AES_KEY_WRAP, RSA_UNWRAP_KEY_BITS, RSA_UNWRAP_KEY_BITS, CKF_UNWRAP)

#define P11_MECH_ROW(t, lo, hi, f) { (t), (lo), (hi), (f) },

/* An EC row (the one key-size range in bits) carries all EC capability flags,
 * and no other row carries any. */
#define P11_MECH_CHECK(t, lo, hi, f)                                                               \
    _Static_assert(                                                                                \
        ((f) & ~(CK_FLAGS)(P11_IMPLEMENTED_FLAGS | EC_MECH_FLAGS)) == 0,                           \
        #t " has an unimplemented flag"                                                            \
    );                                                                                             \
    _Static_assert(                                                                                \
        ((f) & EC_MECH_FLAGS) ==                                                                   \
            ((((lo) == EC_MIN_KEY_BITS) && ((hi) == EC_MAX_KEY_BITS)) ? EC_MECH_FLAGS : 0),        \
        #t " has the EC capability flags exactly if it is an EC row"                               \
    );                                                                                             \
    _Static_assert((lo) <= (hi), #t " has an empty key-size range");

P11_MECHS(P11_MECH_CHECK)

const tsra_pkcs11_mech_t tsra_pkcs11_mechs[] = { P11_MECHS(P11_MECH_ROW) };

_Static_assert(
    sizeof(tsra_pkcs11_mechs) / sizeof(tsra_pkcs11_mechs[0]) == TSRA_PKCS11_MECH_COUNT,
    "TSRA_PKCS11_MECH_COUNT must match the table"
);

const tsra_pkcs11_mech_t *tsra_pkcs11_mech_find(CK_MECHANISM_TYPE type)
{
    for (size_t i = 0; i < TSRA_PKCS11_MECH_COUNT; i++)
    {
        if (tsra_pkcs11_mechs[i].type == type)
        {
            return &tsra_pkcs11_mechs[i];
        }
    }
    return NULL;
}
