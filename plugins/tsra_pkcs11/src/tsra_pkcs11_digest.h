// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Host-side digest operations (SHA-1/256/384/512). Digests run on the host
 * rather than through the SDK because the SDK digest needs a logged-in TSRA
 * session while PKCS#11 digests must work in public sessions; self-contained
 * FIPS 180-4 cores also keep the no-device build free of libcrypto.
 */

/* Digest lengths in bytes (FIPS 180-4). */
#define TSRA_PKCS11_SHA1_DIGEST_LEN 20
#define TSRA_PKCS11_SHA256_DIGEST_LEN 32
#define TSRA_PKCS11_SHA384_DIGEST_LEN 48
#define TSRA_PKCS11_SHA512_DIGEST_LEN 64
/* The largest digest the module produces, for sizing output buffers. */
#define TSRA_PKCS11_DIGEST_MAX_LEN TSRA_PKCS11_SHA512_DIGEST_LEN

/* One in-flight digest operation; created by _new, released by _free. */
typedef struct tsra_pkcs11_digest_op tsra_pkcs11_digest_op_t;

/* The digest length in bytes for `mech`, or 0 if it is not a supported digest
 * mechanism. Lets callers validate a mechanism without allocating an
 * operation. */
CK_ULONG tsra_pkcs11_digest_mech_len(CK_MECHANISM_TYPE mech);

/*
 * Start a digest operation for `mech`. Returns CKR_ARGUMENTS_BAD if `out` is
 * NULL, CKR_MECHANISM_INVALID if `mech` is not a supported digest mechanism,
 * and CKR_HOST_MEMORY if allocation fails. On CKR_OK the caller owns *out and
 * releases it with tsra_pkcs11_digest_op_free.
 */
CK_RV tsra_pkcs11_digest_op_new(CK_MECHANISM_TYPE mech, tsra_pkcs11_digest_op_t **out);

/* The operation's digest length in bytes. */
CK_ULONG tsra_pkcs11_digest_op_len(const tsra_pkcs11_digest_op_t *op);

/* Absorb `len` bytes of message data. */
void tsra_pkcs11_digest_op_update(tsra_pkcs11_digest_op_t *op, const CK_BYTE *data, CK_ULONG len);

/* Finish the operation and write tsra_pkcs11_digest_op_len(op) bytes to
 * `out`. The operation must not be used again afterwards (only freed). */
void tsra_pkcs11_digest_op_final(tsra_pkcs11_digest_op_t *op, CK_BYTE *out);

/* Release an operation; NULL is a no-op. */
void tsra_pkcs11_digest_op_free(tsra_pkcs11_digest_op_t *op);

#ifdef __cplusplus
}
#endif
