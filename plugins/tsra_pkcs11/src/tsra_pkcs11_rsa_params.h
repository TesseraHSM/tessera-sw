// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * The parameters of the RSA mechanisms: CK_RSA_PKCS_PSS_PARAMS of the PSS
 * signature mechanisms and CK_RSA_PKCS_OAEP_PARAMS of CKM_RSA_PKCS_OAEP. It
 * depends on neither the device nor the object store, so it is unit-tested on
 * its own (tests/rsa_params_test.c). sign.c and crypt.c run it at init.
 *
 * The SDK takes the MGF of PSS as given and then uses MGF1 with the signature
 * hash (api/native algo/rsa/sign.rs), and OAEP only with MGF1 of the OAEP hash
 * (api/native algo/rsa/enc.rs, which also refuses SHA-1 for OAEP). So the
 * checks here refuse every other pairing rather than let the device compute
 * something else than the caller asked for.
 */

/*
 * Check the parameter of the sign mechanism `mech` (a row of
 * tsra_pkcs11_sign_mech_find): the PSS mechanisms take CK_RSA_PKCS_PSS_PARAMS,
 * every other one none. On CKR_OK *is_pss says whether `mech` is a PSS
 * mechanism and *pss holds its parameters (zeroed otherwise). Returns:
 *   CKR_ARGUMENTS_BAD             NULL `mech`, `pss` or `is_pss`
 *   CKR_MECHANISM_PARAM_INVALID   a parameter on a mechanism that takes none;
 *                                 for PSS a NULL or wrongly sized parameter, a
 *                                 hashAlg other than the mechanism's hash (any
 *                                 of SHA-1, SHA-256, SHA-384 and SHA-512 for
 *                                 the pre-hashed CKM_RSA_PKCS_PSS), or an mgf
 *                                 other than MGF1 with that hash
 *   CKR_OK                        otherwise
 * The salt length depends on the key and is checked once the key is known
 * (tsra_pkcs11_pss_salt_ok).
 */
CK_RV tsra_pkcs11_sign_params_check(
    const CK_MECHANISM *mech,
    CK_RSA_PKCS_PSS_PARAMS *pss,
    bool *is_pss
);

/*
 * Whether the PSS parameters `pss` (as tsra_pkcs11_sign_params_check accepted
 * them) fit a key of `mod_bits` bits: sLen <= emLen - hLen - 2 with
 * emLen = ceil((modBits - 1) / 8) (RFC 8017 section 9.1.1). false for a NULL
 * `pss` or an unknown hash.
 */
bool tsra_pkcs11_pss_salt_ok(CK_ULONG mod_bits, const CK_RSA_PKCS_PSS_PARAMS *pss);

/* What tsra_pkcs11_oaep_params_check takes from CK_RSA_PKCS_OAEP_PARAMS. The
 * label points into the caller's parameter, so the caller copies it before the
 * C_*Init call returns. */
typedef struct
{
    CK_MECHANISM_TYPE hash; /* CKM_SHA256 / 384 / 512: the OAEP and the MGF1 hash */
    const CK_BYTE *label;   /* pSourceData; NULL when the label is empty */
    CK_ULONG label_len;
} tsra_pkcs11_oaep_params;

/*
 * Validate the CKM_RSA_PKCS_OAEP parameter `param` (`len` bytes) into *out
 * (cleared first, meaningful on CKR_OK only). Returns:
 *   CKR_ARGUMENTS_BAD             NULL `out`
 *   CKR_MECHANISM_PARAM_INVALID   a NULL or wrongly sized parameter, a hashAlg
 *                                 other than SHA-256, SHA-384 or SHA-512 (SHA-1
 *                                 among them: the SDK refuses it), an mgf other
 *                                 than MGF1 with that hash, a source other than
 *                                 CKZ_DATA_SPECIFIED, a NULL pSourceData with a
 *                                 length, or a label beyond 32 bits
 *   CKR_OK                        otherwise; an empty label (NULL or not) is
 *                                 no label
 */
CK_RV tsra_pkcs11_oaep_params_check(const void *param, CK_ULONG len, tsra_pkcs11_oaep_params *out);

/* The longest message CKM_RSA_PKCS_OAEP encrypts under a key of `mod_len`
 * bytes with `hash`: k - 2hLen - 2 (RFC 8017 section 7.1.1); 0 for an
 * unknown hash or a key too short for any message. */
CK_ULONG tsra_pkcs11_oaep_max_msg(CK_ULONG mod_len, CK_MECHANISM_TYPE hash);

#ifdef __cplusplus
}
#endif
