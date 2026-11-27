// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_attr_policy.h"
#include "tsra_pkcs11_compat.h"
#include "tsra_pkcs11_ec_template.h"
#include "tsra_pkcs11_template.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * CKM_ECDH1_DERIVE and CKM_HKDF_DERIVE: the CK_MECHANISM, base key and
 * template logic C_DeriveKey runs around its device calls. It depends on
 * neither the device nor the object store, so it is unit-tested on its own
 * (tests/derive_params_test.c).
 *
 * The SDK fixes the shape of both. ECDH runs without a KDF and yields a
 * shared secret as long as the curve, which only derives: a CKK_GENERIC_SECRET
 * object here. HKDF runs extract and expand together from such a secret, with
 * a salt of bytes or none, into an AES key of the CBC family or an HMAC key of
 * one hash (CKK_SHA256_HMAC, CKK_SHA384_HMAC, CKK_SHA512_HMAC).
 */

/* HKDF salt and info: the device command holds at most this many bytes of
 * each (ddi/mbor/types DdiHkdfDeriveReq salt and info). */
#define HKDF_MAX_SALT_LEN 256
#define HKDF_MAX_INFO_LEN 256

/* The ECDH peer key: the device command holds a DER SubjectPublicKeyInfo of
 * at most this many bytes (ddi/mbor/types DdiEcdhKeyExchangeReq pub_key_der). */
#define ECDH_PEER_DER_MAX 192

/* The shared secrets ECDH yields, the base keys HKDF takes: as long as a
 * coordinate of P-256 and of P-521 (tsra_pkcs11_ec_coord_len). */
#define ECDH_SECRET_MIN_BYTES 32
#define ECDH_SECRET_MAX_BYTES 66

/* What tsra_pkcs11_derive_params_check takes from the mechanism. The
 * pointers are the caller's, valid for the C_DeriveKey call. */
typedef struct
{
    CK_MECHANISM_TYPE mech;     /* CKM_ECDH1_DERIVE or CKM_HKDF_DERIVE */
    CK_KEY_TYPE base_key_type;  /* CKK_EC for ECDH, CKK_GENERIC_SECRET for HKDF */
    const CK_BYTE *public_data; /* ECDH: the peer's point, raw or in DER */
    CK_ULONG public_len;
    CK_MECHANISM_TYPE prf; /* HKDF: CKM_SHA256, CKM_SHA384 or CKM_SHA512 */
    const CK_BYTE *salt;   /* HKDF: NULL for none */
    CK_ULONG salt_len;
    const CK_BYTE *info; /* HKDF: NULL for none */
    CK_ULONG info_len;
} tsra_pkcs11_derive_params;

/*
 * Validate a C_DeriveKey mechanism into *out. out->mech and
 * out->base_key_type are set for either mechanism even when its parameter is
 * refused. Returns:
 *   CKR_ARGUMENTS_BAD             NULL `mech` or `out`
 *   CKR_MECHANISM_INVALID         any mechanism but CKM_ECDH1_DERIVE and
 *                                 CKM_HKDF_DERIVE
 *   CKR_MECHANISM_PARAM_INVALID   a NULL or wrongly sized parameter block;
 *                                 for ECDH a kdf other than CKD_NULL, shared
 *                                 data, or no public data; for HKDF not both
 *                                 bExtract and bExpand, a PRF other than
 *                                 SHA-256, SHA-384 or SHA-512 (SHA-1 among
 *                                 them), a salt type other than
 *                                 CKF_HKDF_SALT_NULL (with no salt length) or
 *                                 CKF_HKDF_SALT_DATA (the salt from a key is
 *                                 refused), a salt or info over
 *                                 HKDF_MAX_SALT_LEN / HKDF_MAX_INFO_LEN, or a
 *                                 NULL salt or info with a length
 *   CKR_OK                        otherwise; the ECDH point is judged against
 *                                 the base key's curve by
 *                                 tsra_pkcs11_ecdh_peer_spki
 */
CK_RV tsra_pkcs11_derive_params_check(const CK_MECHANISM *mech, tsra_pkcs11_derive_params *out);

/*
 * The DER SubjectPublicKeyInfo the SDK takes for the ECDH peer whose public
 * data is `data` (`len` bytes), on the base key's `curve`: an uncompressed
 * point, raw or as the DER OCTET STRING CKA_EC_POINT holds, of exactly the
 * curve's length. `spki` has room for *spki_len bytes (EC_SPKI_DER_MAX is
 * always enough); on CKR_OK *spki_len is the bytes written. Returns
 * CKR_ARGUMENTS_BAD for NULL outputs or no curve, CKR_BUFFER_TOO_SMALL with
 * the length needed in *spki_len for a short `spki`, and
 * CKR_MECHANISM_PARAM_INVALID for anything else: no data, a compressed or
 * hybrid point, another length, or a DER length not in its minimal form.
 * Whether the point is on the curve is the SDK's check at the device call.
 */
CK_RV tsra_pkcs11_ecdh_peer_spki(
    tsra_pkcs11_ec_curve_t curve,
    const CK_BYTE *data,
    CK_ULONG len,
    CK_BYTE *spki,
    CK_ULONG *spki_len
);

/* What C_DeriveKey takes from the base key besides its masked blob. */
typedef struct
{
    tsra_pkcs11_ec_curve_t curve; /* ECDH: from CKA_EC_PARAMS */
    CK_BBOOL always_sensitive;    /* CKA_ALWAYS_SENSITIVE, FALSE unless TRUE */
    CK_BBOOL never_extractable;   /* CKA_NEVER_EXTRACTABLE, FALSE unless TRUE */
} tsra_pkcs11_derive_base;

/*
 * Whether the object `read` sees may be the base key of `mech`, and what *out
 * needs from it. A missing or malformed attribute permits nothing. Returns:
 *   CKR_ARGUMENTS_BAD                NULL `read` or `out`, or another mechanism
 *   CKR_KEY_TYPE_INCONSISTENT        not CKK_EC (ECDH) or CKK_GENERIC_SECRET
 *                                    (HKDF), not a private key (ECDH) or a
 *                                    secret key (HKDF), or for ECDH no
 *                                    CKA_EC_PARAMS of a supported curve
 *   CKR_KEY_FUNCTION_NOT_PERMITTED   CKA_DERIVE absent or FALSE, or a
 *                                    CKA_ALLOWED_MECHANISMS without `mech`
 *   any other failure of `read`, passed through
 *   CKR_OK                           otherwise
 */
CK_RV tsra_pkcs11_derive_base_check(
    CK_MECHANISM_TYPE mech,
    tsra_pkcs11_attr_reader read,
    void *ctx,
    tsra_pkcs11_derive_base *out
);

/*
 * What C_DeriveKey makes of its template. The appended CKA_VALUE_LEN points
 * into the struct, so it must not be copied while `tmpl` is in use.
 */
typedef struct
{
    CK_ATTRIBUTE tmpl[TEMPLATE_MAX_ATTRS + 1]; /* the caller's, plus CKA_VALUE_LEN if absent */
    CK_ULONG count;
    CK_ULONG value_len;                      /* the key's length in bytes */
    const tsra_pkcs11_keygen_policy *policy; /* the key family */
    CK_BBOOL token;                          /* CKA_TOKEN */
} tsra_pkcs11_derive_target;

/*
 * Validate a C_DeriveKey template for `mech` (with the base key's `curve` for
 * ECDH) and fill *out. CKA_CLASS and CKA_KEY_TYPE are required. ECDH makes a
 * CKK_GENERIC_SECRET whose CKA_VALUE_LEN, if given, is the curve's secret
 * length. HKDF makes a CKK_AES key by the key-generation rules
 * (tsra_pkcs11_keygen_check_template; CKA_VALUE_LEN required) in the CBC
 * family only, or an HMAC key whose CKA_VALUE_LEN, if given, is its hash
 * length. A derived key is sensitive and unextractable, and a token key
 * private. Returns, the attribute shapes in template order first:
 *   CKR_ARGUMENTS_BAD             NULL `out`, a NULL template with a count, a
 *                                 count over TEMPLATE_MAX_ATTRS, another
 *                                 mechanism, or ECDH without a curve
 *   CKR_ATTRIBUTE_VALUE_INVALID   values over TEMPLATE_MAX_VALUE_BYTES, a
 *                                 value of the wrong shape, an empty or
 *                                 over-long CKA_ALLOWED_MECHANISMS, or a
 *                                 CKA_VALUE_LEN the key cannot have
 *   CKR_ATTRIBUTE_TYPE_INVALID    an attribute array
 *   CKR_ATTRIBUTE_READ_ONLY       an attribute only the token sets
 *   CKR_TEMPLATE_INCONSISTENT     a repeated type, a class other than
 *                                 CKO_SECRET_KEY, a key type the mechanism
 *                                 does not make (CKK_GENERIC_SECRET from HKDF
 *                                 among them), key material, CKA_SENSITIVE
 *                                 FALSE, CKA_EXTRACTABLE TRUE, a token key
 *                                 with CKA_PRIVATE FALSE, an AES key of the
 *                                 GCM or XTS family, a generic secret or HMAC
 *                                 key with a usage TRUE that its device key
 *                                 lacks, or a CKA_ALLOWED_MECHANISMS naming
 *                                 a mechanism outside the key's family
 *   CKR_TEMPLATE_INCOMPLETE       no CKA_CLASS or CKA_KEY_TYPE, or an AES key
 *                                 without CKA_VALUE_LEN
 *   CKR_OK                        otherwise; unknown types are stored verbatim
 */
CK_RV tsra_pkcs11_derive_check_template(
    CK_MECHANISM_TYPE mech,
    tsra_pkcs11_ec_curve_t curve,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    tsra_pkcs11_derive_target *out
);

#ifdef __cplusplus
}
#endif
