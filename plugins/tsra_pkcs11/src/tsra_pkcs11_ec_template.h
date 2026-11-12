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
 * EC key-pair template handling and the EC encodings: the CKA_EC_PARAMS
 * curve, the CKA_EC_POINT the device's public key info becomes, and the
 * ECDSA lengths. Like tsra_pkcs11_template.h it depends on neither the device
 * nor the object store, so it is unit-tested on its own
 * (tests/ec_template_test.c). Everything here speaks CK_RV only.
 */

/*
 * The curves the device generates keys on. Named here rather than as
 * TSRA_ECC_CURVE_* so the entry points stay compilable without tsra.h; the
 * values are the SDK's, checked in tsra_pkcs11_key.c.
 */
typedef enum
{
    TSRA_PKCS11_CURVE_NONE = 0,
    TSRA_PKCS11_CURVE_P256 = 1,
    TSRA_PKCS11_CURVE_P384 = 2,
    TSRA_PKCS11_CURVE_P521 = 3,
} tsra_pkcs11_ec_curve_t;

/* The EC key sizes in bits the mechanism table reports (P-256 to P-521). */
#define EC_MIN_KEY_BITS 256
#define EC_MAX_KEY_BITS 521

/* The capabilities every EC mechanism row reports: curves over a prime field,
 * named by OID in CKA_EC_PARAMS, with uncompressed points. */
#define EC_MECH_FLAGS (CKF_EC_F_P | CKF_EC_OID | CKF_EC_UNCOMPRESS)

/* The longest CKA_EC_POINT: a DER OCTET STRING (tag, two length bytes) around
 * the uncompressed P-521 point. */
#define EC_POINT_DER_MAX (3 + 1 + (2 * 66))

/*
 * The curve a CKA_EC_PARAMS value names. CKR_OK for the named-curve OID of
 * P-256, P-384 or P-521; CKR_CURVE_NOT_SUPPORTED for any other well-formed
 * DER value (another OID, explicit parameters, implicitlyCA, a curve name);
 * CKR_ATTRIBUTE_VALUE_INVALID for a NULL or empty value or one that is not a
 * single DER element. *out is TSRA_PKCS11_CURVE_NONE unless CKR_OK.
 */
CK_RV tsra_pkcs11_ec_params_curve(const void *value, CK_ULONG len, tsra_pkcs11_ec_curve_t *out);

/* The byte length of one coordinate (and of r and of s) on `curve`; 0 for
 * any other value. */
CK_ULONG tsra_pkcs11_ec_coord_len(tsra_pkcs11_ec_curve_t curve);

/*
 * Whether a CKA_EC_POINT value is a point of `curve` as this token stores
 * one: a DER OCTET STRING holding the uncompressed point, 0x04 then both
 * coordinates. CKR_OK if so, else CKR_ATTRIBUTE_VALUE_INVALID: a bare point
 * without the OCTET STRING, a compressed point, a length of another curve, or
 * bytes after the string. Whether the point lies on the curve is not checked.
 */
CK_RV tsra_pkcs11_ec_point_check(const void *value, CK_ULONG len, tsra_pkcs11_ec_curve_t curve);

/*
 * The CKA_EC_POINT value of an EC public key on `curve`, from the DER
 * SubjectPublicKeyInfo the device reports for it: the uncompressed point,
 * wrapped in a DER OCTET STRING as PKCS#11 encodes ECPoint. `out` has room for
 * *out_len bytes (EC_POINT_DER_MAX is always enough); on CKR_OK *out_len is
 * the bytes written. CKR_DEVICE_ERROR when the info is not an EC key on that
 * curve with an uncompressed point, CKR_BUFFER_TOO_SMALL with the length
 * needed in *out_len when `out` is too short, CKR_ARGUMENTS_BAD for NULL
 * arguments or no curve.
 */
CK_RV tsra_pkcs11_ec_point_from_spki(
    const CK_BYTE *spki,
    CK_ULONG spki_len,
    tsra_pkcs11_ec_curve_t curve,
    CK_BYTE *out,
    CK_ULONG *out_len
);

/* Whether CKM_ECDSA takes a hash of `len` bytes: 20, 32, 48 or 64, the
 * lengths from which the SDK infers the hash. */
bool tsra_pkcs11_ecdsa_raw_len_ok(CK_ULONG len);

/*
 * What C_GenerateKeyPair with CKM_EC_KEY_PAIR_GEN asks for. The device makes
 * a private key that either signs or derives, never both, and a public key
 * that verifies or derives to match.
 */
typedef struct
{
    tsra_pkcs11_ec_curve_t curve;
    bool sign;          /* CKA_SIGN; else CKA_DERIVE */
    CK_BBOOL pub_token; /* CKA_TOKEN of each template */
    CK_BBOOL priv_token;
    const CK_ATTRIBUTE *params; /* the public template's CKA_EC_PARAMS */
} tsra_pkcs11_ec_keygen;

/*
 * Validate the two templates of C_GenerateKeyPair for `mech` and extract what
 * the device needs into *out (cleared first, meaningful on CKR_OK only). When
 * a template is refused as inconsistent, *why names the rule it broke for
 * the debug trace (PKCS#11 carries no message); `why` may be NULL. Returns:
 *   CKR_ARGUMENTS_BAD             NULL `out`, a NULL template with count > 0,
 *                                 or count > TEMPLATE_MAX_ATTRS
 *   CKR_MECHANISM_INVALID         `mech` is not CKM_EC_KEY_PAIR_GEN
 *   then per attribute, the public template first, in template order:
 *   CKR_ATTRIBUTE_VALUE_INVALID   values over TEMPLATE_MAX_VALUE_BYTES, a
 *                                 value of the wrong shape
 *                                 (tsra_pkcs11_attr_check), or a
 *                                 CKA_ALLOWED_MECHANISMS that is empty or
 *                                 longer than KEYGEN_MAX_ALLOWED_MECHS
 *   CKR_ATTRIBUTE_TYPE_INVALID    an attribute array (tsra_pkcs11_attr_check)
 *   CKR_TEMPLATE_INCONSISTENT     a repeated attribute type, a CKA_CLASS or
 *                                 CKA_KEY_TYPE not of an EC public or private
 *                                 key, key material, CKA_EC_POINT (the token
 *                                 computes it), CKA_SENSITIVE FALSE or
 *                                 CKA_EXTRACTABLE TRUE on the private key
 *   CKR_ATTRIBUTE_READ_ONLY       an attribute only the token sets
 *                                 (tsra_pkcs11_attr_is_token_set)
 *   then over both templates:
 *   CKR_TEMPLATE_INCOMPLETE       no CKA_EC_PARAMS in the public template
 *   (tsra_pkcs11_ec_params_curve) a value naming no supported curve
 *   CKR_TEMPLATE_INCONSISTENT     a private CKA_EC_PARAMS unlike the public
 *                                 one; CKA_SIGN and CKA_DERIVE both TRUE on
 *                                 the private key, or neither; a public key
 *                                 asking for CKA_VERIFY with a deriving
 *                                 private key or CKA_DERIVE with a signing one
 *   CKR_OK                        otherwise; unknown types are accepted and
 *                                 later stored verbatim
 */
CK_RV tsra_pkcs11_ec_keygen_check(
    CK_MECHANISM_TYPE mech,
    const CK_ATTRIBUTE *pub,
    CK_ULONG pub_count,
    const CK_ATTRIBUTE *priv,
    CK_ULONG priv_count,
    tsra_pkcs11_ec_keygen *out,
    const char **why
);

/*
 * Attributes tsra_pkcs11_ec_keygen_build appends to the caller's public
 * template: CKA_CLASS, CKA_KEY_TYPE, CKA_PRIVATE, CKA_VERIFY, CKA_DERIVE
 * (each only if absent), plus CKA_EC_POINT, CKA_LOCAL and
 * CKA_KEY_GEN_MECHANISM (always); and to the private template: CKA_CLASS,
 * CKA_KEY_TYPE, CKA_EC_PARAMS, CKA_PRIVATE, CKA_SENSITIVE, CKA_EXTRACTABLE,
 * CKA_SIGN, CKA_DERIVE (each only if absent), plus CKA_LOCAL,
 * CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE and CKA_KEY_GEN_MECHANISM
 * (always). Bound the headroom the caller reserves in the output arrays.
 */
#define EC_PUB_APPENDED_ATTRS 8
#define EC_PRIV_APPENDED_ATTRS 12

/* Storage for the values of the appended attributes; the built templates
 * point into it (and into the caller's public CKA_EC_PARAMS), so it must
 * outlive their use. */
typedef struct
{
    CK_OBJECT_CLASS pub_cls;
    CK_OBJECT_CLASS priv_cls;
    CK_KEY_TYPE kt;
    CK_BBOOL btrue;
    CK_BBOOL bfalse;
    CK_MECHANISM_TYPE kgm;
    CK_BYTE point[EC_POINT_DER_MAX];
} tsra_pkcs11_ec_keygen_fill;

/*
 * Build the two templates C_GenerateKeyPair stores: each caller template
 * copied verbatim, then the attributes the token decides (see
 * EC_PUB_APPENDED_ATTRS). The public key is not private unless the caller says
 * so, the private key is, and the usage flags follow `kg`. `point` is the
 * CKA_EC_POINT value (at most EC_POINT_DER_MAX bytes). `pub_full` and
 * `priv_full` have room for each count plus the appended attributes; *pub_n
 * and *priv_n receive the numbers written. The templates are expected to have
 * passed tsra_pkcs11_ec_keygen_check, which filled `kg`. CKR_ARGUMENTS_BAD for
 * NULL arguments, a NULL template with count > 0, or a point that is empty or
 * longer than EC_POINT_DER_MAX.
 */
CK_RV tsra_pkcs11_ec_keygen_build(
    const tsra_pkcs11_ec_keygen *kg,
    const CK_ATTRIBUTE *pub,
    CK_ULONG pub_count,
    const CK_ATTRIBUTE *priv,
    CK_ULONG priv_count,
    const CK_BYTE *point,
    CK_ULONG point_len,
    tsra_pkcs11_ec_keygen_fill *fill,
    CK_ATTRIBUTE *pub_full,
    CK_ULONG *pub_n,
    CK_ATTRIBUTE *priv_full,
    CK_ULONG *priv_n
);

#ifdef __cplusplus
}
#endif
