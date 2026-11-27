// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"
#include "tsra_pkcs11_digest.h"
#include "tsra_pkcs11_ec_template.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * C_UnwrapKey with CKM_RSA_AES_KEY_WRAP into an RSA or EC private key: the
 * template rules, the key size or curve the blob's length names, and the two
 * objects the unwrap leaves, the private key and its companion public key. It
 * depends on neither the device nor the object store, so it is unit-tested
 * on its own (tests/unwrap_params_test.c); tsra_pkcs11_unwrap.c runs it
 * around the device call.
 *
 * The blob is the RSA-OAEP block under the unwrapping key, then the PKCS#8 DER
 * of the private key wrapped with RFC 5649 (fw/core/key-unwrap). The SDK needs
 * the RSA size or the EC curve before the device unwraps, and a key of one
 * size or curve has a PKCS#8 length of its own, so the blob's length names
 * it. The firmware takes an rsaEncryption key with NULL parameters and all
 * eight PKCS#1 components, a modulus of 256, 384 or 512 bytes, a public
 * exponent of at most four bytes and primes and CRT components of at most
 * half the modulus; and an EC key on P-256, P-384 or P-521 with a private
 * scalar exactly as long as the curve's order, its uncompressed public point
 * in [1] and no [0] parameters (fw/plat/std/common/pal_src/key_assurance.rs).
 *
 * The SDK verifies and encrypts only with a device key, and has no public key
 * import, so the unwrap also stores the public key, with the same masked
 * pair blob, as a generated pair has it.
 */

/* What C_UnwrapKey makes of a private-key template and the blob's length. */
typedef struct
{
    CK_KEY_TYPE key_type;         /* CKK_RSA or CKK_EC */
    CK_ULONG rsa_bits;            /* RSA: the modulus size the blob's length names */
    tsra_pkcs11_ec_curve_t curve; /* EC: the curve the blob's length names */
    CK_ATTRIBUTE_TYPE usage;      /* the one use: CKA_SIGN, CKA_DECRYPT or CKA_DERIVE */
    CK_BBOOL token;               /* CKA_TOKEN of both objects */
} tsra_pkcs11_private_target;

/*
 * The size or curve of a key of type `key_type` (CKK_RSA or CKK_EC) carried
 * in a blob of `wrapped_len` bytes: *rsa_bits (2048, 3072 or 4096) for RSA,
 * *curve for EC. An EC key's PKCS#8 has one length per curve. An RSA key's
 * varies with its components, between all of them at their shortest DER
 * encodings the firmware takes and all at their longest; the windows of the
 * three sizes would overlap only for keys with components far shorter than
 * any real key has, so each size starts above the longest of the size below.
 * CKR_WRAPPED_KEY_LEN_RANGE for a length in no window, CKR_ARGUMENTS_BAD for
 * NULL outputs or another key type.
 */
CK_RV tsra_pkcs11_private_blob_size(
    CK_KEY_TYPE key_type,
    CK_ULONG wrapped_len,
    CK_ULONG *rsa_bits,
    tsra_pkcs11_ec_curve_t *curve
);

/*
 * Validate a C_UnwrapKey template for a private key carried in a blob of
 * `wrapped_len` bytes, and fill *out (cleared first, meaningful on CKR_OK
 * only). When a template is refused as inconsistent, *why names the rule it
 * broke for the debug trace; `why` may be NULL. Returns, in this order:
 *   CKR_ARGUMENTS_BAD             NULL `out`, a NULL template with count > 0,
 *                                 or count > TEMPLATE_MAX_ATTRS
 *   CKR_ATTRIBUTE_VALUE_INVALID   values over TEMPLATE_MAX_VALUE_BYTES
 *   then per attribute, in template order, first failure wins:
 *   CKR_ATTRIBUTE_VALUE_INVALID   a value of the wrong shape
 *                                 (tsra_pkcs11_attr_check), a
 *                                 CKA_ALLOWED_MECHANISMS that is empty or
 *                                 longer than KEYGEN_MAX_ALLOWED_MECHS, or
 *                                 CKA_ALWAYS_AUTHENTICATE TRUE
 *   CKR_ATTRIBUTE_TYPE_INVALID    an attribute array (tsra_pkcs11_attr_check)
 *   CKR_TEMPLATE_INCONSISTENT     a repeated attribute type, a CKA_CLASS other
 *                                 than CKO_PRIVATE_KEY, a CKA_KEY_TYPE other
 *                                 than CKK_RSA or CKK_EC, key material or a
 *                                 public value (modulus, its size, the public
 *                                 exponent, the EC point, the public key
 *                                 info: the blob carries them),
 *                                 CKA_SENSITIVE FALSE or
 *                                 CKA_EXTRACTABLE TRUE
 *   CKR_ATTRIBUTE_READ_ONLY       an attribute only the token sets
 *                                 (tsra_pkcs11_attr_is_token_set)
 *   then over the whole template:
 *   CKR_TEMPLATE_INCOMPLETE       no CKA_CLASS or no CKA_KEY_TYPE
 *   CKR_TEMPLATE_INCONSISTENT     CKA_TOKEN TRUE with CKA_PRIVATE FALSE (the
 *                                 file store seals only private records); not
 *                                 exactly one of CKA_SIGN and CKA_DECRYPT TRUE
 *                                 for RSA, or of CKA_SIGN and CKA_DERIVE for
 *                                 EC, or any other usage TRUE (the device key
 *                                 has one use); a CKA_EC_PARAMS on an RSA key
 *   (tsra_pkcs11_ec_params_curve) a CKA_EC_PARAMS naming no supported curve:
 *                                 CKR_ATTRIBUTE_VALUE_INVALID or
 *                                 CKR_CURVE_NOT_SUPPORTED, as at EC keygen
 *   CKR_WRAPPED_KEY_LEN_RANGE     a blob length of no key of the type
 *                                 (tsra_pkcs11_private_blob_size)
 *   CKR_TEMPLATE_INCONSISTENT     a CKA_EC_PARAMS that names another curve
 *                                 than the blob's length
 *   CKR_OK                        otherwise; unknown types are accepted and
 *                                 later stored verbatim on the private key
 */
CK_RV tsra_pkcs11_unwrap_private_check(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ULONG wrapped_len,
    tsra_pkcs11_private_target *out,
    const char **why
);

/*
 * Attributes tsra_pkcs11_unwrap_private_build appends at most to the caller's
 * template for the private key: CKA_PRIVATE, CKA_SENSITIVE, CKA_EXTRACTABLE,
 * CKA_ID and the five private usages (each only if absent), the public values
 * (CKA_MODULUS and CKA_PUBLIC_EXPONENT, or CKA_EC_PARAMS if absent), and
 * CKA_LOCAL, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE and
 * CKA_KEY_GEN_MECHANISM. And the most attributes of the public key, all the
 * token's: class, key type, CKA_TOKEN, CKA_PRIVATE, CKA_ID, CKA_LABEL, the five
 * public usages, CKA_MODULUS, CKA_PUBLIC_EXPONENT and CKA_MODULUS_BITS (or
 * CKA_EC_PARAMS and CKA_EC_POINT), CKA_LOCAL and CKA_KEY_GEN_MECHANISM.
 */
#define UNWRAP_PRIV_APPENDED_ATTRS 15
#define UNWRAP_PUB_ATTRS 16

/* Storage for the values the built templates point into, besides the
 * caller's template and the public key info. */
typedef struct
{
    CK_OBJECT_CLASS pub_cls;
    CK_KEY_TYPE kt;
    CK_BBOOL btrue;
    CK_BBOOL bfalse;
    CK_BBOOL token;
    CK_MECHANISM_TYPE kgm;
    CK_ULONG bits;
    CK_BYTE id[TSRA_PKCS11_SHA1_DIGEST_LEN];
    CK_BYTE point[EC_POINT_DER_MAX];
} tsra_pkcs11_private_fill;

/*
 * Build the templates of the two objects C_UnwrapKey stores for the target
 * `t` (from tsra_pkcs11_unwrap_private_check over `tmpl`), with the public
 * values from `spki`, the DER SubjectPublicKeyInfo the device reports for the
 * unwrapped key. The private key keeps the caller's template verbatim and
 * gets what UNWRAP_PRIV_APPENDED_ATTRS lists: private, sensitive and not
 * extractable unless the template says so, FALSE for the usages besides its
 * one, the public values where PKCS#11 defines them on a private key, and,
 * since the key came from outside, CKA_LOCAL, CKA_ALWAYS_SENSITIVE and
 * CKA_NEVER_EXTRACTABLE FALSE and CKA_KEY_GEN_MECHANISM unavailable. The public
 * key is not private, takes CKA_ID, CKA_LABEL and CKA_TOKEN from the template,
 * verifies for a signing key, encrypts for a decrypting one and derives for a
 * deriving one, and carries every public value. Without a CKA_ID in the
 * template both get the SHA-1 of the modulus (RSA) or of the uncompressed EC
 * point, as NSS and OpenSC derive one. `priv_full` needs room for count +
 * UNWRAP_PRIV_APPENDED_ATTRS entries and `pub_full` for UNWRAP_PUB_ATTRS;
 * *priv_n and *pub_n receive the numbers written. The templates point into
 * `tmpl`, `spki` and `fill`, which must outlive their use. Returns
 * CKR_ARGUMENTS_BAD for NULL arguments (a NULL tmpl with a count included),
 * CKR_DEVICE_ERROR when `spki` is not a public key of `t`'s type and size or
 * curve, CKR_HOST_MEMORY when the digest cannot be set up.
 */
CK_RV tsra_pkcs11_unwrap_private_build(
    const tsra_pkcs11_private_target *t,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    const CK_BYTE *spki,
    CK_ULONG spki_len,
    tsra_pkcs11_private_fill *fill,
    CK_ATTRIBUTE *priv_full,
    CK_ULONG *priv_n,
    CK_ATTRIBUTE *pub_full,
    CK_ULONG *pub_n
);

#ifdef __cplusplus
}
#endif
