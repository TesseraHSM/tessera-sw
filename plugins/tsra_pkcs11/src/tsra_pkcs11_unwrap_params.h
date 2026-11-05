// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_attr_policy.h"
#include "tsra_pkcs11_compat.h"
#include "tsra_pkcs11_digest.h"
#include "tsra_pkcs11_template.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * CKM_RSA_AES_KEY_WRAP and the partition's RSA unwrapping key pair: the
 * CK_MECHANISM, CK_ATTRIBUTE and DER logic C_UnwrapKey and C_GenerateKeyPair
 * run around their device calls. It depends on neither the device nor the
 * object store, so it is unit-tested on its own (tests/unwrap_params_test.c).
 *
 * A CKM_RSA_AES_KEY_WRAP blob is the RSA-OAEP encryption of a fresh AES key
 * under the unwrapping key, as long as its modulus, followed by the target key
 * wrapped under that AES key with RFC 5649 (AES key wrap with padding).
 *
 * An AES-XTS key is the exception. The device holds its two halves as two
 * keys, and on the module's device session (V1) the SDK unwraps them from a
 * container of its own (api/lib HsmAesXtsKeyPairBlob): a 16-byte header (the
 * magic "TSRA-XTS", version 1, both blob lengths, all little-endian), then
 * one such blob per 32-byte half. A single blob of the 64-byte key does not
 * unwrap.
 */

/* The OAEP block that starts every blob: one modulus of the unwrapping key. */
#define RSA_UNWRAP_MODULUS_BYTES (RSA_UNWRAP_KEY_BITS / 8)

/* What RFC 5649 adds to a key whose length is a multiple of 8 bytes, as every
 * AES key is: one integrity check block. */
#define AES_KWP_OVERHEAD 8

/* The header of the SDK's AES-XTS container. */
#define AES_XTS_BLOB_HEADER 16

/* What tsra_pkcs11_unwrap_params_check takes from CK_RSA_AES_KEY_WRAP_PARAMS. */
typedef struct
{
    CK_MECHANISM_TYPE hash; /* CKM_SHA256 / 384 / 512: the OAEP and the MGF1 hash */
    CK_ULONG aes_key_bits;  /* the AES key-encryption key: 128, 192 or 256 */
} tsra_pkcs11_rsa_aes_params;

/*
 * Validate a C_UnwrapKey mechanism into *out. Returns:
 *   CKR_ARGUMENTS_BAD             NULL `mech` or `out`
 *   CKR_MECHANISM_INVALID         any mechanism but CKM_RSA_AES_KEY_WRAP
 *   CKR_MECHANISM_PARAM_INVALID   a NULL or wrongly sized
 *                                 CK_RSA_AES_KEY_WRAP_PARAMS, ulAESKeyBits
 *                                 other than 128, 192 or 256, a NULL
 *                                 pOAEPParams, an OAEP hash other than SHA-256,
 *                                 SHA-384 or SHA-512, an MGF other than MGF1
 *                                 with that same hash (the SDK takes no other
 *                                 pairing), a source other than
 *                                 CKZ_DATA_SPECIFIED, or a label: the SDK does
 *                                 not pass one to the device on unwrap, so a
 *                                 labelled blob could never unwrap
 *   CKR_OK                        otherwise
 */
CK_RV tsra_pkcs11_unwrap_params_check(const CK_MECHANISM *mech, tsra_pkcs11_rsa_aes_params *out);

/*
 * What C_UnwrapKey makes of its template and the wrapped key's length. The
 * appended CKA_VALUE_LEN points into the struct, so it must not be copied
 * while `tmpl` is in use.
 */
typedef struct
{
    CK_ATTRIBUTE tmpl[TEMPLATE_MAX_ATTRS + 1]; /* the caller's, plus CKA_VALUE_LEN if absent */
    CK_ULONG count;
    CK_ULONG value_len;                      /* the key's length in bytes */
    const tsra_pkcs11_keygen_policy *policy; /* the key family */
    CK_BBOOL token;                          /* CKA_TOKEN */
} tsra_pkcs11_unwrap_target;

/*
 * Validate a C_UnwrapKey template for an AES, AES-GCM or AES-XTS key carried in
 * a blob of `wrapped_len` bytes, and fill *out. The template follows the
 * key-generation rules (tsra_pkcs11_keygen_check_template): CKA_KEY_TYPE
 * CKK_AES_XTS picks the XTS family, CKK_AES the plain one or, with
 * CKA_ALLOWED_MECHANISMS = { CKM_AES_GCM }, the GCM one, and an unwrapped key
 * is sensitive and unextractable like a generated one. Unlike generation,
 * CKA_VALUE_LEN may be left out: the blob's length gives it. Returns, in this
 * order:
 *   CKR_ARGUMENTS_BAD, then the codes of tsra_pkcs11_keygen_check_template
 *                                 for the family's generation mechanism
 *   CKR_TEMPLATE_INCOMPLETE       no CKA_CLASS or no CKA_KEY_TYPE
 *   CKR_WRAPPED_KEY_LEN_RANGE     a blob whose length is not that of a key of
 *                                 the template's CKA_VALUE_LEN or, without
 *                                 one, of a length the family has (for XTS,
 *                                 the SDK's container of two halves)
 *   CKR_OK                        otherwise
 */
CK_RV tsra_pkcs11_unwrap_check_template(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ULONG wrapped_len,
    tsra_pkcs11_unwrap_target *out
);

/*
 * Whether the object `read` sees may unwrap with CKM_RSA_AES_KEY_WRAP. Returns:
 *   CKR_ARGUMENTS_BAD                      NULL `read`
 *   CKR_UNWRAPPING_KEY_HANDLE_INVALID      `read` finds no such object
 *   CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT   not an RSA private key
 *   CKR_KEY_FUNCTION_NOT_PERMITTED         CKA_UNWRAP absent or FALSE
 *   any other failure of `read`, passed through
 *   CKR_OK                                 otherwise
 * A stored value of the wrong width counts as absent.
 */
CK_RV tsra_pkcs11_unwrapping_key_check(tsra_pkcs11_attr_reader read, void *ctx);

/*
 * Validate a C_GenerateKeyPair request for the partition's RSA unwrapping key
 * pair, the only RSA key the device has. It is one fixed key, so only a
 * request for exactly that key is accepted: the public template needs
 * CKA_MODULUS_BITS 2048 and CKA_WRAP TRUE, the private one CKA_UNWRAP TRUE, and
 * every other usage attribute must be absent or FALSE. *pub_token and
 * *priv_token receive each half's CKA_TOKEN. Returns:
 *   CKR_ARGUMENTS_BAD             NULL outputs, a NULL template with a count,
 *                                 or a count over TEMPLATE_MAX_ATTRS
 *   CKR_MECHANISM_INVALID         any mechanism but CKM_RSA_PKCS_KEY_PAIR_GEN
 *   then for the public, then the private template, first failure wins:
 *   CKR_ATTRIBUTE_VALUE_INVALID   values over TEMPLATE_MAX_VALUE_BYTES, or a
 *                                 value of the wrong shape
 *   CKR_ATTRIBUTE_TYPE_INVALID    an attribute array
 *   CKR_ATTRIBUTE_READ_ONLY       an attribute only the token sets
 *   CKR_TEMPLATE_INCONSISTENT     anything else that does not ask for that
 *                                 key: a repeated type, the wrong class, a key
 *                                 type other than CKK_RSA, a modulus, another
 *                                 size, a public exponent in the private
 *                                 template, another usage, a non-sensitive or
 *                                 extractable private key, a
 *                                 CKA_ALLOWED_MECHANISMS naming anything but
 *                                 CKM_RSA_AES_KEY_WRAP, key material, or no
 *                                 CKA_WRAP / CKA_UNWRAP TRUE
 *   CKR_TEMPLATE_INCOMPLETE       no CKA_MODULUS_BITS
 *   CKR_OK                        otherwise
 * A CKA_PUBLIC_EXPONENT in the public template is checked against the key once
 * it is known (tsra_pkcs11_unwrapping_half_build).
 */
CK_RV tsra_pkcs11_unwrapping_pair_check(
    CK_MECHANISM_TYPE mech,
    const CK_ATTRIBUTE *pub,
    CK_ULONG npub,
    const CK_ATTRIBUTE *priv,
    CK_ULONG npriv,
    CK_BBOOL *pub_token,
    CK_BBOOL *priv_token
);

/* An RSA public key as CKA_MODULUS and CKA_PUBLIC_EXPONENT carry it: big-endian
 * without leading zero bytes. Both point into the DER they were read from. */
typedef struct
{
    const CK_BYTE *n;
    CK_ULONG n_len;
    const CK_BYTE *e;
    CK_ULONG e_len;
} tsra_pkcs11_rsa_public;

/*
 * Read the modulus and public exponent out of a DER SubjectPublicKeyInfo of an
 * rsaEncryption key (RFC 3279). false for anything else: another algorithm, a
 * truncated or over-long element, bytes after the structure, or a negative or
 * zero integer.
 */
bool tsra_pkcs11_spki_rsa(const CK_BYTE *der, CK_ULONG len, tsra_pkcs11_rsa_public *out);

/*
 * Attributes tsra_pkcs11_unwrapping_half_build appends at most: class, key
 * type, CKA_PRIVATE, CKA_ID, modulus, public exponent, four usage defaults,
 * CKA_ALLOWED_MECHANISMS, CKA_LOCAL and CKA_KEY_GEN_MECHANISM, and for the
 * private half the sensitivity quartet.
 */
#define UNWRAPPING_PAIR_APPENDED_ATTRS 17

/* Storage for the appended values; the built template points into it. */
typedef struct
{
    CK_OBJECT_CLASS cls;
    CK_KEY_TYPE kt;
    CK_BBOOL btrue;
    CK_BBOOL bfalse;
    CK_MECHANISM_TYPE kgm;
    CK_MECHANISM_TYPE mech;
    CK_BYTE id[TSRA_PKCS11_SHA1_DIGEST_LEN];
} tsra_pkcs11_pair_fill;

/*
 * Build the template C_GenerateKeyPair stores for the private (`priv`) or the
 * public half of the unwrapping key `key`: the caller's checked template
 * verbatim, then what the token decides, each only where the caller left it
 * out unless noted: class and CKK_RSA; CKA_PRIVATE (TRUE for the private half,
 * FALSE for the public one); CKA_ID, the SHA-1 of the modulus as NSS and
 * OpenSC derive it, so every pair for the one key carries the same ID; the
 * modulus (always); the public exponent (always on the private half); FALSE for
 * the half's other usages; CKA_ALLOWED_MECHANISMS = { CKM_RSA_AES_KEY_WRAP };
 * CKA_LOCAL TRUE and CKA_KEY_GEN_MECHANISM (always); and for the private half
 * sensitive and unextractable, always so. `full` needs room for count +
 * UNWRAPPING_PAIR_APPENDED_ATTRS entries; *n receives the number written.
 * Returns CKR_ARGUMENTS_BAD for NULL arguments (a NULL tmpl with a count
 * included), CKR_TEMPLATE_INCONSISTENT for a public template whose
 * CKA_PUBLIC_EXPONENT is not the key's, CKR_HOST_MEMORY when the digest cannot
 * be set up.
 */
CK_RV tsra_pkcs11_unwrapping_half_build(
    bool priv,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    const tsra_pkcs11_rsa_public *key,
    tsra_pkcs11_pair_fill *fill,
    CK_ATTRIBUTE *full,
    CK_ULONG *n
);

#ifdef __cplusplus
}
#endif
