// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"
#include "tsra_pkcs11_ec_template.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* AES-CBC block and IV length in bytes. The device CBC IV width is checked
 * against this in the TSRA_WITH_HSM build (tsra_pkcs11_key.c). */
#define AES_BLOCK_LEN 16

/*
 * AES-GCM: the device takes a fixed 12-byte IV and produces a fixed 16-byte
 * tag; no other lengths are expressible through its params struct, so the
 * entry point rejects any other CK_GCM_PARAMS shape. Both widths are checked
 * against the device struct in the TSRA_WITH_HSM build.
 */
#define AES_GCM_IV_LEN 12
#define AES_GCM_TAG_LEN 16

/* The SDK pads GCM additional data to this boundary and hands the device the
 * padded AAD followed by the data as one buffer with a 32-bit length
 * (ddi/nix align_aad_in_place), so the two together must fit 32 bits. */
#define AES_GCM_AAD_ALIGN 32

/*
 * AES-XTS: a 16-byte tweak (the little-endian sector number), and one data
 * unit per one-shot call. The device caps a data unit at 8192 bytes
 * (api/lib HsmAesXtsAlgo::MAX_DUL_SIZE), which bounds a one-shot XTS message.
 */
#define AES_XTS_TWEAK_LEN 16
#define AES_XTS_MAX_DATA_LEN 8192

/* The size of the partition's one RSA unwrapping key, the only RSA key the
 * device generates (api/lib HsmRsaKeyUnwrappingKeyGenAlgo). */
#define RSA_UNWRAP_KEY_BITS 2048

/* The RSA key sizes the device takes for an unwrapped key (api/lib
 * algo/rsa/key.rs validate_key_size). */
#define RSA_MIN_KEY_BITS 2048
#define RSA_MID_KEY_BITS 3072
#define RSA_MAX_KEY_BITS 4096

/*
 * The TSRA key kinds this module can bind. PKCS#11 has one CKK_AES (and
 * CKK_AES_XTS), while the device has three disjoint kinds with distinct
 * handles and validators, so the kind travels with every key call. Named
 * here rather than as TSRA_KEY_KIND_* so the entry points stay compilable
 * without tsra.h; tsra_pkcs11_key.c translates it (device_kind() for the AES
 * kinds, hkdf_target() for what HKDF derives) and refuses any other value.
 * The shared secret and the HMAC kinds exist only as C_DeriveKey output, and
 * the RSA kind only names the key pair CKM_RSA_PKCS_OAEP runs on, which
 * tsra_pkcs11_key_rsa_unmask binds.
 */
typedef enum
{
    TSRA_PKCS11_KIND_AES = 0,       /* CKM_AES_CBC, CKM_AES_CBC_PAD */
    TSRA_PKCS11_KIND_AES_GCM,       /* CKM_AES_GCM */
    TSRA_PKCS11_KIND_AES_XTS,       /* CKM_AES_XTS */
    TSRA_PKCS11_KIND_SHARED_SECRET, /* the ECDH secret, CKM_HKDF_DERIVE */
    TSRA_PKCS11_KIND_HMAC_SHA256,   /* CKK_SHA256_HMAC */
    TSRA_PKCS11_KIND_HMAC_SHA384,   /* CKK_SHA384_HMAC */
    TSRA_PKCS11_KIND_HMAC_SHA512,   /* CKK_SHA512_HMAC */
    TSRA_PKCS11_KIND_RSA,           /* CKM_RSA_PKCS_OAEP, an RSA key pair */
} tsra_pkcs11_key_kind_t;

/*
 * Which device masking key encrypts a generated key's masked blob, and so how
 * long the blob unmasks (tsra_pkcs11_key_scope_props makes the choice). Named
 * here rather than as TSRA_KEY_PROP_ID_SESSION for the same reason as the kind.
 */
typedef enum
{
    TSRA_PKCS11_SCOPE_PARTITION = 0, /* lasts as long as the partition's provisioning */
    TSRA_PKCS11_SCOPE_SESSION,       /* gone when the device session closes */
} tsra_pkcs11_key_scope_t;

/*
 * HSM key binding: the tsra_key_* / tsra_crypt_* half of the HSM-binding
 * layer (partition/session calls live in tsra_pkcs11_hsm.h). Like that layer it is the
 * only place these tsra_* families are called and the only place their
 * statuses become CK_RV; the no-device build provides stubs that return
 * CKR_FUNCTION_NOT_SUPPORTED so the entry points above stay link- and
 * validation-testable without a device.
 *
 * Keys never live on the device between uses: generation reads back the opaque
 * masked blob (the only durable form of an TSRA key) and frees the device
 * handle; every operation unmasks the blob into a fresh session-scoped handle
 * and releases it when the operation ends.
 */

/*
 * Generate an AES key of `kind` and `bit_len` bits in the device session
 * `hsm_session`, masked under the masking key `scope` names, and return its
 * masked blob in a malloc'd buffer the caller owns (wipe before free: it is
 * opaque but still key-derived material). The transient device handle is
 * already freed on return. The device accepts 128/192/256 bits for the plain
 * AES kind, 256 for GCM and 512 for XTS; the template layer holds that policy
 * and this call passes it through.
 *
 * The device key always carries both encrypt and decrypt usage: the SDK
 * requires the pair on AES keys (api/lib HsmAesKey::validate_props), so a
 * one-directional CKA_ENCRYPT/CKA_DECRYPT policy is enforced host-side by the
 * operation-init gate, like the rest of the PKCS#11 object model.
 */
CK_RV tsra_pkcs11_key_aes_generate(
    uint32_t hsm_session,
    tsra_pkcs11_key_kind_t kind,
    uint32_t bit_len,
    tsra_pkcs11_key_scope_t scope,
    CK_BYTE **out_blob,
    CK_ULONG *out_blob_len
);

/*
 * Unmask a stored AES masked blob of `kind` into a live device key handle in
 * `hsm_session`. The handle is session-scoped: release it with
 * tsra_pkcs11_key_release when the operation ends (it also dies with the session).
 * A blob unmasked under the wrong kind is refused by the device, which is the
 * fail-closed backstop behind the host-side mechanism/key-type gates.
 */
CK_RV tsra_pkcs11_key_aes_unmask(
    uint32_t hsm_session,
    tsra_pkcs11_key_kind_t kind,
    const CK_BYTE *blob,
    CK_ULONG blob_len,
    uint32_t *out_key
);

/* Free a device key handle obtained from generate/unmask (no-op if 0). */
void tsra_pkcs11_key_release(uint32_t key_handle);

/*
 * Fetch the partition's RSA unwrapping key in the device session
 * `hsm_session`. The device has exactly one, of 2048 bits, and returns the
 * same key on every call, so this creates nothing on the device. On success
 * *out_spki is a malloc'd copy of its public key as DER SubjectPublicKeyInfo
 * (the caller frees it), and, when `out_priv` is non-NULL, *out_priv a handle
 * to the private key for tsra_pkcs11_key_aes_unwrap, to be released with
 * tsra_pkcs11_key_release. That release frees the handle only: the SDK never
 * deletes the device's internal key. While the device is still staging the key
 * after a reset the SDK retries with a bounded backoff, and a call that still
 * finds it pending returns CKR_FUNCTION_FAILED.
 */
CK_RV tsra_pkcs11_key_unwrapping_pair(
    uint32_t hsm_session,
    uint32_t *out_priv,
    CK_BYTE **out_spki,
    CK_ULONG *out_spki_len
);

/*
 * Unwrap a CKM_RSA_AES_KEY_WRAP blob with the unwrapping key `unwrapping_key`
 * into a new AES key of `kind` and `bit_len` bits, masked under the masking
 * key `scope` names, and return its masked blob as tsra_pkcs11_key_aes_generate
 * does. `oaep_hash` (CKM_SHA256, CKM_SHA384 or CKM_SHA512) is the OAEP and
 * MGF1 hash and `aes_key_bits` the size of the AES key-encryption key, both as
 * tsra_pkcs11_unwrap_params_check accepted them. Every failure of the unwrap
 * itself returns CKR_WRAPPED_KEY_INVALID: a caller who can tell an OAEP
 * failure from a key-wrap failure holds a decryption oracle.
 */
CK_RV tsra_pkcs11_key_aes_unwrap(
    uint32_t unwrapping_key,
    CK_MECHANISM_TYPE oaep_hash,
    CK_ULONG aes_key_bits,
    tsra_pkcs11_key_kind_t kind,
    uint32_t bit_len,
    tsra_pkcs11_key_scope_t scope,
    const CK_BYTE *wrapped,
    CK_ULONG wrapped_len,
    CK_BYTE **out_blob,
    CK_ULONG *out_blob_len
);

/*
 * One-shot AES-CBC encrypt/decrypt with the 16-byte IV `iv`. Two-call sizing:
 * with out == NULL, *out_len receives the required length and the call returns
 * CKR_OK; a too-small *out_len gets the required length with
 * CKR_BUFFER_TOO_SMALL; on success *out_len is the bytes written. Every call
 * is self-contained (the IV seed is re-applied), so probing and retrying with
 * the same inputs is safe.
 */
CK_RV tsra_pkcs11_key_aes_cbc(
    bool encrypt,
    bool pad,
    uint32_t key_handle,
    const CK_BYTE *iv,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *out,
    CK_ULONG *out_len
);

/*
 * One-shot AES-GCM encrypt/decrypt with the 12-byte `iv` and optional AAD.
 * Unlike CBC the output length is deterministic, so there is no sizing pass:
 * `out` must be non-NULL with *out_len holding its capacity, and on success
 * *out_len is the bytes written (the ciphertext or plaintext only — the tag is
 * carried separately, because the device keeps it in its params struct while
 * PKCS#11 appends it to the ciphertext; the entry point does that splice).
 * `tag` is AES_GCM_TAG_LEN bytes: written on encrypt, read on decrypt.
 */
CK_RV tsra_pkcs11_key_aes_gcm(
    bool encrypt,
    uint32_t key_handle,
    const CK_BYTE *iv,
    const CK_BYTE *aad,
    CK_ULONG aad_len,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *tag,
    CK_BYTE *out,
    CK_ULONG *out_len
);

/*
 * One-shot AES-XTS encrypt/decrypt of a single data unit with the 16-byte
 * little-endian `tweak`. `in_len` is the data-unit length and must be a
 * non-zero multiple of AES_BLOCK_LEN not above AES_XTS_MAX_DATA_LEN (the
 * entry point enforces that as a *_LEN_RANGE first), and the tweak must not be
 * all 0xFF, which the SDK cannot advance past the data unit (the entry point
 * refuses that at init). Sizing works as for GCM: `out` is non-NULL, *out_len
 * its capacity in and the bytes written out.
 */
CK_RV tsra_pkcs11_key_aes_xts(
    bool encrypt,
    uint32_t key_handle,
    const CK_BYTE *tweak,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *out,
    CK_ULONG *out_len
);

/*
 * AES-CBC / AES-CBC-PAD streaming through the SDK's stream context
 * (tsra_crypt_*_init / _update / _finish), behind the multi-part
 * C_EncryptUpdate family. The type is opaque because the SDK keeps a pointer
 * to the params struct it was opened with and writes the chained IV back into
 * it on every call: the stream owns that struct together with the context
 * handle, so the two live and die together.
 *
 * The SDK stream holds back the last full block even without padding (only a
 * padded decrypt needs that, to strip the padding at the end), so an update's
 * output trails its input by up to one block and the final call releases it.
 */
typedef struct tsra_pkcs11_aes_cbc_stream tsra_pkcs11_aes_cbc_stream_t;

/*
 * The most a stream's final call writes: the held-back block plus, on a padded
 * encrypt, a whole padding block. A padded decrypt also asks for this much
 * room although it returns less than one block after unpadding.
 */
#define AES_CBC_STREAM_FINAL_MAX (2 * AES_BLOCK_LEN)

/* The longest part one update takes: its output (up to the held-back block
 * plus the part) must still fit the device's 32-bit buffer length. */
#define AES_CBC_STREAM_MAX_PART ((CK_ULONG)UINT32_MAX - AES_BLOCK_LEN)

/*
 * Open a CBC stream over the unmasked device key `key_handle`, seeded with the
 * 16-byte `iv`; `pad` selects CKM_AES_CBC_PAD. On success *out is the stream,
 * to be released with tsra_pkcs11_key_aes_cbc_stream_free (the key handle
 * stays the caller's and must outlive the stream).
 */
CK_RV tsra_pkcs11_key_aes_cbc_stream_new(
    bool encrypt,
    bool pad,
    uint32_t key_handle,
    const CK_BYTE *iv,
    tsra_pkcs11_aes_cbc_stream_t **out
);

/*
 * Feed `in` (at most AES_CBC_STREAM_MAX_PART bytes) and receive the blocks the
 * SDK releases. `out` must be non-NULL: a PKCS#11 sizing probe is answered above
 * this layer, because the SDK's sizing call runs the update whenever no output
 * is due. *out_len is the capacity in and the bytes written out; a too-small
 * one gets the required length with CKR_BUFFER_TOO_SMALL and leaves the
 * stream untouched, since the SDK sizes before it consumes.
 */
CK_RV tsra_pkcs11_key_aes_cbc_stream_update(
    tsra_pkcs11_aes_cbc_stream_t *stream,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *out,
    CK_ULONG *out_len
);

/*
 * Finish the stream into `out`, whose capacity *out_len must be at least
 * AES_CBC_STREAM_FINAL_MAX; *out_len receives the bytes written. The SDK
 * refuses an unpadded finish over no data or a partial block, so the entry
 * point settles those lengths itself before calling this. After any outcome
 * the stream can only be freed.
 */
CK_RV tsra_pkcs11_key_aes_cbc_stream_final(
    tsra_pkcs11_aes_cbc_stream_t *stream,
    CK_BYTE *out,
    CK_ULONG *out_len
);

/* Free a stream: the SDK context first, then the params it points at. NULL-safe. */
void tsra_pkcs11_key_aes_cbc_stream_free(tsra_pkcs11_aes_cbc_stream_t *stream);

/*
 * Generate an EC key pair on `curve` in the device session `hsm_session`,
 * masked under the masking key `scope` names. The private key signs when
 * `sign` is set and derives otherwise, and the public key verifies or derives
 * to match: the SDK takes no other combination. Returns the pair's masked
 * blob (one blob unmasks both halves; wipe it before free, as for AES) and the
 * public key's DER SubjectPublicKeyInfo, each in a malloc'd buffer the caller
 * owns. The transient device handles are already freed on return.
 */
CK_RV tsra_pkcs11_key_ec_generate(
    uint32_t hsm_session,
    tsra_pkcs11_ec_curve_t curve,
    bool sign,
    tsra_pkcs11_key_scope_t scope,
    CK_BYTE **out_blob,
    CK_ULONG *out_blob_len,
    CK_BYTE **out_spki,
    CK_ULONG *out_spki_len
);

/*
 * Unmask a stored EC key pair blob into live device handles for both halves
 * in `hsm_session`, and report the pair's curve as the device states it.
 * Release both handles with tsra_pkcs11_key_release when the operation ends;
 * on failure there are none.
 */
CK_RV tsra_pkcs11_key_ec_unmask(
    uint32_t hsm_session,
    const CK_BYTE *blob,
    CK_ULONG blob_len,
    uint32_t *out_priv,
    uint32_t *out_pub,
    tsra_pkcs11_ec_curve_t *out_curve
);

/*
 * Unwrap a CKM_RSA_AES_KEY_WRAP blob of a PKCS#8 private key with the
 * unwrapping key `unwrapping_key` into a key pair, masked under the masking
 * key `scope` names; `oaep_hash` and `aes_key_bits` as for
 * tsra_pkcs11_key_aes_unwrap. `key_type` is CKK_RSA, with the modulus size in
 * `rsa_bits` (the private key is the CRT kind), or CKK_EC, with `curve`.
 * `usage` is the private key's one use, CKA_SIGN, CKA_DECRYPT (RSA only) or
 * CKA_DERIVE (EC only), and the public key gets its counterpart; the SDK
 * takes no other combination. Returns the pair's masked blob, which unmasks
 * both halves (wipe it before free), and the public key's DER
 * SubjectPublicKeyInfo, each in a malloc'd buffer the caller owns; the device
 * handles are freed on return. Every failure of the unwrap itself returns
 * CKR_WRAPPED_KEY_INVALID, for the reason tsra_pkcs11_key_aes_unwrap gives.
 */
CK_RV tsra_pkcs11_key_pair_unwrap(
    uint32_t unwrapping_key,
    CK_MECHANISM_TYPE oaep_hash,
    CK_ULONG aes_key_bits,
    CK_KEY_TYPE key_type,
    CK_ULONG rsa_bits,
    tsra_pkcs11_ec_curve_t curve,
    CK_ATTRIBUTE_TYPE usage,
    tsra_pkcs11_key_scope_t scope,
    const CK_BYTE *wrapped,
    CK_ULONG wrapped_len,
    CK_BYTE **out_blob,
    CK_ULONG *out_blob_len,
    CK_BYTE **out_spki,
    CK_ULONG *out_spki_len
);

/*
 * Unmask a stored RSA key pair blob into live device handles for both halves
 * in `hsm_session`, and report the modulus size in bits as the device states
 * it (2048, 3072 or 4096). Release both handles with tsra_pkcs11_key_release
 * when the operation ends; on failure there are none.
 */
CK_RV tsra_pkcs11_key_rsa_unmask(
    uint32_t hsm_session,
    const CK_BYTE *blob,
    CK_ULONG blob_len,
    uint32_t *out_priv,
    uint32_t *out_pub,
    CK_ULONG *out_bits
);

/*
 * One-shot CKM_RSA_PKCS_OAEP under the device key `key_handle`: the public
 * key encrypts (`encrypt`), the private key decrypts. `hash` (CKM_SHA256,
 * CKM_SHA384 or CKM_SHA512) is the OAEP and the MGF1 hash, and `label`
 * (`label_len` bytes, none when 0) the OAEP label, as
 * tsra_pkcs11_oaep_params_check accepted them. *out_len is the capacity of
 * `out` in, at least the modulus length, and the bytes written out. The SDK
 * decrypts the raw RSA block into `out` before it removes the padding, so a
 * decrypt must be handed a buffer of the caller's own. Every failure of a
 * decrypt returns CKR_ENCRYPTED_DATA_INVALID: one answer for every bad
 * ciphertext, label or padding, so the result is no padding oracle.
 */
CK_RV tsra_pkcs11_key_rsa_oaep(
    bool encrypt,
    uint32_t key_handle,
    CK_MECHANISM_TYPE hash,
    const CK_BYTE *label,
    CK_ULONG label_len,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *out,
    CK_ULONG *out_len
);

/*
 * One-shot sign of `in` with the sign mechanism `mech` (a row of
 * tsra_pkcs11_sign_mech_find) under the device key `key_handle`. `pss` is the
 * CK_RSA_PKCS_PSS_PARAMS of a PSS mechanism as tsra_pkcs11_sign_params_check
 * and tsra_pkcs11_pss_salt_ok accepted them, NULL for every other mechanism.
 * *sig_len is the capacity of `sig` in and the bytes written out; the caller
 * sizes `sig` from the key, so a too-small one is CKR_BUFFER_TOO_SMALL with
 * nothing written. `in` and `sig` may overlap.
 */
CK_RV tsra_pkcs11_key_sign(
    CK_MECHANISM_TYPE mech,
    const CK_RSA_PKCS_PSS_PARAMS *pss,
    uint32_t key_handle,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *sig,
    CK_ULONG *sig_len
);

/* One-shot verify of `sig` over `in`, `pss` as for tsra_pkcs11_key_sign:
 * CKR_OK for a valid signature, CKR_SIGNATURE_INVALID for one that does not
 * verify. */
CK_RV tsra_pkcs11_key_verify(
    CK_MECHANISM_TYPE mech,
    const CK_RSA_PKCS_PSS_PARAMS *pss,
    uint32_t key_handle,
    const CK_BYTE *in,
    CK_ULONG in_len,
    const CK_BYTE *sig,
    CK_ULONG sig_len
);

/*
 * Multi-part sign (`sign`) or verify through the SDK's stream context, for a
 * mechanism that hashes the message (`pss` as for tsra_pkcs11_key_sign; the
 * SDK keeps no pointer to it). *out_ctx is the context: feed it with
 * tsra_pkcs11_key_sign_stream_update, finish it with
 * tsra_pkcs11_key_sign_stream_final or tsra_pkcs11_key_verify_stream_final,
 * and release it with tsra_pkcs11_key_sign_stream_free whatever happened.
 * The key handle stays the caller's and must outlive the context.
 */
CK_RV tsra_pkcs11_key_sign_stream_new(
    bool sign,
    CK_MECHANISM_TYPE mech,
    const CK_RSA_PKCS_PSS_PARAMS *pss,
    uint32_t key_handle,
    uint32_t *out_ctx
);

/* Feed `in` (at most 32 bits long) to a stream of the direction `sign`. */
CK_RV tsra_pkcs11_key_sign_stream_update(
    bool sign,
    uint32_t ctx,
    const CK_BYTE *in,
    CK_ULONG in_len
);

/* Finish a sign stream into `sig`; *sig_len as for tsra_pkcs11_key_sign. */
CK_RV tsra_pkcs11_key_sign_stream_final(uint32_t ctx, CK_BYTE *sig, CK_ULONG *sig_len);

/* Finish a verify stream against `sig`; results as for tsra_pkcs11_key_verify. */
CK_RV tsra_pkcs11_key_verify_stream_final(uint32_t ctx, const CK_BYTE *sig, CK_ULONG sig_len);

/* Free a sign or verify stream context (no-op if 0). */
void tsra_pkcs11_key_sign_stream_free(uint32_t ctx);

/*
 * CKM_ECDH1_DERIVE with CKD_NULL: unmask the EC key pair blob `blob` in
 * `hsm_session`, check that the device puts it on `curve` (the curve the
 * object names), and agree with the peer whose DER SubjectPublicKeyInfo is
 * `peer` on that curve. Returns the masked blob of the shared secret (a
 * shared-secret key that only derives, as long as the curve: 256, 384 or 521
 * bits), masked under the masking key `scope` names, as
 * tsra_pkcs11_key_aes_generate returns its blob. Device handles are released
 * on every path. CKR_MECHANISM_PARAM_INVALID when the SDK refuses the peer
 * key (a point not on the curve), CKR_KEY_HANDLE_INVALID when the pair is not
 * on `curve`.
 */
CK_RV tsra_pkcs11_key_ecdh(
    uint32_t hsm_session,
    const CK_BYTE *blob,
    CK_ULONG blob_len,
    tsra_pkcs11_ec_curve_t curve,
    const CK_BYTE *peer,
    CK_ULONG peer_len,
    tsra_pkcs11_key_scope_t scope,
    CK_BYTE **out_blob,
    CK_ULONG *out_blob_len
);

/*
 * CKM_HKDF_DERIVE, extract and expand: unmask the shared secret blob `secret`
 * in `hsm_session` and derive from it, with HMAC over `prf` (CKM_SHA256,
 * CKM_SHA384 or CKM_SHA512), the optional `salt` and `info`, a key of `kind`
 * (TSRA_PKCS11_KIND_AES or an HMAC kind) and `bit_len` bits, masked under the
 * masking key `scope` names. Returns its masked blob as
 * tsra_pkcs11_key_aes_generate does. An empty salt or info is passed as none,
 * which HKDF treats alike (RFC 5869). The caller bounds both lengths
 * (HKDF_MAX_SALT_LEN, HKDF_MAX_INFO_LEN). Device handles are released on
 * every path.
 */
CK_RV tsra_pkcs11_key_hkdf(
    uint32_t hsm_session,
    const CK_BYTE *secret,
    CK_ULONG secret_len,
    CK_MECHANISM_TYPE prf,
    const CK_BYTE *salt,
    CK_ULONG salt_len,
    const CK_BYTE *info,
    CK_ULONG info_len,
    tsra_pkcs11_key_kind_t kind,
    uint32_t bit_len,
    tsra_pkcs11_key_scope_t scope,
    CK_BYTE **out_blob,
    CK_ULONG *out_blob_len
);

#ifdef __cplusplus
}
#endif
