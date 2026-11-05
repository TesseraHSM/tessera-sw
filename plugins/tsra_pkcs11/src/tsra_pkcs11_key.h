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

/*
 * The TSRA key kinds this module can bind. PKCS#11 has one CKK_AES (and
 * CKK_AES_XTS), while the device has three disjoint kinds with distinct
 * handles and validators, so the kind travels with every key call. Named
 * here rather than as TSRA_KEY_KIND_* so the entry points stay compilable
 * without tsra.h; tsra_pkcs11_key.c translates it in device_kind() and
 * refuses any value outside the enum.
 */
typedef enum
{
    TSRA_PKCS11_KIND_AES = 0, /* CKM_AES_CBC, CKM_AES_CBC_PAD */
    TSRA_PKCS11_KIND_AES_GCM, /* CKM_AES_GCM */
    TSRA_PKCS11_KIND_AES_XTS, /* CKM_AES_XTS */
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
 * One-shot sign of `in` with the sign mechanism `mech` (a row of
 * tsra_pkcs11_sign_mech_find) under the device key `key_handle`. *sig_len is
 * the capacity of `sig` in and the bytes written out; the caller sizes `sig`
 * from the key, so a too-small one is CKR_BUFFER_TOO_SMALL with nothing
 * written. `in` and `sig` may overlap.
 */
CK_RV tsra_pkcs11_key_sign(
    CK_MECHANISM_TYPE mech,
    uint32_t key_handle,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *sig,
    CK_ULONG *sig_len
);

/* One-shot verify of `sig` over `in`: CKR_OK for a valid signature,
 * CKR_SIGNATURE_INVALID for one that does not verify. */
CK_RV tsra_pkcs11_key_verify(
    CK_MECHANISM_TYPE mech,
    uint32_t key_handle,
    const CK_BYTE *in,
    CK_ULONG in_len,
    const CK_BYTE *sig,
    CK_ULONG sig_len
);

/*
 * Multi-part sign (`sign`) or verify through the SDK's stream context, for a
 * mechanism that hashes the message. *out_ctx is the context: feed it with
 * tsra_pkcs11_key_sign_stream_update, finish it with
 * tsra_pkcs11_key_sign_stream_final or tsra_pkcs11_key_verify_stream_final,
 * and release it with tsra_pkcs11_key_sign_stream_free whatever happened.
 * The key handle stays the caller's and must outlive the context.
 */
CK_RV tsra_pkcs11_key_sign_stream_new(
    bool sign,
    CK_MECHANISM_TYPE mech,
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

#ifdef __cplusplus
}
#endif
