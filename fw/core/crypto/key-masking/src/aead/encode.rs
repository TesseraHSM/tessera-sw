// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Masking pipeline ([`mask`]): wrap a target key under a 32-byte
//! AES-256 masking key into a self-contained AEAD blob.
//!
//! Follows the firmware **query-size-then-fill** convention: pass
//! `out = None` to learn the required blob length without performing
//! any crypto work, then call again with `Some(&mut buf)` of at least
//! that length to actually mask.
//!
//! The PAL generates the nonce and masks directly in the final envelope.
//! Shared code does not allocate IV, AAD or payload staging buffers.

use tsra_fw_core_crypto_aead_envelope::write_header;
use tsra_fw_core_crypto_aead_envelope::AeadAlg;
use tsra_fw_core_crypto_aead_envelope::HEADER_LEN;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyMasking;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use zerocopy::IntoBytes;

use crate::aead::format::blob_len;
use crate::aead::format::MaskedKeyMetadata;
use crate::aead::format::KEY_LABEL_MAX;
use crate::aead::format::META_LEN;

/// Caller-supplied parameters for a v2 masked-key blob.
///
/// Carries only the fields the caller owns; magic, version, padding,
/// and the reserved tail of [`MaskedKeyMetadata`] are produced by
/// [`mask`] and cannot be set by callers.
///
/// `key_kind` and `usage_flags` pass through unchanged to / from the
/// vault types — masked-key blobs are firmware-internal, so we carry
/// the same primitives the vault speaks
/// ([`vault_key_kind`](tsra_fw_hsm_pal_traits::HsmVault::vault_key_kind),
/// [`vault_key_attrs`](tsra_fw_hsm_pal_traits::HsmVault::vault_key_attrs)).
pub struct MaskParams<'a> {
    /// Vault kind tag for the masked key.
    pub key_kind: HsmVaultKeyKind,

    /// PKCS#11-style permission bitfield, identical to what the
    /// vault stores alongside live keys.
    pub key_attrs: HsmVaultKeyAttrs,

    /// Partition SVN at mask time (from `part_mfgr_svn`). Bound by the
    /// AEAD tag so blobs cannot be replayed across SVN bumps.
    pub svn: u64,

    /// Owner-seed (BKS2) lineage identifier (from `part_owner_svn`).
    /// Bound by the AEAD tag so blobs cannot be replayed across
    /// owner-seed rotations.
    pub owner_seed_id: u16,

    /// Opaque caller-supplied label (e.g. `b"BK3"`, `b"MK"`). Length
    /// MUST be ≤ [`KEY_LABEL_MAX`].
    pub key_label: &'a HsmDmaBuf,
}

/// Mask `target_key` under `key` into a self-contained masked-key
/// AEAD blob.
///
/// The blob is an [`aead_envelope`](tsra_fw_core_crypto_aead_envelope)
/// envelope (algorithm chosen by `alg`) whose AAD is exactly one
/// fixed [`MaskedKeyMetadata`] record built from `params`. The
/// envelope binds every metadata byte (magic, version, `key_kind`,
/// `key_label_len`, `usage_flags`, `key_label`, padding count, reserved tail) to
/// the ciphertext via the AEAD tag.
///
/// # Parameters
///
/// * `crypto`     — PAL providing [`HsmKeyMasking`].
/// * `io`         — caller's I/O context.
/// * `_alloc`     — retained for caller compatibility; no scratch is allocated.
/// * `alg`        — AEAD algorithm for this blob (e.g.
///   [`AeadAlg::AesGcm256Iv16`]). Determines the required `key` length
///   via [`AeadAlg::key_len`].
/// * `key`        — AEAD masking key; length MUST equal
///   `alg.key_len()`. Ignored when `out == None`.
/// * `params`     — caller-supplied vault fields and label.
/// * `target_key` — raw key bytes to mask.
/// * `out`        — destination buffer of at least the required
///   blob length (which the caller discovers by invoking this
///   function with `out = None`), or `None` to perform that size
///   query without any crypto work.
///
/// # Returns
///
/// * `Ok(n)`  — the blob length in bytes. When `out == Some`, exactly
///   `n` bytes have been written to `&out[..n]`; trailing bytes are
///   untouched.
/// * `Err(HsmError::InvalidArg)` — `key.len() != alg.key_len()`,
///   `params.key_label.len() > KEY_LABEL_MAX`, or `out` is too small.
/// * Any [`HsmError`] surfaced by the masking PAL or header encoder.
///
/// On failure, callers must not publish the partial envelope.
/// IO teardown scrubs its backing storage.
pub async fn mask<P: HsmKeyMasking>(
    crypto: &P,
    io: &P::Io,
    _alloc: &impl HsmScopedAlloc,
    alg: AeadAlg,
    key: &HsmDmaBuf,
    params: &MaskParams<'_>,
    target_key: &HsmDmaBuf,
    out: Option<&mut HsmDmaBuf>,
) -> HsmResult<usize> {
    let (total, pad) = mask_len(crypto, alg, target_key.len())?;

    // Size-query short-circuit — no crypto, no IO, no buffer writes,
    // no allocation.
    let Some(out) = out else {
        return Ok(total);
    };

    prepare(alg, key, params, total, pad, out)?;
    let at = payload_offset(alg);
    out[at..at + target_key.len()].copy_from_slice(target_key);
    crypto
        .key_mask_in_place(io, key, META_LEN, &mut out[HEADER_LEN..total])
        .await?;
    Ok(total)
}

/// Offset inside a masked blob at which the plaintext key must be
/// written for [`mask_in_place`].
#[must_use]
pub const fn payload_offset(alg: AeadAlg) -> usize {
    tsra_fw_core_crypto_aead_envelope::payload_offset(alg, META_LEN)
}

/// Mask a key that the caller has **already written** into `out` at
/// [`payload_offset`], rather than holding it in a separate buffer.
///
/// Same envelope and same AAD as [`mask`]; the only difference is that
/// shared code never copies the plaintext, because it is already where the
/// ciphertext belongs. PAL implementations may use internal scratch buffers.
/// Avoiding a second DMA payload allocation is important for large keys:
/// an ML-DSA-87 blob is 4928 bytes, and on the 16 KB per-IO DMA heap
/// keeping a second copy is the difference between fitting and
/// `NotEnoughSpace`.
///
/// # Safety of failure
///
/// On error, callers must not publish the partial envelope or staged plaintext.
/// IO teardown scrubs the backing storage.
pub async fn mask_in_place<P: HsmKeyMasking>(
    crypto: &P,
    io: &P::Io,
    _alloc: &impl HsmScopedAlloc,
    alg: AeadAlg,
    key: &HsmDmaBuf,
    params: &MaskParams<'_>,
    pt_len: usize,
    out: &mut HsmDmaBuf,
) -> HsmResult<usize> {
    let (total, pad) = mask_len(crypto, alg, pt_len)?;
    prepare(alg, key, params, total, pad, out)?;
    crypto
        .key_mask_in_place(io, key, META_LEN, &mut out[HEADER_LEN..total])
        .await?;
    Ok(total)
}

fn mask_len(crypto: &impl HsmKeyMasking, alg: AeadAlg, pt_len: usize) -> HsmResult<(usize, u8)> {
    if alg != AeadAlg::AesGcm256Iv16 {
        return Err(HsmError::InvalidArg);
    }
    let (len, pad) = crypto.key_mask_len(META_LEN, pt_len)?;
    let total = len.checked_add(HEADER_LEN).ok_or(HsmError::InvalidArg)?;
    if pad as usize != (16 - pt_len % 16) % 16 || total != blob_len(alg, pt_len) {
        return Err(HsmError::InternalError);
    }
    Ok((total, pad))
}

fn prepare(
    alg: AeadAlg,
    key: &HsmDmaBuf,
    params: &MaskParams<'_>,
    total: usize,
    data_pad_len: u8,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    if key.len() != alg.key_len() || params.key_label.len() > KEY_LABEL_MAX || out.len() < total {
        return Err(HsmError::InvalidArg);
    }

    let metadata = MaskedKeyMetadata::new_v2(
        params.key_kind,
        params.key_attrs,
        params.svn,
        params.owner_seed_id,
        params.key_label,
        data_pad_len,
    )?;

    write_header(out, alg, META_LEN)?;
    let aad_at = HEADER_LEN + alg.iv_len();
    out[aad_at..aad_at + META_LEN].copy_from_slice(metadata.as_bytes());
    let tag_at = total - alg.tag_len();
    out[tag_at - data_pad_len as usize..tag_at].fill(0);
    Ok(())
}
