// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE labelled KDF helpers.
//!
//! Two-stage (HKDF) suites use LabeledExtract and LabeledExpand
//! (RFC 9180 §4), thin wrappers that prepend HPKE domain-separation
//! labels before calling the PAL's HKDF Extract/Expand:
//!
//! ```text
//! labeled_ikm  = "HPKE-v1" || suite_id || label || ikm
//! labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
//! ```
//!
//! One-stage (SHAKE256) suites use LabeledDerive
//! (draft-ietf-hpke-hpke §4.4):
//!
//! ```text
//! labeled_ikm = ikm || "HPKE-v1" || suite_id || lengthPrefixed(label)
//!               || I2OSP(L, 2) || context
//! out         = SHAKE256(labeled_ikm, L)
//! ```
//!
//! Every helper assembles its labelled buffer from the caller's
//! [`HsmScopedAlloc`], while the PAL allocates any internal scratch
//! per call.

use core::num::NonZeroU16;

use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHash;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmKdf;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

// =============================================================================
// Constants
// =============================================================================

/// HPKE version string prepended to every labelled input (RFC 9180 §4).
const HPKE_V1: &[u8] = b"HPKE-v1";

// =============================================================================
// Helpers
// =============================================================================

/// Allocate a buffer from `alloc`, concatenate `parts` into it, and
/// return the filled slice.
///
/// The returned buffer is scoped to the surrounding PAL allocation
/// region and is released automatically when that alloc ends.
fn concat_alloc<'a>(
    parts: &[&[u8]],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<&'a mut HsmDmaBuf> {
    concat3_alloc(&[], parts, &[], alloc)
}

/// [`concat_alloc`] over three part lists, concatenated in order.
fn concat3_alloc<'a>(
    a: &[&[u8]],
    b: &[&[u8]],
    c: &[&[u8]],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let parts = || a.iter().chain(b).chain(c);
    let total = parts().try_fold(0usize, |n, p| n.checked_add(p.len()));
    let dst = alloc.dma_alloc(total.ok_or(HsmError::InvalidArg)?)?;
    let mut pos = 0;
    for part in parts() {
        dst[pos..pos + part.len()].copy_from_slice(part);
        pos += part.len();
    }
    Ok(dst)
}

/// `I2OSP(len, 2)`, or `InvalidArg` when `len` does not fit two bytes.
pub(crate) fn i2osp2(len: usize) -> HsmResult<[u8; 2]> {
    u16::try_from(len)
        .map(u16::to_be_bytes)
        .map_err(|_| HsmError::InvalidArg)
}

// =============================================================================
// Labelled Extract / Expand
// =============================================================================

/// HPKE `LabeledExtract` (RFC 9180 §4):
///
/// ```text
/// labeled_ikm = "HPKE-v1" || suite_id || label || ikm
/// PRK         = Extract(salt, labeled_ikm)
/// ```
///
/// Allocates `labeled_ikm` and the output scratch from `alloc`,
/// while the PAL allocates its internal HKDF scratch per call.
///
/// # Type parameters
///
/// * `P` — any [`HsmKdf`] PAL implementation.
///
/// # Parameters
///
/// * `pal` — PAL providing the underlying HKDF.
/// * `io` — caller's I/O context (per-IO scope).
/// * `algo` — hash algorithm used by HKDF (selects `Nh`).
/// * `suite_id` — HPKE suite identifier (`"HPKE" || I2OSP(kem_id,
///   2) || …`, opaque to this function).
/// * `salt` — HKDF salt as a DMA buffer, or `None` for the RFC 5869
///   default (all-zero) salt.
/// * `label` — context-specific label (e.g. `b"eae_prk"`).
/// * `ikm` — input keying material.
/// * `prk_out` — destination DMA buffer for the pseudo-random key;
///   must be at least `algo.digest_len()` bytes.  Only the leading
///   `digest_len` bytes are written.  The PAL writes into it directly —
///   no intermediate scratch or copy.
/// * `alloc` — scoped allocator used for the labelled input buffer.
///
/// # Returns
///
/// * `Ok(())` — `prk_out[..digest_len]` populated.
/// * `Err(HsmError::NotEnoughSpace)` — one of the required scoped
///   allocations could not be satisfied.
/// * `Err(HsmError)` — propagated from
///   [`HsmKdf::hkdf_extract`].
pub async fn labeled_extract<'a, P>(
    pal: &P,
    io: &P::Io,
    algo: HsmHashAlgo,
    suite_id: &[u8],
    salt: Option<&HsmDmaBuf>,
    label: &[u8],
    ikm: &[u8],
    prk_out: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmKdf + HsmAlloc + 'a,
{
    let labeled_ikm = concat_alloc(&[HPKE_V1, suite_id, label, ikm], alloc)?;
    pal.hkdf_extract(io, algo, salt, labeled_ikm, Some(prk_out))
        .await
        .map(|_| ())
}

/// HPKE `LabeledExpand` (RFC 9180 §4):
///
/// ```text
/// labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
/// out          = Expand(prk, labeled_info, L)
/// ```
///
/// Allocates `labeled_info` and the output scratch from `alloc`,
/// while the PAL allocates its internal HKDF scratch per call.
///
/// # Type parameters
///
/// * `P` — any [`HsmKdf`] PAL implementation.
///
/// # Parameters
///
/// * `pal` — PAL providing the underlying HKDF.
/// * `io` — caller's I/O context (per-IO scope).
/// * `algo` — hash algorithm used by HKDF.
/// * `suite_id` — HPKE suite identifier.
/// * `prk` — pseudo-random key DMA buffer from a prior
///   [`labeled_extract`] call.
/// * `label` — context-specific label (e.g. `b"shared_secret"`).
/// * `info` — application-specific context bytes (may be empty).
/// * `out` — destination DMA buffer; `L = out.len()` is encoded as a
///   2-byte big-endian prefix in `labeled_info`.  RFC 9180 caps
///   `L` at `255 * Nh`.  The PAL writes into it directly — no
///   intermediate scratch or copy.
/// * `alloc` — scoped allocator used for the labelled input buffer.
///
/// # Returns
///
/// * `Ok(())` — `out` filled with the derived key bytes.
/// * `Err(HsmError::InvalidArg)` — `out.len() > 255 * Nh`
///   (propagated from `hkdf_expand`).
/// * `Err(HsmError::NotEnoughSpace)` — one of the required scoped
///   allocations could not be satisfied.
/// * `Err(HsmError)` — propagated from
///   [`HsmKdf::hkdf_expand`].
pub async fn labeled_expand<'a, P>(
    pal: &P,
    io: &P::Io,
    algo: HsmHashAlgo,
    suite_id: &[u8],
    prk: &HsmDmaBuf,
    label: &[u8],
    info: &[u8],
    out: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmKdf + HsmAlloc + 'a,
{
    let l_bytes = (out.len() as u16).to_be_bytes();
    let labeled_info = concat_alloc(&[&l_bytes, HPKE_V1, suite_id, label, info], alloc)?;
    pal.hkdf_expand(io, algo, prk, Some(labeled_info), out)
        .await
}

/// HPKE one-stage `LabeledDerive` (draft-ietf-hpke-hpke §4.4) with
/// SHAKE256 as `Derive`:
///
/// ```text
/// labeled_ikm = ikm || "HPKE-v1" || suite_id || lengthPrefixed(label)
///               || I2OSP(L, 2) || context
/// out         = SHAKE256(labeled_ikm, L)
/// ```
///
/// `ikm` and `context` are passed as part lists that are concatenated
/// in order, so callers can supply length prefixes without a copy.
/// The labelled input is assembled into one scoped DMA buffer and
/// hashed in a single call (some PALs only support one-shot SHAKE).
///
/// # Parameters
///
/// * `pal` — PAL providing SHAKE256.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite_id` — HPKE or KEM suite identifier.
/// * `ikm` — input keying material parts.
/// * `label` — context-specific label (e.g. `b"secret"`).
/// * `context` — context parts (may be empty).
/// * `out` — destination; `L = out.len()`, `1..=65535` bytes.
/// * `alloc` — scoped allocator used for the labelled input buffer.
///
/// # Returns
///
/// * `Ok(())` — `out` filled with the derived bytes.
/// * `Err(HsmError::InvalidArg)` — `L` or `len(label)` out of range,
///   or the labelled input exceeds the PAL's SHAKE input limit.
/// * `Err(HsmError::NotEnoughSpace)` — scoped allocation failed.
/// * `Err(HsmError)` — propagated from [`HsmHash::hash`].
pub async fn labeled_derive<'a, P>(
    pal: &P,
    io: &P::Io,
    suite_id: &[u8],
    ikm: &[&[u8]],
    label: &[u8],
    context: &[&[u8]],
    out: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmHash + HsmAlloc + 'a,
{
    let l = u16::try_from(out.len())
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or(HsmError::InvalidArg)?;
    let label_len = i2osp2(label.len())?;
    let l_bytes = l.get().to_be_bytes();
    let labeled_ikm = concat3_alloc(
        ikm,
        &[HPKE_V1, suite_id, &label_len, label, &l_bytes],
        context,
        alloc,
    )?;
    pal.hash(
        io,
        HsmHashAlgo::Shake256(l),
        labeled_ikm,
        HsmDigestForm::Standard,
        Some(out),
    )
    .await
    .map(|_| ())
}
