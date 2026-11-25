// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE labelled KDF helpers.
//!
//! Two-stage (HKDF) suites use LabeledExtract and LabeledExpand
//! (RFC 9180 §4), thin wrappers around [`HkdfAlgo`] that prepend HPKE
//! domain-separation labels:
//!
//! ```text
//! labeled_ikm  = "HPKE-v1" ‖ suite_id ‖ label ‖ ikm
//! labeled_info = I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info
//! ```
//!
//! One-stage (SHAKE256) suites use LabeledDerive
//! (draft-ietf-hpke-hpke §4.4):
//!
//! ```text
//! labeled_ikm = ikm ‖ "HPKE-v1" ‖ suite_id ‖ I2OSP(len(label), 2)
//!               ‖ label ‖ I2OSP(L, 2) ‖ context
//! out         = SHAKE256(labeled_ikm, L)
//! ```
//!
//! The helpers allocate small `Vec`s for the labelled buffers — the
//! crate is `std` only and we trade the per-call allocation for a
//! significantly simpler API than the firmware's scoped-allocator
//! equivalent.

use std::num::NonZeroUsize;

use zeroize::Zeroizing;

use crate::CryptoError;
use crate::DeriveOp;
use crate::ExportableKey;
use crate::GenericSecretKey;
use crate::HashAlgo;
use crate::Hasher;
use crate::HkdfAlgo;
use crate::HkdfMode;
use crate::ImportableKey;

/// HPKE version string prepended to every labelled input (RFC 9180 §4).
const HPKE_V1: &[u8] = b"HPKE-v1";

/// `LabeledExtract(salt, label, ikm)` per RFC 9180 §4.
///
/// Returns a fresh `Vec<u8>` of length `algo.size()` (the PRK).
pub(crate) fn labeled_extract(
    algo: &HashAlgo,
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut labeled_ikm =
        Vec::with_capacity(HPKE_V1.len() + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(HPKE_V1);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let ikm_key = GenericSecretKey::from_bytes(&labeled_ikm)?;
    let hkdf = HkdfAlgo::new(HkdfMode::Extract, algo, Some(salt), None);
    let prk = hkdf.derive(&ikm_key, algo.size())?;

    extract_bytes(&prk, algo.size())
}

/// `LabeledExpand(prk, label, info, L)` per RFC 9180 §4.
///
/// Returns a fresh `Vec<u8>` of length `out_len`. RFC 9180 caps
/// `out_len` at `255 * Nh`.
pub(crate) fn labeled_expand(
    algo: &HashAlgo,
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if out_len > 255 * algo.size() {
        return Err(CryptoError::HpkeExportTooLarge);
    }

    let l_bytes = (out_len as u16).to_be_bytes();
    let mut labeled_info =
        Vec::with_capacity(2 + HPKE_V1.len() + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&l_bytes);
    labeled_info.extend_from_slice(HPKE_V1);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    let prk_key = GenericSecretKey::from_bytes(prk)?;
    let hkdf = HkdfAlgo::new(HkdfMode::Expand, algo, None, Some(&labeled_info));
    let okm = hkdf.derive(&prk_key, out_len)?;

    extract_bytes(&okm, out_len)
}

/// `I2OSP(len, 2)`; errors if `len` does not fit in 16 bits.
pub(crate) fn i2osp2(len: usize) -> Result<[u8; 2], CryptoError> {
    u16::try_from(len)
        .map(u16::to_be_bytes)
        .map_err(|_| CryptoError::HpkeInvalidBufferSize)
}

/// `LabeledDerive(ikm, label, context, L)` (draft-ietf-hpke-hpke §4.4)
/// with SHAKE256, writing `out.len() = L` bytes.
///
/// `ikm` and `context` are passed as slices of parts that are
/// concatenated in order, so callers need not pre-assemble them.
///
/// # Errors
///
/// * [`CryptoError::HpkeInvalidBufferSize`] — `L` is 0 or exceeds
///   65535, or `label` is longer than 65535 bytes.
/// * Other [`CryptoError`] variants propagated from SHAKE256.
pub(crate) fn labeled_derive(
    suite_id: &[u8],
    ikm: &[&[u8]],
    label: &[u8],
    context: &[&[u8]],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let l = i2osp2(out.len())?;
    let out_len = NonZeroUsize::new(out.len()).ok_or(CryptoError::HpkeInvalidBufferSize)?;
    let label_len = i2osp2(label.len())?;
    let mid: [&[u8]; 5] = [HPKE_V1, suite_id, &label_len, label, &l];
    let total: usize = ikm
        .iter()
        .chain(mid.iter())
        .chain(context.iter())
        .map(|p| p.len())
        .sum();
    let mut labeled_ikm = Zeroizing::new(Vec::with_capacity(total));
    for part in ikm.iter().chain(mid.iter()).chain(context.iter()) {
        labeled_ikm.extend_from_slice(part);
    }
    let written = Hasher::hash(&mut HashAlgo::shake256(out_len), &labeled_ikm, Some(out))?;
    if written != out.len() {
        return Err(CryptoError::HpkeKeyScheduleFailed);
    }
    Ok(())
}

/// Helper to copy bytes out of a `GenericSecretKey` of known length.
fn extract_bytes(key: &GenericSecretKey, len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; len];
    let written = key.to_bytes(Some(&mut out))?;
    out.truncate(written);
    Ok(out)
}
