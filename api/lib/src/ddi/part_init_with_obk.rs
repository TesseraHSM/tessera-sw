// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owner-backup-key (OBK) partition provisioning over the TBOR transport at
//! the DDI layer.
//!
//! Host-side dispatch for the in-session Crypto-Officer `PartInitWithObk`
//! command (opcode `0x30`), mirroring the firmware handler. It provisions an
//! `Enabled` partition from the masked owner backup key (MOBK) UEFI sealed
//! with the TPM and the partition owner's (POTA) endorsement of the
//! partition identity — the TBOR counterpart of the v1 `init` provisioning
//! step — **inside an already-open session**: the session is opened first,
//! then the partition is provisioned, optionally restoring a prior
//! `local_mk` backup.
//!
//! The MOBK and the POTA endorsement are resolved exactly as the v1 `init`
//! resolves them (see [`get_mobk_from_config`] and [`HsmPotaEndorsement`]).
//! The MOBK then travels in an AEAD-GCM envelope under the session
//! `param_key`, whose AAD binds it to the session id and to this command, and
//! the POTA public key and signature are converted to the session's
//! [`WireOrder`].

use tsra_crypto::*;
use tsra_ddi_tbor_types::*;

use super::*;

/// Seal the MOBK under the active session's `param_key` as the
/// `mobk_envelope` wire blob.
///
/// Uses a fresh random IV and the session-bound AAD from
/// [`build_part_init_with_obk_aad`]. Returns the exact bytes that occupy the
/// `mobk_envelope` field of [`TborPartInitWithObkReq`].
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when `mobk` is empty or longer than
/// [`OBK_MOBK_MAX_LEN`], and [`HsmError::InternalError`] on any RNG or AEAD
/// failure.
fn seal_mobk_envelope(param_key: &AesKey, session_id: u16, mobk: &[u8]) -> HsmResult<Vec<u8>> {
    if mobk.is_empty() || mobk.len() > OBK_MOBK_MAX_LEN {
        return Err(HsmError::InvalidArgument);
    }

    let aad = build_part_init_with_obk_aad(session_id);
    let iv = Rng::rand_vec(aead_envelope::AeadAlg::AesGcm256.iv_len())
        .map_err(|_| HsmError::InternalError)?;

    // First pass sizes the output buffer; second pass writes the sealed
    // envelope into it.
    let total = aead_envelope::seal(
        aead_envelope::AeadAlg::AesGcm256,
        param_key,
        &iv,
        &aad,
        mobk,
        None,
    )
    .map_err(|_| HsmError::InternalError)?;
    let mut envelope = vec![0u8; total];
    let written = aead_envelope::seal(
        aead_envelope::AeadAlg::AesGcm256,
        param_key,
        &iv,
        &aad,
        mobk,
        Some(&mut envelope),
    )
    .map_err(|_| HsmError::InternalError)?;
    envelope.truncate(written);
    Ok(envelope)
}

/// SHA-384 of `0x04 ‖ x ‖ y` for the partition identity key — the digest the
/// POTA endorses. The key is read over TBOR `PartInfo`, which reports it as
/// raw big-endian `x ‖ y`.
fn pid_pub_key_digest(dev: &HsmDev) -> HsmResult<Vec<u8>> {
    let mut cookie = None;
    let info = dev
        .exec_op_tbor(&TborPartInfoReq::new(), None, &mut cookie)
        .map_err(HsmError::from)?;

    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&info.pid_pub_key);
    let mut digest = vec![0u8; 48];
    HashAlgo::sha384()
        .hash(&uncompressed, Some(&mut digest))
        .map_err(|_| HsmError::InternalError)?;
    Ok(digest)
}

/// Resolve the POTA endorsement into its raw `(signature, public key DER)`
/// parts: the caller-supplied endorsement as is, or — for the TPM source — a
/// TPM signature over the partition identity digest.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when the endorsement data does not
/// match its source (missing for `Caller`, present for `Tpm`).
fn resolve_pota_endorsement(
    dev: &HsmDev,
    pota_endorsement: &HsmPotaEndorsement,
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    match pota_endorsement.source() {
        HsmPotaEndorsementSource::Caller => {
            let data = pota_endorsement
                .endorsement()
                .ok_or(HsmError::InvalidArgument)?;
            Ok((data.signature().to_vec(), data.pub_key().to_vec()))
        }
        HsmPotaEndorsementSource::Tpm => {
            // The TPM source must not carry caller-provided endorsement data.
            if pota_endorsement.endorsement().is_some() {
                return Err(HsmError::InvalidArgument);
            }
            tpm_ecc_sign_digest(&pid_pub_key_digest(dev)?)
        }
        _ => Err(HsmError::InvalidArgument),
    }
}

/// Convert the POTA endorsement to the TBOR wire form: the DER
/// `SubjectPublicKeyInfo` public key to raw `x ‖ y` and the raw big-endian
/// `r ‖ s` signature, each P-384 component in `order`.
///
/// Returns `(pub_key, sig)`.
///
/// # Errors
///
/// Returns [`HsmError::InvalidKey`] when `pub_key_der` is not a DER ECC
/// public key, and [`HsmError::InvalidArgument`] when it is not a P-384 key
/// or `sig` is not a P-384 `r ‖ s` pair.
fn pota_wire(order: WireOrder, pub_key_der: &[u8], sig: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let coord = HsmEccCurve::P384.component_size();
    let pub_key = DerEccPublicKey::from_der(pub_key_der).map_err(|_| HsmError::InvalidKey)?;
    if pub_key.x().len() != coord || pub_key.y().len() != coord || sig.len() != 2 * coord {
        return Err(HsmError::InvalidArgument);
    }

    let wire_pub_key = order.pair_from_be(pub_key.x(), pub_key.y(), coord)?;
    let wire_sig = order.pair_from_be(&sig[..coord], &sig[coord..], coord)?;
    Ok((wire_pub_key, wire_sig))
}

/// Convert a `PartInitWithObk` device error to the [`HsmError`] callers act on.
///
/// The firmware statuses this command is specified to return are surfaced as
/// their dedicated variants; every other error takes the generic DDI mapping.
fn map_obk_error(err: DdiError) -> HsmError {
    match err {
        DdiError::TborStatus(TborStatus::PartitionAlreadyProvisioned) => {
            HsmError::PartitionAlreadyProvisioned
        }
        DdiError::TborStatus(TborStatus::EccVerifyFailed) => HsmError::EccVerifyFailed,
        DdiError::TborStatus(TborStatus::MaskedKeyDecodeFailed) => HsmError::MaskedKeyDecodeFailed,
        other => HsmError::from(other),
    }
}

/// Keep `mobk` on the partition handle, where [`HsmPartition::mobk`] and the
/// C `MASKED_OWNER_BACKUP_KEY` property expose it.
fn cache_mobk(partition: &HsmPartition, mobk: &[u8]) {
    partition.inner().write().set_mobk(mobk.to_vec());
}

/// Issue `PartInitWithObk` (opcode `0x30`) on the active CO session.
///
/// Resolves the MOBK from `obk_config` and the POTA endorsement from
/// `pota_endorsement` (both as the v1 `init` does), seals the MOBK under the
/// session `param_key`, and ships it with the endorsement and the optional
/// `prev_local_mk_backup`. Returns the MOBK together with the current
/// `local_mk` backup envelope.
///
/// With a raw owner backup key the device masks it via `InitBk3`, a one-shot
/// per power cycle. Every check that needs no device state runs first, so a
/// malformed input cannot consume it, and the MOBK is cached on the partition
/// handle ([`HsmPartition::mobk`]) as soon as it exists, so a rejection by the
/// device (for example an unrotated PSK) does not lose it: retry with that
/// MOBK instead of the raw key.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active CO session id this request binds to.
/// * `rev` - The session's negotiated API revision; selects the wire byte
///   order and the revision of the MBOR commands used to resolve the MOBK.
/// * `param_key` - The session's per-session AES wrap key used to seal the
///   MOBK.
/// * `obk_config` - Owner backup key source and material.
/// * `pota_endorsement` - POTA endorsement source and data.
/// * `prev_local_mk_backup` - Optional prior `local_mk` backup envelope to
///   restore; `None` on first provisioning.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when a present
/// `prev_local_mk_backup` is not exactly [`LOCAL_MK_BACKUP_LEN`] bytes or the
/// configuration or endorsement is malformed; returns
/// [`HsmError::InternalError`] if the device returns a malformed
/// (wrong-length) `local_mk_backup`; and surfaces DDI/device failures from
/// the round-trips, including [`HsmError::PartitionAlreadyProvisioned`] and
/// [`HsmError::EccVerifyFailed`].
pub(crate) fn part_init_with_obk(
    partition: &HsmPartition,
    session_id: u16,
    rev: HsmApiRev,
    param_key: &AesKey,
    obk_config: &HsmOwnerBackupKeyConfig,
    pota_endorsement: &HsmPotaEndorsement,
    prev_local_mk_backup: Option<&[u8]>,
    ddi_cookie: &parking_lot::Mutex<Option<u64>>,
) -> HsmResult<HsmPartInitWithObkResult> {
    // The firmware treats a non-empty `prev_local_mk_backup` as a
    // fixed-size envelope of exactly `LOCAL_MK_BACKUP_LEN` bytes, so
    // reject any other present length up front (deterministic guard).
    if prev_local_mk_backup.is_some_and(|b| b.len() != LOCAL_MK_BACKUP_LEN) {
        return Err(HsmError::InvalidArgument);
    }

    let (pota_pub_key, pota_sig, mobk) = {
        let inner = partition.inner().read();
        let dev = inner.dev();

        let (pota_sig, pota_pub_key_der) = resolve_pota_endorsement(dev, pota_endorsement)?;
        let (pota_pub_key, pota_sig) =
            pota_wire(WireOrder::for_rev(rev), &pota_pub_key_der, &pota_sig)?;
        (
            pota_pub_key,
            pota_sig,
            get_mobk_from_config(dev, rev, obk_config)?,
        )
    };

    // A raw OBK was just masked by the one-shot `InitBk3`, so a rejection
    // below would lose the only copy of the MOBK. Keep it on the partition
    // handle, where `HsmPartition::mobk` exposes it for the retry.
    if obk_config.key().is_some() {
        cache_mobk(partition, &mobk);
    }

    let req = TborPartInitWithObkReq {
        session_id,
        mobk_envelope: seal_mobk_envelope(param_key, session_id, &mobk)?,
        pota_pub_key,
        pota_sig,
        prev_local_mk_backup: prev_local_mk_backup.unwrap_or_default().to_vec(),
    };

    // Thread the session's DDI-backend cookie through explicitly (see
    // `part_init_ex`): this call runs outside `HsmSession::with_dev`'s
    // `with_session_cookie` scope.
    let result = {
        let inner = partition.inner().read();
        with_explicit_cookie(ddi_cookie, |cookie| {
            inner.dev().exec_op_tbor(&req, None, cookie)
        })
    };
    let resp = result.map_err(map_obk_error)?;

    // The firmware always returns a fixed-size `local_mk_backup`
    // envelope; reject a malformed (wrong-length) device response rather
    // than surfacing it to callers.
    if resp.local_mk_backup.len() != LOCAL_MK_BACKUP_LEN {
        return Err(HsmError::InternalError);
    }

    // The device accepted the MOBK, so it is now the partition's MOBK
    // whatever its source.
    cache_mobk(partition, &mobk);
    Ok(HsmPartInitWithObkResult {
        mobk,
        local_mk_backup: resp.local_mk_backup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DER `SubjectPublicKeyInfo` of a fresh P-384 key, with its coordinates.
    fn p384_spki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let key = EccPrivateKey::from_curve(EccCurve::P384).expect("P-384 key");
        let (x, y) = key.coord_vec().expect("coordinates");
        let der = DerEccPublicKey::new(EccCurve::P384, &x, &y).expect("public key");
        let len = der.to_der(None).expect("DER length");
        let mut out = vec![0u8; len];
        der.to_der(Some(&mut out)).expect("DER");
        (out, x, y)
    }

    fn reversed(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().rev().copied().collect()
    }

    /// The POTA key and signature reach the wire as `a ‖ b` pairs with each
    /// 48-byte component in the session's byte order.
    #[test]
    fn pota_fields_follow_the_wire_order() {
        let (der, x, y) = p384_spki();
        let sig: Vec<u8> = (1..=96).collect();

        let (pub_key, wire_sig) = pota_wire(WireOrder::Be, &der, &sig).expect("BE wire");
        assert_eq!(pub_key, [x.clone(), y.clone()].concat());
        assert_eq!(wire_sig, sig);

        let (pub_key, wire_sig) = pota_wire(WireOrder::Le, &der, &sig).expect("LE wire");
        assert_eq!(pub_key, [reversed(&x), reversed(&y)].concat());
        let expected_sig = [reversed(&sig[..48]), reversed(&sig[48..])].concat();
        assert_eq!(wire_sig, expected_sig);
    }

    /// A key or signature that is not a P-384 pair is rejected rather than
    /// padded into one.
    #[test]
    fn pota_fields_reject_the_wrong_sizes() {
        let (der, _, _) = p384_spki();
        let sig = vec![0xA5u8; 96];

        let err = pota_wire(WireOrder::Le, &der, &sig[..95]).expect_err("short signature");
        assert_eq!(err, HsmError::InvalidArgument);
        let err = pota_wire(WireOrder::Le, &[0u8; 4], &sig).expect_err("malformed key");
        assert_eq!(err, HsmError::InvalidKey);
    }

    /// The MOBK envelope length is bounded before any device work.
    #[test]
    fn mobk_envelope_rejects_empty_and_oversized_blobs() {
        let key = AesKey::from_bytes(&[0x11u8; 32]).expect("AES key");

        let err = seal_mobk_envelope(&key, 0, &[]).expect_err("empty MOBK");
        assert_eq!(err, HsmError::InvalidArgument);
        let oversized = [0u8; OBK_MOBK_MAX_LEN + 1];
        let err = seal_mobk_envelope(&key, 0, &oversized).expect_err("oversized MOBK");
        assert_eq!(err, HsmError::InvalidArgument);

        let largest = [0u8; OBK_MOBK_MAX_LEN];
        let envelope = seal_mobk_envelope(&key, 0, &largest).expect("seal");
        assert_eq!(envelope.len(), OBK_MOBK_ENVELOPE_MAX_LEN);
    }
}
