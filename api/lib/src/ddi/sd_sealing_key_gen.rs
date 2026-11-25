// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain sealing-key generation over the TBOR transport at
//! the DDI layer.
//!
//! This module hosts the host-side dispatch for the in-session
//! `SdSealingKeyGen` command, mirroring the firmware handler:
//!
//! * **`SdSealingKeyGen`** (opcode `0x09`) — generate a new
//!   security-domain sealing key and return it as a **masked**
//!   (AEAD-GCM-256) private-key blob plus its public key. The key is
//!   not stored on the device; the masked blob is returned to the host
//!   and unmasked on-use by the security-domain backup commands.
//!
//! It also hosts the companion **`KeyReport`** dispatch, which attests an
//! unpinned masked key (the sealing key) by its masked-key envelope
//! rather than a device handle.
//!
//! It runs **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`]: the request carries the
//! active session id, which the firmware dispatcher cross-checks
//! against the SQE-carried session id. Unlike `PartInit`, no host-side
//! crypto is required — the request only conveys the active session id
//! and the requested key `scope`. The response returns the masked
//! sealing key, which the host retains and unmasks on-use (via
//! `UnmaskKey`) when a security-domain backup command needs it.
//!
//! The wire schema lives in [`tsra_ddi_tbor_types`]. The `scope`
//! byte is the 1-byte `KeyScope` discriminant (host mirror of the
//! firmware `HsmKeyScope`); this host crate is firewalled from the
//! firmware PAL types, so it is carried as a raw `u8`.

use tsra_crypto::DerEccPublicKey;
use tsra_crypto::EccCurve;
use tsra_crypto::aead_envelope;
use tsra_ddi_tbor_types::*;

use super::*;

/// Length of the masked sealing-key blob's AAD region: a fixed 192-byte
/// masked-key metadata record.
const SEALING_META_LEN: usize = 192;

/// Length, in bytes, of the AES-256-GCM tag on the masked blob.
const SEALING_GCM_TAG_LEN: usize = 16;

/// Masked-blob overhead around the private seed:
/// `AEAD header ‖ IV ‖ AAD ‖ seed ‖ GCM tag`.
const SEALING_MASK_OVERHEAD: usize = aead_envelope::HEADER_LEN
    + aead_envelope::AeadAlg::AesGcm256.iv_len()
    + SEALING_META_LEN
    + SEALING_GCM_TAG_LEN;

/// Pin the P-384 layout (48-byte scalar) to the wire schema so a future
/// `MASKED_SEALING_KEY_LEN` change can't silently desync the validator.
const _: () = assert!(MASKED_SEALING_KEY_LEN == SEALING_MASK_OVERHEAD + 48);
const _: () = assert!(MASKED_SEALING_KEY_MAX_LEN == SEALING_MASK_OVERHEAD + 64);

impl HsmTransferKem {
    /// Maps a sealing key props bit length to its KEM.
    pub(crate) fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            384 => Some(Self::P384),
            1024 => Some(Self::MlKem1024),
            1408 => Some(Self::MlKem1024P384),
            _ => None,
        }
    }

    /// The TBOR `TransferKemId` discriminant.
    pub(crate) fn wire(self) -> u8 {
        match self {
            Self::P384 => TRANSFER_KEM_P384,
            Self::MlKem1024 => TRANSFER_KEM_MLKEM1024,
            Self::MlKem1024P384 => TRANSFER_KEM_MLKEM1024_P384,
        }
    }

    /// Length of the private seed carried in a masked recipient key.
    fn seed_len(self) -> usize {
        match self {
            Self::P384 => 48,
            Self::MlKem1024 => 64,
            Self::MlKem1024P384 => 32,
        }
    }

    /// Length of a masked recipient (SD sealing or DARC KEX) key.
    pub(crate) fn masked_key_len(self) -> usize {
        SEALING_MASK_OVERHEAD + self.seed_len()
    }

    /// Length of the returned public key.
    pub(crate) fn pub_key_len(self) -> usize {
        match self {
            Self::P384 => SD_SEALING_PUB_KEY_LEN,
            Self::MlKem1024 => SD_SEALING_MLKEM1024_PUB_KEY_LEN,
            Self::MlKem1024P384 => SD_SEALING_MLKEM1024_P384_PUB_KEY_LEN,
        }
    }

    /// All supported KEMs.
    pub(crate) const ALL: [Self; 3] = [Self::P384, Self::MlKem1024, Self::MlKem1024P384];
}

/// Checks that `masked` has the length of a masked sealing key of some
/// supported KEM and returns it as an owned wire field.
pub(crate) fn masked_sealing_key_wire(masked: &[u8]) -> HsmResult<Vec<u8>> {
    let valid = HsmTransferKem::ALL
        .iter()
        .any(|kem| masked.len() == kem.masked_key_len());
    if !valid {
        return Err(HsmError::InvalidArgument);
    }
    Ok(masked.to_vec())
}

pub(crate) fn remote_backup_len_valid(len: usize) -> bool {
    const ENVELOPE_OVERHEAD: usize = POK_REMOTE_BACKUP_LEN - 97 - 109;
    [
        97,
        SD_SEALING_MLKEM1024_PUB_KEY_LEN,
        SD_SEALING_MLKEM1024_P384_PUB_KEY_LEN,
    ]
    .iter()
    .any(|enc| {
        [109, 4641]
            .iter()
            .any(|sign1| len == ENVELOPE_OVERHEAD + enc + sign1)
    })
}

/// Copy a complete signed backup of any supported recipient/signature pair.
pub(crate) fn remote_backup_wire(backup: &[u8]) -> HsmResult<Vec<u8>> {
    if !remote_backup_len_valid(backup.len()) {
        return Err(HsmError::InvalidArgument);
    }
    Ok(backup.to_vec())
}

const _: () = assert!(POK_REMOTE_BACKUP_MAX_LEN == POK_REMOTE_BACKUP_LEN - 97 - 109 + 1665 + 4641);

/// Sanity-checks the firmware-returned masked sealing key before it is
/// cached and later handed back for unmask-on-use.
///
/// The host cannot verify the AEAD tag (the masking key is
/// device-internal), but it can confirm the firmware returned a
/// well-formed IV16 AES-256-GCM masked-key envelope of the expected shape
/// for `kem`: valid header/magic, the masked-key profile, and the 192-byte
/// metadata AAD.
pub(crate) fn validate_masked_sealing_key(kem: HsmTransferKem, masked_key: &[u8]) -> HsmResult<()> {
    if masked_key.len() != kem.masked_key_len() {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    let env = aead_envelope::inspect(masked_key).map_err(|_| HsmError::MaskedKeyDecodeFailed)?;
    if !matches!(env.alg, aead_envelope::AeadAlg::AesGcm256) || env.aad.len() != SEALING_META_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    Ok(())
}

/// Encodes the response's raw P-384 public key as a DER SPKI blob.
///
/// The wire form is `x ‖ y` affine coordinates in `order`; DER SPKI
/// expects big-endian coordinates.
fn sealing_pub_key_to_der(order: WireOrder, pub_key: &[u8]) -> HsmResult<Vec<u8>> {
    let (x, y) = order.pair_to_be(pub_key, SD_SEALING_PUB_KEY_LEN / 2)?;

    let der = DerEccPublicKey::new(EccCurve::P384, &x, &y).map_err(|_| HsmError::InternalError)?;
    let der_len = der.to_der(None).map_err(|_| HsmError::InternalError)?;
    let mut out = vec![0u8; der_len];
    der.to_der(Some(&mut out))
        .map_err(|_| HsmError::InternalError)?;
    Ok(out)
}

/// Issue `SdSealingKeyGen` (opcode `0x09`) on the active session.
///
/// Ships the active session id, the requested key `scope` and `kem`. The
/// firmware returns the new sealing key as a masked (AEAD-GCM-256)
/// private-key blob (plus its public key); the key is not stored on the
/// device. Per the firmware contract the blob is returned to the host
/// as-is — it is *not* re-imported into the partition vault here — and
/// is unmasked on-use by the security-domain backup commands.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `scope` - Requested key scope (lifecycle / visibility domain) as
///   the 1-byte `KeyScope` discriminant (mirror of the firmware
///   `HsmKeyScope`).
/// * `kem` - The sealing-key KEM.
///
/// # Returns
///
/// The masked blob and, for P-384, the DER SPKI public key. ML-KEM-1024
/// and MLKEM1024-P384 public keys are attested by the key report instead.
///
/// # Errors
///
/// Returns [`HsmError::InvalidSession`] on a non-security-domain (V1)
/// session, and surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_sealing_key_gen(
    session: &HsmSession,
    scope: u8,
    kem: HsmTransferKem,
) -> HsmResult<(Vec<u8>, Option<Vec<u8>>)> {
    let req = TborSdSealingKeyGenReq {
        session_id: session.ex_session_id()?,
        scope,
        kem: kem.wire(),
    };

    let mut cookie = None;
    let rev = session.api_rev();
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(rev, &req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    // The masked blob is not stored on the device or in the vault; it is
    // unmasked on-use by the backup commands.
    validate_masked_sealing_key(kem, &resp.masked_key)?;
    if resp.pub_key.len() != kem.pub_key_len() {
        return Err(HsmError::InternalError);
    }
    let pub_key_der = match kem {
        HsmTransferKem::P384 => Some(sealing_pub_key_to_der(
            WireOrder::of(session),
            &resp.pub_key,
        )?),
        HsmTransferKem::MlKem1024 | HsmTransferKem::MlKem1024P384 => None,
    };
    Ok((resp.masked_key, pub_key_der))
}

/// Issue `KeyReport` on the active session to attest an unpinned
/// masked key (such as the sealing key produced by
/// [`sd_sealing_key_gen`]).
///
/// The key is attested by its masked-key envelope rather than a device
/// handle. Ships the active session id, the masked-key envelope, and the
/// caller's [`KEY_REPORT_DATA_LEN`]-byte report data; returns the tagged
/// COSE_Sign1 attestation report signed by the PID key.
///
/// Follows the size-query convention: a `None` `report` returns the
/// maximum report size ([`KEY_REPORT_MAX_LEN`]) without a round-trip.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `masked_key` - The masked-key envelope to attest (at most
///   [`KEY_REPORT_MASKED_KEY_MAX_LEN`] bytes).
/// * `report_data` - Caller-supplied [`KEY_REPORT_DATA_LEN`]-byte report
///   data bound into the report.
/// * `report` - Optional output buffer for the report; `None` returns the
///   maximum report size.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when `report_data` is not
/// [`KEY_REPORT_DATA_LEN`] bytes or `masked_key` is empty or exceeds
/// [`KEY_REPORT_MASKED_KEY_MAX_LEN`], [`HsmError::BufferTooSmall`] when
/// the supplied buffer is shorter than the returned report, and surfaces
/// DDI/device failures from the round-trip.
pub(crate) fn masked_key_report(
    session: &HsmSession,
    masked_key: &[u8],
    report_data: &[u8],
    report: Option<&mut [u8]>,
) -> HsmResult<usize> {
    if report_data.len() != KEY_REPORT_DATA_LEN
        || masked_key.is_empty()
        || masked_key.len() > KEY_REPORT_MASKED_KEY_MAX_LEN
    {
        return Err(HsmError::InvalidArgument);
    }

    let Some(report) = report else {
        return Ok(KEY_REPORT_MAX_LEN);
    };

    let mut report_data_arr = [0u8; KEY_REPORT_DATA_LEN];
    report_data_arr.copy_from_slice(report_data);

    let mut req = TborKeyReportReq {
        session_id: session.ex_session_id()?,
        masked_key: masked_key.to_vec(),
        report_data: report_data_arr,
        auth_envelope: Vec::new(),
    };
    req.auth_envelope = session.key_report_auth(&req)?;

    let mut cookie = None;
    let rev = session.api_rev();
    let mut out = vec![0u8; KEY_REPORT_MAX_LEN];
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor_oob(rev, &req, &mut [TborOobItem::Out(&mut out)], &mut cookie)
            .map_err(HsmError::from)
    })?;

    let len = usize::from(resp.report_len.get());
    if len > out.len() {
        return Err(HsmError::InternalError);
    }
    if report.len() < len {
        return Err(HsmError::BufferTooSmall);
    }
    report[..len].copy_from_slice(&out[..len]);
    Ok(len)
}

#[cfg(test)]
mod tests {
    use tsra_crypto::AesKey;
    use tsra_crypto::ImportableKey;

    use super::*;

    /// Builds a masked-key blob with the given AEAD header fields
    /// over a sealed, version-1 sealing-key envelope.
    fn masked_key_with_header(magic: [u8; 4], alg: u8, aad_len: u16) -> Vec<u8> {
        masked_kem_key_with_header(HsmTransferKem::P384, magic, alg, aad_len)
    }

    /// As [`masked_key_with_header`] for a sealing key of `kem`.
    fn masked_kem_key_with_header(
        kem: HsmTransferKem,
        magic: [u8; 4],
        alg: u8,
        aad_len: u16,
    ) -> Vec<u8> {
        let key = AesKey::from_bytes(&[0x42; 32]).expect("masking key");
        let mut metadata = [0u8; SEALING_META_LEN];
        metadata[..4].copy_from_slice(b"MKEY");
        metadata[4..6].copy_from_slice(&1u16.to_le_bytes());
        metadata[6] = match kem {
            HsmTransferKem::P384 => KEY_KIND_SD_SEALING,
            HsmTransferKem::MlKem1024 => KEY_KIND_SD_SEALING_MLKEM1024,
            HsmTransferKem::MlKem1024P384 => KEY_KIND_SD_SEALING_MLKEM1024_P384,
        };
        // Metadata carries packed vault flags, not request KeyUsage bits.
        let usage = (1u64 << 16) | (3u64 << 17);
        metadata[8..16].copy_from_slice(&usage.to_le_bytes());
        let mut blob = vec![0u8; SEALING_MASK_OVERHEAD + kem.seed_len()];
        aead_envelope::seal(
            aead_envelope::AeadAlg::AesGcm256,
            &key,
            &[0x24; 16],
            &metadata,
            &vec![0x55; kem.seed_len()],
            Some(&mut blob),
        )
        .expect("seal version-1 sealing key");
        blob[0..4].copy_from_slice(&magic);
        blob[4] = alg;
        blob[5] = 0;
        blob[6..8].copy_from_slice(&aad_len.to_be_bytes());
        blob
    }

    /// AES-256-GCM envelope discriminant.
    const ALG_AES_GCM_256: u8 = 0x03;

    #[test]
    fn validate_accepts_iv16_sealing_key_with_v1_metadata() {
        let blob = masked_key_with_header(*b"AEAD", ALG_AES_GCM_256, SEALING_META_LEN as u16);
        assert!(validate_masked_sealing_key(HsmTransferKem::P384, &blob).is_ok());
        let props = HsmMaskedKey::to_key_props(&blob).expect("parse version-1 sealing key");
        assert_eq!(props.kind(), HsmKeyKind::Sealing);
        assert_eq!(props.bits(), 384);
        assert!(props.can_derive());
    }

    /// PQ sealing keys carry their seed length and map to their KEM's
    /// props bit length; a blob is rejected for a different KEM.
    #[test]
    fn validate_accepts_pq_sealing_keys() {
        for (kem, bits) in [
            (HsmTransferKem::MlKem1024, 1024),
            (HsmTransferKem::MlKem1024P384, 1408),
        ] {
            let blob =
                masked_kem_key_with_header(kem, *b"AEAD", ALG_AES_GCM_256, SEALING_META_LEN as u16);
            assert!(validate_masked_sealing_key(kem, &blob).is_ok());
            assert_eq!(
                validate_masked_sealing_key(HsmTransferKem::P384, &blob),
                Err(HsmError::MaskedKeyDecodeFailed),
            );
            assert!(masked_sealing_key_wire(&blob).is_ok());
            let props = HsmMaskedKey::to_key_props(&blob).expect("parse PQ sealing key");
            assert_eq!(props.kind(), HsmKeyKind::Sealing);
            assert_eq!(props.bits(), bits);
            assert_eq!(HsmTransferKem::from_bits(bits), Some(kem));
        }
        assert!(masked_sealing_key_wire(&[0u8; MASKED_SEALING_KEY_LEN + 1]).is_err());
    }

    #[test]
    fn remote_backup_lengths_follow_kem() {
        for len in [431, 1902, 1999, 4963, 6434, 6531] {
            assert!(remote_backup_wire(&vec![0u8; len]).is_ok(), "{len}");
        }
        for len in [
            0, 322, 1793, 1890, 430, 432, 1901, 1903, 1998, 2000, 4962, 4964, 6433, 6435, 6530,
            6532,
        ] {
            assert!(remote_backup_wire(&vec![0u8; len]).is_err(), "{len}");
        }
    }

    #[test]
    fn validate_rejects_removed_iv16_algorithm() {
        let blob = masked_key_with_header(*b"AEAD", 0x04, SEALING_META_LEN as u16);
        assert_eq!(
            validate_masked_sealing_key(HsmTransferKem::P384, &blob),
            Err(HsmError::MaskedKeyDecodeFailed),
        );
    }

    #[test]
    fn validate_rejects_bad_magic() {
        let blob = masked_key_with_header(*b"XXXX", ALG_AES_GCM_256, SEALING_META_LEN as u16);
        assert_eq!(
            validate_masked_sealing_key(HsmTransferKem::P384, &blob),
            Err(HsmError::MaskedKeyDecodeFailed),
        );
    }

    #[test]
    fn validate_rejects_unsupported_alg() {
        let blob = masked_key_with_header(*b"AEAD", 0xFF, SEALING_META_LEN as u16);
        assert_eq!(
            validate_masked_sealing_key(HsmTransferKem::P384, &blob),
            Err(HsmError::MaskedKeyDecodeFailed),
        );
    }

    #[test]
    fn validate_rejects_wrong_aad_len() {
        // 32 is a valid GCM AAD granularity but not the sealing
        // metadata size, so it must be rejected.
        let blob = masked_key_with_header(*b"AEAD", ALG_AES_GCM_256, 32);
        assert_eq!(
            validate_masked_sealing_key(HsmTransferKem::P384, &blob),
            Err(HsmError::MaskedKeyDecodeFailed),
        );
    }

    /// The wire public key is `x ‖ y` in the session's wire order; the
    /// DER SPKI must carry big-endian coordinates.
    #[test]
    fn pub_key_to_der_converts_coordinates() {
        let coord = SD_SEALING_PUB_KEY_LEN / 2;
        let mut raw = [0u8; SD_SEALING_PUB_KEY_LEN];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }

        for order in [WireOrder::Le, WireOrder::Be] {
            let der = sealing_pub_key_to_der(order, &raw).expect("encode der");
            let parsed = DerEccPublicKey::from_der(&der).expect("parse der");

            let mut x_be = raw[..coord].to_vec();
            let mut y_be = raw[coord..].to_vec();
            order.convert_in_place(&mut x_be);
            order.convert_in_place(&mut y_be);

            assert_eq!(parsed.curve(), EccCurve::P384);
            assert_eq!(parsed.x(), x_be.as_slice());
            assert_eq!(parsed.y(), y_be.as_slice());
        }
    }
}
