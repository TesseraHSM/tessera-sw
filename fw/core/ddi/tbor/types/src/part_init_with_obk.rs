// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PartInitWithObk` wire schema — owner-backup-key (OBK)
//! partition provisioning.
//!
//! `PartInitWithObk` is a CO-session command that provisions a partition
//! from the masked owner backup key (MOBK) that UEFI sealed with the TPM,
//! instead of the policy / PTA flow of
//! [`PartInit`](crate::part_init) + [`PartFinal`](crate::part_final).  It
//! replaces the v1 `EstablishCredential` provisioning step for a v2
//! session: the host opens a session first, then provisions.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried CO session id; cross-checked against the
//!   SQE-carried session id (parity with the other in-session commands).
//! * `mobk_envelope` — the MOBK (BK3 masked under the partition's
//!   `BK_BOOT`), wrapped in an AEAD-GCM envelope under the active session's
//!   `param_key`.  The MOBK is the TPM-unsealed content of the blob UEFI
//!   stored with `SetSealedBk3`.
//! * `pota_pub_key` / `pota_sig` — the partition-owner trust anchor (POTA)
//!   endorsement of the partition identity: a P-384 public key and its
//!   signature over `SHA-384(0x04 ‖ PID public key)`.  Both are carried in
//!   the device byte order (see the TBOR README, "Crypto operand byte
//!   order").
//! * `prev_local_mk_backup` — optional `local_mk` backup to restore.  An
//!   **empty** field means absent: the handler then generates a fresh
//!   `local_mk`.
//!
//! Outputs:
//!
//! * `local_mk_backup` — the current `local_mk` backup envelope, to be
//!   persisted by the host and replayed as `prev_local_mk_backup` on
//!   subsequent launches (the OBK analogue of the v1 BMK).
//!
//! ## AEAD envelope contents
//!
//! Wrapped by [`tsra_fw_core_crypto_aead_envelope`] (AES-256-GCM) under the
//! active session's `param_key`:
//!
//! * **AAD** (wire-embedded, **32 bytes**, authenticated plaintext — length
//!   pinned to satisfy the AEAD crate's 32-byte AAD granularity):
//!     * `"part-init-obk-v1"` (16 B) — domain/version label.
//!     * `session_id` (2 B little-endian) — binds the envelope to the
//!       active session.
//!     * reserved-zero (14 B) — padding to 32 B.
//! * **Plaintext**: the MOBK, at most [`OBK_MOBK_MAX_LEN`] bytes.

use tsra_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `PartInitWithObk`.
pub const TBOR_OP_PART_INIT_WITH_OBK: u8 = 0x30;

/// Domain/version label embedded in the AEAD envelope's AAD that wraps the
/// MOBK.  Pinned per spec to bind the envelope to this command + version.
pub const PART_INIT_OBK_AAD_LABEL: &[u8; 16] = b"part-init-obk-v1";

/// Length of the AAD bound into the MOBK AEAD envelope.
///
/// Pinned to 32 B to satisfy the AEAD-envelope crate's AAD-granularity
/// invariant.  Layout: `label(16) ‖ session_id(2 LE) ‖ rsv0(14)`.
pub const PART_INIT_OBK_AAD_LEN: usize = 32;

/// Maximum length of the MOBK (masked BK3) plaintext.
///
/// The MOBK is a v1 AES-CBC-256 + HMAC-SHA-384 `MaskedKey` envelope around
/// the 48-byte BK3.  The TPM-sealed blob that carries it is capped at 512 B
/// (`SEALED_BK3_MAX_LEN`) and is strictly larger than the MOBK it wraps, so
/// 512 B bounds the MOBK.
pub const OBK_MOBK_MAX_LEN: usize = 512;

/// Maximum on-the-wire length of the wrapped `mobk_envelope`:
/// `header(8) + iv(16) + aad(32) + ct(MOBK) + tag(16)`.
pub const OBK_MOBK_ENVELOPE_MAX_LEN: usize = 8 + 16 + PART_INIT_OBK_AAD_LEN + OBK_MOBK_MAX_LEN + 16;

/// Length of the raw POTA public key (`x ‖ y`, two 48-byte P-384
/// coordinates in device byte order).
pub const OBK_POTA_PUB_KEY_LEN: usize = 96;

/// Length of the raw POTA endorsement signature (`r ‖ s`, two 48-byte
/// P-384 components in device byte order).
pub const OBK_POTA_SIG_LEN: usize = 96;

// The TBOR derive requires integer literals for `len` / `max_len`, so the
// fields below hardcode them; pin each literal to its constant so the two
// cannot silently drift.
const _: () = assert!(OBK_MOBK_ENVELOPE_MAX_LEN == 584);
const _: () = assert!(OBK_POTA_PUB_KEY_LEN == 96);
const _: () = assert!(OBK_POTA_SIG_LEN == 96);
const _: () = assert!(crate::part_final::LOCAL_MK_BACKUP_LEN == 264);

/// `PartInitWithObk` request schema.
///
/// Provisions the partition from the OBK: verifies the POTA endorsement of
/// the partition identity, unmasks BK3 from the MOBK, derives the local
/// masking-key backup key from BK3 and the POTA public key, and generates
/// — or restores from `prev_local_mk_backup` — the partition local masking
/// key.
#[tbor(opcode = 0x30, pair = TborPartInitWithObkResp)]
pub struct TborPartInitWithObkReq<'a> {
    /// CO session id this request is bound to.  Typed
    /// [`SessionId`](tsra_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// AEAD-GCM envelope wrapping the MOBK under the active session's
    /// `param_key`.  Length bounded by [`OBK_MOBK_ENVELOPE_MAX_LEN`]; see
    /// the module docs for the AAD layout.
    ///
    /// Marked `#[tbor(mutable)]` so the FW handler can AEAD-open the
    /// envelope in place — the field is exposed as the `mobk_envelope`
    /// member of the generated `TborPartInitWithObkReqViewMut` view.
    #[tbor(buffer, max_len = 584, mutable)]
    pub mobk_envelope: &'a [u8],

    /// POTA public key: raw P-384 `x ‖ y` in device byte order.  Fixed
    /// length [`OBK_POTA_PUB_KEY_LEN`]; a malformed length is rejected at
    /// decode with `TborInvalidFixedLength`.
    #[tbor(buffer, len = 96)]
    pub pota_pub_key: &'a [u8],

    /// POTA endorsement signature over `SHA-384(0x04 ‖ PID public key)`:
    /// raw P-384 `r ‖ s` in device byte order.  Fixed length
    /// [`OBK_POTA_SIG_LEN`].
    #[tbor(buffer, len = 96)]
    pub pota_sig: &'a [u8],

    /// Optional previously-generated `local_mk` backup envelope to
    /// restore.  An **empty** field means absent; when present it is
    /// exactly [`LOCAL_MK_BACKUP_LEN`](crate::part_final::LOCAL_MK_BACKUP_LEN)
    /// (264 B).
    ///
    /// Marked `#[tbor(mutable)]` so the handler can AEAD-unmask the
    /// envelope **in place** in the request buffer.
    #[tbor(buffer, max_len = 264, mutable)]
    pub prev_local_mk_backup: &'a [u8],
}

/// `PartInitWithObk` response schema.
///
/// Carries the current `local_mk` backup envelope.
#[tbor(response, pair = TborPartInitWithObkReq)]
pub struct TborPartInitWithObkResp<'a> {
    /// Current `local_mk` backup envelope.  Always exactly
    /// [`LOCAL_MK_BACKUP_LEN`](crate::part_final::LOCAL_MK_BACKUP_LEN)
    /// (264 B).
    #[tbor(buffer, len = 264)]
    pub local_mk_backup: &'a [u8],
}

/// Builds the 32-byte AEAD AAD bound into a `PartInitWithObk` MOBK
/// envelope.
///
/// Layout: [`PART_INIT_OBK_AAD_LABEL`] (16 B) `‖ session_id` (2 B LE)
/// `‖ rsv0` (14 B).
///
/// This is the **single source of truth** for the AAD layout on the
/// firmware side; the host wrapper constructs the identical layout, and a
/// host test cross-validates the two.
#[must_use]
pub fn build_part_init_with_obk_aad(session_id: u16) -> [u8; PART_INIT_OBK_AAD_LEN] {
    let mut aad = [0u8; PART_INIT_OBK_AAD_LEN];
    aad[..PART_INIT_OBK_AAD_LABEL.len()].copy_from_slice(PART_INIT_OBK_AAD_LABEL);
    aad[PART_INIT_OBK_AAD_LABEL.len()..PART_INIT_OBK_AAD_LABEL.len() + 2]
        .copy_from_slice(&session_id.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_layout_label_then_session_id_le_then_zero_padding() {
        let aad = build_part_init_with_obk_aad(0x1234);
        assert_eq!(&aad[..16], PART_INIT_OBK_AAD_LABEL);
        assert_eq!(&aad[16..18], &[0x34, 0x12]);
        assert!(aad[18..].iter().all(|&b| b == 0));
        assert_eq!(aad.len(), PART_INIT_OBK_AAD_LEN);
    }

    #[test]
    fn aad_binds_the_session_id() {
        assert_ne!(
            build_part_init_with_obk_aad(1),
            build_part_init_with_obk_aad(2)
        );
    }

    #[test]
    fn envelope_cap_fits_tbor_data_limits() {
        // TBOR `MAX_DATA_SIZE` is 8191; the request must stay well below it.
        const { assert!(OBK_MOBK_ENVELOPE_MAX_LEN + 2 * 96 + 264 < 8191) };
    }
}
