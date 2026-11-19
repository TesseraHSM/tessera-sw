// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `PartInitWithObk` command.
//!
//! `PartInitWithObk` is a CO-session command that provisions a partition
//! from the masked owner backup key (MOBK) UEFI sealed with the TPM,
//! replacing the v1 `EstablishCredential` provisioning step: the host
//! opens a session first, then provisions.  It carries the MOBK in an
//! AEAD envelope under the session `param_key`, the partition-owner trust
//! anchor (POTA) endorsement of the partition identity, and an optional
//! prior `local_mk` backup to restore; it returns the current `local_mk`
//! backup.  See `tsra_fw_ddi_tbor_types::part_init_with_obk` for the full
//! wire schema.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `PartInitWithObk`.
pub const TBOR_OP_PART_INIT_WITH_OBK: u8 = 0x30;

/// AAD label prefix bound into the `mobk_envelope` AAD.
pub const PART_INIT_OBK_AAD_LABEL: &[u8; 16] = b"part-init-obk-v1";

/// Total AAD length bound into the `mobk_envelope` (label + session_id LE +
/// zero-padding).
pub const PART_INIT_OBK_AAD_LEN: usize = 32;

/// Maximum length of the MOBK (masked BK3) plaintext.
pub const OBK_MOBK_MAX_LEN: usize = 512;

/// Maximum on-the-wire length of the `mobk_envelope`
/// (`header(8) + iv(16) + aad(32) + ct(MOBK) + tag(16)`).
pub const OBK_MOBK_ENVELOPE_MAX_LEN: usize = 8 + 16 + PART_INIT_OBK_AAD_LEN + OBK_MOBK_MAX_LEN + 16;

/// Length of the raw POTA public key (`x ‖ y`, device byte order).
pub const OBK_POTA_PUB_KEY_LEN: usize = 96;

/// Length of the raw POTA endorsement signature (`r ‖ s`, device byte order).
pub const OBK_POTA_SIG_LEN: usize = 96;

// The TBOR derive requires integer literals for `max_len`; pin each literal
// below to its constant so the two cannot silently drift.
const _: () = assert!(OBK_MOBK_ENVELOPE_MAX_LEN == 584);
const _: () = assert!(OBK_POTA_PUB_KEY_LEN == 96);
const _: () = assert!(OBK_POTA_SIG_LEN == 96);

/// Builds the 32-byte AEAD AAD bound into a `PartInitWithObk` MOBK
/// envelope.
///
/// Layout: [`PART_INIT_OBK_AAD_LABEL`] (16 B) `‖ session_id` (2 B LE)
/// `‖ rsv0` (14 B).
///
/// This is the **single source of truth** for the host-side AAD layout; the
/// FW handler builds the identical layout via its own helper of the same
/// name.
#[must_use]
pub fn build_part_init_with_obk_aad(session_id: u16) -> [u8; PART_INIT_OBK_AAD_LEN] {
    let mut aad = [0u8; PART_INIT_OBK_AAD_LEN];
    aad[..PART_INIT_OBK_AAD_LABEL.len()].copy_from_slice(PART_INIT_OBK_AAD_LABEL);
    aad[PART_INIT_OBK_AAD_LABEL.len()..PART_INIT_OBK_AAD_LABEL.len() + 2]
        .copy_from_slice(&session_id.to_le_bytes());
    aad
}

/// Host-facing TBOR `PartInitWithObk` request.
///
/// Field sizes are pinned to the FW schema; passing a slice of the wrong
/// length produces a host-side encode error before the request reaches the
/// device (the fixed-length POTA fields are enforced by the firmware
/// decoder).
#[tbor(opcode = TBOR_OP_PART_INIT_WITH_OBK, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborPartInitWithObkReq {
    /// CO session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// AEAD-GCM envelope wrapping the MOBK under the active session's
    /// `param_key`, with the AAD from [`build_part_init_with_obk_aad`].
    #[tbor(max_len = 584)]
    pub mobk_envelope: Vec<u8>,

    /// POTA public key: raw P-384 `x ‖ y` in device byte order.
    #[tbor(max_len = 96)]
    pub pota_pub_key: Vec<u8>,

    /// POTA endorsement signature over `SHA-384(0x04 ‖ PID public key)`:
    /// raw P-384 `r ‖ s` in device byte order.
    #[tbor(max_len = 96)]
    pub pota_sig: Vec<u8>,

    /// Optional previously-generated `local_mk` backup to restore.  Empty
    /// on first provisioning.
    #[tbor(max_len = 264)]
    pub prev_local_mk_backup: Vec<u8>,
}

/// Host-facing TBOR `PartInitWithObk` response.
///
/// The byte field is an owned `Vec<u8>` so callers don't have to carry
/// max-sized padding buffers around.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborPartInitWithObkResp {
    /// Current `local_mk` backup envelope.
    #[tbor(max_len = 264)]
    pub local_mk_backup: Vec<u8>,
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
}
