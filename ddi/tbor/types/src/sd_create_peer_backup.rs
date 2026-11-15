// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdCreatePeerBackup` command.
//!
//! `SdCreatePeerBackup` is an **in-session** command that creates a
//! peer-transferable backup of a security domain: it
//! recovers BKS3 from the caller's device-local backup (`pok_local_backup`)
//! and HPKE Base-seals it to the destination peer named by `dst_evidence`,
//! returning the envelope and PID-signed `SdBackup` report.
//! Peer cloning is gated by the security
//! domain's `allow_peer_cloning` policy flag.
//!
//! Both wire schemas are shared with the firmware handler via
//! `tsra_fw_ddi_tbor_types::sd_create_peer_backup`; this module adds the
//! host-facing value types so [`exec_op_tbor`] returns owned response
//! values.  The firmware splices the destination attestation evidence in
//! as an `Evidence` field group; the host derive has no field-group
//! support, so this wrapper spells those four TOC entries out explicitly
//! as the `dst_*` cert-chain / report descriptor fields.
//!
//! [`exec_op_tbor`]: ../../tsra_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::evidence::ReportDescriptor;
use crate::sd_create_remote_backup::MASKED_SD_LEN;
use crate::tbor;
use crate::tbor_int::U16;
use crate::CertDescriptor;

/// TBOR opcode for `SdCreatePeerBackup`.
pub const TBOR_OP_SD_CREATE_PEER_BACKUP: u8 = 0x0E;

/// Host-facing TBOR `SdCreatePeerBackup` request.
#[tbor(opcode = TBOR_OP_SD_CREATE_PEER_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdCreatePeerBackupReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Unified [`PartPolicy`] describing the security domain being backed
    /// up.  Encoded as its deterministic CBOR document of at most 384 bytes.
    #[tbor(max_len = 384)]
    pub policy: Vec<u8>,

    /// Destination manufacturer certificate-chain descriptors.  Flattened
    /// from the firmware `dst_evidence` field group (first of its four TOC
    /// entries); the DER bytes travel out of band.
    #[tbor(max_len = 8)]
    pub dst_mfgr_cert_chain: Vec<CertDescriptor>,

    /// Destination owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub dst_owner_cert_chain: Vec<CertDescriptor>,

    /// Destination partition-owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub dst_part_owner_cert_chain: Vec<CertDescriptor>,

    /// Destination attestation-report (COSE_Sign1) descriptor.
    pub dst_report: ReportDescriptor,

    /// Device-local partition-owner-key backup (a masked BKS3 wrapped under
    /// `PartLocalMK`) from which BKS3 is recovered.  Exactly
    /// [`MASKED_SD_LEN`] (280 B); the firmware schema is the length
    /// authority.
    #[tbor(align = 4)]
    pub pok_local_backup: [u8; MASKED_SD_LEN],
}

/// Host-facing TBOR `SdCreatePeerBackup` response.
#[tbor(response)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdCreatePeerBackupResp {
    /// Peer backup: an HPKE Base seal of BKS3: [`POK_REMOTE_BACKUP_LEN`](crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN)
    /// (322 B) for a P-384 recipient, up to
    /// [`POK_REMOTE_BACKUP_MAX_LEN`](crate::sd_create_remote_backup::POK_REMOTE_BACKUP_MAX_LEN)
    /// for ML-KEM-1024 / MLKEM1024-P384.
    #[tbor(align = 4, min_len = 322, max_len = 1890)]
    pub pok_peer_backup: Vec<u8>,
    /// Bytes of the PID-signed SdBackup report written to out-of-band item
    /// [`SD_BACKUP_REPORT_OOB_INDEX`](crate::SD_BACKUP_REPORT_OOB_INDEX).
    pub report_len: U16,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborSdCreatePeerBackupReq {
            session_id: 9,
            policy: alloc::vec![0; crate::policy::PART_POLICY_MAX_LEN],
            dst_mfgr_cert_chain: Vec::new(),
            dst_owner_cert_chain: Vec::new(),
            dst_part_owner_cert_chain: Vec::new(),
            dst_report: ReportDescriptor::default(),
            pok_local_backup: [0xABu8; MASKED_SD_LEN],
        };

        let mut buf = [0u8; 2048];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The crate::policy::PART_POLICY_MAX_LEN-byte policy plus the sealing key and the backup must be
        // carried in the data section.
        assert!(
            frame.len() > crate::policy::PART_POLICY_MAX_LEN + MASKED_SD_LEN,
            "encoded frame must carry the policy, key, and backup"
        );
    }
}
