// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdCreateRemoteBackup` command.
//!
//! `SdCreateRemoteBackup` is an **in-session Crypto Officer** command
//! that creates a new security domain under the active session's
//! partition from the caller-supplied unified `PartPolicy`, returning
//! the remote partition-owner-key backup (`pok_remote_backup`) together
//! with the local partition-owner-key backup (`pok_local_backup`) and the
//! security-domain masking-key backup (`sd_mk_backup`).
//!
//! Both wire schemas are shared with the firmware handler via
//! `tsra_fw_ddi_tbor_types::sd_create_remote_backup`; this module adds
//! the host-facing value types so [`exec_op_tbor`] returns owned
//! response values.
//!
//! [`exec_op_tbor`]: ../../tsra_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::evidence::ReportDescriptor;
use crate::tbor;
use crate::tbor_int::U16;
use crate::CertDescriptor;

/// TBOR opcode for `SdCreateRemoteBackup`.
pub const TBOR_OP_SD_CREATE_REMOTE_BACKUP: u8 = 0x0A;

/// Exact on-the-wire length of a **masked** security-domain blob (a
/// masked BKS3).  Retained as the shared length authority for the rest
/// of the Security-Domain backup family (`SdReseal`, `SdRestore*`), which
/// re-export it; **this** command's response is an HPKE Base seal sized
/// by [`POK_REMOTE_BACKUP_LEN`].
pub const MASKED_SD_LEN: usize = 280;

/// Exact on-the-wire length of the remote partition-owner-key backup (an
/// ES384 COSE_Sign1 containing `header(161) || enc(97) || ct(48) || tag(16)`). Mirrors
/// `tsra_fw_ddi_tbor_types::sd_create_remote_backup::
/// POK_REMOTE_BACKUP_LEN`; the firmware schema is the length authority.
pub const POK_REMOTE_BACKUP_LEN: usize = 431;
/// Largest complete backup: hybrid encrypted envelope and ML-DSA-87 signature.
pub const POK_REMOTE_BACKUP_MAX_LEN: usize = 6531;

/// Maximum complete signed SD-backup length.
pub const SD_BACKUP_REPORT_MAX_LEN: usize = POK_REMOTE_BACKUP_MAX_LEN;
/// Out-of-band item that receives the complete PID-signed backup of
/// `SdCreateRemoteBackup`, `SdCreatePeerBackup` and `SdResealRemoteBackup`;
/// request descriptors index the items after it.
pub const SD_BACKUP_REPORT_OOB_INDEX: usize = 0;

/// Maximum attestation / receiver key-report length accepted as evidence:
/// an ML-DSA-87 signature over a report attesting the largest key.
pub const SD_EVIDENCE_REPORT_MAX_LEN: usize = 8192;

/// Exact on-the-wire length of the security-domain masking-key backup
/// envelope (`SDMK` masked under `SDBMK`).  Mirrors the firmware
/// `LOCAL_MK_BACKUP_LEN`; the firmware schema is the length authority.
pub const SD_MK_BACKUP_LEN: usize = 264;

/// Host-facing TBOR `SdCreateRemoteBackup` request.
#[tbor(opcode = TBOR_OP_SD_CREATE_REMOTE_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdCreateRemoteBackupReq {
    /// CO session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Receiver key certificate-chain descriptors (spec `RcvrCertChain`).
    /// Always present; validated and anchored to the policy **SATA** key,
    /// its leaf public key is the recipient public key (`RcvrPub`) the
    /// remote backup is sealed to.  The DER bytes travel out of band.
    #[tbor(max_len = 24)]
    pub receiver_cert_chain: Vec<CertDescriptor>,

    /// Optional key report, signed by the receiver leaf, attesting the
    /// recipient's sealing KEM key.  Empty: the leaf P-384 key is used.
    #[tbor(max_len = 1)]
    pub receiver_key_report: Vec<ReportDescriptor>,

    /// Receiver manufacturer certificate-chain descriptors.  Flattened
    /// from the firmware `receiver_evidence` field group (first of its
    /// four TOC entries); the DER bytes travel out of band.
    #[tbor(max_len = 8)]
    pub receiver_mfgr_cert_chain: Vec<CertDescriptor>,

    /// Receiver owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub receiver_owner_cert_chain: Vec<CertDescriptor>,

    /// Receiver partition-owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub receiver_part_owner_cert_chain: Vec<CertDescriptor>,

    /// Receiver attestation-report (COSE_Sign1) descriptor.
    pub receiver_report: ReportDescriptor,

    /// Unified [`PartPolicy`] describing the security domain to create.
    /// Encoded as its deterministic CBOR document of at most 384 bytes.
    #[tbor(max_len = 384)]
    pub policy: Vec<u8>,
}

/// Host-facing TBOR `SdCreateRemoteBackup` response.
#[tbor(response)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdCreateRemoteBackupResp {
    /// Local partition-owner-key backup: the fresh BKS3 masked under the
    /// partition-local masking key (exactly [`MASKED_SD_LEN`] = 280 B on
    /// the wire).  Persisted by the host and replayed to recover the
    /// security domain locally.
    #[tbor(align = 4)]
    pub pok_local_backup: [u8; MASKED_SD_LEN],

    /// Security-domain masking-key backup: the freshly minted `SDMK`
    /// masked under the derived `SDBMK` (exactly [`SD_MK_BACKUP_LEN`] =
    /// 264 B on the wire).  Persisted by the host and replayed on restore.
    #[tbor(align = 4)]
    pub sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
    /// Bytes of the complete signed backup written to out-of-band item
    /// [`SD_BACKUP_REPORT_OOB_INDEX`](crate::SD_BACKUP_REPORT_OOB_INDEX).
    pub report_len: U16,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_and_policy() {
        let req = TborSdCreateRemoteBackupReq {
            session_id: 9,
            receiver_cert_chain: Vec::new(),
            receiver_key_report: Vec::new(),
            receiver_mfgr_cert_chain: Vec::new(),
            receiver_owner_cert_chain: Vec::new(),
            receiver_part_owner_cert_chain: Vec::new(),
            receiver_report: ReportDescriptor::default(),
            policy: alloc::vec![0; crate::policy::PART_POLICY_MAX_LEN],
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf, (1, 1)).expect("encode");

        // The crate::policy::PART_POLICY_MAX_LEN-byte policy image must be carried in the data section.
        assert!(
            frame.len() > crate::policy::PART_POLICY_MAX_LEN,
            "encoded frame must carry the policy"
        );
    }
}
