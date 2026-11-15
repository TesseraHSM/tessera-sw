// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdRestoreRemoteBackup` command.
//!
//! `SdRestoreRemoteBackup` is an **in-session** command that restores a
//! security domain from a **remote** backup: it
//! verifies the mandatory `SdBackup` report and target policy before
//! HPKE Base-opening with the actual recipient key, recovers `SDMK`
//! from `prev_sd_mk_backup`, and returns the
//! device-local backups (`pok_local_backup`, `sd_mk_backup`).
//! SAPOTA authenticates source PID identity only under trusted-SA policy;
//! otherwise the supplied PID key establishes signature integrity only.
//!
//! Both wire schemas are shared with the firmware handler via
//! `tsra_fw_ddi_tbor_types::sd_restore_remote_backup`; this module
//! adds the host-facing value types so [`exec_op_tbor`] returns owned
//! response values.
//!
//! [`exec_op_tbor`]: ../../tsra_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::evidence::ReportDescriptor;
use crate::sd_create_remote_backup::SD_MK_BACKUP_LEN;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `SdRestoreRemoteBackup`.
pub const TBOR_OP_SD_RESTORE_REMOTE_BACKUP: u8 = 0x0C;

/// Length of a raw P-384 sender PID key (`X || Y`).
pub const SENDER_PID_P384_LEN: usize = 96;

/// Length of an encoded ML-DSA-87 sender PID key.
pub const SENDER_PID_MLDSA87_LEN: usize = 2592;

/// Host-facing TBOR `SdRestoreRemoteBackup` request.
#[tbor(opcode = TBOR_OP_SD_RESTORE_REMOTE_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdRestoreRemoteBackupReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The receiver's masked SD-sealing key (from `SdSealingKeyGen`):
    /// 280 B (P-384), 296 B (ML-KEM-1024) or 264 B
    /// (MLKEM1024-P384).  Unmasked on-device to recover the receiver's
    /// private HPKE key (`RcvrPriv`).
    #[tbor(align = 4, min_len = 264, max_len = 296)]
    pub masked_sealing_key: Vec<u8>,

    /// Unified [`PartPolicy`] describing the security domain being
    /// restored.  Encoded as its deterministic CBOR document of at most 384 bytes.
    #[tbor(max_len = 384)]
    pub policy: Vec<u8>,

    /// Operation report signer PID: raw big-endian P-384 X || Y
    /// ([`SENDER_PID_P384_LEN`], 96 B) or an encoded ML-DSA-87 key
    /// ([`SENDER_PID_MLDSA87_LEN`], 2592 B).
    #[tbor(min_len = 96, max_len = 2592)]
    pub sender_pid_pub_key: Vec<u8>,

    /// Sender manufacturer certificate-chain descriptors.  Flattened from
    /// the firmware `sender_evidence` field group (first of its four TOC
    /// entries); the DER bytes travel out of band.
    #[tbor(max_len = 8)]
    pub sender_mfgr_cert_chain: Vec<CertDescriptor>,

    /// Sender owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub sender_owner_cert_chain: Vec<CertDescriptor>,

    /// Sender partition-owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub sender_part_owner_cert_chain: Vec<CertDescriptor>,

    /// Mandatory SdBackup operation-report (COSE_Sign1) descriptor.
    pub sender_report: ReportDescriptor,

    /// Remote backup to restore: an HPKE Base seal of BKS3: [`POK_REMOTE_BACKUP_LEN`](crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN)
    /// (322 B) for a P-384 recipient, up to
    /// [`POK_REMOTE_BACKUP_MAX_LEN`](crate::sd_create_remote_backup::POK_REMOTE_BACKUP_MAX_LEN)
    /// for ML-KEM-1024 / MLKEM1024-P384.
    #[tbor(min_len = 322, max_len = 1890)]
    pub src_remote_backup: Vec<u8>,

    /// Previous security-domain masking-key backup (SDMK masked under the
    /// derived SDBMK), exactly [`SD_MK_BACKUP_LEN`] (264 B), from which
    /// `SDMK` is recovered.
    pub prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
}

/// Host-facing TBOR `SdRestoreRemoteBackup` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdRestoreRemoteBackupResp {
    /// Partition-owner-key backup re-wrapped under the device-local key
    /// (exactly 280 B on the wire; the firmware schema is the length
    /// authority).
    #[tbor(align = 4, max_len = 280)]
    pub pok_local_backup: Vec<u8>,

    /// Security-domain masking-key backup envelope (exactly 264 B on the
    /// wire; the firmware schema is the length authority).
    #[tbor(align = 4, max_len = 264)]
    pub sd_mk_backup: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
    use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;

    #[test]
    fn request_encodes_all_fields() {
        let req = TborSdRestoreRemoteBackupReq {
            session_id: 9,
            masked_sealing_key: alloc::vec![0u8; MASKED_SEALING_KEY_LEN],
            policy: alloc::vec![0; crate::policy::PART_POLICY_MAX_LEN],
            sender_pid_pub_key: alloc::vec![0; SENDER_PID_P384_LEN],
            sender_mfgr_cert_chain: Vec::new(),
            sender_owner_cert_chain: Vec::new(),
            sender_part_owner_cert_chain: Vec::new(),
            sender_report: ReportDescriptor::default(),
            src_remote_backup: alloc::vec![0xABu8; POK_REMOTE_BACKUP_LEN],
            prev_sd_mk_backup: [0xCDu8; SD_MK_BACKUP_LEN],
        };

        let mut buf = [0u8; 2048];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The crate::policy::PART_POLICY_MAX_LEN-byte policy plus the sealing key and the two backups must
        // be carried in the data section.
        assert!(
            frame.len()
                > crate::policy::PART_POLICY_MAX_LEN
                    + MASKED_SEALING_KEY_LEN
                    + POK_REMOTE_BACKUP_LEN
                    + SD_MK_BACKUP_LEN,
            "encoded frame must carry the policy, key, and backups"
        );
    }
}
