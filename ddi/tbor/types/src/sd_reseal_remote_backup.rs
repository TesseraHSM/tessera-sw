// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdResealRemoteBackup` command.
//!
//! `SdResealRemoteBackup` is an **in-session** command run by a Sealing
//! Authority that **reseals** a remote security-domain backup from a source
//! recipient to a destination recipient: it HPKE-unseals the caller-supplied
//! `src_remote_backup` with the masked receiver key (recovering the BKS3)
//! and HPKE-reseals that BKS3 to the destination receiver, returning
//! one directly signed `dst_remote_backup` under the local PID.
//! The source report and destination PublicKey report bind the client SD
//! policy, which may differ from the SA-local policy.
//!
//! Both wire schemas are shared with the firmware handler via
//! `tsra_fw_ddi_tbor_types::sd_reseal_remote_backup`; this module adds
//! the host-facing value types so [`exec_op_tbor`] returns owned
//! response values. Source identity/operation evidence and destination
//! PublicKey evidence are flattened into descriptor fields below.
//!
//! [`exec_op_tbor`]: ../../tsra_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::evidence::ReportDescriptor;
use crate::tbor;
use crate::tbor_int::U16;
use crate::CertDescriptor;

/// TBOR opcode for `SdResealRemoteBackup`.
pub const TBOR_OP_SD_RESEAL_REMOTE_BACKUP: u8 = 0x0B;

/// Host-facing TBOR `SdResealRemoteBackup` request.
#[tbor(opcode = TBOR_OP_SD_RESEAL_REMOTE_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdResealRemoteBackupReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked SD-sealing key (from `SdSealingKeyGen`): 280 B (P-384), 296 B (ML-KEM-1024) or 264 B
    /// (MLKEM1024-P384).
    /// Unmasked on-device to recover the receiver's private HPKE key; never
    /// a vault handle.
    #[tbor(align = 4, min_len = 264, max_len = 296)]
    pub masked_sealing_key: Vec<u8>,

    /// Unified [`PartPolicy`] the source and destination must share.
    /// Encoded as its deterministic CBOR document of at most 384 bytes.
    #[tbor(max_len = 384)]
    pub policy: Vec<u8>,

    /// Source manufacturer certificate-chain descriptors.  Flattened from
    /// the firmware `src_evidence` field group (its three TOC entries); the
    /// DER bytes travel out of band.
    #[tbor(max_len = 8)]
    pub src_mfgr_cert_chain: Vec<CertDescriptor>,

    /// Source owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub src_owner_cert_chain: Vec<CertDescriptor>,

    /// Source partition-owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub src_part_owner_cert_chain: Vec<CertDescriptor>,

    /// Destination manufacturer certificate-chain descriptors.  Flattened
    /// from the firmware `dest_evidence` field group (its four TOC
    /// entries).
    #[tbor(max_len = 8)]
    pub dest_mfgr_cert_chain: Vec<CertDescriptor>,

    /// Destination owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub dest_owner_cert_chain: Vec<CertDescriptor>,

    /// Destination partition-owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub dest_part_owner_cert_chain: Vec<CertDescriptor>,

    /// Destination attestation-report (COSE_Sign1) descriptor.
    pub dest_report: ReportDescriptor,

    /// Out-of-band complete source PID-signed backup.
    pub src_remote_backup: ReportDescriptor,
}

/// Host-facing TBOR `SdResealRemoteBackup` response.
#[tbor(response)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdResealRemoteBackupResp {
    /// Bytes of the complete destination PID-signed backup written to out-of-band item
    /// [`SD_BACKUP_REPORT_OOB_INDEX`](crate::SD_BACKUP_REPORT_OOB_INDEX).
    pub report_len: U16,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
    use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;

    #[test]
    fn request_encodes_session_policy_and_src_remote_backup() {
        let req = TborSdResealRemoteBackupReq {
            session_id: 9,
            masked_sealing_key: alloc::vec![0u8; MASKED_SEALING_KEY_LEN],
            policy: alloc::vec![0; crate::policy::PART_POLICY_MAX_LEN],
            src_mfgr_cert_chain: Vec::new(),
            src_owner_cert_chain: Vec::new(),
            src_part_owner_cert_chain: Vec::new(),
            dest_mfgr_cert_chain: Vec::new(),
            dest_owner_cert_chain: Vec::new(),
            dest_part_owner_cert_chain: Vec::new(),
            dest_report: ReportDescriptor::default(),
            src_remote_backup: ReportDescriptor {
                index: 0,
                length: U16::new(POK_REMOTE_BACKUP_LEN as u16),
            },
        };

        let mut buf = [0u8; 2048];
        let frame = req.encode_request(&mut buf, (1, 1)).expect("encode");

        assert!(
            frame.len() > crate::policy::PART_POLICY_MAX_LEN + MASKED_SEALING_KEY_LEN,
            "encoded frame must carry the policy and key"
        );
    }
}
