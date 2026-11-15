// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Create an SD with an HPKE Base envelope (P-384, ML-KEM-1024 or
//! MLKEM1024-P384 recipient) and a PID-signed SdBackup report.

use tsra_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::part_final::LOCAL_MK_BACKUP_LEN;
pub use crate::policy::PART_POLICY_MAX_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_MAX_LEN;
use crate::tbor_int::U16;

/// Create-remote opcode.
pub const TBOR_OP_SD_CREATE_REMOTE_BACKUP: u8 = 0x0A;
/// Local masked BKS3; masking format is unchanged.
pub const MASKED_SD_LEN: usize = 280;
/// Canonical SD header, encapsulation, BKS3 ciphertext, and tag.
pub const POK_REMOTE_BACKUP_LEN: usize = 161 + 97 + 48 + 16;
/// Largest remote-backup envelope (MLKEM1024-P384 encapsulation).
pub const POK_REMOTE_BACKUP_MAX_LEN: usize = 161 + 1665 + 48 + 16;
/// Maximum PID-signed SD operation-report length: an ML-DSA-87 signature
/// (4627 B) over the fixed SdBackup payload.
pub const SD_BACKUP_REPORT_MAX_LEN: usize = 5120;
/// Out-of-band item that receives the PID-signed SdBackup report of
/// `SdCreateRemoteBackup`, `SdCreatePeerBackup` and `SdResealRemoteBackup`;
/// request descriptors index the items after it.
pub const SD_BACKUP_REPORT_OOB_INDEX: usize = 0;

/// Maximum attestation / receiver key-report length accepted as evidence:
/// an ML-DSA-87 signature over a report attesting the largest key.
pub const SD_EVIDENCE_REPORT_MAX_LEN: usize = 8192;
/// Local masked SDMK; masking format is unchanged.
pub const SD_MK_BACKUP_LEN: usize = LOCAL_MK_BACKUP_LEN;

/// Create an SD on its policy-designated backing partition.
#[tbor(opcode = 0x0A, pair = TborSdCreateRemoteBackupResp)]
pub struct TborSdCreateRemoteBackupReq<'a> {
    /// Active CO session.
    #[tbor(session_id)]
    pub session_id: SessionId,
    /// Always-required SATA-authorized recipient certificate chain.
    #[tbor(buffer, max_len = 24)]
    pub receiver_cert_chain: &'a [CertDescriptor],
    /// Optional (0 or 1 descriptor) key report signed by the receiver leaf
    /// that attests its sealing KEM key (P-384, ML-KEM-1024 or
    /// MLKEM1024-P384).  Absent: the receiver leaf P-384 key is the
    /// recipient.
    #[tbor(buffer, max_len = 3)]
    pub receiver_key_report: &'a [ReportDescriptor],
    /// Optional SAPOTA recipient-key attestation; required by trusted-SA policy.
    #[tbor(include)]
    pub receiver_evidence: Evidence<'a>,
    /// Bound SD policy.
    #[tbor(buffer, max_len = 384)]
    pub policy: &'a [u8],
}

/// Persist and transport the report with the remote envelope.
#[tbor(response, pair = TborSdCreateRemoteBackupReq)]
pub struct TborSdCreateRemoteBackupResp<'a> {
    /// HPKE Base envelope of BKS3 (length depends on the recipient KEM).
    #[tbor(align = 4, buffer, min_len = 322, max_len = 1890, mutable)]
    pub pok_remote_backup: &'a [u8],
    /// Unchanged local BKS3 backup.
    #[tbor(align = 4, buffer, len = 280, mutable)]
    pub pok_local_backup: &'a [u8],
    /// Unchanged local SDMK backup.
    #[tbor(align = 4, buffer, len = 264, mutable)]
    pub sd_mk_backup: &'a [u8],
    /// Bytes of the PID-signed SdBackup report (with the SD policy hash)
    /// written to out-of-band item [`SD_BACKUP_REPORT_OOB_INDEX`].
    pub report_len: U16,
}
