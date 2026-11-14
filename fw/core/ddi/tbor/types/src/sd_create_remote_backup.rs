// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Create an SD with a P-384 Base envelope and a PID-signed SdBackup report.

use tsra_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::part_final::LOCAL_MK_BACKUP_LEN;
pub use crate::policy::PART_POLICY_MAX_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;

/// Create-remote opcode.
pub const TBOR_OP_SD_CREATE_REMOTE_BACKUP: u8 = 0x0A;
/// Local masked BKS3; masking format is unchanged.
pub const MASKED_SD_LEN: usize = 280;
/// Canonical SD header, encapsulation, BKS3 ciphertext, and tag.
pub const POK_REMOTE_BACKUP_LEN: usize = 161 + 97 + 48 + 16;
/// Maximum signed SD operation-report length.
pub const SD_BACKUP_REPORT_MAX_LEN: usize = 896;
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
    /// P-384 HPKE Base envelope of BKS3.
    #[tbor(buffer, len = 322)]
    pub pok_remote_backup: &'a [u8],
    /// Unchanged local BKS3 backup.
    #[tbor(align = 4, buffer, len = 280)]
    pub pok_local_backup: &'a [u8],
    /// Unchanged local SDMK backup.
    #[tbor(align = 4, buffer, len = 264)]
    pub sd_mk_backup: &'a [u8],
    /// PID-signed SdBackup report with the SD policy hash.
    #[tbor(buffer, min_len = 1, max_len = 896)]
    pub report: &'a [u8],
}
