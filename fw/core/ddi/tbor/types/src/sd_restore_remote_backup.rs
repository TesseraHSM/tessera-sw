// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Restore an SD after validating its signed operation and policy binding.

use tsra_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_MAX_LEN;
pub use crate::sd_create_remote_backup::MASKED_SD_LEN;
pub use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
pub use crate::sd_create_remote_backup::SD_MK_BACKUP_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;

/// Restore-remote opcode.
pub const TBOR_OP_SD_RESTORE_REMOTE_BACKUP: u8 = 0x0C;

/// SATA is not a sender trust anchor. Without trusted-SA policy, the supplied
/// PID public key establishes signature integrity, not authenticated identity.
#[tbor(opcode = 0x0C, pair = TborSdRestoreRemoteBackupResp)]
pub struct TborSdRestoreRemoteBackupReq<'a> {
    /// Active CO session.
    #[tbor(session_id)]
    pub session_id: SessionId,
    /// Actual recipient private key, masked locally.
    #[tbor(align = 4, buffer, len = 280)]
    pub masked_sealing_key: &'a [u8],
    /// Bound SD policy.
    #[tbor(buffer, max_len = 384)]
    pub policy: &'a [u8],
    /// SEC1 uncompressed P-384 operation-report signer: 0x04 || X_be || Y_be.
    #[tbor(buffer, len = 97)]
    pub sender_pid_pub_key: &'a [u8],
    /// Always-required SdBackup report; identity chains are SAPOTA-checked
    /// only when the policy requires trusted SA identity.
    #[tbor(include)]
    pub sender_evidence: Evidence<'a>,
    /// Canonical Base envelope.
    #[tbor(buffer, len = 322)]
    pub src_remote_backup: &'a [u8],
    /// Existing SDMK backup, authenticated by the recovered BKS3 derivation.
    #[tbor(buffer, len = 264)]
    pub prev_sd_mk_backup: &'a [u8],
}

/// Unchanged local restore outputs.
#[tbor(response, pair = TborSdRestoreRemoteBackupReq)]
pub struct TborSdRestoreRemoteBackupResp<'a> {
    /// Local BKS3 backup.
    #[tbor(align = 4, buffer, len = 280)]
    pub pok_local_backup: &'a [u8],
    /// Refreshed SDMK backup.
    #[tbor(align = 4, buffer, len = 264)]
    pub sd_mk_backup: &'a [u8],
}
