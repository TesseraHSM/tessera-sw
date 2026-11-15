// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Peer restore requires POTA-authorized PID evidence and matching SD policy.

use tsra_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_MAX_LEN;
pub use crate::sd_create_remote_backup::MASKED_SD_LEN;
pub use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
pub use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_MAX_LEN;
pub use crate::sd_create_remote_backup::SD_MK_BACKUP_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_MAX_LEN;

/// Restore-peer opcode.
pub const TBOR_OP_SD_RESTORE_PEER_BACKUP: u8 = 0x0F;

/// One-shot SD restoration with peer cloning permitted by the bound policy.
#[tbor(opcode = 0x0F, pair = TborSdRestorePeerBackupResp)]
pub struct TborSdRestorePeerBackupReq<'a> {
    /// Active CO session.
    #[tbor(session_id)]
    pub session_id: SessionId,
    /// Actual recipient's masked key.
    #[tbor(align = 4, buffer, min_len = 264, max_len = 296)]
    pub masked_sealing_key: &'a [u8],
    /// Bound SD policy.
    #[tbor(buffer, max_len = 384)]
    pub policy: &'a [u8],
    /// Source PID chains and its mandatory SdBackup operation report.
    #[tbor(include)]
    pub src_evidence: Evidence<'a>,
    /// Canonical peer envelope.
    #[tbor(buffer, min_len = 322, max_len = 1890)]
    pub pok_peer_backup: &'a [u8],
    /// Existing SDMK backup.
    #[tbor(buffer, len = 264)]
    pub prev_sd_mk_backup: &'a [u8],
}

/// Unchanged local provisioning outputs.
#[tbor(response, pair = TborSdRestorePeerBackupReq)]
pub struct TborSdRestorePeerBackupResp<'a> {
    /// Local BKS3 backup.
    #[tbor(align = 4, buffer, len = 280, mutable)]
    pub pok_local_backup: &'a [u8],
    /// Refreshed SDMK backup.
    #[tbor(align = 4, buffer, len = 264, mutable)]
    pub sd_mk_backup: &'a [u8],
}
