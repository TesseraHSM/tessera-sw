// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stateless reseal; reports bind the client SD policy, not the SA policy.

use tsra_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_MAX_LEN;
pub use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
pub use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_MAX_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_MAX_LEN;
use crate::tbor_int::U16;

/// Reseal opcode.
pub const TBOR_OP_SD_RESEAL_REMOTE_BACKUP: u8 = 0x0B;

/// Source PID chains and destination key attestation remain POTA-authorized.
#[tbor(opcode = 0x0B, pair = TborSdResealRemoteBackupResp)]
pub struct TborSdResealRemoteBackupReq<'a> {
    /// Active CO session.
    #[tbor(session_id)]
    pub session_id: SessionId,
    /// Actual source-envelope recipient key.
    #[tbor(align = 4, buffer, min_len = 264, max_len = 296)]
    pub masked_sealing_key: &'a [u8],
    /// Client SD policy shared by source report and destination evidence.
    #[tbor(buffer, max_len = 384)]
    pub policy: &'a [u8],
    /// POTA-authorized PID chains and the source SdBackup report.
    #[tbor(include)]
    pub src_evidence: Evidence<'a>,
    /// POTA-authorized destination SD-sealing PublicKey report.
    #[tbor(include)]
    pub dest_evidence: Evidence<'a>,
    /// Source Base envelope.
    #[tbor(buffer, min_len = 322, max_len = 1890)]
    pub src_remote_backup: &'a [u8],
}

/// Fresh recipient-bound envelope and SA-PID-signed report.
#[tbor(response, pair = TborSdResealRemoteBackupReq)]
pub struct TborSdResealRemoteBackupResp<'a> {
    /// Destination Base envelope.
    #[tbor(align = 4, buffer, min_len = 322, max_len = 1890, mutable)]
    pub dst_remote_backup: &'a [u8],
    /// Bytes of the sdBackup report binding the request's SD policy written to out-of-band item
    /// [`SD_BACKUP_REPORT_OOB_INDEX`](crate::SD_BACKUP_REPORT_OOB_INDEX).
    pub report_len: U16,
}
