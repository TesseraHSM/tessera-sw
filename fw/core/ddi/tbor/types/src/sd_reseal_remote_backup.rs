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
    /// POTA-authorized source PID identity chains.
    #[tbor(include)]
    pub src_evidence: IdentityEvidence<'a>,
    /// POTA-authorized destination SD-sealing PublicKey report.
    #[tbor(include)]
    pub dest_evidence: Evidence<'a>,
    /// Out-of-band complete source PID-signed Base envelope.
    #[tbor(buffer, len = 3)]
    pub src_remote_backup: &'a ReportDescriptor,
}

/// Fresh recipient-bound, SA-PID-signed envelope.
#[tbor(response, pair = TborSdResealRemoteBackupReq)]
pub struct TborSdResealRemoteBackupResp {
    /// Bytes of the complete destination PID-signed backup written to out-of-band item
    /// [`SD_BACKUP_REPORT_OOB_INDEX`](crate::SD_BACKUP_REPORT_OOB_INDEX).
    pub report_len: U16,
}
