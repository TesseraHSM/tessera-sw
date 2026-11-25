// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stateless reseal; reports bind the client SD policy, not the SA policy.

use tsra_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_MAX_LEN;
pub use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;

/// Reseal opcode.
pub const TBOR_OP_SD_RESEAL_REMOTE_BACKUP: u8 = 0x0B;

/// Source PID chains and destination key attestation remain POTA-authorized.
#[tbor(opcode = 0x0B, pair = TborSdResealRemoteBackupResp)]
pub struct TborSdResealRemoteBackupReq<'a> {
    /// Active CO session.
    #[tbor(session_id)]
    pub session_id: SessionId,
    /// Actual source-envelope recipient key.
    #[tbor(align = 4, buffer, len = 280)]
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
    /// Source PID-signed Base envelope.
    #[tbor(buffer, len = 431)]
    pub src_remote_backup: &'a [u8],
}

/// Fresh recipient-bound, SA-PID-signed envelope.
#[tbor(response, pair = TborSdResealRemoteBackupReq)]
pub struct TborSdResealRemoteBackupResp<'a> {
    /// Destination PID-signed Base envelope.
    #[tbor(buffer, len = 431)]
    pub dst_remote_backup: &'a [u8],
}
