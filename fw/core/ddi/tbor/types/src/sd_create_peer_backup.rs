// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Clone a local SD seed to an authorized same-policy peer.

use tsra_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_MAX_LEN;
pub use crate::sd_create_remote_backup::MASKED_SD_LEN;
pub use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;

/// Create-peer opcode.
pub const TBOR_OP_SD_CREATE_PEER_BACKUP: u8 = 0x0E;

/// Stateless peer export; no sender sealing key is needed.
#[tbor(opcode = 0x0E, pair = TborSdCreatePeerBackupResp)]
pub struct TborSdCreatePeerBackupReq<'a> {
    /// Active CO session.
    #[tbor(session_id)]
    pub session_id: SessionId,
    /// Bound SD policy, permitting peer cloning.
    #[tbor(buffer, max_len = 384)]
    pub policy: &'a [u8],
    /// POTA-authorized recipient PublicKey report with matching policy.
    #[tbor(include)]
    pub dst_evidence: Evidence<'a>,
    /// Local BKS3 backup.
    #[tbor(align = 4, buffer, len = 280)]
    pub pok_local_backup: &'a [u8],
}

/// Directly signed peer envelope.
#[tbor(response, pair = TborSdCreatePeerBackupReq)]
pub struct TborSdCreatePeerBackupResp<'a> {
    /// PID-signed P-384 HPKE Base envelope.
    #[tbor(buffer, len = 431)]
    pub pok_peer_backup: &'a [u8],
}
