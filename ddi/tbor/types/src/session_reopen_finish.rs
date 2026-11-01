// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SessionReopenFinish` command
//! (session-reopen Phase 2).

use alloc::vec::Vec;

use crate::tbor;
use crate::MAC_FIN_LEN;
use crate::SEED_ENVELOPE_LEN;

/// TBOR opcode for `SessionReopenFinish`.
pub const TBOR_OP_SESSION_REOPEN_FINISH: u8 = 0x31;

/// Host-facing TBOR `SessionReopenFinish` request.
///
/// Same as [`TborSessionOpenFinishReq`](crate::TborSessionOpenFinishReq)
/// plus the session's prior `bmk_session`.  `seed_envelope` must carry
/// the session's **original** seed: the HSM unwraps `bmk_session` under
/// `BK_SESSION = KBKDF(BK_BOOT, "SESSION_BK", seed)` to restore the
/// session's `masking_key`.
#[tbor(opcode = TBOR_OP_SESSION_REOPEN_FINISH, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSessionReopenFinishReq {
    /// Reopen-Pending session.
    #[tbor(session_id)]
    pub session_id: u16,
    /// Phase-2 confirmation MAC.
    pub mac_fin: [u8; MAC_FIN_LEN],
    /// AEAD envelope carrying the session's original seed.
    pub seed_envelope: [u8; SEED_ENVELOPE_LEN],
    /// `bmk_session` from the session's previous open/reopen.
    pub bmk_session: Vec<u8>,
}

impl Default for TborSessionReopenFinishReq {
    fn default() -> Self {
        Self {
            session_id: 0,
            mac_fin: [0u8; MAC_FIN_LEN],
            seed_envelope: [0u8; SEED_ENVELOPE_LEN],
            bmk_session: Vec::new(),
        }
    }
}

/// Host-facing TBOR `SessionReopenFinish` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSessionReopenFinishResp {
    /// Fresh `bmk_session` wrapping the same `masking_key`.
    pub bmk_session: Vec<u8>,
}
