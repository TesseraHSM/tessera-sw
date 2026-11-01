// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SessionReopenInit` command
//! (session-reopen Phase 1).

use crate::tbor;
use crate::tbor_int::U8;
use crate::MAC_RESP_LEN;
use crate::PK_INIT_LEN;
use crate::PK_RESP_LEN;
use crate::SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256;

/// TBOR opcode for `SessionReopenInit`.
pub const TBOR_OP_SESSION_REOPEN_INIT: u8 = 0x30;

/// Host-facing TBOR `SessionReopenInit` request.
///
/// Re-runs the [`TborSessionOpenInitReq`](crate::TborSessionOpenInitReq)
/// handshake against an existing session that needs renegotiation (for
/// example after a partition reset).  The PSK is the one currently
/// bound to the session's role (implied by `session_id`); the HPKE
/// info, transcript and MAC labels are identical to `SessionOpenInit`.
#[tbor(opcode = TBOR_OP_SESSION_REOPEN_INIT, session_ctrl = in_session)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborSessionReopenInitReq {
    /// Session to reopen.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Channel-level integrity profile; must match the session role.
    pub session_type: U8,

    /// Cryptographic suite identifier.
    pub suite_id: U8,

    /// Per-handshake ephemeral public key supplied by the VM.
    pub pk_init: [u8; PK_INIT_LEN],
}

impl Default for TborSessionReopenInitReq {
    fn default() -> Self {
        Self {
            session_id: 0,
            session_type: 1,
            suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
            pk_init: [0u8; PK_INIT_LEN],
        }
    }
}

/// Host-facing TBOR `SessionReopenInit` response.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborSessionReopenInitResp {
    /// HSM's HPKE response ephemeral.
    pub pk_resp: [u8; PK_RESP_LEN],
    /// Phase-1 confirmation MAC.
    pub mac_resp: [u8; MAC_RESP_LEN],
}
