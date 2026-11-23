// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SessionClose` command.

use crate::tbor;

/// TBOR opcode for `SessionClose`.
pub const TBOR_OP_SESSION_CLOSE: u8 = 0x05;

/// Host-facing TBOR `SessionClose` request.
#[tbor(opcode = TBOR_OP_SESSION_CLOSE, session_ctrl = close)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborSessionCloseReq {
    /// Session identifier to tear down.
    #[tbor(session_id)]
    pub session_id: u16,
}

/// Host-facing TBOR `SessionClose` response (empty ack).
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborSessionCloseResp;

/// Explicit plaintext cleanup, accepted only for a renegotiating slot.
#[tbor(opcode = TBOR_OP_SESSION_CLOSE, session_ctrl = no_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborSessionClosePlainReq {
    /// Partition-local stale session identifier.
    #[tbor(session_id)]
    pub session_id: u16,
}

/// Plaintext close uses the same acknowledgement as protected close.
pub type TborSessionClosePlainResp = TborSessionCloseResp;
