// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionReopenInit` wire schema (session-reopen Phase 1).
//!
//! Re-runs the `SessionOpenInit` HPKE handshake against an existing
//! session slot that needs renegotiation (e.g. after a partition
//! disable/NSSR).  The role (and so the PSK) is implied by the
//! session id; on success the slot becomes Pending under the same id.

use tsra_fw_ddi_tbor_api::tbor;

use crate::SessionKind;
use crate::SuiteId;

/// `SessionReopenInit` request.
#[tbor(opcode = 0x30, pair = TborSessionReopenInitResp)]
pub struct TborSessionReopenInitReq<'a> {
    /// Session slot to reopen; must need renegotiation.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Channel-level integrity profile; must match the session role.
    #[tbor(U8)]
    pub session_type: SessionKind,

    /// Cryptographic suite.
    #[tbor(U8)]
    pub suite_id: SuiteId,

    /// VM's per-handshake ephemeral public key (SEC1 uncompressed).
    #[tbor(buffer, len = 97)]
    pub pk_init: &'a [u8],
}

/// `SessionReopenInit` response.
#[tbor(response, pair = TborSessionReopenInitReq)]
pub struct TborSessionReopenInitResp<'a> {
    /// HSM's HPKE response ephemeral.
    #[tbor(buffer, len = 97)]
    pub pk_resp: &'a [u8],

    /// Phase-1 confirmation MAC.
    #[tbor(buffer, len = 48)]
    pub mac_resp: &'a [u8],
}
