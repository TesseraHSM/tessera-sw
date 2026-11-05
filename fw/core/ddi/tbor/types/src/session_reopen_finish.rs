// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionReopenFinish` wire schema (session-reopen Phase 2).
//!
//! Identical to `SessionOpenFinish` plus the `bmk_session` returned by
//! the session's original open: the HSM unwraps it under
//! `BK_SESSION = KBKDF(BK_BOOT, "SESSION_BK", seed)` (with the original
//! `seed` carried in `seed_envelope`) to restore the session's
//! `masking_key` instead of generating a new one.

use tsra_fw_ddi_tbor_api::tbor;

/// `SessionReopenFinish` request.
#[tbor(opcode = 0x31, pair = TborSessionReopenFinishResp)]
pub struct TborSessionReopenFinishReq<'a> {
    /// Reopen-Pending session slot.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Phase-2 confirmation MAC (HMAC-SHA-384).
    #[tbor(buffer, len = 48)]
    pub mac_fin: &'a [u8],

    /// AEAD envelope carrying the session's original 32-byte seed.
    #[tbor(buffer, len = 72, mutable)]
    pub seed_envelope: &'a [u8],

    /// `bmk_session` from the session's previous open/reopen.
    #[tbor(buffer, max_len = 512, mutable)]
    pub bmk_session: &'a [u8],
}

/// `SessionReopenFinish` response.
#[tbor(response, pair = TborSessionReopenFinishReq)]
pub struct TborSessionReopenFinishResp<'a> {
    /// Fresh `bmk_session` wrapping the same `masking_key`.
    #[tbor(buffer, max_len = 512)]
    pub bmk_session: &'a [u8],
}
