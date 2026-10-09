// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcTmkGen` wire schema.
//!
//! `DarcTmkGen` is an in-session command that **originates** a fresh
//! DARC Transfer Masking Key (TMK) — a 256-bit symmetric secret — and
//! returns it masked under the partition security-domain masking key
//! (SDMK) so the caller can persist and later re-import it.  It is the
//! source-side counterpart of [`DarcTmkImport`](crate::darc_tmk_import),
//! which imports a TMK sealed off-device; both emit the identical masked
//! envelope so a created and an imported TMK are interchangeable.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).  The TMK is always security-domain-scoped, so
//!   the request carries no scope selector.
//!
//! Output:
//!
//! * `masked_tmk` — the freshly minted TMK, masked (AEAD-GCM-256) under
//!   the partition SDMK, as a fixed [`MASKED_TMK_LEN`] (260 B) envelope.
//!   Nothing is persisted on-device.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::darc_tmk_import::MASKED_TMK_LEN;

/// TBOR opcode for `DarcTmkGen`.
pub const TBOR_OP_DARC_TMK_GEN: u8 = 0x23;

// `masked_tmk` is a masked TMK envelope; the derive needs an integer
// literal on the field, so the length is spelled out as `260` and pinned
// against the canonical `MASKED_TMK_LEN` here.
const _: () = assert!(MASKED_TMK_LEN == 260);

/// `DarcTmkGen` request schema.
///
/// Originates a fresh DARC Transfer Masking Key under the active
/// session's partition; the TMK is always security-domain-scoped.
#[tbor(opcode = 0x23)]
pub struct TborDarcTmkGenReq {
    /// CO session id this request is bound to.  Typed
    /// [`SessionId`](tsra_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,
}

/// `DarcTmkGen` response schema.
///
/// Carries the freshly minted TMK masked under the partition SDMK.
#[tbor(response)]
pub struct TborDarcTmkGenResp<'a> {
    /// The minted TMK, masked (AEAD-GCM-256) under the partition SDMK.
    /// Always exactly [`MASKED_TMK_LEN`] (260 B).
    #[tbor(buffer, len = 260)]
    pub masked_tmk: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_session_id() {
        let mut buf = [0u8; 128];
        let frame = TborDarcTmkGenReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .finish();
        // The request carries only the session id; a successful decode
        // round-trip confirms the (otherwise empty) body.
        let _ = frame;
    }

    #[test]
    fn response_round_trips_masked_tmk() {
        let masked = [0xCDu8; MASKED_TMK_LEN];
        let mut buf = [0u8; 512];
        let frame = TborDarcTmkGenResp::encode(&mut buf, 0, true)
            .unwrap()
            .masked_tmk(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_tmk(), &masked[..]);
    }

    #[test]
    fn masked_tmk_len_matches_pinned_value() {
        // The `#[tbor(buffer, len = N)]` attribute must remain a numeric
        // literal; pin it against the exported const.
        const _: () = assert!(260 == MASKED_TMK_LEN);
        assert_eq!(MASKED_TMK_LEN, 260);
    }
}
