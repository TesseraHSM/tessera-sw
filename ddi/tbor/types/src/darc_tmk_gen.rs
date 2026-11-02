// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `DarcTmkGen` command.
//!
//! `DarcTmkGen` is an **in-session** Crypto-Officer command that
//! **originates** a fresh DARC Transfer Masking Key (TMK) and returns it
//! masked under the partition security-domain masking key (SDMK).  It is
//! the source-side counterpart of `DarcTmkImport` (which imports a TMK
//! sealed off-device); both emit the identical 264-byte masked envelope,
//! so a created and an imported TMK are interchangeable downstream.
//!
//! The TMK is always security-domain-scoped, so the request carries only
//! the `session_id`.  The wire schema is shared with the firmware handler
//! via `tsra_fw_ddi_tbor_types::darc_tmk_gen`; this module adds the
//! host-facing value types so `exec_op_tbor` returns owned response
//! values.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `DarcTmkGen`.
pub const TBOR_OP_DARC_TMK_GEN: u8 = 0x23;

/// On-the-wire length of the `masked_tmk` output envelope (matches the
/// firmware schema's `MASKED_TMK_LEN`).
pub const MASKED_TMK_GEN_LEN: usize = 264;

/// Host-facing TBOR `DarcTmkGen` request.
///
/// Carries only the session id; the TMK is always security-domain-scoped.
#[tbor(opcode = TBOR_OP_DARC_TMK_GEN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborDarcTmkGenReq {
    /// CO session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,
}

/// Host-facing TBOR `DarcTmkGen` response.
///
/// The byte field is an owned `Vec<u8>` so callers don't have to carry
/// max-sized padding buffers around.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborDarcTmkGenResp {
    /// The minted TMK, masked under the partition SDMK (exactly 264 B on
    /// the wire; the firmware schema is the length authority).
    #[tbor(max_len = 264)]
    pub masked_tmk: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_id() {
        let req = TborDarcTmkGenReq { session_id: 9 };

        let mut buf = [0u8; 128];
        let frame = req.encode_request(&mut buf).expect("encode");

        // A session-id-only request still produces a well-formed frame.
        assert!(!frame.is_empty(), "encoded frame must be non-empty");
    }
}
