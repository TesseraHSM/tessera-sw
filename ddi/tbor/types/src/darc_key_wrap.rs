// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `DarcKeyWrap` command.
//!
//! `DarcKeyWrap` is an **in-session** Crypto-Officer command that exports
//! a local EC private key by AES-KWP-wrapping it — encoded as an EC2
//! `COSE_Key` — under a DARC Transfer Masking Key (TMK).  It is the
//! source-side mirror of `DarcKeyUnwrap`: the resulting `wrapped_key` is
//! byte-compatible with what `DarcKeyUnwrap` consumes.
//!
//! The device unmasks the TMK and the local masked EC private key,
//! re-derives the public key, encodes the EC2 private `COSE_Key` (its
//! `key_ops` derived from the key's own vault attributes, its `alg` from
//! the curve, and its `kid` set to the key's masked-key label), then
//! AES-KWP-wraps it under the TMK.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `DarcKeyWrap`.
pub const TBOR_OP_DARC_KEY_WRAP: u8 = 0x25;

/// On-the-wire length of the masked TMK envelope (matches the firmware
/// schema's `MASKED_TMK_LEN`).  Kept module-private to avoid an ambiguous
/// glob re-export with `darc_tmk_import`'s public `MASKED_TMK_LEN`;
/// callers use that one.
const MASKED_TMK_LEN: usize = 260;

/// Max masked EC private-key envelope length accepted as input (matches
/// the firmware schema's `DARC_UNWRAP_MASKED_KEY_MAX_LEN`).
pub const DARC_WRAP_MASKED_KEY_MAX_LEN: usize = 296;

/// Max AES-KWP-wrapped `COSE_Key` length returned (matches the firmware
/// schema's `DARC_UNWRAP_WRAPPED_KEY_MAX_LEN`).
pub const DARC_WRAP_WRAPPED_KEY_MAX_LEN: usize = 512;

/// Host-facing TBOR `DarcKeyWrap` request.
///
/// Field sizes are pinned to the FW schema; passing a slice of the wrong
/// length produces a host-side encode error before the request reaches
/// the device.
#[tbor(opcode = TBOR_OP_DARC_KEY_WRAP, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborDarcKeyWrapReq {
    /// CO session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked TMK envelope from `DarcTmkImport`/`DarcTmkGen`, exactly
    /// [`MASKED_TMK_LEN`] (260 B).
    pub masked_tmk: [u8; MASKED_TMK_LEN],

    /// The local masked EC private key to export (from `EccGenerateKey` /
    /// `DarcKeyUnwrap`); its masked-key kind must be one of
    /// `Ecc{256,384,521}Private`.
    #[tbor(max_len = 296)]
    pub masked_key: Vec<u8>,
}

/// Host-facing TBOR `DarcKeyWrap` response.
///
/// The byte field is an owned `Vec<u8>` so callers don't have to carry
/// max-sized padding buffers around.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborDarcKeyWrapResp {
    /// The AES-KWP-wrapped EC2 `COSE_Key` — byte-for-byte what
    /// `DarcKeyUnwrap` consumes.
    #[tbor(max_len = 512)]
    pub wrapped_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborDarcKeyWrapReq {
            session_id: 7,
            masked_tmk: [0x5Au8; MASKED_TMK_LEN],
            masked_key: alloc::vec![0xA5u8; 120],
        };
        let mut buf = [0u8; 2048];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.len() > MASKED_TMK_LEN + 120,
            "encoded frame must carry the masked TMK and masked key",
        );
    }
}
