// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `DarcKeyUnwrap` command.
//!
//! `DarcKeyUnwrap` is an **in-session** Crypto-Officer command that
//! imports an externally-generated EC private key — encoded as an EC2
//! `COSE_Key` and AES-KWP-wrapped under a DARC Transfer Masking Key
//! (TMK) — and re-masks it under the requested scope's masking key.  The
//! TMK is supplied as the masked envelope produced by `DarcTmkImport`.
//!
//! The `scope` is a raw 1-byte discriminant and `key_usage` is a raw
//! `u64` bitfield (the firmware types them as the `KeyScope` open-enum and
//! the `KeyUsage` bitfield; this host crate is firewalled from the
//! firmware PAL types).  The device intersects `key_usage` with the
//! COSE_Key's own `key_ops` restriction.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `DarcKeyUnwrap`.
pub const TBOR_OP_DARC_KEY_UNWRAP: u8 = 0x22;

/// On-the-wire length of the masked TMK envelope from `DarcTmkImport`
/// (matches the firmware schema's `MASKED_TMK_LEN`).  Kept module-private
/// to avoid an ambiguous glob re-export with `darc_tmk_import`'s public
/// `MASKED_TMK_LEN`; callers use that one.
const MASKED_TMK_LEN: usize = 260;

/// Max AES-KWP-wrapped `COSE_Key` length (matches the firmware schema's
/// `DARC_UNWRAP_WRAPPED_KEY_MAX_LEN`).
pub const DARC_UNWRAP_WRAPPED_KEY_MAX_LEN: usize = 512;

/// Max masked recovered-key envelope length (matches the firmware
/// schema's `DARC_UNWRAP_MASKED_KEY_MAX_LEN`).
pub const DARC_UNWRAP_MASKED_KEY_MAX_LEN: usize = 296;

/// Max recovered public-key length (matches the firmware schema's
/// `DARC_UNWRAP_PUB_KEY_MAX_LEN`).
pub const DARC_UNWRAP_PUB_KEY_MAX_LEN: usize = 136;

/// `KeyScope` discriminant for an ephemeral key.
pub const KEY_SCOPE_EPHEMERAL: u8 = 0b010;
/// `KeyScope` discriminant for a partition-local key.
pub const KEY_SCOPE_LOCAL: u8 = 0b011;

/// Host-facing TBOR `DarcKeyUnwrap` request.
///
/// Field sizes are pinned to the FW schema; passing a slice of the wrong
/// length produces a host-side encode error before the request reaches
/// the device.
#[tbor(opcode = TBOR_OP_DARC_KEY_UNWRAP, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborDarcKeyUnwrapReq {
    /// CO session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope (masks the recovered key), 1-byte `KeyScope`
    /// (see `KEY_SCOPE_*`).  The device restricts this to `Ephemeral` /
    /// `Local`.
    pub scope: u8,

    /// Requested key-usage permissions, `KeyUsage` bitfield (u64) (see
    /// `KEY_USAGE_*`).  The device intersects these with the COSE_Key's
    /// `key_ops`.
    pub key_usage: u64,

    /// The masked TMK envelope from `DarcTmkImport`, exactly
    /// [`MASKED_TMK_LEN`] (260 B).
    pub masked_tmk: [u8; MASKED_TMK_LEN],

    /// The AES-KWP-wrapped EC2 `COSE_Key`.
    #[tbor(max_len = 512)]
    pub wrapped_key: Vec<u8>,
}

/// Host-facing TBOR `DarcKeyUnwrap` response.
///
/// The byte fields are owned `Vec<u8>` so callers don't have to carry
/// max-sized padding buffers around.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborDarcKeyUnwrapResp {
    /// The recovered key's vault-kind discriminant (one of
    /// `Ecc{256,384,521}Private`).
    pub key_kind: u8,

    /// The recovered EC private key, masked under the scope's masking key.
    #[tbor(max_len = 296)]
    pub masked_key: Vec<u8>,

    /// The recovered key's wire public key (`x ‖ y`, wire-LE).
    #[tbor(max_len = 136)]
    pub pub_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::KEY_USAGE_SIGN;
    use crate::KEY_USAGE_VERIFY;

    #[test]
    fn request_encodes_fields() {
        let req = TborDarcKeyUnwrapReq {
            session_id: 7,
            scope: KEY_SCOPE_LOCAL,
            key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
            masked_tmk: [0x5Au8; MASKED_TMK_LEN],
            wrapped_key: alloc::vec![0xA5u8; 240],
        };
        let mut buf = [0u8; 2048];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.len() > MASKED_TMK_LEN + 240,
            "encoded frame must carry the masked TMK and wrapped key",
        );
    }
}
