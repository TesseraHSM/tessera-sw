// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcKeyWrap` wire schema.
//!
//! `DarcKeyWrap` is the source-side mirror of
//! [`DarcKeyUnwrap`](crate::darc_key_unwrap): it exports a local EC
//! private key by AES-KWP (RFC 5649) wrapping it — encoded as an EC2
//! `COSE_Key` — under a DARC Transfer Masking Key (TMK), producing a
//! `wrapped_key` byte-compatible with what `DarcKeyUnwrap` consumes.
//!
//! The handler unmasks the TMK and the local masked EC private key,
//! re-derives the public key, encodes the EC2 private `COSE_Key` (its
//! `key_ops` derived from the key's own vault attributes, its `alg` from
//! the curve, and its `kid` set to the key's masked-key label), then
//! AES-KWP-wraps it under the TMK.  Only the P-256 / P-384 / P-521 EC
//! curves are supported.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the
//!   dispatcher.
//! * `masked_tmk` — the masked TMK envelope from `DarcTmkImport`/
//!   `DarcTmkGen`, exactly [`MASKED_TMK_LEN`] (260 B); its masked-key
//!   kind must be
//!   [`DarcTmk`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind::DarcTmk).
//! * `masked_key` — the local masked EC private key to export, up to
//!   [`DARC_UNWRAP_MASKED_KEY_MAX_LEN`] (296 B); its masked-key kind must
//!   be one of `Ecc{256,384,521}Private`.
//!
//! Output:
//!
//! * `wrapped_key` — the AES-KWP-wrapped EC2 `COSE_Key`, up to
//!   [`DARC_UNWRAP_WRAPPED_KEY_MAX_LEN`] (512 B).

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::darc_key_unwrap::DARC_UNWRAP_MASKED_KEY_MAX_LEN;
pub use crate::darc_key_unwrap::DARC_UNWRAP_WRAPPED_KEY_MAX_LEN;
pub use crate::darc_tmk_import::MASKED_TMK_LEN;

/// TBOR opcode for `DarcKeyWrap`.
pub const TBOR_OP_DARC_KEY_WRAP: u8 = 0x25;

// Tripwires: keep the shared length constants in lock-step with the
// `#[tbor(buffer, ... = ...)]` literals below (the derive requires integer
// literals, so the two cannot share a symbol).
const _: () = assert!(MASKED_TMK_LEN == 260);
const _: () = assert!(DARC_UNWRAP_MASKED_KEY_MAX_LEN == 296);
const _: () = assert!(DARC_UNWRAP_WRAPPED_KEY_MAX_LEN == 512);

/// `DarcKeyWrap` request schema.
///
/// Exports a local masked EC private key as an AES-KWP-wrapped EC2
/// `COSE_Key` under a DARC TMK.
#[tbor(opcode = 0x25, pair = TborDarcKeyWrapResp)]
pub struct TborDarcKeyWrapReq<'a> {
    /// CO session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The masked TMK envelope from `DarcTmkImport`/`DarcTmkGen`, exactly
    /// [`MASKED_TMK_LEN`] (260 B).  Unmasked on-device to recover the
    /// 32-byte TMK used as the AES-KWP key.
    #[tbor(buffer, len = 260)]
    pub masked_tmk: &'a [u8],

    /// The local masked EC private key to export, up to
    /// [`DARC_UNWRAP_MASKED_KEY_MAX_LEN`] (296 B).  Unmasked on-device;
    /// its masked-key kind must be one of `Ecc{256,384,521}Private`.
    #[tbor(buffer, max_len = 296)]
    pub masked_key: &'a [u8],
}

/// `DarcKeyWrap` response schema.
#[tbor(response, pair = TborDarcKeyWrapReq)]
pub struct TborDarcKeyWrapResp<'a> {
    /// The AES-KWP-wrapped EC2 `COSE_Key`, up to
    /// [`DARC_UNWRAP_WRAPPED_KEY_MAX_LEN`] (512 B).  Byte-for-byte what
    /// `DarcKeyUnwrap` consumes.
    #[tbor(buffer, max_len = 512)]
    pub wrapped_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 1024];
        let masked_tmk = [0x5Au8; MASKED_TMK_LEN];
        let masked_key = [0xA5u8; 120];
        let frame = TborDarcKeyWrapReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .masked_tmk(&masked_tmk)
            .unwrap()
            .masked_key(&masked_key)
            .unwrap()
            .finish();

        assert_eq!(frame.masked_tmk().len(), MASKED_TMK_LEN);
        assert_eq!(frame.masked_key(), &masked_key[..]);
    }

    #[test]
    fn response_round_trips_fields() {
        let mut buf = [0u8; 1024];
        let wrapped = [0xCDu8; 240];
        let frame = TborDarcKeyWrapResp::encode(&mut buf, 0, false)
            .unwrap()
            .wrapped_key(&wrapped)
            .unwrap()
            .finish();
        assert_eq!(frame.wrapped_key(), &wrapped[..]);
    }
}
