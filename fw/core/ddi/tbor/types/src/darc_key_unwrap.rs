// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcKeyUnwrap` wire schema.
//!
//! `DarcKeyUnwrap` is an in-session command that imports an
//! externally-generated **EC private key** that was:
//!
//! 1. encoded as an EC2 `COSE_Key` (see the internal COSE Key Definition
//!    Format spec), then
//! 2. AES-KWP (RFC 5649) wrapped under a DARC Transfer Masking Key (TMK),
//!    where
//! 3. the TMK itself is supplied as the **masked** envelope produced by
//!    [`DarcTmkImport`](crate::darc_tmk_import).
//!
//! The handler unmasks the TMK, AES-KWP-unwraps the COSE_Key, decodes the
//! EC private key, and re-masks it under the caller-chosen scope's masking
//! key — returning the masked private key plus its wire public key.  Only
//! the P-256 / P-384 / P-521 EC curves are supported.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the
//!   dispatcher.
//! * `scope` — the [`KeyScope`] whose masking key wraps the recovered
//!   key.  Restricted by the handler to `Ephemeral` / `Local`.
//! * `key_usage` — the requested [`KeyUsage`] permissions; the handler
//!   intersects these with the COSE_Key's own `key_ops` restriction.
//! * `masked_tmk` — the masked TMK envelope from `DarcTmkImport`, exactly
//!   [`MASKED_TMK_LEN`] (264 B); its masked-key kind must be
//!   [`DarcTmk`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind::DarcTmk).
//! * `wrapped_key` — the AES-KWP-wrapped EC2 `COSE_Key`, up to
//!   [`DARC_UNWRAP_WRAPPED_KEY_MAX_LEN`].
//!
//! Outputs:
//!
//! * `key_kind` — the recovered key's
//!   [`HsmVaultKeyKind`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind)
//!   discriminant (one of `Ecc{256,384,521}Private`).
//! * `masked_key` — the recovered EC private key, masked (AEAD-GCM-256)
//!   under the scope's masking key.
//! * `pub_key` — the recovered key's wire public key (`x ‖ y`, wire-LE).

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::darc_tmk_import::MASKED_TMK_LEN;
use crate::key_props::KeyScope;
use crate::key_props::KeyUsage;

/// TBOR opcode for `DarcKeyUnwrap`.
pub const TBOR_OP_DARC_KEY_UNWRAP: u8 = 0x22;

/// Max AES-KWP-wrapped `COSE_Key` length.  Sized for the largest
/// supported key: a P-521 EC2 private `COSE_Key` (`kty`, `kid`, `alg`,
/// `key_ops`, `crv`, and three 66-byte field elements) plus the AES-KWP
/// AIV / padding overhead.  Pinned into the `#[tbor(buffer, max_len =
/// 512)]` literal on [`TborDarcKeyUnwrapReq::wrapped_key`].
pub const DARC_UNWRAP_WRAPPED_KEY_MAX_LEN: usize = 512;

/// Max masked recovered-key envelope length: an AES-256-GCM `MaskedKey`
/// envelope around the largest EC vault scalar (P-521, 68 B) —
/// `header(8) + iv(16) + MaskedKeyMetadata aad(192) + ct(68) + tag(16)`
/// = 312 B.  Pinned into the `#[tbor(buffer, max_len = 312)]` literal on
/// [`TborDarcKeyUnwrapResp::masked_key`].
pub const DARC_UNWRAP_MASKED_KEY_MAX_LEN: usize = 8 + 16 + 192 + 80 + 16;

/// Max recovered public-key length (P-521 wire `x ‖ y`, each 68 B).
/// Pinned into the `#[tbor(buffer, max_len = 136)]` literal on
/// [`TborDarcKeyUnwrapResp::pub_key`].
pub const DARC_UNWRAP_PUB_KEY_MAX_LEN: usize = 2 * 68;

// Tripwires: keep the public length constants in lock-step with the
// `#[tbor(buffer, max_len = ...)]` literals below (the derive requires
// integer literals, so the two cannot share a symbol).
const _: () = assert!(DARC_UNWRAP_WRAPPED_KEY_MAX_LEN == 512);
const _: () = assert!(DARC_UNWRAP_MASKED_KEY_MAX_LEN == 312);
const _: () = assert!(DARC_UNWRAP_PUB_KEY_MAX_LEN == 136);
const _: () = assert!(MASKED_TMK_LEN == 264);

/// `DarcKeyUnwrap` request schema.
///
/// Imports an AES-KWP-wrapped EC2 `COSE_Key` private key under a DARC TMK
/// and re-masks it under the requested scope.
#[tbor(opcode = 0x22, pair = TborDarcKeyUnwrapResp)]
pub struct TborDarcKeyUnwrapReq<'a> {
    /// CO session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (masks the recovered key), 1-byte [`KeyScope`].
    /// The handler restricts this to `Ephemeral` / `Local`.
    #[tbor(U8)]
    pub scope: KeyScope,

    /// Requested key-usage permissions, [`KeyUsage`] bitfield (u64).  The
    /// handler intersects these with the COSE_Key's `key_ops`.
    #[tbor(U64)]
    pub key_usage: KeyUsage,

    /// The masked TMK envelope from `DarcTmkImport`, exactly
    /// [`MASKED_TMK_LEN`] (264 B).  Unmasked on-device to recover the
    /// 32-byte TMK used as the AES-KWP key.
    #[tbor(buffer, len = 264)]
    pub masked_tmk: &'a [u8],

    /// The AES-KWP-wrapped EC2 `COSE_Key`, up to
    /// [`DARC_UNWRAP_WRAPPED_KEY_MAX_LEN`] bytes.
    #[tbor(buffer, max_len = 512)]
    pub wrapped_key: &'a [u8],
}

/// `DarcKeyUnwrap` response schema.
#[tbor(response, pair = TborDarcKeyUnwrapReq)]
pub struct TborDarcKeyUnwrapResp<'a> {
    /// The recovered key's vault-kind discriminant (`HsmVaultKeyKind`);
    /// one of `Ecc{256,384,521}Private`.
    #[tbor(U8)]
    pub key_kind: u8,

    /// The recovered EC private key, masked (AEAD-GCM-256) under the
    /// scope's masking key.
    ///
    /// `#[tbor(mutable)]` so the handler can reserve the slot and mask the
    /// recovered key straight into it (`decode_mut`) — no scratch buffer.
    #[tbor(buffer, max_len = 312, mutable)]
    pub masked_key: &'a [u8],

    /// The recovered key's wire public key (`x ‖ y`, wire-LE).
    ///
    /// `#[tbor(mutable)]` so the handler can reserve the slot and derive
    /// the wire public key straight into it (`decode_mut`) — no scratch
    /// buffer, no copy.
    #[tbor(buffer, max_len = 136, mutable)]
    pub pub_key: &'a [u8],
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
        let wrapped = [0xA5u8; 240];
        let frame = TborDarcKeyUnwrapReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .key_usage(KeyUsage::from_bits(KeyUsage::SIGN | KeyUsage::VERIFY))
            .unwrap()
            .masked_tmk(&masked_tmk)
            .unwrap()
            .wrapped_key(&wrapped)
            .unwrap()
            .finish();

        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(
            frame.key_usage(),
            KeyUsage::from_bits(KeyUsage::SIGN | KeyUsage::VERIFY)
        );
        assert_eq!(frame.masked_tmk().len(), MASKED_TMK_LEN);
        assert_eq!(frame.wrapped_key(), &wrapped[..]);
    }

    #[test]
    fn response_round_trips_fields() {
        let mut buf = [0u8; 1024];
        let masked = [0xABu8; 200];
        let pub_key = [0xCDu8; 136];
        let frame = TborDarcKeyUnwrapResp::encode(&mut buf, 0, true)
            .unwrap()
            .key_kind(14)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .finish();
        assert_eq!(frame.key_kind(), 14);
        assert_eq!(frame.masked_key(), &masked[..]);
        assert_eq!(frame.pub_key(), &pub_key[..]);
    }
}
