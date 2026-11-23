// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EccSign` wire schema.
//!
//! `EccSign` is an in-session command that produces a raw ECDSA `r ‖ s`
//! signature over a host-supplied **pre-computed digest** using a
//! caller-held **masked** ECC private key (from
//! [`EccGenerateKey`](crate::ecc_generate_key) or imported via
//! [`UnwrapKey`](crate::unwrap_key)).  The device unmasks the key
//! on-device (recovering its curve from the key kind), signs, and returns
//! the signature.  Firmware does **no** hashing — the caller supplies the
//! digest.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `masked_key` — the masked ECC private key (unmasked in place).
//! * `hash_algo` — the [`HashAlgo`] that produced the digest: SHA-256,
//!   SHA-384 or SHA-512.
//! * `input` — the packed ECDSA operand `k ‖ digest`, in device byte order:
//!   a zero `k` lane of the curve's wire coordinate length (the device
//!   generates `k`), then the digest at the start of a zero-padded lane of
//!   `max(coordinate length, digest length rounded up to the lane pad)`.
//!   The device signs straight from it.
//!
//! Outputs:
//!
//! * `signature` — raw `r ‖ s`, each component in device byte order and
//!   sized to the curve's wire coordinate length (`r ‖ s` is 64 / 96 B for
//!   P-256 / P-384; 144 B big-endian or 136 B little-endian for P-521).

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::ecc_generate_key::MASKED_ECC_KEY_MAX_LEN;
pub use crate::ecc_generate_key::MASKED_ECC_KEY_MIN_LEN;
use crate::key_props::HashAlgo;

/// TBOR opcode for `EccSign`.
pub const TBOR_OP_ECC_SIGN: u8 = 0x18;

/// Maximum packed `k ‖ digest` input length (bytes): P-521 with 8-byte
/// padded lanes.  Pinned into the `#[tbor(align = 4, buffer, max_len = 144,
/// mutable)]` literal on [`TborEccSignReq::input`].
pub const ECC_SIGN_INPUT_MAX_LEN: usize = 144;

/// Maximum wire ECDSA signature length (`r ‖ s`, P-521 8-byte-padded big-endian lanes).  Pinned
/// into the `#[tbor(buffer, max_len = 144)]` literal on
/// [`TborEccSignResp::signature`].
pub const ECC_SIG_MAX_LEN: usize = 144;

/// `EccSign` request schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can `unmask` it **in
/// place** in the request buffer (via `decode_mut`) — no scratch copy — and
/// sign directly from the recovered key.
#[tbor(opcode = 0x18, pair = TborEccSignResp)]
pub struct TborEccSignReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Digest algorithm, 1-byte [`HashAlgo`].
    #[tbor(U8)]
    pub hash_algo: HashAlgo,

    /// The masked ECC private key (from `EccGenerateKey` / `UnwrapKey`), an
    /// AEAD-GCM-256 envelope of 264..=312 B.  Its kind recovers the curve.
    #[tbor(align = 4, buffer, min_len = 264, max_len = 312, mutable)]
    pub masked_key: &'a [u8],

    /// The packed `k ‖ digest` operand in device byte order (see the module
    /// docs).  `mutable` and word-aligned so the device signs from it in
    /// place.
    #[tbor(align = 4, buffer, max_len = 144, mutable)]
    pub input: &'a [u8],
}

/// `EccSign` response schema.
#[tbor(response, pair = TborEccSignReq)]
pub struct TborEccSignResp<'a> {
    /// Raw ECDSA `r ‖ s`, each component in device byte order and sized to
    /// the curve wire coordinate length: 64 / 96 B for P-256 / P-384;
    /// 144 B (big-endian) or 136 B (little-endian) for P-521.
    #[tbor(buffer, max_len = 144, mutable)]
    pub signature: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 512];
        let masked = [0x11u8; MASKED_ECC_KEY_MIN_LEN];
        let input = [0x22u8; 64];
        let frame = TborEccSignReq::encode(&mut buf, (1, 1))
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .hash_algo(HashAlgo::Sha256)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .input(&input)
            .unwrap()
            .finish();
        assert_eq!(frame.hash_algo(), HashAlgo::Sha256);
        assert_eq!(frame.input(), &input[..]);
    }

    #[test]
    fn response_round_trips_signature() {
        let mut buf = [0u8; 256];
        let sig = [0x33u8; ECC_SIG_MAX_LEN];
        let frame = TborEccSignResp::encode(&mut buf, (1, 1), 0, true)
            .unwrap()
            .signature(&sig)
            .unwrap()
            .finish();
        assert_eq!(frame.signature(), &sig[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(144 == ECC_SIGN_INPUT_MAX_LEN);
        const _: () = assert!(144 == ECC_SIG_MAX_LEN);
        assert_eq!(ECC_SIGN_INPUT_MAX_LEN, 144);
        assert_eq!(ECC_SIG_MAX_LEN, 144);
    }
}
