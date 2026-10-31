// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesEncryptDecrypt` wire schema.
//!
//! `AesEncryptDecrypt` is an in-session command that AES encrypts or
//! decrypts a host-supplied message in any [`AesMode`] (CBC, ECB, CFB-128,
//! OFB or CTR) using a caller-held **masked** AES key (the `masked_key`
//! from [`AesGenerateKey`](crate::aes_generate_key) or imported via
//! [`UnwrapKey`](crate::unwrap_key)).  The device unmasks the key
//! on-device (verifying the AEAD tag), runs the AES transform, and returns
//! the transformed message plus the output chaining IV so the host can
//! chain subsequent calls — the TBOR analogue of MBOR `AesEncryptDecrypt`
//! (which remains CBC/ECB only), keyed by a masked blob rather than a vault
//! `key_id`.  Nothing is persisted.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//! * `op` — the [`AesOp`] selecting encrypt or decrypt.
//! * `mode` — the [`AesMode`].
//! * `iv` — the input IV: empty for ECB, otherwise [`AES_IV_LEN`] bytes
//!   (the initial counter block for CTR).
//! * `msg` — the message to transform: non-empty, up to
//!   [`AES_MSG_MAX_LEN`] bytes, and a multiple of the 16-byte AES block for
//!   CBC / ECB.
//! * `masked_key` — the masked AES key (an AEAD-GCM-256 envelope,
//!   [`MASKED_AES_KEY_MIN_LEN`]..=[`MASKED_AES_KEY_MAX_LEN`] B).  Its
//!   scope (read from the cleartext, tag-bound metadata) selects the
//!   masking key; the key kind confirms it is an AES key.
//!
//! The request carries `[iv | msg]` contiguously and the response
//! `[msg | iv]` at the same payload offset, so the device transforms the
//! request bytes in place (the tiger `AesOp` buffer layout).
//!
//! Outputs:
//!
//! * `msg` — the transformed message (same length as the input).
//! * `iv` — the output chaining IV (same length as the input `iv`):
//!
//!   | Mode | Output IV                                         |
//!   |------|---------------------------------------------------|
//!   | CBC  | last ciphertext block                             |
//!   | ECB  | empty                                             |
//!   | CFB  | last complete ciphertext block (input IV if none) |
//!   | OFB  | last keystream block                              |
//!   | CTR  | next counter block (128-bit big-endian increment) |

use open_enum::open_enum;
use tsra_fw_ddi_tbor_api::tbor;

pub use crate::aes_generate_key::MASKED_AES_KEY_MAX_LEN;
pub use crate::aes_generate_key::MASKED_AES_KEY_MIN_LEN;

/// TBOR opcode for `AesEncryptDecrypt`.
pub const TBOR_OP_AES_ENCRYPT_DECRYPT: u8 = 0x16;

/// AES block size in bytes — also the IV length for every mode but ECB.
pub const AES_IV_LEN: usize = 16;

/// Maximum message length (bytes) accepted by `AesEncryptDecrypt`,
/// matching the MBOR `AesEncryptDecrypt` command's message bound.  Pinned
/// into the `#[tbor(buffer, max_len = 1024)]` literals on
/// [`TborAesEncryptDecryptReq::msg`] / [`TborAesEncryptDecryptResp::msg`].
pub const AES_MSG_MAX_LEN: usize = 1024;

/// AES encrypt / decrypt operation selector on the TBOR wire.
///
/// The 1-byte discriminants mirror the MBOR `DdiAesOp` values
/// (`Encrypt = 1`, `Decrypt = 2`).  Kept as an [`open_enum`] so an
/// unrecognized discriminant round-trips as `AesOp(x)` and is rejected
/// on-device rather than failing to decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesOp {
    /// Encrypt the message.
    Encrypt = 1,

    /// Decrypt the message.
    Decrypt = 2,
}

/// AES confidentiality mode on the TBOR wire.
///
/// The 1-byte discriminants match the PAL `HsmAesMode` (and the tiger
/// `AesMode`).  Kept as an [`open_enum`] so an unrecognized discriminant
/// round-trips as `AesMode(x)` and is rejected on-device rather than
/// failing to decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesMode {
    /// Cipher block chaining.
    Cbc = 0,

    /// Electronic codebook (no IV).
    Ecb = 1,

    /// 128-bit cipher feedback.
    Cfb = 2,

    /// Output feedback.
    Ofb = 3,

    /// Counter mode.
    Ctr = 4,
}

/// `AesEncryptDecrypt` request schema.
///
/// AES encrypts or decrypts `msg` under the masked AES key in `mode`,
/// starting from `iv`.
#[tbor(opcode = 0x16, pair = TborAesEncryptDecryptResp)]
pub struct TborAesEncryptDecryptReq<'a> {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The direction, carried as the 1-byte [`AesOp`] discriminant.
    #[tbor(U8)]
    pub op: AesOp,

    /// The mode, carried as the 1-byte [`AesMode`] discriminant.
    #[tbor(U8)]
    pub mode: AesMode,

    /// The input IV: empty for ECB, otherwise 16 bytes.
    #[tbor(buffer, max_len = 16, mutable)]
    pub iv: &'a [u8],

    /// The message to transform: non-empty, up to [`AES_MSG_MAX_LEN`]
    /// (1024) bytes; a multiple of the 16-byte AES block for CBC / ECB.
    #[tbor(buffer, max_len = 1024, mutable)]
    pub msg: &'a [u8],

    /// The masked AES key (from `AesGenerateKey` / `UnwrapKey`), an
    /// AEAD-GCM-256 envelope of 248..=264 B, unmasked and wiped in place.
    /// Placed after `iv` / `msg` so those fields can become the compact
    /// response without overlapping the live key.
    #[tbor(buffer, min_len = 248, max_len = 264, mutable)]
    pub masked_key: &'a [u8],
}

/// `AesEncryptDecrypt` response schema.
///
/// The response `[msg | iv]` occupies the same payload bytes as the request
/// `[iv | msg]`.  The handler transforms them in place, then describes the
/// existing bytes with `msg_existing` / `iv_existing` without clearing or
/// copying them.
#[tbor(response, pair = TborAesEncryptDecryptReq)]
pub struct TborAesEncryptDecryptResp<'a> {
    /// The transformed message (same length as the input `msg`).
    #[tbor(buffer, max_len = 1024, mutable)]
    pub msg: &'a [u8],

    /// The output chaining IV (empty for ECB, otherwise 16 bytes); see the
    /// module docs for its per-mode meaning.
    #[tbor(buffer, max_len = 16, mutable)]
    pub iv: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 1536];
        let masked = [0x11u8; MASKED_AES_KEY_MIN_LEN];
        let msg = [0x22u8; 64];
        let iv = [0x33u8; AES_IV_LEN];
        let frame = TborAesEncryptDecryptReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .op(AesOp::Encrypt)
            .unwrap()
            .mode(AesMode::Ctr)
            .unwrap()
            .iv(&iv)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .finish();

        assert_eq!(frame.op(), AesOp::Encrypt);
        assert_eq!(frame.mode(), AesMode::Ctr);
        assert_eq!(frame.msg(), &msg[..]);
        assert_eq!(frame.iv(), &iv[..]);
    }

    #[test]
    fn request_accepts_empty_iv_and_unknown_mode() {
        let mut buf = [0u8; 1536];
        let masked = [0x11u8; MASKED_AES_KEY_MIN_LEN];
        let msg = [0x22u8; 32];
        let frame = TborAesEncryptDecryptReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .op(AesOp::Decrypt)
            .unwrap()
            .mode(AesMode(9))
            .unwrap()
            .iv(&[])
            .unwrap()
            .msg(&msg)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .finish();

        assert_eq!(frame.mode(), AesMode(9));
        assert!(frame.iv().is_empty());
        assert_eq!(frame.msg(), &msg[..]);
    }

    #[test]
    fn response_round_trips_msg_and_iv() {
        let mut buf = [0u8; 1536];
        let msg = [0x44u8; 48];
        let iv = [0x55u8; AES_IV_LEN];
        let frame = TborAesEncryptDecryptResp::encode(&mut buf, 0, true)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .iv(&iv)
            .unwrap()
            .finish();
        assert_eq!(frame.msg(), &msg[..]);
        assert_eq!(frame.iv(), &iv[..]);
    }

    #[test]
    fn response_reserve_matches_value_layout() {
        // A frame built with the `*_reserve` setters must have the same
        // wire layout (header + TOC + total length) as one built with the
        // value setters; only the data bytes are left for fill-later.
        let mut buf_v = [0u8; 1536];
        let msg = [0x44u8; 48];
        let iv = [0x55u8; AES_IV_LEN];
        let frame_v = TborAesEncryptDecryptResp::encode(&mut buf_v, 0, true)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .iv(&iv)
            .unwrap()
            .finish();
        let len_v = frame_v.as_bytes().len();

        let mut buf_r = [0u8; 1536];
        let frame_r = TborAesEncryptDecryptResp::encode(&mut buf_r, 0, true)
            .unwrap()
            .msg_reserve(48)
            .unwrap()
            .iv_reserve(AES_IV_LEN)
            .unwrap()
            .finish();

        // Identical total length, and the reserved slots report the
        // reserved sizes (their bytes are whatever was in the buffer — the
        // zero-initialized `buf_r` here).
        assert_eq!(frame_r.as_bytes().len(), len_v, "reserve length == value");
        assert_eq!(frame_r.msg().len(), 48);
        assert_eq!(frame_r.iv().len(), AES_IV_LEN);
        assert!(
            frame_r.msg().iter().all(|&b| b == 0),
            "reserved region is left untouched for fill-later",
        );
    }

    #[test]
    fn response_reserve_rejects_oversize() {
        // The reserve setter enforces the same length bound as the value
        // setter: the IV slot holds at most 16 bytes.
        let mut buf = [0u8; 1536];
        let err = TborAesEncryptDecryptResp::encode(&mut buf, 0, true)
            .unwrap()
            .msg_reserve(48)
            .unwrap()
            .iv_reserve(17);
        assert!(err.is_err(), "IV reserve must reject more than 16 bytes");
    }

    #[test]
    fn lengths_match_pinned_values() {
        // The `#[tbor(buffer, ... = N)]` attributes must remain numeric
        // literals; pin them against the exported consts.
        const _: () = assert!(1024 == AES_MSG_MAX_LEN);
        const _: () = assert!(16 == AES_IV_LEN);
        const _: () = assert!(248 == MASKED_AES_KEY_MIN_LEN);
        const _: () = assert!(264 == MASKED_AES_KEY_MAX_LEN);
        assert_eq!(AES_MSG_MAX_LEN, 1024);
        assert_eq!(AES_IV_LEN, 16);
    }
}
