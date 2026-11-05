// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesXtsEncryptDecrypt` wire schema.
//!
//! `AesXtsEncryptDecrypt` is an in-session command that AES-256-XTS
//! encrypts or decrypts one or more data units of host data under a caller-held
//! **masked** XTS key (the double-wide `masked_key` from
//! [`AesXtsGenerateKey`](crate::aes_xts_generate_key)).  The device
//! unmasks the key on-device (verifying the AEAD tag) and runs AES-XTS;
//! nothing is persisted.
//!
//! The data travels **out of band**: the SQE's OOB descriptor page holds
//! an **in** and an **out** SGL Data Block, referenced by `in_index` /
//! `out_index`.  The AES engine reads `data_len` bytes from the in block
//! and writes the result (same length) to the out block directly — host
//! to host, nothing staged in HSM memory.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//! * `op` — the [`AesOp`] selecting encrypt or decrypt.
//! * `data_len` — the total length: 16..=[`XTS_DATA_MAX_LEN`] bytes, a
//!   multiple of `dul`.
//! * `dul` — the data-unit length: at least 16, a multiple of the 16-byte
//!   AES block.
//! * `in_index` / `out_index` — OOB descriptor-page indices of the in /
//!   out SGL Data Blocks; each must describe exactly `data_len` bytes.
//! * `tweak` — [`XTS_TWEAK_LEN`] bytes: the little-endian number of the
//!   first data unit; it increments by one per subsequent data unit and
//!   must not overflow 64 bits.
//! * `masked_key` — the masked XTS key ([`MASKED_AES_XTS_KEY_LEN`] B).
//!
//! Outputs: none in the response frame; the transformed data is in the
//! out SGL Data Block.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::aes_encrypt_decrypt::AesOp;
pub use crate::aes_xts_generate_key::MASKED_AES_XTS_KEY_LEN;

/// TBOR opcode for `AesXtsEncryptDecrypt`.
pub const TBOR_OP_AES_XTS_ENCRYPT_DECRYPT: u8 = 0x2D;

/// XTS tweak length in bytes (64-bit data-unit number).
pub const XTS_TWEAK_LEN: usize = 8;

/// Maximum total data length (bytes): one 16 KiB SGL Data Block.
pub const XTS_DATA_MAX_LEN: usize = 16 * 1024;

/// `AesXtsEncryptDecrypt` request schema.
#[tbor(opcode = 0x2D, pair = TborAesXtsEncryptDecryptResp)]
pub struct TborAesXtsEncryptDecryptReq<'a> {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The direction, carried as the 1-byte [`AesOp`] discriminant.
    #[tbor(U8)]
    pub op: AesOp,

    /// The total data length: 16..=[`XTS_DATA_MAX_LEN`], a multiple of
    /// `dul`.
    pub data_len: u16,

    /// The data-unit length: at least 16, a multiple of 16.
    pub dul: u16,

    /// OOB descriptor-page index of the in SGL Data Block.
    pub in_index: u8,

    /// OOB descriptor-page index of the out SGL Data Block.
    pub out_index: u8,

    /// The 8-byte little-endian number of the first data unit.
    #[tbor(buffer, len = 8)]
    pub tweak: &'a [u8],

    /// The masked XTS key, an AEAD-GCM-256 envelope of 296 B, unmasked and
    /// wiped in place.
    #[tbor(buffer, len = 296, mutable)]
    pub masked_key: &'a [u8],
}

/// `AesXtsEncryptDecrypt` response schema (empty; the result is in the
/// out SGL Data Block).
#[tbor(response, pair = TborAesXtsEncryptDecryptReq)]
pub struct TborAesXtsEncryptDecryptResp;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 512];
        let tweak = 0x0102_0304_0506_0708u64.to_le_bytes();
        let masked = [0x11u8; MASKED_AES_XTS_KEY_LEN];
        let frame = TborAesXtsEncryptDecryptReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .op(AesOp::Encrypt)
            .unwrap()
            .data_len(4096)
            .unwrap()
            .dul(512)
            .unwrap()
            .in_index(0)
            .unwrap()
            .out_index(1)
            .unwrap()
            .tweak(&tweak)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .finish();

        assert_eq!(frame.op(), AesOp::Encrypt);
        assert_eq!(frame.data_len(), 4096);
        assert_eq!(frame.dul(), 512);
        assert_eq!(frame.in_index(), 0);
        assert_eq!(frame.out_index(), 1);
        assert_eq!(frame.tweak(), &tweak[..]);
        assert_eq!(frame.masked_key(), &masked[..]);
    }

    #[test]
    fn request_rejects_16_byte_tweak() {
        let mut buf = [0u8; 512];
        let err = TborAesXtsEncryptDecryptReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .op(AesOp::Encrypt)
            .unwrap()
            .data_len(16)
            .unwrap()
            .dul(16)
            .unwrap()
            .in_index(0)
            .unwrap()
            .out_index(1)
            .unwrap()
            .tweak(&[0u8; 16]);
        assert!(err.is_err(), "tweak must be exactly 8 bytes");
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(8 == XTS_TWEAK_LEN);
        const _: () = assert!(16384 == XTS_DATA_MAX_LEN);
        const _: () = assert!(296 == MASKED_AES_XTS_KEY_LEN);
        const _: () = assert!(XTS_DATA_MAX_LEN <= u16::MAX as usize);
    }
}
