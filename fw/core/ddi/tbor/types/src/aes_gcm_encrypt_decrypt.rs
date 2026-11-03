// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesGcmEncryptDecrypt` wire schema.
//!
//! `AesGcmEncryptDecrypt` is an in-session command that AES-256-GCM
//! encrypts or decrypts host data under a caller-held **masked** AES-256
//! key (the `masked_key` from [`AesGenerateKey`](crate::aes_generate_key)
//! or imported via [`UnwrapKey`](crate::unwrap_key)).  The device unmasks
//! the key on-device (verifying the AEAD tag) and runs AES-GCM; nothing is
//! persisted.
//!
//! The data travels **out of band**: the SQE's OOB descriptor page holds
//! an **in** and an **out** SGL Data Block, referenced by `in_index` /
//! `out_index`.  The AES engine reads `[padded_AAD | text]` (`data_len` bytes,
//! the `pad_aad` layout of `HsmAesGcm::gcm_encrypt`) from the in block and
//! writes `[padded_AAD | text']` (same layout and length) to the out block
//! directly — host to host, nothing staged in HSM memory.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//! * `op` — the [`AesOp`] selecting encrypt or decrypt.
//! * `iv_source` — the [`GcmIvSource`]: the host supplies the IV, or (for
//!   encrypt only) the device generates it from its RNG.
//! * `aad_len` — **unpadded** AAD length in bytes (0 for none).
//! * `data_len` — total in / out length, `round_up_32(aad_len) + text_len`,
//!   1..=[`GCM_DATA_MAX_LEN`].
//! * `in_index` / `out_index` — OOB descriptor-page indices of the in /
//!   out SGL Data Blocks; each must describe exactly `data_len` bytes.
//! * `iv` — [`GCM_IV_LEN`] bytes.  The IV when host-supplied; ignored and
//!   overwritten when device-generated.
//! * `tag` — [`GCM_TAG_LEN`] bytes.  The tag to verify on decrypt; ignored
//!   and overwritten on encrypt.
//! * `masked_key` — the masked AES-256 key
//!   ([`MASKED_AES_KEY_MAX_LEN`] B).
//!
//! The request carries `[iv | tag]` at the payload start, and the response
//! carries `[iv | tag]` at the same offset, so the device fills them in
//! place.
//!
//! Outputs:
//!
//! * `iv` — the IV used (the device-generated one when
//!   [`GcmIvSource::Device`]).
//! * `tag` — the computed tag on encrypt; the verified input tag on
//!   decrypt.
//! * The transformed data, in the out SGL Data Block.

use open_enum::open_enum;
use tsra_fw_ddi_tbor_api::tbor;

pub use crate::aes_encrypt_decrypt::AesOp;
pub use crate::aes_generate_key::MASKED_AES_KEY_MAX_LEN;

/// TBOR opcode for `AesGcmEncryptDecrypt`.
pub const TBOR_OP_AES_GCM_ENCRYPT_DECRYPT: u8 = 0x2C;

/// GCM IV length in bytes (96 bits).
pub const GCM_IV_LEN: usize = 12;

/// GCM authentication tag length in bytes (128 bits).
pub const GCM_TAG_LEN: usize = 16;

/// Maximum in / out length (bytes): one 16 KiB SGL Data Block.
pub const GCM_DATA_MAX_LEN: usize = 16 * 1024;

/// Source of the GCM IV on the TBOR wire.
///
/// Kept as an [`open_enum`] so an unrecognized discriminant round-trips
/// as `GcmIvSource(x)` and is rejected on-device rather than failing to
/// decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcmIvSource {
    /// The host supplies the IV in the request `iv` field.
    Host = 0,

    /// The device generates the IV from its RNG and returns it in the
    /// response.  Valid for encrypt only.
    Device = 1,
}

/// `AesGcmEncryptDecrypt` request schema.
#[tbor(opcode = 0x2C, pair = TborAesGcmEncryptDecryptResp)]
pub struct TborAesGcmEncryptDecryptReq<'a> {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The direction, carried as the 1-byte [`AesOp`] discriminant.
    #[tbor(U8)]
    pub op: AesOp,

    /// The IV source, carried as the 1-byte [`GcmIvSource`] discriminant.
    #[tbor(U8)]
    pub iv_source: GcmIvSource,

    /// Unpadded AAD length in bytes (0 for none).
    pub aad_len: u16,

    /// Total in / out length, `round_up_32(aad_len) + text_len`.
    pub data_len: u16,

    /// OOB descriptor-page index of the in SGL Data Block.
    pub in_index: u8,

    /// OOB descriptor-page index of the out SGL Data Block.
    pub out_index: u8,

    /// The 12-byte IV (ignored when device-generated).
    #[tbor(buffer, len = 12, mutable)]
    pub iv: &'a [u8],

    /// The 16-byte tag to verify on decrypt (ignored on encrypt).
    #[tbor(buffer, len = 16, mutable)]
    pub tag: &'a [u8],

    /// The masked AES-256 key, an AEAD-GCM-256 envelope of 264 B,
    /// unmasked and wiped in place.  Placed after `iv` / `tag` so those
    /// fields can become the response without overlapping the live key.
    #[tbor(buffer, len = 264, mutable)]
    pub masked_key: &'a [u8],
}

/// `AesGcmEncryptDecrypt` response schema.
///
/// The response `[iv | tag]` occupies the same payload bytes as the
/// request `[iv | tag]`; the handler fills them in place and describes
/// them with the `*_existing` setters.
#[tbor(response, pair = TborAesGcmEncryptDecryptReq)]
pub struct TborAesGcmEncryptDecryptResp<'a> {
    /// The IV used.
    #[tbor(buffer, len = 12, mutable)]
    pub iv: &'a [u8],

    /// The authentication tag.
    #[tbor(buffer, len = 16, mutable)]
    pub tag: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 512];
        let iv = [0x33u8; GCM_IV_LEN];
        let tag = [0x44u8; GCM_TAG_LEN];
        let masked = [0x11u8; MASKED_AES_KEY_MAX_LEN];
        let frame = TborAesGcmEncryptDecryptReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .op(AesOp::Decrypt)
            .unwrap()
            .iv_source(GcmIvSource::Host)
            .unwrap()
            .aad_len(20)
            .unwrap()
            .data_len(GCM_DATA_MAX_LEN as u16)
            .unwrap()
            .in_index(0)
            .unwrap()
            .out_index(1)
            .unwrap()
            .iv(&iv)
            .unwrap()
            .tag(&tag)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .finish();

        assert_eq!(frame.op(), AesOp::Decrypt);
        assert_eq!(frame.iv_source(), GcmIvSource::Host);
        assert_eq!(frame.aad_len(), 20);
        assert_eq!(frame.data_len(), GCM_DATA_MAX_LEN as u16);
        assert_eq!(frame.in_index(), 0);
        assert_eq!(frame.out_index(), 1);
        assert_eq!(frame.iv(), &iv[..]);
        assert_eq!(frame.tag(), &tag[..]);
        assert_eq!(frame.masked_key(), &masked[..]);
    }

    #[test]
    fn request_rejects_wrong_iv_len() {
        let mut buf = [0u8; 512];
        let err = TborAesGcmEncryptDecryptReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .op(AesOp::Encrypt)
            .unwrap()
            .iv_source(GcmIvSource::Device)
            .unwrap()
            .aad_len(0)
            .unwrap()
            .data_len(16)
            .unwrap()
            .in_index(0)
            .unwrap()
            .out_index(1)
            .unwrap()
            .iv(&[0u8; 16]);
        assert!(err.is_err(), "IV must be exactly 12 bytes");
    }

    #[test]
    fn response_data_starts_at_request_data_offset() {
        // The in-place handler relies on `[iv | tag]` sitting at the same
        // payload offset in the request and the response.
        assert_eq!(
            tsra_fw_ddi_tbor::REQ_HEADER_LEN + TborAesGcmEncryptDecryptReq::TOC_COUNT * 4,
            tsra_fw_ddi_tbor::RESP_HEADER_LEN + TborAesGcmEncryptDecryptResp::TOC_COUNT * 4,
        );
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(12 == GCM_IV_LEN);
        const _: () = assert!(16 == GCM_TAG_LEN);
        const _: () = assert!(16384 == GCM_DATA_MAX_LEN);
        const _: () = assert!(264 == MASKED_AES_KEY_MAX_LEN);
        const _: () = assert!(GCM_DATA_MAX_LEN <= u16::MAX as usize);
    }
}
