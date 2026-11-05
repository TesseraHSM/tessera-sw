// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `AesGcmEncryptDecrypt` command.
//!
//! `AesGcmEncryptDecrypt` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that AES-256-GCM encrypts or decrypts host data under a
//! caller-held **masked** AES-256 key (from
//! [`AesGenerateKey`](crate::aes_generate_key) or
//! [`UnwrapKey`](crate::unwrap_key)).  The data travels **out of band**:
//! the OOB descriptor page holds an **in** and an **out** SGL Data Block
//! (`in_index` / `out_index`).  The device reads `[padded_AAD | text]`
//! (`data_len` bytes, `pad_aad` layout) from the in block and writes
//! `[padded_AAD | text']` (same layout and length) to the out block.  The
//! IV is host-supplied, or device-generated on encrypt
//! ([`GCM_IV_SOURCE_DEVICE`]); the response carries the IV used and the
//! tag.  Nothing is persisted.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `AesGcmEncryptDecrypt`.
pub const TBOR_OP_AES_GCM_ENCRYPT_DECRYPT: u8 = 0x2C;

/// GCM IV length in bytes (96 bits).
pub const GCM_IV_LEN: usize = 12;

/// GCM authentication tag length in bytes (128 bits).
pub const GCM_TAG_LEN: usize = 16;

/// Maximum in / out length (bytes): one 16 KiB SGL Data Block.
pub const GCM_DATA_MAX_LEN: usize = 16 * 1024;

/// `GcmIvSource` discriminant: the host supplies the IV.
pub const GCM_IV_SOURCE_HOST: u8 = 0;
/// `GcmIvSource` discriminant: the device generates the IV (encrypt only).
pub const GCM_IV_SOURCE_DEVICE: u8 = 1;

/// Host-facing TBOR `AesGcmEncryptDecrypt` request.
#[tbor(opcode = TBOR_OP_AES_GCM_ENCRYPT_DECRYPT, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesGcmEncryptDecryptReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The direction as the 1-byte `AesOp` discriminant (see
    /// [`AES_OP_ENCRYPT`](crate::AES_OP_ENCRYPT) /
    /// [`AES_OP_DECRYPT`](crate::AES_OP_DECRYPT)).
    pub op: u8,

    /// The IV source as the 1-byte `GcmIvSource` discriminant (see
    /// [`GCM_IV_SOURCE_HOST`] / [`GCM_IV_SOURCE_DEVICE`]).
    pub iv_source: u8,

    /// Unpadded AAD length in bytes (0 for none).
    pub aad_len: u16,

    /// Total in / out length, `round_up_32(aad_len) + text_len`,
    /// 1..=[`GCM_DATA_MAX_LEN`].
    pub data_len: u16,

    /// OOB descriptor-page index of the in SGL Data Block.
    pub in_index: u8,

    /// OOB descriptor-page index of the out SGL Data Block.
    pub out_index: u8,

    /// The 12-byte IV; any value (e.g. zeros) when device-generated.
    #[tbor(min_len = 12, max_len = 12)]
    pub iv: Vec<u8>,

    /// The 16-byte tag to verify on decrypt; any value (e.g. zeros) on
    /// encrypt.
    #[tbor(min_len = 16, max_len = 16)]
    pub tag: Vec<u8>,

    /// The masked AES-256 key, placed last so firmware can return
    /// `iv` / `tag` in place.
    #[tbor(min_len = 264, max_len = 264)]
    pub masked_key: Vec<u8>,
}

/// Host-facing TBOR `AesGcmEncryptDecrypt` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesGcmEncryptDecryptResp {
    /// The IV used (the device-generated one when requested).
    #[tbor(min_len = 12, max_len = 12)]
    pub iv: Vec<u8>,

    /// The computed tag on encrypt; the verified input tag on decrypt.
    #[tbor(min_len = 16, max_len = 16)]
    pub tag: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::AES_OP_DECRYPT;
    use crate::MASKED_AES_KEY_MAX_LEN;

    #[test]
    fn request_encodes_iv_and_tag() {
        let req = TborAesGcmEncryptDecryptReq {
            session_id: 7,
            op: AES_OP_DECRYPT,
            iv_source: GCM_IV_SOURCE_HOST,
            aad_len: 20,
            data_len: 92,
            in_index: 0,
            out_index: 1,
            iv: alloc::vec![0x33u8; GCM_IV_LEN],
            tag: alloc::vec![0x44u8; GCM_TAG_LEN],
            masked_key: alloc::vec![0x11u8; MASKED_AES_KEY_MAX_LEN],
        };

        let mut buf = [0u8; 512];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(frame.windows(12).any(|w| w == [0x33u8; 12]));
        assert!(frame.windows(16).any(|w| w == [0x44u8; 16]));
    }
}
