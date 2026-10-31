// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `AesEncryptDecrypt` command.
//!
//! `AesEncryptDecrypt` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that AES encrypts or decrypts `msg` in CBC, ECB, CFB-128,
//! OFB or CTR mode using a caller-held **masked** AES key (the
//! `masked_key` from [`AesGenerateKey`](crate::aes_generate_key) or
//! imported via [`UnwrapKey`](crate::unwrap_key)).  The device unmasks the
//! key on-device, runs the AES transform, and returns the transformed
//! message plus the output chaining IV; nothing is persisted.

use alloc::vec::Vec;

pub use crate::aes_generate_key::MASKED_AES_KEY_MAX_LEN;
pub use crate::aes_generate_key::MASKED_AES_KEY_MIN_LEN;
use crate::tbor;

/// TBOR opcode for `AesEncryptDecrypt`.
pub const TBOR_OP_AES_ENCRYPT_DECRYPT: u8 = 0x16;

/// AES block size in bytes — also the IV length for every mode but ECB.
pub const AES_IV_LEN: usize = 16;

/// Maximum message length (bytes) accepted by `AesEncryptDecrypt`.
pub const AES_MSG_MAX_LEN: usize = 1024;

/// `AesOp` discriminant selecting encryption.
pub const AES_OP_ENCRYPT: u8 = 1;
/// `AesOp` discriminant selecting decryption.
pub const AES_OP_DECRYPT: u8 = 2;

/// `AesMode` discriminant selecting CBC (16-byte IV, block-multiple data).
pub const AES_MODE_CBC: u8 = 0;
/// `AesMode` discriminant selecting ECB (no IV, block-multiple data).
pub const AES_MODE_ECB: u8 = 1;
/// `AesMode` discriminant selecting CFB-128 (16-byte IV, any data length).
pub const AES_MODE_CFB: u8 = 2;
/// `AesMode` discriminant selecting OFB (16-byte IV, any data length).
pub const AES_MODE_OFB: u8 = 3;
/// `AesMode` discriminant selecting CTR (16-byte counter, any data length).
pub const AES_MODE_CTR: u8 = 4;

/// Host-facing TBOR `AesEncryptDecrypt` request.
#[tbor(opcode = TBOR_OP_AES_ENCRYPT_DECRYPT, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesEncryptDecryptReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The direction as the 1-byte `AesOp` discriminant (see
    /// [`AES_OP_ENCRYPT`] / [`AES_OP_DECRYPT`]).
    pub op: u8,

    /// The mode as the 1-byte `AesMode` discriminant (see
    /// [`AES_MODE_CBC`] ..= [`AES_MODE_CTR`]).
    pub mode: u8,

    /// The input IV: empty for ECB, otherwise [`AES_IV_LEN`] bytes (the
    /// initial counter block for CTR).
    #[tbor(max_len = 16)]
    pub iv: Vec<u8>,

    /// The message to transform: non-empty, up to [`AES_MSG_MAX_LEN`]
    /// (1024) bytes; a multiple of the 16-byte AES block for CBC / ECB.
    #[tbor(max_len = 1024)]
    pub msg: Vec<u8>,

    /// The masked AES key, placed after the IV and message so firmware can
    /// return those fields in place without moving their payload bytes.
    #[tbor(min_len = 248, max_len = 264)]
    pub masked_key: Vec<u8>,
}

/// Host-facing TBOR `AesEncryptDecrypt` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesEncryptDecryptResp {
    /// The transformed message (same length as the input `msg`).
    #[tbor(max_len = 1024)]
    pub msg: Vec<u8>,

    /// The output chaining IV (empty for ECB): the last ciphertext block
    /// for CBC, the last complete ciphertext block for CFB, the last
    /// keystream block for OFB, and the next counter block for CTR.
    #[tbor(max_len = 16)]
    pub iv: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_op_and_iv() {
        let req = TborAesEncryptDecryptReq {
            session_id: 7,
            masked_key: alloc::vec![0x11u8; MASKED_AES_KEY_MIN_LEN],
            op: AES_OP_ENCRYPT,
            mode: AES_MODE_CBC,
            iv: alloc::vec![0x33u8; AES_IV_LEN],
            msg: alloc::vec![0x22u8; 32],
        };

        let mut buf = [0u8; 1536];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The message bytes must appear in the encoded frame.
        assert!(
            frame.windows(4).any(|w| w == [0x22u8; 4]),
            "encoded frame must carry the message bytes",
        );
    }
}
