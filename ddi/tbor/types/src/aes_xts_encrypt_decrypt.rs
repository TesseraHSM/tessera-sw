// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `AesXtsEncryptDecrypt` command.
//!
//! `AesXtsEncryptDecrypt` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that AES-256-XTS encrypts or decrypts one or more data
//! units under
//! a caller-held **masked** XTS key (from
//! [`AesXtsGenerateKey`](crate::aes_xts_generate_key)).  The data travels
//! **out of band**: the OOB descriptor page holds an **in** and an **out**
//! SGL Data Block (`in_index` / `out_index`), each `data_len` bytes; the
//! device reads the in block and writes the result to the out block.
//! The tweak of the first data unit is `tweak`; it increments by one per
//! subsequent data unit (`dul` bytes each).
//! Nothing is persisted.

use crate::tbor;

/// TBOR opcode for `AesXtsEncryptDecrypt`.
pub const TBOR_OP_AES_XTS_ENCRYPT_DECRYPT: u8 = 0x2D;

/// XTS tweak length in bytes (64-bit little-endian data-unit number).
pub const XTS_TWEAK_LEN: usize = 8;

/// Maximum total data length (bytes): one 16 KiB SGL Data Block.
pub const XTS_DATA_MAX_LEN: usize = 16 * 1024;

/// Host-facing TBOR `AesXtsEncryptDecrypt` request.
#[tbor(opcode = TBOR_OP_AES_XTS_ENCRYPT_DECRYPT, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesXtsEncryptDecryptReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The direction as the 1-byte `AesOp` discriminant (see
    /// [`AES_OP_ENCRYPT`](crate::AES_OP_ENCRYPT) /
    /// [`AES_OP_DECRYPT`](crate::AES_OP_DECRYPT)).
    pub op: u8,

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
    #[tbor(min_len = 8, max_len = 8)]
    pub tweak: alloc::vec::Vec<u8>,

    /// The masked XTS key.
    #[tbor(min_len = 296, max_len = 296)]
    pub masked_key: alloc::vec::Vec<u8>,
}

/// Host-facing TBOR `AesXtsEncryptDecrypt` response (empty; the result is
/// in the out SGL Data Block).
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborAesXtsEncryptDecryptResp;

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::AES_OP_ENCRYPT;
    use crate::MASKED_AES_XTS_KEY_LEN;

    #[test]
    fn request_encodes_tweak() {
        let req = TborAesXtsEncryptDecryptReq {
            session_id: 7,
            op: AES_OP_ENCRYPT,
            data_len: 512,
            dul: 256,
            in_index: 0,
            out_index: 1,
            tweak: 0x0102_0304_0506_0708u64.to_le_bytes().to_vec(),
            masked_key: alloc::vec![0x11u8; MASKED_AES_XTS_KEY_LEN],
        };

        let mut buf = [0u8; 512];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(frame
            .windows(8)
            .any(|w| w == 0x0102_0304_0506_0708u64.to_le_bytes()));
    }
}
