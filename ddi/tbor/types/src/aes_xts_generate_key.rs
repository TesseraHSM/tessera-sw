// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `AesXtsGenerateKey` command.
//!
//! `AesXtsGenerateKey` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that generates a fresh random AES-256-XTS key — the
//! double-wide `K1 ‖ K2` (64 bytes) — and returns it as a **masked** blob
//! of [`MASKED_AES_XTS_KEY_LEN`] bytes.  The key is not stored on-device;
//! the caller passes the masked blob to
//! [`AesXtsEncryptDecrypt`](crate::aes_xts_encrypt_decrypt).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `AesXtsGenerateKey`.
pub const TBOR_OP_AES_XTS_GENERATE_KEY: u8 = 0x2E;

/// AES-256-XTS key length in bytes (`K1 ‖ K2`).
pub const AES_XTS_KEY_LEN: usize = 64;

/// Masked AES-256-XTS key envelope length: `header(8) ‖ iv(16) ‖
/// aad(192) ‖ pt(64) ‖ tag(16)`.
pub const MASKED_AES_XTS_KEY_LEN: usize = 8 + 16 + 192 + AES_XTS_KEY_LEN + 16;

/// Host-facing TBOR `AesXtsGenerateKey` request.
#[tbor(opcode = TBOR_OP_AES_XTS_GENERATE_KEY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesXtsGenerateKeyReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope as the 1-byte `KeyScope` discriminant.
    pub scope: u8,

    /// Requested key-usage permissions, `KeyUsage` bitfield (u64) — a
    /// generated XTS key carries exactly `ENCRYPT | DECRYPT`.
    pub key_usage: u64,

    /// Caller-supplied key label recorded in the masked blob's metadata,
    /// up to 128 bytes.  Empty for an unlabeled key.
    #[tbor(max_len = 128)]
    pub key_label: Vec<u8>,
}

/// Host-facing TBOR `AesXtsGenerateKey` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesXtsGenerateKeyResp {
    /// The freshly generated XTS key, masked (AEAD-GCM-256) under the
    /// requested scope's masking key; 296 B.
    #[tbor(min_len = 296, max_len = 296)]
    pub masked_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::KEY_USAGE_DECRYPT;
    use crate::KEY_USAGE_ENCRYPT;

    #[test]
    fn request_encodes_label() {
        let req = TborAesXtsGenerateKeyReq {
            session_id: 5,
            scope: 0b011,
            key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
            key_label: b"my-xts-key".to_vec(),
        };

        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(frame.windows(10).any(|w| w == b"my-xts-key"));
    }

    #[test]
    fn masked_key_len_matches_firmware() {
        const _: () = assert!(MASKED_AES_XTS_KEY_LEN == 296);
    }
}
