// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `RsaEncryptDecrypt` command.
//!
//! The command encrypts or decrypts with a caller-held masked RSA private
//! key. Padding is mandatory: OAEP with SHA-256/384/512, or PKCS#1 v1.5
//! encryption padding. It is distinct from raw `RsaModExp`; it does not
//! expose signatures or an unpadded mode.

use alloc::vec::Vec;

use open_enum::open_enum;

use crate::tbor;

/// TBOR opcode for `RsaEncryptDecrypt`.
pub const TBOR_OP_RSA_ENCRYPT_DECRYPT: u8 = 0x34;

/// Maximum masked RSA private-key envelope length (RSA-4096-CRT).
pub const RSA_ENCRYPT_DECRYPT_MASKED_KEY_MAX_LEN: usize = 3168;
/// Maximum RSA input/output length (RSA-4096 modulus size).
pub const RSA_ENCRYPT_DECRYPT_MAX_LEN: usize = 512;
/// Maximum OAEP label length.
pub const RSA_OAEP_LABEL_MAX_LEN: usize = 256;

/// `RsaEncryptDecryptOp` wire discriminants.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaEncryptDecryptOp {
    /// Encrypt using the masked key's `encrypt` permission.
    Encrypt = 1,
    /// Decrypt using the masked key's `decrypt` permission.
    Decrypt = 2,
}

/// `RsaEncryptPadding` wire discriminants.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaEncryptPadding {
    /// RSAES-OAEP with a mandatory SHA-256/384/512 selector.
    Oaep = 1,
    /// RSAES-PKCS1-v1_5, without a hash selector.
    Pkcs1v15 = 2,
}

/// Direction discriminant for encryption.
pub const RSA_ENCRYPT_DECRYPT_OP_ENCRYPT: u8 = 1;
/// Direction discriminant for decryption.
pub const RSA_ENCRYPT_DECRYPT_OP_DECRYPT: u8 = 2;
/// Padding discriminant for OAEP.
pub const RSA_ENCRYPT_PADDING_OAEP: u8 = 1;
/// Padding discriminant for PKCS#1 v1.5.
pub const RSA_ENCRYPT_PADDING_PKCS1V15: u8 = 2;

/// Host-facing TBOR `RsaEncryptDecrypt` request.
#[tbor(opcode = TBOR_OP_RSA_ENCRYPT_DECRYPT, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborRsaEncryptDecryptReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,
    /// Direction discriminant (see `RSA_ENCRYPT_DECRYPT_OP_*`).
    pub op: u8,
    /// Mandatory padding discriminant (see `RSA_ENCRYPT_PADDING_*`).
    pub padding: u8,
    /// OAEP hash selector (SHA-256/384/512), absent for PKCS#1 v1.5.
    pub hash_algo: Option<u8>,
    /// OAEP label; PKCS#1 v1.5 requires this to be empty.
    #[tbor(max_len = 256)]
    pub label: Vec<u8>,
    /// Plaintext for encryption or one modulus-sized ciphertext for decryption.
    #[tbor(align = 4, max_len = 512)]
    pub input: Vec<u8>,
    /// Masked RSA private key imported with `UnwrapKey`.
    #[tbor(align = 4, min_len = 264, max_len = 3168)]
    pub masked_key: Vec<u8>,
}

/// Host-facing TBOR `RsaEncryptDecrypt` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborRsaEncryptDecryptResp {
    /// Ciphertext (modulus-sized) or recovered plaintext (actual length).
    #[tbor(max_len = 512)]
    pub output: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn maximum_request_fits_transport_frame() {
        let req = TborRsaEncryptDecryptReq {
            session_id: 7,
            op: RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
            padding: RSA_ENCRYPT_PADDING_OAEP,
            hash_algo: Some(crate::HASH_ALGO_SHA512),
            label: alloc::vec![0x31; RSA_OAEP_LABEL_MAX_LEN],
            input: alloc::vec![0x42; RSA_ENCRYPT_DECRYPT_MAX_LEN],
            masked_key: alloc::vec![0x53; RSA_ENCRYPT_DECRYPT_MASKED_KEY_MAX_LEN],
        };
        let mut frame = [0u8; 4096];
        let encoded = req
            .encode_request(&mut frame, (1, 1))
            .expect("maximum request encodes");
        assert!(encoded.len() <= frame.len());
    }

    #[test]
    fn request_uses_in_session_control_and_stable_selectors() {
        let req = TborRsaEncryptDecryptReq::default();
        assert_eq!(TborRsaEncryptDecryptReq::OPCODE, 0x34);
        assert_eq!(req.session_ctrl(), crate::SessionControlKind::InSession);
        assert_eq!(
            RsaEncryptDecryptOp::Encrypt.0,
            RSA_ENCRYPT_DECRYPT_OP_ENCRYPT
        );
        assert_eq!(
            RsaEncryptDecryptOp::Decrypt.0,
            RSA_ENCRYPT_DECRYPT_OP_DECRYPT
        );
        assert_eq!(RsaEncryptPadding::Oaep.0, RSA_ENCRYPT_PADDING_OAEP);
        assert_eq!(RsaEncryptPadding::Pkcs1v15.0, RSA_ENCRYPT_PADDING_PKCS1V15);
    }
}
