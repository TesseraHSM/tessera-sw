// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `RsaEncryptDecrypt` wire schema.
//!
//! This in-session command performs padded RSA encryption/decryption with
//! a caller-held masked private key. Padding is mandatory; OAEP requires
//! SHA-256/384/512 and PKCS#1 v1.5 requires no hash. This is separate from
//! raw `RsaModExp` and does not provide signing or an unpadded operation.

use open_enum::open_enum;
use tsra_fw_ddi_tbor_api::tbor;

pub use crate::rsa_mod_exp::RSA_MASKED_KEY_MAX_LEN;
pub use crate::rsa_mod_exp::RSA_MASKED_KEY_MIN_LEN;

/// TBOR opcode for `RsaEncryptDecrypt`.
pub const TBOR_OP_RSA_ENCRYPT_DECRYPT: u8 = 0x34;
/// Maximum OAEP label length.
pub const RSA_OAEP_LABEL_MAX_LEN: usize = 256;
/// Maximum input/output length (RSA-4096 modulus size).
pub const RSA_ENCRYPT_DECRYPT_MAX_LEN: usize = 512;

/// RSA encryption/decryption direction on the TBOR wire.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaEncryptDecryptOp {
    /// Encrypt; requires the `encrypt` usage attribute.
    Encrypt = 1,
    /// Decrypt; requires the `decrypt` usage attribute.
    Decrypt = 2,
}

/// RSA encryption padding on the TBOR wire.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaEncryptPadding {
    /// OAEP; requires an explicit SHA-256/384/512 selector.
    Oaep = 1,
    /// PKCS#1 v1.5 encryption; forbids a hash selector.
    Pkcs1v15 = 2,
}

/// `RsaEncryptDecrypt` request schema.
#[tbor(opcode = 0x34, pair = TborRsaEncryptDecryptResp)]
pub struct TborRsaEncryptDecryptReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,
    /// Direction selector.
    #[tbor(U8)]
    pub op: RsaEncryptDecryptOp,
    /// Mandatory padding selector.
    #[tbor(U8)]
    pub padding: RsaEncryptPadding,
    /// OAEP hash selector (wire `HashAlgo`: 1=SHA-256, 2=SHA-384,
    /// 3=SHA-512); absent for PKCS#1 v1.5.
    pub hash_algo: Option<u8>,
    /// OAEP label; PKCS#1 v1.5 requires an empty label.
    #[tbor(buffer, max_len = 256)]
    pub label: &'a [u8],
    /// Plaintext for encryption or a modulus-sized ciphertext for decryption.
    #[tbor(align = 4, buffer, max_len = 512)]
    pub input: &'a [u8],
    /// Masked RSA private key, authenticated and unmasked in place.
    #[tbor(align = 4, buffer, min_len = 264, max_len = 3168, mutable)]
    pub masked_key: &'a [u8],
}

/// `RsaEncryptDecrypt` response schema.
#[tbor(response, pair = TborRsaEncryptDecryptReq)]
pub struct TborRsaEncryptDecryptResp<'a> {
    /// Modulus-sized ciphertext or recovered plaintext of its actual length.
    #[tbor(buffer, max_len = 512, mutable)]
    pub output: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn maximum_request_schema_fits_4096_bytes() {
        const {
            assert!(TborRsaEncryptDecryptReq::MAX_ENCODED_SIZE <= 4096);
        }
        let mut buf = [0u8; 4096];
        let label = [0x31; RSA_OAEP_LABEL_MAX_LEN];
        let input = [0x42; RSA_ENCRYPT_DECRYPT_MAX_LEN];
        let key = [0x53; 3168];
        let frame = TborRsaEncryptDecryptReq::encode(&mut buf, (1, 1))
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .op(RsaEncryptDecryptOp::Encrypt)
            .unwrap()
            .padding(RsaEncryptPadding::Oaep)
            .unwrap()
            .hash_algo(Some(3))
            .unwrap()
            .label(&label)
            .unwrap()
            .input(&input)
            .unwrap()
            .masked_key(&key)
            .unwrap()
            .finish();
        assert_eq!(frame.as_bytes()[5], 0x34);
        assert!(frame.as_bytes().len() <= 4096);
    }

    #[test]
    fn response_allows_empty_plaintext() {
        let mut buf = [0u8; 64];
        let frame = TborRsaEncryptDecryptResp::encode(&mut buf, (1, 1), 0, true)
            .unwrap()
            .output(&[])
            .unwrap()
            .finish();
        assert!(frame.output().is_empty());
    }
}
