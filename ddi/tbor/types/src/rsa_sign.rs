// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `RsaSign` command.
//!
//! The device authenticates a caller-held masked RSA private key, hashes the
//! raw OOB message internally, and returns a modulus-sized signature.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `RsaSign`.
pub const TBOR_OP_RSA_SIGN: u8 = 0x35;
/// Maximum raw message length hashed by `RsaSign` and `RsaVerify`.
pub const RSA_SIGN_MESSAGE_MAX_LEN: usize = 8192;
/// Maximum masked RSA private-key envelope length.
pub use crate::rsa_mod_exp::RSA_MASKED_KEY_MAX_LEN as RSA_SIGN_MASKED_KEY_MAX_LEN;
/// Maximum RSA signature length.
pub const RSA_SIGNATURE_MAX_LEN: usize = 512;

/// `HashAlgo` discriminant for SHA-256.
pub const RSA_HASH_SHA256: u8 = 1;
/// `HashAlgo` discriminant for SHA-384.
pub const RSA_HASH_SHA384: u8 = 2;
/// `HashAlgo` discriminant for SHA-512.
pub const RSA_HASH_SHA512: u8 = 3;

/// `RsaPadding` discriminant for RSASSA-PSS.
pub const RSA_PADDING_PSS: u8 = 0;
/// `RsaPadding` discriminant for RSASSA-PKCS1-v1_5.
pub const RSA_PADDING_PKCS1_V15: u8 = 1;

/// Host-facing TBOR `RsaSign` request.
#[tbor(opcode = TBOR_OP_RSA_SIGN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborRsaSignReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Authenticated masked RSA private-key envelope.
    #[tbor(align = 4, max_len = 3168)]
    pub masked_key: Vec<u8>,

    /// Signature encoding: `RSA_PADDING_PSS` or `RSA_PADDING_PKCS1_V15`.
    pub padding: u8,

    /// Required SHA-256, SHA-384, or SHA-512 selector.
    pub hash_algo: u8,

    /// Required for PSS (including an explicit zero); absent for v1.5.
    pub salt_len: Option<u16>,

    /// Index of the raw message's OOB input SGL descriptor.
    pub message_index: u8,

    /// Raw message length, from zero through 8192 inclusive.
    pub message_len: u16,
}

/// Host-facing TBOR `RsaSign` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborRsaSignResp {
    /// Exactly one modulus-sized signature in device operand byte order.
    #[tbor(max_len = 512)]
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::codec::ResponseEncoder;

    #[test]
    fn maximum_request_and_response_fit_exchange_frame() {
        let req = TborRsaSignReq {
            session_id: 7,
            masked_key: alloc::vec![0x11; RSA_SIGN_MASKED_KEY_MAX_LEN],
            padding: RSA_PADDING_PSS,
            hash_algo: RSA_HASH_SHA512,
            salt_len: Some(64),
            message_index: 0,
            message_len: RSA_SIGN_MESSAGE_MAX_LEN as u16,
        };
        let mut buf = [0u8; 4096];
        let frame = req
            .encode_request(&mut buf, (1, 1))
            .expect("encode request");
        assert!(frame.len() <= buf.len());

        let signature = alloc::vec![0x33; RSA_SIGNATURE_MAX_LEN];
        let frame = ResponseEncoder::new(&mut buf, (1, 1), 0, false)
            .buffer(&signature)
            .expect("encode response signature")
            .finish()
            .expect("finish response");
        assert!(frame.len() <= buf.len());
    }
}
