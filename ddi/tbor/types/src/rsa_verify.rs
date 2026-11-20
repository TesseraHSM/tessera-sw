// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `RsaVerify` command.
//!
//! The device authenticates a caller-held masked RSA private key, derives its
//! public key on-device, hashes the raw OOB message internally, and returns an
//! empty response only when the signature is valid.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `RsaVerify`.
pub const TBOR_OP_RSA_VERIFY: u8 = 0x36;

/// Host-facing TBOR `RsaVerify` request.
#[tbor(opcode = TBOR_OP_RSA_VERIFY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborRsaVerifyReq {
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

    /// Modulus-sized signature in device operand byte order.
    #[tbor(max_len = 512)]
    pub signature: Vec<u8>,
}

/// Host-facing TBOR `RsaVerify` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborRsaVerifyResp;

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn maximum_request_fits_exchange_frame() {
        let req = TborRsaVerifyReq {
            session_id: 7,
            masked_key: alloc::vec![0x11; 3168],
            padding: crate::RSA_PADDING_PSS,
            hash_algo: crate::RSA_HASH_SHA512,
            salt_len: Some(64),
            message_index: 0,
            message_len: crate::RSA_SIGN_MESSAGE_MAX_LEN as u16,
            signature: alloc::vec![0x33; 512],
        };
        let mut buf = [0u8; 4096];
        let frame = req
            .encode_request(&mut buf, (1, 1))
            .expect("encode request");
        assert!(frame.len() <= buf.len());
    }
}
