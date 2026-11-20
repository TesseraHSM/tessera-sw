// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `RsaVerify` wire schema for masked-key RSA signature verification.

use tsra_fw_ddi_tbor_api::tbor;

use crate::rsa_sign::RsaPadding;
pub use crate::rsa_sign::RSA_MASKED_KEY_MAX_LEN;
pub use crate::rsa_sign::RSA_SIGNATURE_MAX_LEN;
pub use crate::rsa_sign::RSA_SIGN_MESSAGE_MAX_LEN;

/// TBOR opcode for `RsaVerify`.
pub const TBOR_OP_RSA_VERIFY: u8 = 0x36;

/// `RsaVerify` request schema.
#[tbor(opcode = 0x36, pair = TborRsaVerifyResp)]
pub struct TborRsaVerifyReq<'a> {
    /// CO/CU session id bound to this request.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Authenticated masked RSA private-key envelope.
    #[tbor(align = 4, buffer, max_len = 3168, mutable)]
    pub masked_key: &'a [u8],

    /// Required padding selector.
    #[tbor(U8)]
    pub padding: RsaPadding,

    /// Required SHA-256 / SHA-384 / SHA-512 selector.
    #[tbor(U8)]
    pub hash_algo: crate::key_props::HashAlgo,

    /// Present only for PSS; a present zero is distinct from absence.
    pub salt_len: Option<u16>,

    /// OOB input SGL descriptor index for the raw message.
    pub message_index: u8,

    /// Raw message length, at most 8192 bytes.
    pub message_len: u16,

    /// Exactly one modulus-sized signature in device operand order.
    #[tbor(buffer, max_len = 512)]
    pub signature: &'a [u8],
}

/// `RsaVerify` response schema.
///
/// Success has an empty body; invalid signatures are returned as
/// `HsmError::RsaVerifyFailed`.
#[tbor(response, pair = TborRsaVerifyReq)]
pub struct TborRsaVerifyResp;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn maximum_request_and_empty_response_fit_exchange_frame() {
        let mut buf = [0u8; 4096];
        let key = [0x11u8; RSA_MASKED_KEY_MAX_LEN];
        let signature = [0x33u8; RSA_SIGNATURE_MAX_LEN];
        let frame = TborRsaVerifyReq::encode(&mut buf, (1, 1))
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .masked_key(&key)
            .unwrap()
            .padding(RsaPadding::Pss)
            .unwrap()
            .hash_algo(crate::key_props::HashAlgo::Sha512)
            .unwrap()
            .salt_len(Some(64))
            .unwrap()
            .message_index(0)
            .unwrap()
            .message_len(RSA_SIGN_MESSAGE_MAX_LEN as u16)
            .unwrap()
            .signature(&signature)
            .unwrap()
            .finish();
        assert!(frame.len() <= buf.len());

        let frame = TborRsaVerifyResp::encode(&mut buf, (1, 1), 0, true)
            .unwrap()
            .finish();
        assert!(frame.len() <= buf.len());
    }
}
