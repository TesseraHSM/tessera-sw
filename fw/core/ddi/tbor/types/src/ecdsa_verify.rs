// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EcdsaVerify` schema for internally hashing an OOB message.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::ecdsa_sign::MASKED_ECC_KEY_MAX_LEN;
pub use crate::ecdsa_sign::MASKED_ECC_KEY_MIN_LEN;
use crate::key_props::HashAlgo;

/// TBOR opcode for message-level `EcdsaVerify`.
pub const TBOR_OP_ECDSA_VERIFY: u8 = 0x38;
/// Maximum raw message length accepted by the command.
pub use crate::ecdsa_sign::ECDSA_MESSAGE_MAX_LEN;
pub use crate::ecdsa_sign::ECDSA_SIGNATURE_MAX_LEN;

const _: () = assert!(MASKED_ECC_KEY_MIN_LEN == 264);
const _: () = assert!(MASKED_ECC_KEY_MAX_LEN == 312);

/// `EcdsaVerify` request. The host must keep the referenced OOB memory
/// accessible and unchanged until command completion.
#[tbor(opcode = 0x38, pair = TborEcdsaVerifyResp)]
pub struct TborEcdsaVerifyReq<'a> {
    /// CO/CU session id bound to this request.
    #[tbor(session_id)]
    pub session_id: SessionId,
    /// Authenticated masked ECC private-key envelope.
    #[tbor(align = 4, buffer, min_len = 264, max_len = 312, mutable)]
    pub masked_key: &'a [u8],
    /// Required SHA-256, SHA-384, or SHA-512 selector.
    #[tbor(U8)]
    pub hash_algo: HashAlgo,
    /// OOB descriptor index containing the raw message; zero for empty input.
    pub message_index: u8,
    /// Raw message length, from zero through `ECDSA_MESSAGE_MAX_LEN`.
    pub message_len: u16,
    /// Raw `r || s` in device operand order with zero-padded coordinate lanes.
    #[tbor(buffer, max_len = 144)]
    pub signature: &'a [u8],
}

/// `EcdsaVerify` response. A valid signature has an empty success body.
#[tbor(response, pair = TborEcdsaVerifyReq)]
pub struct TborEcdsaVerifyResp;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_required_fields() {
        let mut buf = [0u8; 1024];
        let key = [0x11; MASKED_ECC_KEY_MAX_LEN];
        let sig = [0x22; ECDSA_SIGNATURE_MAX_LEN];
        let frame = TborEcdsaVerifyReq::encode(&mut buf, (1, 1))
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .masked_key(&key)
            .unwrap()
            .hash_algo(HashAlgo::Sha512)
            .unwrap()
            .message_index(1)
            .unwrap()
            .message_len(8192)
            .unwrap()
            .signature(&sig)
            .unwrap()
            .finish();
        assert_eq!(frame.signature().len(), ECDSA_SIGNATURE_MAX_LEN);
        assert_eq!(frame.message_len(), 8192);
    }

    #[test]
    fn response_is_empty() {
        let mut buf = [0u8; 512];
        let frame = TborEcdsaVerifyResp::encode(&mut buf, (1, 1), 0, true)
            .unwrap()
            .finish();
        assert!(frame.as_bytes().len() <= buf.len());
    }
}
