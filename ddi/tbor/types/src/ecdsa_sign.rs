// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR message-level `EcdsaSign` command.

use alloc::vec::Vec;

pub use crate::ecc_generate_key::MASKED_ECC_KEY_MAX_LEN;
pub use crate::ecc_generate_key::MASKED_ECC_KEY_MIN_LEN;
use crate::tbor;

/// TBOR opcode for message-level `EcdsaSign`.
pub const TBOR_OP_ECDSA_SIGN: u8 = 0x37;
/// Maximum raw message length.
pub const ECDSA_MESSAGE_MAX_LEN: usize = 8192;
/// Maximum padded ECDSA signature length, including std Duo P-521.
pub const ECDSA_SIGNATURE_MAX_LEN: usize = 144;

const _: () = assert!(MASKED_ECC_KEY_MIN_LEN == 264);
const _: () = assert!(MASKED_ECC_KEY_MAX_LEN == 312);

/// Host-facing TBOR `EcdsaSign` request.
#[tbor(opcode = TBOR_OP_ECDSA_SIGN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborEcdsaSignReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,
    /// Authenticated masked ECC private-key envelope.
    #[tbor(align = 4, min_len = 264, max_len = 312)]
    pub masked_key: Vec<u8>,
    /// Required SHA-256, SHA-384, or SHA-512 selector.
    pub hash_algo: u8,
    /// OOB descriptor index containing the message (zero for empty input).
    pub message_index: u8,
    /// Raw message length, from zero through 8192 bytes.
    pub message_len: u16,
}

/// Host-facing TBOR `EcdsaSign` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborEcdsaSignResp {
    /// Raw padded `r || s` in device operand order.
    #[tbor(max_len = 144)]
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn maximum_request_and_response_fit_exchange_capacity() {
        let req = TborEcdsaSignReq {
            session_id: 7,
            masked_key: alloc::vec![0x11; MASKED_ECC_KEY_MAX_LEN],
            hash_algo: 3,
            message_index: 1,
            message_len: ECDSA_MESSAGE_MAX_LEN as u16,
        };
        let mut req_buf = [0u8; 4096];
        let request = req
            .encode_request(&mut req_buf, (1, 1))
            .expect("encode request");
        assert!(request.len() <= req_buf.len());
    }
}
