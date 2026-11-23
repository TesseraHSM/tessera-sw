// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EccVerify` wire schema.
//!
//! The caller supplies an authenticated masked ECC private key and packed
//! signature/digest operands. Firmware derives the public key on-device.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::ecc_generate_key::MASKED_ECC_KEY_MAX_LEN;
pub use crate::ecc_generate_key::MASKED_ECC_KEY_MIN_LEN;
use crate::key_props::HashAlgo;

/// TBOR opcode for `EccVerify`.
pub const TBOR_OP_ECC_VERIFY: u8 = 0x33;

/// Maximum packed P-521 verify input length on std Duo.
pub const ECC_VERIFY_INPUT_MAX_LEN: usize = 216;

/// `EccVerify` request schema.
#[tbor(opcode = 0x33, pair = TborEccVerifyResp)]
pub struct TborEccVerifyReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Hash algorithm selector.
    #[tbor(U8)]
    pub hash_algo: HashAlgo,

    /// Masked ECC private key, authenticated and unmasked in place.
    #[tbor(align = 4, buffer, min_len = 264, max_len = 312, mutable)]
    pub masked_key: &'a [u8],

    /// Packed `r || s || digest_lane` in device byte order.
    #[tbor(align = 4, buffer, min_len = 96, max_len = 216)]
    pub input: &'a [u8],
}

/// `EccVerify` response schema. Success carries no payload.
#[tbor(response, pair = TborEccVerifyReq)]
pub struct TborEccVerifyResp;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn ecc_verify_max_request_has_aligned_mutable_key_and_input() {
        let mut buf = [0u8; 640];
        let masked_key = [0x11u8; MASKED_ECC_KEY_MAX_LEN];
        let input = [0x22u8; ECC_VERIFY_INPUT_MAX_LEN];
        let frame = TborEccVerifyReq::encode(&mut buf, (1, 1))
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .hash_algo(HashAlgo::Sha512)
            .unwrap()
            .masked_key(&masked_key)
            .unwrap()
            .input(&input)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked_key[..]);
        assert_eq!(frame.input(), &input[..]);
        assert_eq!(frame.masked_key().as_ptr() as usize % 4, 0);
        assert_eq!(frame.input().as_ptr() as usize % 4, 0);
        assert_eq!(frame.len(), 564);
    }

    #[test]
    fn ecc_verify_empty_response_is_typed() {
        let mut buf = [0u8; 64];
        let _ = TborEccVerifyResp::encode(&mut buf, (1, 1), 0, true)
            .unwrap()
            .finish();
    }
}
