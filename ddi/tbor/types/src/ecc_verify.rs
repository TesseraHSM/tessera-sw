// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `EccVerify` command.
//!
//! Verification uses an authenticated masked ECC private-key blob. Firmware
//! derives the public key on-device and verifies a precomputed digest.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `EccVerify`.
pub const TBOR_OP_ECC_VERIFY: u8 = 0x33;

/// Maximum packed P-521 verify input length on std Duo.
pub const ECC_VERIFY_INPUT_MAX_LEN: usize = 216;

/// Host-facing TBOR `EccVerify` request.
#[tbor(opcode = TBOR_OP_ECC_VERIFY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborEccVerifyReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Hash algorithm selector (SHA-256, SHA-384, or SHA-512).
    pub hash_algo: u8,

    /// The masked ECC private key (from `EccGenerateKey` / `UnwrapKey`).
    #[tbor(align = 4, min_len = 264, max_len = 312)]
    pub masked_key: Vec<u8>,

    /// Packed `r || s || digest_lane` in device byte order.
    #[tbor(align = 4, min_len = 96, max_len = 216)]
    pub input: Vec<u8>,
}

/// Host-facing TBOR `EccVerify` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborEccVerifyResp;

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::codec::ResponseEncoder;
    use tsra_ddi_tbor_types::TborOpReq;
    use tsra_ddi_tbor_types::TborResp;

    use super::*;

    #[test]
    fn ecc_verify_request_encodes_aligned_fields() {
        let req = TborEccVerifyReq {
            session_id: 7,
            hash_algo: 3,
            masked_key: alloc::vec![0x11; 312],
            input: alloc::vec![0x22; ECC_VERIFY_INPUT_MAX_LEN],
        };
        let mut buf = [0u8; 640];
        let frame = req.encode_request(&mut buf, (1, 1)).expect("encode");
        assert_eq!(frame.len(), 564);
        assert_eq!(
            frame
                .windows(ECC_VERIFY_INPUT_MAX_LEN)
                .filter(|window| *window == [0x22; ECC_VERIFY_INPUT_MAX_LEN])
                .count(),
            1
        );
    }

    #[test]
    fn ecc_verify_empty_response_decodes() {
        let mut buf = [0u8; 32];
        let frame = ResponseEncoder::new(&mut buf, (1, 1), 0, false)
            .none()
            .expect("none")
            .finish()
            .expect("finish");
        assert_eq!(
            TborEccVerifyResp::decode_response(frame).expect("decode"),
            TborEccVerifyResp
        );
    }

    #[test]
    fn ecc_verify_failed_status_survives_response_decoding() {
        let mut buf = [0u8; 32];
        let frame = ResponseEncoder::new(&mut buf, (1, 1), 0x0870_0024, false)
            .none()
            .expect("none")
            .finish()
            .expect("finish");
        assert!(matches!(
            TborEccVerifyResp::decode_response(frame),
            Err(tsra_ddi_tbor_types::codec::DecodeError::FwError(
                0x0870_0024
            ))
        ));
    }
}
