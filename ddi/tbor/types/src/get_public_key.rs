// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `GetPublicKey` command.
//!
//! `GetPublicKey` is an **in-session** command that takes a masked private
//! key (RSA / RSA-CRT / ECC), unmasks it on-device (verifying the AEAD
//! tag), and returns its wire public key in the same format as
//! [`TborUnwrapKeyResp::pub_key`](crate::TborUnwrapKeyResp): `n_le ‖ e_le`
//! for RSA, `x ‖ y` for ECC.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `GetPublicKey`.
pub const TBOR_OP_GET_PUBLIC_KEY: u8 = 0x2F;

/// Maximum wire length of the `masked_key` request buffer.
pub const GET_PUBLIC_KEY_MASKED_KEY_MAX_LEN: usize = crate::UNWRAP_MASKED_KEY_MAX_LEN;

/// Maximum wire length of the returned `pub_key`.
pub const GET_PUBLIC_KEY_PUB_KEY_MAX_LEN: usize = crate::UNWRAP_PUB_KEY_MAX_LEN;

/// Host-facing TBOR `GetPublicKey` request.
#[tbor(opcode = TBOR_OP_GET_PUBLIC_KEY, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborGetPublicKeyReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked private-key envelope. Variable length up to
    /// [`GET_PUBLIC_KEY_MASKED_KEY_MAX_LEN`].
    #[tbor(max_len = 3168)]
    pub masked_key: Vec<u8>,
}

/// Host-facing TBOR `GetPublicKey` response.
#[tbor(response)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborGetPublicKeyResp {
    /// The wire public key. Variable length up to
    /// [`GET_PUBLIC_KEY_PUB_KEY_MAX_LEN`].
    #[tbor(max_len = 520)]
    pub pub_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_masked_key() {
        let req = TborGetPublicKeyReq {
            session_id: 9,
            masked_key: alloc::vec![0xCD; 180],
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0xCD; 4]),
            "encoded frame must carry the masked key",
        );
    }
}
