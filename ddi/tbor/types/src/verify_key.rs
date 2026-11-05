// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `VerifyKey` command.
//!
//! `VerifyKey` is an **in-session** command that authenticates a masked key
//! of any kind on-device (AEAD tag over the metadata and key material, under
//! the blob's scope masking key) without using it. It persists nothing and
//! returns an empty acknowledgement.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `VerifyKey`.
pub const TBOR_OP_VERIFY_KEY: u8 = 0x32;

/// Maximum wire length of the `masked_key` request buffer.
pub const VERIFY_KEY_MASKED_KEY_MAX_LEN: usize = crate::MASKED_MLDSA_KEY_MAX_LEN;

const _: () = assert!(VERIFY_KEY_MASKED_KEY_MAX_LEN >= crate::MASKED_MLKEM_KEY_MAX_LEN);
const _: () = assert!(VERIFY_KEY_MASKED_KEY_MAX_LEN >= crate::UNWRAP_MASKED_KEY_MAX_LEN);
const _: () = assert!(VERIFY_KEY_MASKED_KEY_MAX_LEN == 5160);

/// Host-facing TBOR `VerifyKey` request.
#[tbor(opcode = TBOR_OP_VERIFY_KEY, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborVerifyKeyReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked-key envelope. Variable length up to
    /// [`VERIFY_KEY_MASKED_KEY_MAX_LEN`].
    #[tbor(max_len = 5160)]
    pub masked_key: Vec<u8>,
}

/// Host-facing TBOR `VerifyKey` response (empty ack).
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborVerifyKeyResp;

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_masked_key() {
        let req = TborVerifyKeyReq {
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
