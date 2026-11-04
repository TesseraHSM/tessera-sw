// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetPublicKey` wire schema.
//!
//! `GetPublicKey` is an in-session command that takes a **masked private
//! key** (RSA / RSA-CRT / ECC), unmasks it (verifying the AEAD tag), and
//! returns the key's wire public key.  It lets a host that holds only the
//! masked blob rebuild the public half of a key pair.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//! * `masked_key` — the masked private-key envelope. Variable length up to
//!   [`GET_PUBLIC_KEY_MASKED_KEY_MAX_LEN`].
//!
//! Outputs:
//!
//! * `pub_key` — the wire public key, in the same format as
//!   [`TborUnwrapKeyResp::pub_key`](crate::unwrap_key::TborUnwrapKeyResp):
//!   `n_le ‖ e_le` for RSA, `x ‖ y` for ECC.

use tsra_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `GetPublicKey`.
pub const TBOR_OP_GET_PUBLIC_KEY: u8 = 0x2F;

/// Maximum wire length of the `masked_key` request buffer. Matches
/// `UnwrapKey` so RSA-4096 CRT envelopes fit. Pinned into the
/// `#[tbor(buffer, max_len = 3168)]` literal on
/// [`TborGetPublicKeyReq::masked_key`].
pub const GET_PUBLIC_KEY_MASKED_KEY_MAX_LEN: usize = crate::UNWRAP_MASKED_KEY_MAX_LEN;

/// Maximum wire length of the returned `pub_key` (RSA-4096
/// `n_le(512) ‖ e_le(4)`). Pinned into the `#[tbor(buffer, max_len = 520)]`
/// literal on [`TborGetPublicKeyResp::pub_key`].
pub const GET_PUBLIC_KEY_PUB_KEY_MAX_LEN: usize = crate::UNWRAP_PUB_KEY_MAX_LEN;

const _: () = assert!(GET_PUBLIC_KEY_MASKED_KEY_MAX_LEN == 3168);
const _: () = assert!(GET_PUBLIC_KEY_PUB_KEY_MAX_LEN == 520);

/// `GetPublicKey` request schema.
#[tbor(opcode = 0x2F, pair = TborGetPublicKeyResp)]
pub struct TborGetPublicKeyReq<'a> {
    /// CO/CU session id this request is bound to. The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The masked private-key envelope. `mutable` so the handler can
    /// unmask it in place.
    #[tbor(buffer, max_len = 3168, mutable)]
    pub masked_key: &'a [u8],
}

/// `GetPublicKey` response schema.
#[tbor(response, pair = TborGetPublicKeyReq)]
pub struct TborGetPublicKeyResp<'a> {
    /// The wire public key (`n_le ‖ e_le` for RSA, `x ‖ y` for ECC).
    #[tbor(buffer, max_len = 520, mutable)]
    pub pub_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_masked_key() {
        let mut buf = [0u8; 1024];
        let masked = [0xCDu8; 180];
        let frame = TborGetPublicKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
    }

    #[test]
    fn response_round_trips_pub_key() {
        let mut buf = [0u8; 1024];
        let pub_key = [0x5Au8; 96];
        let frame = TborGetPublicKeyResp::encode(&mut buf, 0, false)
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .finish();
        assert_eq!(frame.pub_key(), &pub_key[..]);
    }

    #[test]
    fn opcode_is_pinned() {
        assert_eq!(TBOR_OP_GET_PUBLIC_KEY, 0x2F);
    }
}
