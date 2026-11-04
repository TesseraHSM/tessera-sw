// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `VerifyKey` wire schema.
//!
//! `VerifyKey` is an in-session command that authenticates a **masked key**
//! of any kind: it resolves the blob's scope masking key, verifies the AEAD
//! tag (which also covers the cleartext metadata carried as AAD), and
//! validates the metadata. It persists nothing and returns no payload, so a
//! host can authenticate a masked key at unmask time instead of on first use.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//! * `masked_key` — the masked-key envelope. Variable length up to
//!   [`VERIFY_KEY_MASKED_KEY_MAX_LEN`].
//!
//! Outputs: none (empty acknowledgement).

use tsra_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `VerifyKey`.
pub const TBOR_OP_VERIFY_KEY: u8 = 0x32;

/// Maximum wire length of the `masked_key` request buffer. Accommodates
/// expanded ML-DSA-87 keys, the largest generated masked keys. Pinned into the
/// `#[tbor(buffer, max_len = 5160)]` literal on
/// [`TborVerifyKeyReq::masked_key`].
pub const VERIFY_KEY_MASKED_KEY_MAX_LEN: usize = crate::MASKED_MLDSA_KEY_MAX_LEN;

const _: () = assert!(VERIFY_KEY_MASKED_KEY_MAX_LEN >= crate::MASKED_MLKEM_KEY_MAX_LEN);
const _: () = assert!(VERIFY_KEY_MASKED_KEY_MAX_LEN >= crate::UNWRAP_MASKED_KEY_MAX_LEN);
const _: () = assert!(VERIFY_KEY_MASKED_KEY_MAX_LEN == 5160);

/// `VerifyKey` request schema.
#[tbor(opcode = 0x32, pair = TborVerifyKeyResp)]
pub struct TborVerifyKeyReq<'a> {
    /// CO/CU session id this request is bound to. The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The masked-key envelope. `mutable` so the handler can unmask it in
    /// place.
    #[tbor(buffer, max_len = 5160, mutable)]
    pub masked_key: &'a [u8],
}

/// `VerifyKey` response schema.
///
/// No semantic payload — the wire derive emits a `none` TOC entry to
/// satisfy the `toc_count >= 1` codec requirement.
#[tbor(response, pair = TborVerifyKeyReq)]
pub struct TborVerifyKeyResp;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_masked_key() {
        let mut buf = [0u8; 1024];
        let masked = [0xCDu8; 180];
        let frame = TborVerifyKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
    }

    #[test]
    fn request_bounds_largest_generated_key() {
        let masked = [0xCD; VERIFY_KEY_MASKED_KEY_MAX_LEN + 1];
        let mut buf = [0u8; 8192];
        let frame = TborVerifyKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .masked_key(&masked[..VERIFY_KEY_MASKED_KEY_MAX_LEN])
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key().len(), VERIFY_KEY_MASKED_KEY_MAX_LEN);
        assert!(TborVerifyKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .masked_key(&masked)
            .is_err());
    }

    #[test]
    fn opcode_is_pinned() {
        assert_eq!(TBOR_OP_VERIFY_KEY, 0x32);
    }
}
