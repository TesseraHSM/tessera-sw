// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaSign` wire schema.
//!
//! `MlDsaSign` is (temporarily) an out-of-session command that produces an ML-DSA signature
//! over a host-supplied message using a caller-held **masked** ML-DSA
//! secret key (from [`MlDsaGenerateKey`](crate::mldsa_generate_key)).  The
//! device unmasks the key on-device and signs; this types crate only
//! defines the wire schema and performs no cryptography.
//! There is intentionally no `key_kind` request field: the masked blob is
//! self-describing.  Its authenticated key kind already tells the firmware
//! which parameter set the key belongs to.
//!
//! Inputs: `session_id`, the `masked_key`, the message bytes, and the
//! FIPS 204 context string `ctx`.  Output: the ML-DSA signature bytes.
//!
//! `ctx` is the caller-chosen context string of `ML-DSA.Sign(sk, M, ctx)`
//! (FIPS 204 §5.2).  It is domain-separation input that is bound into the
//! signature, so a signature produced under one `ctx` never verifies
//! under another.  It is carried as a buffer of 0..=255 bytes; an empty
//! `ctx` is the FIPS 204 default.  See [`MLDSA_CTX_MAX_LEN`].
//!
//! # TEMPORARY: out-of-session bring-up
//!
//! **This command is wired as `no_session` purely to unblock hardware
//! bring-up and MUST be reverted to `in_session` before any PR.**  TBOR
//! session establishment currently fails on real silicon
//! (`SessionOpenInit` -> `TborDecodeError`), which blocks every
//! in-session command, while the `no_session` path is proven working
//! there by `ApiRev`.  Running out of session means the request carries
//! no `session_id` and the private key is masked under a hardcoded
//! development key rather than a partition masking key, so there is
//! **no authentication, no authorization and no key protection**.
//! Not fit to ship.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::mldsa_generate_key::MASKED_MLDSA_KEY_MAX_LEN;
pub use crate::mldsa_generate_key::MLDSA_CTX_MAX_LEN;
pub use crate::mldsa_generate_key::MLDSA_MESSAGE_MAX_LEN;
pub use crate::mldsa_generate_key::MLDSA_SIGNATURE_MAX_LEN;

/// TBOR opcode for `MlDsaSign`.
pub const TBOR_OP_MLDSA_SIGN: u8 = 0x27;

/// `MlDsaSign` request schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can unmask it **in
/// place** in the request buffer (via `decode_mut`) — no scratch copy —
/// and sign directly from the recovered key.
#[tbor(opcode = 0x27)]
pub struct TborMlDsaSignReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The masked ML-DSA secret key, an AEAD-GCM-256 envelope of 164 B:
    /// the wire ships seed-only keys.  See [`MASKED_MLDSA_KEY_MAX_LEN`].
    #[tbor(buffer, max_len = 5156, mutable)]
    pub masked_key: &'a [u8],

    /// Message to sign.  The TBOR schema caps inline messages at 586 B; see
    /// [`MLDSA_MESSAGE_MAX_LEN`].
    #[tbor(buffer, max_len = 586)]
    pub message: &'a [u8],

    /// FIPS 204 context string `ctx` for `ML-DSA.Sign(sk, M, ctx)`,
    /// 0..=255 bytes.  Empty is the FIPS 204 default.  See
    /// [`MLDSA_CTX_MAX_LEN`].
    #[tbor(buffer, max_len = 255)]
    pub ctx: &'a [u8],
}

/// `MlDsaSign` response schema.
#[tbor(response)]
pub struct TborMlDsaSignResp<'a> {
    /// ML-DSA signature bytes.  Up to 4627 B for ML-DSA-87.
    #[tbor(buffer, max_len = 4627, mutable)]
    pub signature: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 8192];
        let masked = [0x11u8; MASKED_MLDSA_KEY_MAX_LEN];
        let message = [0x22u8; 32];
        let ctx = [0x44u8; 8];
        let frame = TborMlDsaSignReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .message(&message)
            .unwrap()
            .ctx(&ctx)
            .unwrap()
            .finish();
        assert_eq!(frame.message(), &message[..]);
        assert_eq!(frame.ctx(), &ctx[..]);
    }

    #[test]
    fn request_round_trips_empty_ctx() {
        let mut buf = [0u8; 8192];
        let masked = [0x11u8; MASKED_MLDSA_KEY_MAX_LEN];
        let message = [0x22u8; 32];
        let frame = TborMlDsaSignReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .message(&message)
            .unwrap()
            .ctx(&[])
            .unwrap()
            .finish();
        assert!(frame.ctx().is_empty());
    }

    #[test]
    fn request_round_trips_max_sized_fields() {
        let mut buf = [0u8; 8192];
        let masked = [0x11u8; MASKED_MLDSA_KEY_MAX_LEN];
        let message = [0x22u8; MLDSA_MESSAGE_MAX_LEN];
        let ctx = [0x44u8; MLDSA_CTX_MAX_LEN];
        let frame = TborMlDsaSignReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .message(&message)
            .unwrap()
            .ctx(&ctx)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
        assert_eq!(frame.message(), &message[..]);
        assert_eq!(frame.ctx(), &ctx[..]);
    }

    #[test]
    fn response_round_trips_signature() {
        let mut buf = [0u8; 8192];
        let sig = [0x33u8; MLDSA_SIGNATURE_MAX_LEN];
        let frame = TborMlDsaSignResp::encode(&mut buf, 0, true)
            .unwrap()
            .signature(&sig)
            .unwrap()
            .finish();
        assert_eq!(frame.signature(), &sig[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(5156 == MASKED_MLDSA_KEY_MAX_LEN);
        const _: () = assert!(586 == MLDSA_MESSAGE_MAX_LEN);
        const _: () = assert!(255 == MLDSA_CTX_MAX_LEN);
        const _: () = assert!(4627 == MLDSA_SIGNATURE_MAX_LEN);
        assert_eq!(MLDSA_SIGNATURE_MAX_LEN, 4627);
    }
}
