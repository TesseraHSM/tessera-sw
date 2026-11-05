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
//! Inputs: `session_id`, the `masked_key`, the 64-byte message
//! representative `mu`, and the hedge variant `hedge`.  Output: the ML-DSA
//! signature bytes.
//!
//! Like `EccSign`, which signs a digest rather than a message, `MlDsaSign`
//! signs `μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)` rather than
//! `M`.  The caller computes it, binding its FIPS 204 context string `ctx`,
//! and the result is a pure ML-DSA signature over `M` under `ctx`.  See
//! [`MLDSA_MU_LEN`].
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

use open_enum::open_enum;
use tsra_fw_ddi_tbor_api::tbor;

pub use crate::mldsa_generate_key::MASKED_MLDSA_KEY_MAX_LEN;
pub use crate::mldsa_generate_key::MLDSA_MU_LEN;
pub use crate::mldsa_generate_key::MLDSA_SIGNATURE_MAX_LEN;

/// TBOR opcode for `MlDsaSign`.
pub const TBOR_OP_MLDSA_SIGN: u8 = 0x27;

/// How `MlDsaSign` randomizes the signature: FIPS 204's hedged variant,
/// which draws fresh randomness for every signature, or its deterministic
/// variant, which fixes it at zero so the same key and input always yield
/// the same signature.
///
/// Values and meanings follow PKCS#11's `CK_HEDGE_TYPE`.  Kept as an
/// [`open_enum`] so an unrecognized value round-trips as `MlDsaHedge(n)`
/// and the handler can reject it, rather than failing decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaHedge {
    /// Hedged or deterministic, as the device chooses
    /// (`CKH_HEDGE_PREFERRED`).
    Preferred = 0,
    /// Hedged, or fail (`CKH_HEDGE_REQUIRED`).
    Required = 1,
    /// Deterministic, or fail (`CKH_DETERMINISTIC_REQUIRED`).
    Deterministic = 2,
}

/// `MlDsaSign` request schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can unmask it **in
/// place** in the request buffer (via `decode_mut`) — no scratch copy —
/// and sign directly from the recovered key.
#[tbor(opcode = 0x27, pair = TborMlDsaSignResp)]
pub struct TborMlDsaSignReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The masked ML-DSA secret key, an AEAD-GCM-256 envelope of 164 B:
    /// the wire ships seed-only keys.  See [`MASKED_MLDSA_KEY_MAX_LEN`].
    #[tbor(buffer, max_len = 5160, mutable)]
    pub masked_key: &'a [u8],

    /// The message representative `μ` to sign, exactly [`MLDSA_MU_LEN`]
    /// bytes.
    #[tbor(buffer, len = 64)]
    pub mu: &'a [u8],

    /// How the signature is randomized, 1-byte [`MlDsaHedge`]: hedged or
    /// deterministic.
    #[tbor(U8)]
    pub hedge: MlDsaHedge,
}

/// `MlDsaSign` response schema.
#[tbor(response, pair = TborMlDsaSignReq)]
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

    fn encode<'a>(
        buf: &'a mut [u8],
        masked: &[u8],
        mu: &[u8],
        hedge: MlDsaHedge,
    ) -> TborMlDsaSignReqFrame<'a> {
        TborMlDsaSignReq::encode(buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .masked_key(masked)
            .unwrap()
            .mu(mu)
            .unwrap()
            .hedge(hedge)
            .unwrap()
            .finish()
    }

    /// The maximum request is the ML-DSA-87 masked key and `μ`, with its
    /// paired TOC footprint.
    #[test]
    fn max_sized_request_round_trips_fields() {
        let mut buf = [0u8; 8192];
        let masked = [0x11u8; MASKED_MLDSA_KEY_MAX_LEN];
        let mu = [0x55u8; MLDSA_MU_LEN];
        let frame = encode(&mut buf, &masked, &mu, MlDsaHedge::Deterministic);
        assert_eq!(frame.masked_key(), &masked[..]);
        assert_eq!(frame.mu(), &mu[..]);
        assert_eq!(frame.hedge(), MlDsaHedge::Deterministic);
        // header(8) + 4 TOC entries * 4 + data(5160 + 64).
        assert_eq!(frame.len(), 5248);
        assert_eq!(frame.len(), TborMlDsaSignReq::MAX_ENCODED_SIZE);
    }

    #[test]
    fn request_round_trips_every_hedge_and_unknown_values() {
        let mut buf = [0u8; 8192];
        let masked = [0x11u8; MASKED_MLDSA_KEY_MAX_LEN];
        let mu = [0x55u8; MLDSA_MU_LEN];
        for hedge in [
            MlDsaHedge::Preferred,
            MlDsaHedge::Required,
            MlDsaHedge::Deterministic,
            MlDsaHedge(3),
            MlDsaHedge(0xff),
        ] {
            let frame = encode(&mut buf, &masked, &mu, hedge);
            assert_eq!(frame.hedge(), hedge);
            assert_eq!(frame.mu(), &mu[..]);
        }
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
        const _: () = assert!(5160 == MASKED_MLDSA_KEY_MAX_LEN);
        const _: () = assert!(64 == MLDSA_MU_LEN);
        const _: () = assert!(4627 == MLDSA_SIGNATURE_MAX_LEN);
        assert_eq!(MLDSA_SIGNATURE_MAX_LEN, 4627);
    }
}
