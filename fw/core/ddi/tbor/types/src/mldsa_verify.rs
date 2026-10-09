// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaVerify` wire schema.
//!
//! `MlDsaVerify` is (temporarily) an out-of-session command that verifies an ML-DSA
//! signature over a host-supplied message and public key.  The response is
//! an empty frame on success; no key is stored or
//! returned by this command.
//!
//! `ctx` is the caller-chosen context string of
//! `ML-DSA.Verify(pk, M, sigma, ctx)` (FIPS 204 §5.3) and must match the
//! `ctx` used at signing time: it is bound into the signature, so
//! verification under a different context fails.  It is carried as a
//! buffer of 0..=255 bytes; an empty `ctx` is the FIPS 204 default.  See
//! [`MLDSA_CTX_MAX_LEN`].
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

pub use crate::mldsa_generate_key::MLDSA_CTX_MAX_LEN;
pub use crate::mldsa_generate_key::MLDSA_MESSAGE_MAX_LEN;
pub use crate::mldsa_generate_key::MLDSA_PUB_KEY_MAX_LEN;
pub use crate::mldsa_generate_key::MLDSA_SIGNATURE_MAX_LEN;

/// TBOR opcode for `MlDsaVerify`.
pub const TBOR_OP_MLDSA_VERIFY: u8 = 0x28;
/// The ML-DSA parameter set is **not** carried on the wire: it is recovered
/// from the length of `pub_key`, which is unique per parameter set
/// (ML-DSA-44 = 1312 B, ML-DSA-65 = 1952 B, ML-DSA-87 = 2592 B; see the
/// length table in the key vault).  Carrying it explicitly would create a
/// second source of truth that firmware must cross-check against the key,
/// and would let a caller pair a parameter set with a mismatched key.
/// `MlDsaVerify` request schema.
#[tbor(opcode = 0x28)]
pub struct TborMlDsaVerifyReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// ML-DSA public key bytes.  Up to 2592 B for ML-DSA-87.
    #[tbor(buffer, max_len = 2592)]
    pub pub_key: &'a [u8],

    /// Message that was signed.  Capped at 586 B — the residue of the
    /// 8192-byte host staging budget once the maximum public key,
    /// signature and context string are accounted for.  See
    /// [`MLDSA_MESSAGE_MAX_LEN`].
    #[tbor(buffer, max_len = 586)]
    pub message: &'a [u8],

    /// FIPS 204 context string `ctx` for `ML-DSA.Verify(pk, M, sigma,
    /// ctx)`, 0..=255 bytes.  Must match the `ctx` used at signing time.
    /// See [`MLDSA_CTX_MAX_LEN`].
    #[tbor(buffer, max_len = 255)]
    pub ctx: &'a [u8],

    /// ML-DSA signature bytes.  Up to 4627 B for ML-DSA-87.
    #[tbor(buffer, max_len = 4627)]
    pub signature: &'a [u8],
}

/// `MlDsaVerify` response schema.
///
/// Carries no payload: a successful response *is* the affirmative
/// verification result.  A bad signature is reported as the
/// [`MlDsaVerifyFailed`](tsra_fw_hsm_pal_traits::HsmError::MlDsaVerifyFailed)
/// error status, mirroring how `EccVerifyFailed` reports an ECC
/// verification failure.  Returning a boolean instead would let a caller
/// that forgets to inspect it treat any signature as valid; an error
/// status is caught by the normal error path.
#[tbor(response)]
pub struct TborMlDsaVerifyResp;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 8192];
        let pub_key = [0x11u8; MLDSA_PUB_KEY_MAX_LEN];
        let message = [0x22u8; 32];
        let ctx = [0x44u8; 8];
        let signature = [0x33u8; MLDSA_SIGNATURE_MAX_LEN];
        let frame = TborMlDsaVerifyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .message(&message)
            .unwrap()
            .ctx(&ctx)
            .unwrap()
            .signature(&signature)
            .unwrap()
            .finish();
        assert_eq!(frame.message(), &message[..]);
        assert_eq!(frame.ctx(), &ctx[..]);
    }

    #[test]
    fn request_round_trips_empty_ctx() {
        let mut buf = [0u8; 8192];
        let pub_key = [0x11u8; 32];
        let message = [0x22u8; 32];
        let signature = [0x33u8; 64];
        let frame = TborMlDsaVerifyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .message(&message)
            .unwrap()
            .ctx(&[])
            .unwrap()
            .signature(&signature)
            .unwrap()
            .finish();
        assert!(frame.ctx().is_empty());
    }

    /// The worst-case verify request must fit the host encoder's 8192-byte
    /// transport buffer with the data section staged at offset 132.
    #[test]
    fn max_sized_request_fits_the_host_staging_budget() {
        let mut buf = [0u8; 8192];
        let pub_key = [0x11u8; MLDSA_PUB_KEY_MAX_LEN];
        let message = [0x22u8; MLDSA_MESSAGE_MAX_LEN];
        let ctx = [0x44u8; MLDSA_CTX_MAX_LEN];
        let signature = [0x33u8; MLDSA_SIGNATURE_MAX_LEN];
        let frame = TborMlDsaVerifyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .message(&message)
            .unwrap()
            .ctx(&ctx)
            .unwrap()
            .signature(&signature)
            .unwrap()
            .finish();
        assert_eq!(frame.message(), &message[..]);
        assert_eq!(frame.ctx(), &ctx[..]);
        assert_eq!(frame.signature(), &signature[..]);
    }

    #[test]
    fn response_carries_no_payload() {
        let mut buf = [0u8; 512];
        let _ = TborMlDsaVerifyResp::encode(&mut buf, 0, true)
            .unwrap()
            .finish();
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(2592 == MLDSA_PUB_KEY_MAX_LEN);
        const _: () = assert!(586 == MLDSA_MESSAGE_MAX_LEN);
        const _: () = assert!(255 == MLDSA_CTX_MAX_LEN);
        const _: () = assert!(4627 == MLDSA_SIGNATURE_MAX_LEN);
    }

    /// Worst-case verify frame: `header(4) + toc_count(6) * 4 + data`.
    /// The data section is exactly the 8192-byte transport buffer minus
    /// the 132-byte staging offset.
    #[test]
    fn worst_case_frame_fits_both_bounds() {
        const TRANSPORT_BUF_LEN: usize = 8192;
        const STAGE_OFFSET: usize = 132;
        const TOC_COUNT: usize = 6;

        let data = MLDSA_PUB_KEY_MAX_LEN
            + MLDSA_MESSAGE_MAX_LEN
            + MLDSA_CTX_MAX_LEN
            + MLDSA_SIGNATURE_MAX_LEN;
        assert_eq!(data, 8060);
        assert_eq!(STAGE_OFFSET + data, TRANSPORT_BUF_LEN);
        assert_eq!(4 + TOC_COUNT * 4 + data, 8088);
        assert!(4 + TOC_COUNT * 4 + data <= TRANSPORT_BUF_LEN);
    }
}
