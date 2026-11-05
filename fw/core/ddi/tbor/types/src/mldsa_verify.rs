// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaVerify` wire schema.
//!
//! `MlDsaVerify` is (temporarily) an out-of-session command that verifies an ML-DSA
//! signature over a host-supplied 64-byte message representative `μ` and
//! public key.  The response is an empty frame on success; no key is stored
//! or returned by this command.
//!
//! As [`MlDsaSign`](crate::mldsa_sign) signs `μ` rather than a message,
//! verification takes `μ` too: a pure ML-DSA signature over `M` under the
//! FIPS 204 context string `ctx` verifies over
//! `μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)`.  See
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

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::mldsa_generate_key::MLDSA_MU_LEN;
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
#[tbor(opcode = 0x28, pair = TborMlDsaVerifyResp)]
pub struct TborMlDsaVerifyReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// ML-DSA public key bytes.  Up to 2592 B for ML-DSA-87.
    #[tbor(buffer, max_len = 2592)]
    pub pub_key: &'a [u8],

    /// The message representative `μ` the signature covers, exactly
    /// [`MLDSA_MU_LEN`] bytes.
    #[tbor(buffer, len = 64)]
    pub mu: &'a [u8],

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
#[tbor(response, pair = TborMlDsaVerifyReq)]
pub struct TborMlDsaVerifyResp;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    /// The maximum request is the ML-DSA-87 public key, `μ` and signature,
    /// with its paired TOC footprint.
    #[test]
    fn max_sized_request_round_trips_fields() {
        let mut buf = [0u8; 8192];
        let pub_key = [0x11u8; MLDSA_PUB_KEY_MAX_LEN];
        let mu = [0x55u8; MLDSA_MU_LEN];
        let signature = [0x33u8; MLDSA_SIGNATURE_MAX_LEN];
        let frame = TborMlDsaVerifyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .mu(&mu)
            .unwrap()
            .signature(&signature)
            .unwrap()
            .finish();
        assert_eq!(frame.pub_key(), &pub_key[..]);
        assert_eq!(frame.mu(), &mu[..]);
        assert_eq!(frame.signature(), &signature[..]);
        // header(8) + 4 TOC entries * 4 + data(2592 + 64 + 4627).
        assert_eq!(frame.len(), 7307);
        assert_eq!(frame.len(), TborMlDsaVerifyReq::MAX_ENCODED_SIZE);
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
        const _: () = assert!(64 == MLDSA_MU_LEN);
        const _: () = assert!(4627 == MLDSA_SIGNATURE_MAX_LEN);
    }
}
