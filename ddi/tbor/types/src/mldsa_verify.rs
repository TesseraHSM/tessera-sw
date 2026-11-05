// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlDsaVerify` command.
//!
//! `MlDsaVerify` is (temporarily) an **out-of-session** command that verifies an ML-DSA signature over a host-supplied
//! 64-byte message representative `μ` and public key.  Success is signalled
//! by an empty response; an invalid signature arrives as the
//! `MlDsaVerifyFailed` status.
//!
//! As `MlDsaSign` signs `μ` rather than a message, verification takes `μ`
//! too: a pure ML-DSA signature over `M` under the FIPS 204 context string
//! `ctx` verifies over `μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)`.
//! See [`MLDSA_MU_LEN`](crate::MLDSA_MU_LEN).
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

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `MlDsaVerify`.
pub const TBOR_OP_MLDSA_VERIFY: u8 = 0x28;

/// The ML-DSA parameter set is **not** carried on the wire: it is recovered
/// from the length of `pub_key`, which is unique per parameter set
/// (ML-DSA-44 = 1312 B, ML-DSA-65 = 1952 B, ML-DSA-87 = 2592 B; see the
/// length table in the key vault).  Carrying it explicitly would create a
/// second source of truth that firmware must cross-check against the key,
/// and would let a caller pair a parameter set with a mismatched key.
/// Host-facing TBOR `MlDsaVerify` request.
#[tbor(opcode = TBOR_OP_MLDSA_VERIFY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaVerifyReq {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// ML-DSA public key bytes.
    #[tbor(max_len = 2592)]
    pub pub_key: Vec<u8>,

    /// The message representative `μ` the signature covers, exactly
    /// [`MLDSA_MU_LEN`](crate::MLDSA_MU_LEN) bytes.
    #[tbor(min_len = 64, max_len = 64)]
    pub mu: Vec<u8>,

    /// ML-DSA signature bytes.
    #[tbor(max_len = 4627)]
    pub signature: Vec<u8>,
}

/// Host-facing TBOR `MlDsaVerify` response.
///
/// Carries no payload: a successful response *is* the affirmative
/// verification result.  A bad signature arrives as the
/// [`TborStatus::MlDsaVerifyFailed`](crate::TborStatus) error status,
/// mirroring `EccVerifyFailed`.
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborMlDsaVerifyResp;

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::mldsa_generate_key::MLDSA_MU_LEN;
    use crate::mldsa_generate_key::MLDSA_PUB_KEY_MAX_LEN;
    use crate::mldsa_generate_key::MLDSA_SIGNATURE_MAX_LEN;

    /// The worst-case verify request, ML-DSA-87's public key, `μ` and
    /// signature, written directly after the paired TOC.
    #[test]
    fn max_sized_request_fits_the_transport_buffer() {
        let req = TborMlDsaVerifyReq {
            session_id: 7,
            pub_key: alloc::vec![0x11u8; MLDSA_PUB_KEY_MAX_LEN],
            mu: alloc::vec![0x55u8; MLDSA_MU_LEN],
            signature: alloc::vec![0x33u8; MLDSA_SIGNATURE_MAX_LEN],
        };
        let mut buf = [0u8; 8192];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame
                .windows(MLDSA_MU_LEN)
                .any(|w| w == [0x55u8; MLDSA_MU_LEN]),
            "encoded frame must carry mu",
        );
        // header(8) + 4 TOC entries * 4 + data(2592 + 64 + 4627).
        assert_eq!(frame.len(), 7307);
    }
}
