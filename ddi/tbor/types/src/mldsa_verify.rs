// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlDsaVerify` command.
//!
//! `MlDsaVerify` is (temporarily) an **out-of-session** command that verifies an ML-DSA signature over a host-supplied
//! message and public key.  Success is signalled by an empty response;
//! an invalid signature arrives as the `MlDsaVerifyFailed` status.
//!
//! `ctx` is the caller-chosen context string of
//! `ML-DSA.Verify(pk, M, sigma, ctx)` (FIPS 204 §5.3) and must match the
//! `ctx` used at signing time: it is bound into the signature, so
//! verification under a different context fails.  It is carried as a
//! buffer of 0..=255 bytes; an empty `ctx` is the FIPS 204 default.  See
//! [`MLDSA_CTX_MAX_LEN`](crate::MLDSA_CTX_MAX_LEN).
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

    /// Message that was signed.  Capped at 586 B — the residue of the
    /// 8192-byte host staging budget once the maximum public key,
    /// signature and context string are accounted for.  See
    /// [`MLDSA_MESSAGE_MAX_LEN`](crate::MLDSA_MESSAGE_MAX_LEN).
    #[tbor(max_len = 586)]
    pub message: Vec<u8>,

    /// FIPS 204 context string `ctx` for `ML-DSA.Verify(pk, M, sigma,
    /// ctx)`, 0..=255 bytes.  Must match the `ctx` used at signing time.
    /// See [`MLDSA_CTX_MAX_LEN`](crate::MLDSA_CTX_MAX_LEN).
    #[tbor(max_len = 255)]
    pub ctx: Vec<u8>,

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
    use crate::mldsa_generate_key::MLDSA_CTX_MAX_LEN;
    use crate::mldsa_generate_key::MLDSA_MESSAGE_MAX_LEN;
    use crate::mldsa_generate_key::MLDSA_PUB_KEY_MAX_LEN;
    use crate::mldsa_generate_key::MLDSA_SIGNATURE_MAX_LEN;

    #[test]
    fn request_encodes_signature() {
        let req = TborMlDsaVerifyReq {
            session_id: 7,
            pub_key: alloc::vec![0x11u8; 64],
            message: alloc::vec![0x22u8; 32],
            ctx: alloc::vec![0x44u8; 8],
            signature: alloc::vec![0x33u8; 64],
        };
        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0x33u8; 4]),
            "encoded frame must carry the signature bytes",
        );
    }

    #[test]
    fn request_encodes_ctx() {
        let req = TborMlDsaVerifyReq {
            session_id: 7,
            pub_key: alloc::vec![0x11u8; 64],
            message: alloc::vec![0x22u8; 32],
            ctx: alloc::vec![0x44u8; MLDSA_CTX_MAX_LEN],
            signature: alloc::vec![0x33u8; 64],
        };
        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0x44u8; 4]),
            "encoded frame must carry the context-string bytes",
        );
    }

    /// The worst-case verify request must fit the 8192-byte transport
    /// buffer with the data written directly after the paired TOC.
    #[test]
    fn max_sized_request_fits_the_transport_buffer() {
        let req = TborMlDsaVerifyReq {
            session_id: 7,
            pub_key: alloc::vec![0x11u8; MLDSA_PUB_KEY_MAX_LEN],
            message: alloc::vec![0x22u8; MLDSA_MESSAGE_MAX_LEN],
            ctx: alloc::vec![0x44u8; MLDSA_CTX_MAX_LEN],
            signature: alloc::vec![0x33u8; MLDSA_SIGNATURE_MAX_LEN],
        };
        let mut buf = [0u8; 8192];
        let frame = req.encode_request(&mut buf).expect("encode");
        // header(8) + 5 TOC entries * 4 + data(8060).
        assert_eq!(frame.len(), 8088);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(586 == MLDSA_MESSAGE_MAX_LEN);
        const _: () = assert!(255 == MLDSA_CTX_MAX_LEN);
    }
}
