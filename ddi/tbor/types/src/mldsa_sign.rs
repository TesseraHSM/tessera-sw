// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlDsaSign` command.
//!
//! `MlDsaSign` is (temporarily) an **out-of-session** command that signs a host-supplied
//! 64-byte message representative `μ` using a caller-held **masked** ML-DSA
//! secret key; this crate only defines wire types and performs no
//! cryptography.
//!
//! There is intentionally no `key_kind` request field: the masked blob is
//! self-describing.  Its authenticated key kind already tells the firmware
//! which parameter set the key belongs to.
//!
//! Like `EccSign`, which signs a digest rather than a message, `MlDsaSign`
//! signs `μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)` rather than
//! `M`.  The caller computes it, binding its FIPS 204 context string `ctx`,
//! and the result is a pure ML-DSA signature over `M` under `ctx`.  See
//! [`MLDSA_MU_LEN`](crate::MLDSA_MU_LEN).
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

/// TBOR opcode for `MlDsaSign`.
pub const TBOR_OP_MLDSA_SIGN: u8 = 0x27;

/// `MlDsaHedge` discriminant: hedged or deterministic, as the device chooses
/// (PKCS#11 `CKH_HEDGE_PREFERRED`).  The device signs hedged.
pub const MLDSA_HEDGE_PREFERRED: u8 = 0;
/// `MlDsaHedge` discriminant: hedged, or fail (PKCS#11
/// `CKH_HEDGE_REQUIRED`).
pub const MLDSA_HEDGE_REQUIRED: u8 = 1;
/// `MlDsaHedge` discriminant: deterministic, or fail (PKCS#11
/// `CKH_DETERMINISTIC_REQUIRED`).  FIPS 204's deterministic variant, so the
/// same key and input always yield the same signature.
pub const MLDSA_HEDGE_DETERMINISTIC: u8 = 2;

/// Host-facing TBOR `MlDsaSign` request.
#[tbor(opcode = TBOR_OP_MLDSA_SIGN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaSignReq {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked ML-DSA secret key (from `MlDsaGenerateKey`).  164 B:
    /// the wire ships seed-only keys.  See
    /// [`MASKED_MLDSA_KEY_MAX_LEN`](crate::MASKED_MLDSA_KEY_MAX_LEN).
    #[tbor(max_len = 5160)]
    pub masked_key: Vec<u8>,

    /// The message representative `μ` to sign, exactly
    /// [`MLDSA_MU_LEN`](crate::MLDSA_MU_LEN) bytes.
    #[tbor(min_len = 64, max_len = 64)]
    pub mu: Vec<u8>,

    /// How the signature is randomized: `MLDSA_HEDGE_PREFERRED`,
    /// `MLDSA_HEDGE_REQUIRED` or `MLDSA_HEDGE_DETERMINISTIC`, following
    /// PKCS#11's `CK_HEDGE_TYPE`.
    pub hedge: u8,
}

/// Host-facing TBOR `MlDsaSign` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaSignResp {
    /// ML-DSA signature bytes.  Up to 4627 B for ML-DSA-87.
    #[tbor(max_len = 4627)]
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::mldsa_generate_key::MASKED_MLDSA_KEY_MAX_LEN;
    use crate::mldsa_generate_key::MLDSA_MU_LEN;

    /// The worst-case sign request, ML-DSA-87's masked key and `μ`, written
    /// directly after the paired TOC.
    #[test]
    fn max_sized_request_encodes_mu_and_hedge() {
        let req = TborMlDsaSignReq {
            session_id: 7,
            masked_key: alloc::vec![0x11u8; MASKED_MLDSA_KEY_MAX_LEN],
            mu: alloc::vec![0x55u8; MLDSA_MU_LEN],
            hedge: MLDSA_HEDGE_DETERMINISTIC,
        };
        let mut buf = [0u8; 8192];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame
                .windows(MLDSA_MU_LEN)
                .any(|w| w == [0x55u8; MLDSA_MU_LEN]),
            "encoded frame must carry mu",
        );
        // header(8) + 4 TOC entries * 4 + data(5160 + 64).
        assert_eq!(frame.len(), 5248);
    }
}
