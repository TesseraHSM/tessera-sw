// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlDsaSign` command.
//!
//! `MlDsaSign` is (temporarily) an **out-of-session** command that signs a host-supplied message using a caller-held
//! **masked** ML-DSA secret key.  The host supplies raw message bytes and
//! the FIPS 204 context string; this crate only defines wire types and
//! performs no cryptography.
//!
//! There is intentionally no `key_kind` request field: the masked blob is
//! self-describing.  Its authenticated key kind already tells the firmware
//! which parameter set the key belongs to.
//!
//! `ctx` is the caller-chosen context string of `ML-DSA.Sign(sk, M, ctx)`
//! (FIPS 204 §5.2).  It is domain-separation input that is bound into the
//! signature, so a signature produced under one `ctx` never verifies
//! under another.  It is carried as a buffer of 0..=255 bytes; an empty
//! `ctx` is the FIPS 204 default.  See
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

/// TBOR opcode for `MlDsaSign`.
pub const TBOR_OP_MLDSA_SIGN: u8 = 0x27;

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

    /// Message to sign.  The TBOR schema caps inline messages at 586 B; see
    /// [`MLDSA_MESSAGE_MAX_LEN`](crate::MLDSA_MESSAGE_MAX_LEN).
    #[tbor(max_len = 586)]
    pub message: Vec<u8>,

    /// FIPS 204 context string `ctx` for `ML-DSA.Sign(sk, M, ctx)`,
    /// 0..=255 bytes.  Empty is the FIPS 204 default.  See
    /// [`MLDSA_CTX_MAX_LEN`](crate::MLDSA_CTX_MAX_LEN).
    #[tbor(max_len = 255)]
    pub ctx: Vec<u8>,
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
    use crate::mldsa_generate_key::MLDSA_CTX_MAX_LEN;

    #[test]
    fn request_encodes_message() {
        let req = TborMlDsaSignReq {
            session_id: 7,
            masked_key: alloc::vec![0x11u8; MASKED_MLDSA_KEY_MAX_LEN],
            message: alloc::vec![0x22u8; 32],
            ctx: alloc::vec![0x44u8; 8],
        };
        let mut buf = [0u8; 8192];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0x22u8; 4]),
            "encoded frame must carry the message bytes",
        );
    }

    #[test]
    fn request_encodes_ctx() {
        let req = TborMlDsaSignReq {
            session_id: 7,
            masked_key: alloc::vec![0x11u8; MASKED_MLDSA_KEY_MAX_LEN],
            message: alloc::vec![0x22u8; 32],
            ctx: alloc::vec![0x44u8; MLDSA_CTX_MAX_LEN],
        };
        let mut buf = [0u8; 8192];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0x44u8; 4]),
            "encoded frame must carry the context-string bytes",
        );
    }

    #[test]
    fn request_encodes_empty_ctx() {
        let req = TborMlDsaSignReq {
            session_id: 7,
            masked_key: alloc::vec![0x11u8; MASKED_MLDSA_KEY_MAX_LEN],
            message: alloc::vec![0x22u8; 32],
            ctx: Vec::new(),
        };
        let mut buf = [0u8; 8192];
        req.encode_request(&mut buf)
            .expect("an empty ctx is the FIPS 204 default and must encode");
    }
}
