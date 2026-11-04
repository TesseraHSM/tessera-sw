// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlKemEncapsulate` command.
//!
//! `MlKemEncapsulate` is (temporarily) an **out-of-session** command that encapsulates to a host-supplied ML-KEM public key and
//! returns the ciphertext plus a **masked** shared secret under the
//! requested scope's masking key.
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

/// TBOR opcode for `MlKemEncapsulate`.
pub const TBOR_OP_MLKEM_ENCAPSULATE: u8 = 0x2A;

/// The ML-KEM parameter set is **not** carried on the wire: it is recovered
/// from the length of `pub_key`, which is unique per parameter set
/// (ML-KEM-512 = 800 B, ML-KEM-768 = 1184 B, ML-KEM-1024 = 1568 B; see the
/// length table in the key vault).  Carrying it explicitly would create a
/// second source of truth that firmware must cross-check against the key,
/// and would let a caller pair a parameter set with a mismatched key.
/// Host-facing TBOR `MlKemEncapsulate` request.
#[tbor(opcode = TBOR_OP_MLKEM_ENCAPSULATE, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlKemEncapsulateReq {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope as the 1-byte `KeyScope` discriminant.
    pub scope: u8,

    /// ML-KEM public / encapsulation key bytes.
    #[tbor(max_len = 1568)]
    pub pub_key: Vec<u8>,
}

/// Host-facing TBOR `MlKemEncapsulate` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlKemEncapsulateResp {
    /// ML-KEM ciphertext bytes.
    #[tbor(max_len = 1568)]
    pub ciphertext: Vec<u8>,

    /// The 32-byte shared secret, masked under the requested scope's masking key.
    #[tbor(max_len = 264)]
    pub masked_shared_secret: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_pub_key() {
        let req = TborMlKemEncapsulateReq {
            session_id: 7,
            scope: 0b011,
            pub_key: alloc::vec![0x22u8; 64],
        };
        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0x22u8; 4]),
            "encoded frame must carry the public-key bytes",
        );
    }
}
