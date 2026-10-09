// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlKemEncapsulate` wire schema.
//!
//! `MlKemEncapsulate` is (temporarily) an out-of-session command that encapsulates to a
//! host-supplied ML-KEM public key and returns both the ciphertext and the
//! derived shared secret as a **masked** blob under the requested scope's
//! masking key.  This schema carries raw key bytes, not vault key ids.
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

use crate::key_props::KeyScope;
pub use crate::mlkem_generate_key::MASKED_MLKEM_SHARED_SECRET_MAX_LEN;
pub use crate::mlkem_generate_key::MLKEM_CIPHERTEXT_MAX_LEN;
pub use crate::mlkem_generate_key::MLKEM_PUB_KEY_MAX_LEN;

/// TBOR opcode for `MlKemEncapsulate`.
pub const TBOR_OP_MLKEM_ENCAPSULATE: u8 = 0x2A;
/// The ML-KEM parameter set is **not** carried on the wire: it is recovered
/// from the length of `pub_key`, which is unique per parameter set
/// (ML-KEM-512 = 800 B, ML-KEM-768 = 1184 B, ML-KEM-1024 = 1568 B; see the
/// length table in the key vault).  Carrying it explicitly would create a
/// second source of truth that firmware must cross-check against the key,
/// and would let a caller pair a parameter set with a mismatched key.
/// `MlKemEncapsulate` request schema.
#[tbor(opcode = 0x2A)]
pub struct TborMlKemEncapsulateReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (masks the returned shared secret), 1-byte [`KeyScope`].
    #[tbor(U8)]
    pub scope: KeyScope,

    /// ML-KEM public / encapsulation key.  Up to 1568 B for ML-KEM-1024.
    #[tbor(buffer, max_len = 1568)]
    pub pub_key: &'a [u8],
}

/// `MlKemEncapsulate` response schema.
///
/// `masked_shared_secret` is `#[tbor(mutable)]` so the handler can reserve
/// the slot and mask the 32-byte shared secret straight into it.
#[tbor(response)]
pub struct TborMlKemEncapsulateResp<'a> {
    /// ML-KEM ciphertext.  Up to 1568 B for ML-KEM-1024.
    #[tbor(buffer, max_len = 1568, mutable)]
    pub ciphertext: &'a [u8],

    /// The 32-byte ML-KEM shared secret, masked (AEAD-GCM-256) under the
    /// requested scope's masking key.  The envelope is always 164 B.
    #[tbor(buffer, max_len = 260, mutable)]
    pub masked_shared_secret: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 4096];
        let pub_key = [0x11u8; MLKEM_PUB_KEY_MAX_LEN];
        let frame = TborMlKemEncapsulateReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .finish();
        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(frame.pub_key(), &pub_key[..]);
    }

    #[test]
    fn response_round_trips_ciphertext_and_secret() {
        let mut buf = [0u8; 4096];
        let ciphertext = [0x22u8; MLKEM_CIPHERTEXT_MAX_LEN];
        let secret = [0x33u8; MASKED_MLKEM_SHARED_SECRET_MAX_LEN];
        let frame = TborMlKemEncapsulateResp::encode(&mut buf, 0, true)
            .unwrap()
            .ciphertext(&ciphertext)
            .unwrap()
            .masked_shared_secret(&secret)
            .unwrap()
            .finish();
        assert_eq!(frame.ciphertext(), &ciphertext[..]);
        assert_eq!(frame.masked_shared_secret(), &secret[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(1568 == MLKEM_PUB_KEY_MAX_LEN);
        const _: () = assert!(1568 == MLKEM_CIPHERTEXT_MAX_LEN);
        const _: () = assert!(260 == MASKED_MLKEM_SHARED_SECRET_MAX_LEN);
        assert_eq!(MASKED_MLKEM_SHARED_SECRET_MAX_LEN, 260);
    }
}
