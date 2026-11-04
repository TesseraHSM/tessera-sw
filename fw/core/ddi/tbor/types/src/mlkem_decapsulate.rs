// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlKemDecapsulate` wire schema.
//!
//! `MlKemDecapsulate` is (temporarily) an out-of-session command that decapsulates an
//! ML-KEM ciphertext using a caller-held **masked** decapsulation key
//! (from [`MlKemGenerateKey`](crate::mlkem_generate_key)) and returns the
//! shared secret as a **masked** blob under the requested scope's masking
//! key.  This is the TBOR unmask-on-use analogue of the MBOR operation.
//! There is intentionally no `key_kind` request field: the masked blob is
//! self-describing.  Its authenticated key kind already tells the firmware
//! which parameter set the seed belongs to.
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
pub use crate::mlkem_generate_key::MASKED_MLKEM_KEY_MAX_LEN;
pub use crate::mlkem_generate_key::MASKED_MLKEM_SHARED_SECRET_MAX_LEN;
pub use crate::mlkem_generate_key::MLKEM_CIPHERTEXT_MAX_LEN;

/// TBOR opcode for `MlKemDecapsulate`.
pub const TBOR_OP_MLKEM_DECAPSULATE: u8 = 0x2B;

/// `MlKemDecapsulate` request schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can unmask it **in
/// place** in the request buffer (via `decode_mut`) — no scratch copy.
#[tbor(opcode = 0x2B, pair = TborMlKemDecapsulateResp)]
pub struct TborMlKemDecapsulateReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (masks the returned shared secret), 1-byte [`KeyScope`].
    #[tbor(U8)]
    pub scope: KeyScope,

    /// The masked ML-KEM decapsulation key, an AEAD-GCM-256 envelope of
    /// 196 B: the wire ships seed-only keys.  See
    /// [`MASKED_MLKEM_KEY_MAX_LEN`].
    #[tbor(buffer, max_len = 3464, mutable)]
    pub masked_key: &'a [u8],

    /// ML-KEM ciphertext.  Up to 1568 B for ML-KEM-1024.
    #[tbor(buffer, max_len = 1568)]
    pub ciphertext: &'a [u8],
}

/// `MlKemDecapsulate` response schema.
///
/// `masked_shared_secret` is `#[tbor(mutable)]` so the handler can reserve
/// the slot and mask the 32-byte shared secret straight into it.
#[tbor(response, pair = TborMlKemDecapsulateReq)]
pub struct TborMlKemDecapsulateResp<'a> {
    /// The 32-byte ML-KEM shared secret, masked (AEAD-GCM-256) under the
    /// requested scope's masking key.  The envelope is always 164 B.
    #[tbor(buffer, max_len = 264, mutable)]
    pub masked_shared_secret: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 8192];
        let masked = [0x11u8; MASKED_MLKEM_KEY_MAX_LEN];
        let ciphertext = [0x22u8; MLKEM_CIPHERTEXT_MAX_LEN];
        let frame = TborMlKemDecapsulateReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .scope(KeyScope::SecurityDomain)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .ciphertext(&ciphertext)
            .unwrap()
            .finish();
        assert_eq!(frame.scope(), KeyScope::SecurityDomain);
        assert_eq!(frame.ciphertext(), &ciphertext[..]);
    }

    #[test]
    fn response_round_trips_secret() {
        let mut buf = [0u8; 512];
        let secret = [0x33u8; MASKED_MLKEM_SHARED_SECRET_MAX_LEN];
        let frame = TborMlKemDecapsulateResp::encode(&mut buf, 0, true)
            .unwrap()
            .masked_shared_secret(&secret)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_shared_secret(), &secret[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(3464 == MASKED_MLKEM_KEY_MAX_LEN);
        const _: () = assert!(1568 == MLKEM_CIPHERTEXT_MAX_LEN);
        const _: () = assert!(264 == MASKED_MLKEM_SHARED_SECRET_MAX_LEN);
        assert_eq!(MASKED_MLKEM_KEY_MAX_LEN, 3464);
    }
}
