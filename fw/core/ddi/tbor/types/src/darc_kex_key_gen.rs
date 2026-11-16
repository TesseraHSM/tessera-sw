// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcKexKeyGen` wire schema.
//!
//! `DarcKexKeyGen` is an in-session command that generates a new DARC
//! key-exchange (recipient) key and returns it as a masked private-key
//! blob plus the public key.  The private key is not stored on the device
//! (see Outputs below).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `scope` — the requested key [`KeyScope`] (lifecycle / visibility
//!   domain), carried as its 1-byte [`open_enum`](open_enum::open_enum)
//!   discriminant.  Mirrors the firmware
//!   [`HsmKeyScope`](tsra_fw_hsm_pal_traits::HsmKeyScope).
//! * `kem` — the key's HPKE KEM ([`TransferKemId`]): P-384, ML-KEM-1024
//!   (HPKE-13) or MLKEM1024-P384 (HPKE-10).
//!
//! Outputs:
//!
//! * `masked_key` — the new key's **private** half, masked (AEAD-GCM-256)
//!   under the requested scope's masking key: 280 B for the 48-byte P-384
//!   scalar, 296 B for the 64-byte ML-KEM `d ‖ z` seed and 264 B for the
//!   32-byte hybrid seed.  The private key is **not** stored on the
//!   device: the caller holds the masked blob and re-imports it
//!   (unmask-on-use) when the key is later needed.
//! * `pub_key` — the public key.  For P-384 the raw `x ‖ y` affine
//!   coordinates (96 bytes, device byte order per coordinate, **not**
//!   SEC1); for ML-KEM-1024 the 1568-byte encapsulation key; for the hybrid
//!   the 1665-byte `ek_PQ ‖ SEC1(ek_T)`.

use tsra_fw_ddi_tbor_api::tbor;

use crate::key_props::KeyScope;
use crate::key_props::TransferKemId;

/// TBOR opcode for `DarcKexKeyGen`.
pub const TBOR_OP_DARC_KEX_KEY_GEN: u8 = 0x20;

/// Wire length of the returned key-exchange public key: a raw P-384
/// point (`x ‖ y`, 48 + 48 bytes).  Pinned into the `#[tbor(buffer, len
/// = 96)]` literal on [`TborDarcKexKeyGenResp::pub_key`] (see the
/// `pub_key_len_matches_pinned_value` test).
pub const KEX_PUB_KEY_LEN: usize = 96;

/// Wire length of the masked key-exchange private key: an AEAD-GCM-256
/// masked-key envelope (`header(8) ‖ iv(16) ‖ aad(192) ‖ pt(48) ‖
/// tag(16)`) whose plaintext is the 48-byte raw P-384 private scalar and
/// whose AAD is the 192-byte `MaskedKeyMetadata`.  Pinned into the
/// `min_len` .. `max_len` literals on [`TborDarcKexKeyGenResp::masked_key`].
pub const MASKED_KEX_KEY_LEN: usize = 8 + 16 + 192 + 48 + 16;

/// Smallest masked key-exchange private key: the masked 32-byte
/// MLKEM1024-P384 seed.
pub const MASKED_KEX_KEY_MIN_LEN: usize = 8 + 16 + 192 + 32 + 16;

/// Largest masked key-exchange private key: the masked 64-byte
/// ML-KEM-1024 `d ‖ z` seed.
pub const MASKED_KEX_KEY_MAX_LEN: usize = 8 + 16 + 192 + 64 + 16;

/// Largest key-exchange public key (MLKEM1024-P384 `ek_PQ ‖ SEC1(ek_T)`).
pub const KEX_PUB_KEY_MAX_LEN: usize = 1568 + 97;

/// `DarcKexKeyGen` request schema.
///
/// Generates a DARC key-exchange key under the active session's
/// partition with the caller-supplied [`KeyScope`].
#[tbor(opcode = 0x20, pair = TborDarcKexKeyGenResp)]
pub struct TborDarcKexKeyGenReq {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (lifecycle / visibility domain). Carried as
    /// the 1-byte [`KeyScope`] discriminant.
    #[tbor(U8)]
    pub scope: KeyScope,

    /// Key-exchange KEM, carried as the 1-byte [`TransferKemId`]
    /// discriminant.
    #[tbor(U8)]
    pub kem: TransferKemId,
}

/// `DarcKexKeyGen` response schema.
#[tbor(response, pair = TborDarcKexKeyGenReq)]
pub struct TborDarcKexKeyGenResp<'a> {
    /// The new key-exchange key's private half, masked (AEAD-GCM-256)
    /// under the requested scope's masking key; [`MASKED_KEX_KEY_MIN_LEN`]
    /// ..= [`MASKED_KEX_KEY_MAX_LEN`] bytes.  The private key is not stored
    /// on the device; the caller re-imports this blob when needed.
    #[tbor(align = 4, buffer, min_len = 264, max_len = 296)]
    pub masked_key: &'a [u8],

    /// Public key: raw P-384 `x ‖ y` (96 bytes, device byte order per
    /// coordinate, not SEC1), the ML-KEM-1024 encapsulation key, or the
    /// hybrid `ek_PQ ‖ SEC1(ek_T)`.
    #[tbor(buffer, min_len = 96, max_len = 1665)]
    pub pub_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_scope_and_kem() {
        let mut buf = [0u8; 256];
        let frame = TborDarcKexKeyGenReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .kem(TransferKemId::MlKem1024)
            .unwrap()
            .finish();

        // The wire carries the 1-byte scope and KEM discriminants.
        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(frame.kem(), TransferKemId::MlKem1024);
    }

    #[test]
    fn response_round_trips_masked_key_and_pub_key() {
        let mut buf = [0u8; 2048];
        for (masked_len, pub_len) in [
            (MASKED_KEX_KEY_LEN, KEX_PUB_KEY_LEN),
            (MASKED_KEX_KEY_MAX_LEN, 1568),
            (MASKED_KEX_KEY_MIN_LEN, KEX_PUB_KEY_MAX_LEN),
        ] {
            let masked = &[0xCDu8; MASKED_KEX_KEY_MAX_LEN][..masked_len];
            let pub_key = &[0xABu8; KEX_PUB_KEY_MAX_LEN][..pub_len];
            let frame = TborDarcKexKeyGenResp::encode(&mut buf, 0, true)
                .unwrap()
                .masked_key(masked)
                .unwrap()
                .pub_key(pub_key)
                .unwrap()
                .finish();
            assert_eq!(frame.masked_key(), masked);
            assert_eq!(frame.pub_key(), pub_key);
        }
    }

    #[test]
    fn response_lengths_match_pinned_values() {
        // The `#[tbor(buffer, min_len/max_len = N)]` attributes must remain
        // numeric literals; pin them against the exported consts.
        const _: () = assert!(96 == KEX_PUB_KEY_LEN);
        const _: () = assert!(1665 == KEX_PUB_KEY_MAX_LEN);
        const _: () = assert!(264 == MASKED_KEX_KEY_MIN_LEN);
        const _: () = assert!(296 == MASKED_KEX_KEY_MAX_LEN);
        const _: () = assert!(280 == MASKED_KEX_KEY_LEN);
    }
}
