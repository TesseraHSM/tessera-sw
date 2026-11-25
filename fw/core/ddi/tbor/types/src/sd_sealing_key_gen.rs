// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdSealingKeyGen` wire schema.
//!
//! `SdSealingKeyGen` is an in-session command that generates a new
//! security-domain sealing key and returns it as a masked private-key
//! blob plus the public key.  The private key is not stored on the
//! device (see Outputs below).
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
//! * `kem` — the sealing key's HPKE KEM ([`TransferKemId`]): P-384,
//!   ML-KEM-1024 (HPKE-13) or MLKEM1024-P384 (HPKE-10).
//!
//! Outputs:
//!
//! * `masked_key` — the new sealing key's **private** half, masked
//!   (AEAD-GCM-256) under the requested scope's masking key: 280 B for the
//!   48-byte P-384 scalar, 296 B for the 64-byte ML-KEM `d ‖ z` seed and
//!   264 B for the 32-byte hybrid seed.  The private key is **not** stored
//!   on the device: the caller holds the masked blob and re-imports it
//!   (unmask-on-use) when the key is later needed.
//! * `pub_key` — the public key.  For P-384 the raw `x ‖ y` affine
//!   coordinates (96 bytes, device byte order per coordinate, **not**
//!   SEC1); for ML-KEM-1024 the 1568-byte encapsulation key; for the hybrid
//!   the 1665-byte `ek_PQ ‖ SEC1(ek_T)`.

use tsra_fw_ddi_tbor_api::tbor;

use crate::key_props::KeyScope;
use crate::key_props::TransferKemId;

/// TBOR opcode for `SdSealingKeyGen`.
pub const TBOR_OP_SD_SEALING_KEY_GEN: u8 = 0x09;

/// Wire length of the returned sealing public key: a raw P-384 point
/// (`x ‖ y`, 48 + 48 bytes).  Pinned into the `#[tbor(buffer, len =
/// 96)]` literal on [`TborSdSealingKeyGenResp::pub_key`] (see the
/// `pub_key_len_matches_pinned_value` test).
pub const SD_SEALING_PUB_KEY_LEN: usize = 96;

/// Wire length of the masked sealing private key: an AEAD-GCM-256
/// masked-key envelope (`header(8) ‖ iv(16) ‖ aad(192) ‖ pt(48) ‖
/// tag(16)`) whose plaintext is the 48-byte raw P-384 private scalar and
/// whose AAD is the 192-byte `MaskedKeyMetadata`.  Pinned into the
/// `#[tbor(buffer, len = 280)]` literal on
/// [`TborSdSealingKeyGenResp::masked_key`].
pub const MASKED_SEALING_KEY_LEN: usize = 8 + 16 + 192 + 48 + 16;

/// Largest wire length of a sealing public key (MLKEM1024-P384
/// `ek_PQ ‖ SEC1(ek_T)`).  Pinned into the `max_len` literal on
/// [`TborSdSealingKeyGenResp::pub_key`].
pub const SD_SEALING_PUB_KEY_MAX_LEN: usize = 1568 + 97;

/// Largest masked sealing private key: the masked 64-byte ML-KEM-1024
/// `d ‖ z` seed.  Pinned into the `max_len` literals on the masked
/// sealing-key fields.
pub const MASKED_SEALING_KEY_MAX_LEN: usize = 8 + 16 + 192 + 64 + 16;

/// `SdSealingKeyGen` request schema.
///
/// Generates a security-domain sealing key under the active session's
/// partition with the caller-supplied [`KeyScope`].
#[tbor(opcode = 0x09, pair = TborSdSealingKeyGenResp)]
pub struct TborSdSealingKeyGenReq {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (lifecycle / visibility domain). Carried as
    /// the 1-byte [`KeyScope`] discriminant.
    #[tbor(U8)]
    pub scope: KeyScope,

    /// Sealing-key KEM, carried as the 1-byte [`TransferKemId`]
    /// discriminant.
    #[tbor(U8)]
    pub kem: TransferKemId,
}

/// `SdSealingKeyGen` response schema.
#[tbor(response, pair = TborSdSealingKeyGenReq)]
pub struct TborSdSealingKeyGenResp<'a> {
    /// The new sealing key's private half, masked (AEAD-GCM-256) under the
    /// requested scope's masking key; at most [`MASKED_SEALING_KEY_MAX_LEN`].
    /// The private key is not stored on the device; the caller re-imports
    /// this blob when needed.
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
    fn request_round_trips_scope() {
        let mut buf = [0u8; 256];
        let frame = TborSdSealingKeyGenReq::encode(&mut buf, (1, 1))
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .scope(KeyScope::SecurityDomain)
            .unwrap()
            .kem(TransferKemId::MlKem1024P384)
            .unwrap()
            .finish();

        // The wire carries the 1-byte scope and KEM discriminants.
        assert_eq!(frame.scope(), KeyScope::SecurityDomain);
        assert_eq!(frame.kem(), TransferKemId::MlKem1024P384);
    }

    #[test]
    fn response_round_trips_masked_key_and_pub_key() {
        let mut buf = [0u8; 2048];
        for (masked_len, pub_len) in [
            (MASKED_SEALING_KEY_LEN, SD_SEALING_PUB_KEY_LEN),
            (MASKED_SEALING_KEY_MAX_LEN, 1568),
            (264, SD_SEALING_PUB_KEY_MAX_LEN),
        ] {
            let masked = &[0xCDu8; MASKED_SEALING_KEY_MAX_LEN][..masked_len];
            let pub_key = &[0xABu8; SD_SEALING_PUB_KEY_MAX_LEN][..pub_len];
            let frame = TborSdSealingKeyGenResp::encode(&mut buf, (1, 1), 0, true)
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
        // The `#[tbor(buffer, len = N)]` attributes must remain numeric
        // literals; pin them against the exported consts.
        const _: () = assert!(96 == SD_SEALING_PUB_KEY_LEN);
        const _: () = assert!(1665 == SD_SEALING_PUB_KEY_MAX_LEN);
        const _: () = assert!(280 == MASKED_SEALING_KEY_LEN);
        const _: () = assert!(296 == MASKED_SEALING_KEY_MAX_LEN);
    }
}
