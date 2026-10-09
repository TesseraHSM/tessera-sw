// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcKexKeyGen` wire schema.
//!
//! `DarcKexKeyGen` is an in-session command that generates a new Darc
//! key-exchange key and returns it as a masked private-key blob plus the
//! public key.  The private key is not stored on the device (see Outputs
//! below).
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
//!
//! Outputs:
//!
//! * `masked_key` — the new DARC key-exchange key's ECC-P384 **private**
//!   half, masked (AEAD-GCM-256) under the requested scope's masking
//!   key, as a fixed [`MASKED_KEX_KEY_LEN`] (276 B) envelope.  The
//!   private key is **not** stored on the device: the caller holds the
//!   masked blob and re-imports it (unmask-on-use) when the key is later
//!   needed.
//! * `pub_key` — the raw P-384 public key of the new key-exchange key:
//!   the `x ‖ y` affine coordinates (96 bytes, little-endian per
//!   coordinate) as emitted by the PAL.  This is the bare coordinate
//!   pair, **not** a SEC1 point encoding (no `0x04` prefix).  The caller
//!   uses it as the ECDH peer for DARC key-exchange.

use tsra_fw_ddi_tbor_api::tbor;

use crate::key_props::KeyScope;

/// TBOR opcode for `DarcKexKeyGen`.
pub const TBOR_OP_DARC_KEX_KEY_GEN: u8 = 0x20;

/// Wire length of the returned key-exchange public key: a raw P-384
/// point (`x ‖ y`, 48 + 48 bytes).  Pinned into the `#[tbor(buffer, len
/// = 96)]` literal on [`TborDarcKexKeyGenResp::pub_key`] (see the
/// `pub_key_len_matches_pinned_value` test).
pub const KEX_PUB_KEY_LEN: usize = 96;

/// Wire length of the masked key-exchange private key: an AEAD-GCM-256
/// masked-key envelope (`header(8) ‖ iv(12) ‖ aad(192) ‖ pt(48) ‖
/// tag(16)`) whose plaintext is the 48-byte raw P-384 private scalar and
/// whose AAD is the 192-byte `MaskedKeyMetadata`.  Pinned into the
/// `#[tbor(buffer, len = 276)]` literal on
/// [`TborDarcKexKeyGenResp::masked_key`].
pub const MASKED_KEX_KEY_LEN: usize = 8 + 12 + 192 + 48 + 16;

/// `DarcKexKeyGen` request schema.
///
/// Generates a DARC key-exchange key under the active session's
/// partition with the caller-supplied [`KeyScope`].
#[tbor(opcode = 0x20)]
pub struct TborDarcKexKeyGenReq {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (lifecycle / visibility domain). Carried as
    /// the 1-byte [`KeyScope`] discriminant.
    #[tbor(U8)]
    pub scope: KeyScope,
}

/// `DarcKexKeyGen` response schema.
#[tbor(response)]
pub struct TborDarcKexKeyGenResp<'a> {
    /// The new key-exchange key's ECC-P384 private half, masked
    /// (AEAD-GCM-256) under the requested scope's masking key.  Always
    /// exactly [`MASKED_KEX_KEY_LEN`] (276 B).  The private key is not
    /// stored on the device; the caller re-imports this blob when needed.
    #[tbor(buffer, len = 276)]
    pub masked_key: &'a [u8],

    /// Raw P-384 public key (`x ‖ y` affine coordinates, 96 bytes,
    /// little-endian per coordinate) of the new key-exchange key, as
    /// emitted by the PAL.  Not a SEC1 point encoding (no `0x04` prefix).
    #[tbor(buffer, len = 96)]
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
        let frame = TborDarcKexKeyGenReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .finish();

        // The wire carries the 1-byte scope discriminant.
        assert_eq!(frame.scope(), KeyScope::Local);
    }

    #[test]
    fn response_round_trips_masked_key_and_pub_key() {
        let mut buf = [0u8; 512];
        let masked = [0xCDu8; MASKED_KEX_KEY_LEN];
        let pub_key = [0xABu8; KEX_PUB_KEY_LEN];
        let frame = TborDarcKexKeyGenResp::encode(&mut buf, 0, true)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
        assert_eq!(frame.pub_key(), &pub_key[..]);
    }

    #[test]
    fn response_lengths_match_pinned_values() {
        // The `#[tbor(buffer, len = N)]` attributes must remain numeric
        // literals; pin them against the exported consts.
        const _: () = assert!(96 == KEX_PUB_KEY_LEN);
        const _: () = assert!(276 == MASKED_KEX_KEY_LEN);
        assert_eq!(KEX_PUB_KEY_LEN, 96);
        assert_eq!(MASKED_KEX_KEY_LEN, 276);
    }
}
