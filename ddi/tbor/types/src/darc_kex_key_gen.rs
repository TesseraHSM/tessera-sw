// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `DarcKexKeyGen` command.
//!
//! `DarcKexKeyGen` is an **in-session** Crypto-Officer command that
//! generates a new DARC key-exchange key (ECC-P384) and returns the
//! **masked** private key plus its public key.  The private key is not
//! stored on the device; the caller holds the masked blob and
//! re-imports it (unmask-on-use) when the key is later needed.
//!
//! The request carries the requested key `scope` (lifecycle / visibility
//! domain) as its 1-byte discriminant.  The firmware-side schema
//! (`tsra_fw_ddi_tbor_types::darc_kex_key_gen`) types it as the
//! `KeyScope` open-enum (mirror of the PAL `HsmKeyScope`); this host
//! crate is firewalled from the firmware PAL types, so it carries the
//! same byte as a raw `u8`.  The private key is masked under the masking
//! key associated with the scope.

use crate::tbor;

/// TBOR opcode for `DarcKexKeyGen`.
pub const TBOR_OP_DARC_KEX_KEY_GEN: u8 = 0x20;

/// Wire length of the returned key-exchange public key: a raw P-384
/// point (`x ‖ y`, 48 + 48 bytes).
pub const KEX_PUB_KEY_LEN: usize = 96;

/// Wire length of the masked key-exchange private key: an AEAD-GCM-256
/// masked-key envelope (`header(8) ‖ iv(12) ‖ aad(192) ‖ pt(48) ‖
/// tag(16)`) over the 48-byte raw P-384 private scalar.
pub const MASKED_KEX_KEY_LEN: usize = 8 + 12 + 192 + 48 + 16;

/// Host-facing TBOR `DarcKexKeyGen` request.
#[tbor(opcode = TBOR_OP_DARC_KEX_KEY_GEN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborDarcKexKeyGenReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope (lifecycle / visibility domain) as the 1-byte
    /// `KeyScope` discriminant (mirror of the firmware `HsmKeyScope`).
    pub scope: u8,
}

/// Host-facing TBOR `DarcKexKeyGen` response.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborDarcKexKeyGenResp {
    /// The new key-exchange key's ECC-P384 private half, masked
    /// (AEAD-GCM-256) under the requested scope's masking key.  Always
    /// exactly [`MASKED_KEX_KEY_LEN`] (276 B); not stored on-device.
    pub masked_key: [u8; MASKED_KEX_KEY_LEN],

    /// Raw P-384 public key (`x ‖ y` affine coordinates, 96 bytes,
    /// little-endian per coordinate) of the new key-exchange key.  Not a
    /// SEC1 point encoding (no `0x04` prefix).
    pub pub_key: [u8; KEX_PUB_KEY_LEN],
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_and_scope() {
        let req = TborDarcKexKeyGenReq {
            session_id: 9,
            // KeyScope::Local discriminant (0b011).
            scope: 0b011,
        };

        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 1-byte scope discriminant must appear in the encoded frame.
        assert!(
            frame.contains(&0b011),
            "encoded frame must carry the scope discriminant",
        );
    }
}
