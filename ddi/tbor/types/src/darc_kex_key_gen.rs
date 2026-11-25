// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `DarcKexKeyGen` command.
//!
//! `DarcKexKeyGen` is an **in-session** Crypto-Officer command that
//! generates a new DARC key-exchange key (P-384, ML-KEM-1024 or
//! MLKEM1024-P384, selected by the request `kem`) and returns the
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

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `DarcKexKeyGen`.
pub const TBOR_OP_DARC_KEX_KEY_GEN: u8 = 0x20;

/// Wire length of the returned key-exchange public key: a raw P-384
/// point (`x ‖ y`, 48 + 48 bytes).
pub const KEX_PUB_KEY_LEN: usize = 96;

/// Largest key-exchange public key (MLKEM1024-P384 `ek_PQ ‖ SEC1(ek_T)`).
pub const KEX_PUB_KEY_MAX_LEN: usize = 1568 + 97;

/// Wire length of the masked P-384 key-exchange private key: an
/// AEAD-GCM-256 masked-key envelope (`header(8) ‖ iv(16) ‖ aad(192) ‖
/// pt(48) ‖ tag(16)`) over the 48-byte raw P-384 private scalar.
pub const MASKED_KEX_KEY_LEN: usize = 8 + 16 + 192 + 48 + 16;
/// Smallest masked key-exchange private key (32-byte MLKEM1024-P384 seed).
pub const MASKED_KEX_KEY_MIN_LEN: usize = 8 + 16 + 192 + 32 + 16;
/// Largest masked key-exchange private key (64-byte ML-KEM-1024 seed).
pub const MASKED_KEX_KEY_MAX_LEN: usize = 8 + 16 + 192 + 64 + 16;

/// Vault kind of a P-384 DARC key-exchange key in masked-key metadata.
pub const KEY_KIND_DARC_KEX: u8 = 44;
/// Vault kind of an ML-KEM-1024 DARC key-exchange key (64-byte seed).
pub const KEY_KIND_DARC_KEX_MLKEM1024: u8 = 67;
/// Vault kind of an MLKEM1024-P384 DARC key-exchange key (32-byte seed).
pub const KEY_KIND_DARC_KEX_MLKEM1024_P384: u8 = 68;

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

    /// Key-exchange KEM (`TRANSFER_KEM_*`); 0 is P-384.
    pub kem: u8,
}

/// Host-facing TBOR `DarcKexKeyGen` response.
#[tbor(response)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborDarcKexKeyGenResp {
    /// The new key-exchange key's private half, masked (AEAD-GCM-256)
    /// under the requested scope's masking key; not stored on-device.
    #[tbor(align = 4, min_len = 264, max_len = 296)]
    pub masked_key: Vec<u8>,

    /// Public key: raw P-384 `x ‖ y` (96 bytes, device byte order per
    /// coordinate, not SEC1), the ML-KEM-1024 encapsulation key, or the
    /// hybrid `ek_PQ ‖ SEC1(ek_T)`.
    #[tbor(min_len = 96, max_len = 1665)]
    pub pub_key: Vec<u8>,
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
            kem: crate::TRANSFER_KEM_MLKEM1024,
        };

        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf, (1, 1)).expect("encode");

        // The 1-byte scope discriminant must appear in the encoded frame.
        assert!(
            frame.contains(&0b011),
            "encoded frame must carry the scope discriminant",
        );
    }
}
