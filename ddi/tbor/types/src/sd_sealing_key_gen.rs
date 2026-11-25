// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdSealingKeyGen` command.
//!
//! `SdSealingKeyGen` is an **in-session** Crypto-Officer command that
//! generates a new security-domain sealing key (P-384, ML-KEM-1024 or
//! MLKEM1024-P384, selected by the request `kem`) and returns
//! the **masked** private key plus its public key.  The private key is
//! not stored on the device; the caller holds the masked blob and
//! re-imports it (unmask-on-use) when the key is later needed.
//!
//! The request carries the requested key `scope` (lifecycle / visibility
//! domain) as its 1-byte discriminant.  The firmware-side schema
//! (`tsra_fw_ddi_tbor_types::sd_sealing_key_gen`) types it as the
//! `KeyScope` open-enum (mirror of the PAL `HsmKeyScope`); this host
//! crate is firewalled from the firmware PAL types, so it carries the
//! same byte as a raw `u8`.  The private key is masked under the masking
//! key associated with the scope.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `SdSealingKeyGen`.
pub const TBOR_OP_SD_SEALING_KEY_GEN: u8 = 0x09;

/// Vault kind of an SD sealing key in masked-key metadata.
pub const KEY_KIND_SD_SEALING: u8 = 41;
/// Vault kind of an ML-KEM-1024 SD sealing key (64-byte `d ‖ z` seed).
pub const KEY_KIND_SD_SEALING_MLKEM1024: u8 = 65;
/// Vault kind of an MLKEM1024-P384 SD sealing key (32-byte seed).
pub const KEY_KIND_SD_SEALING_MLKEM1024_P384: u8 = 66;

/// `kem` discriminant of `SdSealingKeyGen` and `DarcKexKeyGen`:
/// DHKEM(P-384, HKDF-SHA384).
pub const TRANSFER_KEM_P384: u8 = 0;
/// `kem` discriminant: ML-KEM-1024 (HPKE-13).
pub const TRANSFER_KEM_MLKEM1024: u8 = 1;
/// `kem` discriminant: MLKEM1024-P384 hybrid (HPKE-10).
pub const TRANSFER_KEM_MLKEM1024_P384: u8 = 2;

/// Wire length of the returned sealing public key: a raw P-384 point
/// (`x ‖ y`, 48 + 48 bytes).
pub const SD_SEALING_PUB_KEY_LEN: usize = 96;
/// ML-KEM-1024 encapsulation-key length.
pub const SD_SEALING_MLKEM1024_PUB_KEY_LEN: usize = 1568;
/// MLKEM1024-P384 public-key length (`ek_PQ ‖ SEC1(ek_T)`).
pub const SD_SEALING_MLKEM1024_P384_PUB_KEY_LEN: usize = 1568 + 97;

/// Wire length of the masked sealing private key: an AEAD-GCM-256
/// masked-key envelope (`header(8) ‖ iv(16) ‖ aad(192) ‖ pt(48) ‖
/// tag(16)`) over the 48-byte raw P-384 private scalar.
pub const MASKED_SEALING_KEY_LEN: usize = 8 + 16 + 192 + 48 + 16;
/// Largest masked sealing private key (the 64-byte ML-KEM-1024 seed).
pub const MASKED_SEALING_KEY_MAX_LEN: usize = 8 + 16 + 192 + 64 + 16;

/// Host-facing TBOR `SdSealingKeyGen` request.
#[tbor(opcode = TBOR_OP_SD_SEALING_KEY_GEN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborSdSealingKeyGenReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope (lifecycle / visibility domain) as the 1-byte
    /// `KeyScope` discriminant (mirror of the firmware `HsmKeyScope`).
    pub scope: u8,

    /// Sealing-key KEM (`TRANSFER_KEM_*`); 0 is P-384.
    pub kem: u8,
}

/// Host-facing TBOR `SdSealingKeyGen` response.
#[tbor(response)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdSealingKeyGenResp {
    /// The new sealing key's private half, masked (AEAD-GCM-256) under the
    /// requested scope's masking key: 280 B (P-384), 296 B (ML-KEM-1024)
    /// or 264 B (hybrid); not stored on-device.
    #[tbor(align = 4, min_len = 264, max_len = 296)]
    pub masked_key: Vec<u8>,

    /// Public key: raw P-384 `x ‖ y` (96 bytes, device byte order per
    /// coordinate, not SEC1), the 1568-byte ML-KEM-1024 encapsulation key,
    /// or the 1665-byte hybrid `ek_PQ ‖ SEC1(ek_T)`.
    #[tbor(min_len = 96, max_len = 1665)]
    pub pub_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_and_scope() {
        let req = TborSdSealingKeyGenReq {
            session_id: 9,
            // KeyScope::SecurityDomain discriminant (0b100).
            scope: 0b100,
            kem: TRANSFER_KEM_MLKEM1024_P384,
        };

        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf, (1, 1)).expect("encode");

        // The 1-byte scope discriminant must appear in the encoded frame.
        assert!(
            frame.contains(&0b100),
            "encoded frame must carry the scope discriminant",
        );
    }
}
