// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `RsaModExp` command.
//!
//! `RsaModExp` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that performs a raw RSA exponentiation using a caller-held
//! **masked** RSA private key (imported via [`UnwrapKey`](crate::unwrap_key)
//! with the RSA / RSA-CRT key class). The host applies encryption padding
//! and validates recovered signature blocks.
//!
//! `op_type` is a raw 1-byte discriminant (the firmware types it as the
//! `RsaOp` open-enum; this host crate is firewalled from the firmware PAL
//! types).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `RsaModExp`.
pub const TBOR_OP_RSA_MOD_EXP: u8 = 0x1A;

/// Max masked RSA private-key envelope length (RSA-4096-CRT).
pub const RSA_MASKED_KEY_MAX_LEN: usize = 3168;
/// Max RSA modulus length (bytes) — RSA-4096.
pub const RSA_MOD_EXP_MAX_LEN: usize = 512;

/// `RsaOp` discriminant for the RSA decrypt primitive (requires the
/// masked key's `decrypt` usage attribute).
pub const RSA_OP_DECRYPT: u8 = 1;
/// `RsaOp` discriminant for the RSA sign primitive (requires the masked
/// key's `sign` usage attribute).
pub const RSA_OP_SIGN: u8 = 2;
/// `RsaOp` discriminant for the RSA public encrypt primitive (requires the
/// masked key's `encrypt` usage attribute).
pub const RSA_OP_ENCRYPT: u8 = 3;
/// `RsaOp` discriminant for the RSA public verify primitive (requires the
/// masked key's `verify` usage attribute).
pub const RSA_OP_VERIFY: u8 = 4;

/// Host-facing TBOR `RsaModExp` request.
#[tbor(opcode = TBOR_OP_RSA_MOD_EXP, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborRsaModExpReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The input integer `y` in device byte order, exactly the key's
    /// modulus length (256 / 384 / 512 B). Firmware overwrites it with `x`.
    #[tbor(max_len = 512)]
    pub y: Vec<u8>,

    /// The masked RSA private key (from `UnwrapKey`); its kind recovers the
    /// modulus size and CRT form.
    #[tbor(align = 4, max_len = 3168)]
    pub masked_key: Vec<u8>,

    /// The operation, 1-byte `RsaOp` (see `RSA_OP_*`): gates on the
    /// corresponding `decrypt`, `sign`, `encrypt`, or `verify` usage.
    pub op_type: u8,
}

/// Host-facing TBOR `RsaModExp` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborRsaModExpResp {
    /// The result in device byte order, exactly the key's modulus length
    /// (256 / 384 / 512 B): `y^d mod n` for Decrypt/Sign and `y^e mod n`
    /// for Encrypt/Verify.
    #[tbor(max_len = 512)]
    pub x: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborRsaModExpReq {
            session_id: 7,
            masked_key: alloc::vec![0x11u8; 400],
            op_type: RSA_OP_SIGN,
            y: alloc::vec![0x22u8; 256],
        };
        let mut buf = [0u8; 4096];
        let frame = req.encode_request(&mut buf, (1, 1)).expect("encode");
        assert!(
            frame.contains(&RSA_OP_SIGN),
            "encoded frame must carry the op-type discriminant",
        );
    }

    #[test]
    fn operation_discriminants_are_stable() {
        assert_eq!(RSA_OP_DECRYPT, 1);
        assert_eq!(RSA_OP_SIGN, 2);
        assert_eq!(RSA_OP_ENCRYPT, 3);
        assert_eq!(RSA_OP_VERIFY, 4);
    }
}
