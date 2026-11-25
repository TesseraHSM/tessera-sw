// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `RsaModExp` wire schema.
//!
//! `RsaModExp` is an in-session command that performs a raw RSA
//! exponentiation using a caller-held **masked** RSA private key (imported
//! via [`UnwrapKey`](crate::unwrap_key) with the RSA / RSA-CRT key class).
//! Public operations derive `n || e` from that authenticated key on-device;
//! no raw-public-key input is accepted. Encryption padding and recovered
//! signature-block validation remain host responsibilities.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `masked_key` — the masked RSA private key (unmasked in place); its
//!   kind recovers the modulus size and CRT form.
//! * `op_type` — the [`RsaOp`] selecting the exponent direction and exact
//!   usage attribute (`Decrypt` → `decrypt`, `Sign` → `sign`, `Encrypt` →
//!   `encrypt`, `Verify` → `verify`).
//! * `y` — the input integer in device byte order, exactly the
//!   key's modulus length (256 / 384 / 512 B for RSA-2048 / 3072 / 4096).
//!
//! Outputs:
//!
//! * `x` — the modulus-sized result in device byte order (`y^d mod n` for
//!   Decrypt/Sign, `y^e mod n` for Encrypt/Verify).

use open_enum::open_enum;
use tsra_fw_ddi_tbor_api::tbor;

pub use crate::unwrap_key::UNWRAP_MASKED_KEY_MAX_LEN;

/// TBOR opcode for `RsaModExp`.
pub const TBOR_OP_RSA_MOD_EXP: u8 = 0x1A;

/// Minimum accepted masked RSA private-key envelope length.  A coarse
/// floor (an RSA-2048 masked key is far larger — its modulus alone is
/// 256 B); the authoritative gate is `unmask` (AEAD-tag verification) plus
/// the key-kind check in the handler.  Pinned into the `#[tbor(buffer,
/// min_len = 264)]` literal on [`TborRsaModExpReq::masked_key`].
pub const RSA_MASKED_KEY_MIN_LEN: usize = 264;

/// Maximum accepted masked RSA private-key envelope length — the largest
/// masked key [`UnwrapKey`](crate::unwrap_key) can produce (RSA-4096-CRT).
/// Pinned into the `#[tbor(buffer, max_len = 3168)]` literal on
/// [`TborRsaModExpReq::masked_key`].
pub const RSA_MASKED_KEY_MAX_LEN: usize = UNWRAP_MASKED_KEY_MAX_LEN;

/// Maximum RSA modulus length (bytes) — RSA-4096.  Pinned into the
/// `#[tbor(buffer, max_len = 512)]` literals on
/// [`TborRsaModExpReq::y`] / [`TborRsaModExpResp::x`].
pub const RSA_MOD_EXP_MAX_LEN: usize = 512;

// Keep the schema-literal bounds in sync with the named constants (the
// tbor derive requires integer literals in the attributes).
const _: () = assert!(RSA_MASKED_KEY_MAX_LEN == 3168);

/// RSA operation selector on the TBOR wire.
///
/// Selects which usage attribute the masked key must carry for the
/// modular exponentiation to be permitted. The selector also determines
/// the exponent direction.
/// Kept as an [`open_enum`] so an unrecognized discriminant round-trips as
/// `RsaOp(x)` and is rejected on-device rather than failing to decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaOp {
    /// RSA decrypt primitive — requires the `decrypt` usage attribute.
    Decrypt = 1,

    /// RSA sign primitive — requires the `sign` usage attribute.
    Sign = 2,

    /// RSA encrypt primitive — requires the `encrypt` usage attribute.
    Encrypt = 3,

    /// RSA verify primitive — requires the `verify` usage attribute.
    Verify = 4,
}

/// `RsaModExp` request schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can `unmask` it **in
/// place** in the request buffer (via `decode_mut`) — no scratch copy — and
/// compute directly from the recovered key.
#[tbor(opcode = 0x1A, pair = TborRsaModExpResp)]
pub struct TborRsaModExpReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The input integer `y` in device byte order, exactly the key's
    /// modulus length (256 / 384 / 512 B), replaced in place by the result.
    #[tbor(buffer, max_len = 512, mutable)]
    pub y: &'a [u8],

    /// The masked RSA private key (from `UnwrapKey`), an AEAD-GCM-256
    /// envelope of 264..=3168 B.  Its kind recovers the modulus size and
    /// CRT form.
    #[tbor(align = 4, buffer, min_len = 264, max_len = 3168, mutable)]
    pub masked_key: &'a [u8],

    /// The operation, 1-byte [`RsaOp`] (gates on the corresponding usage).
    #[tbor(U8)]
    pub op_type: RsaOp,
}

/// `RsaModExp` response schema.
///
/// `x` is `#[tbor(mutable)]` so the handler can reserve the slot and have
/// the operation result replace `y` (`decode_mut`).
#[tbor(response, pair = TborRsaModExpReq)]
pub struct TborRsaModExpResp<'a> {
    /// The modulus-sized result in device byte order (`y^d mod n` for
    /// Decrypt/Sign, `y^e mod n` for Encrypt/Verify).
    #[tbor(buffer, max_len = 512, mutable)]
    pub x: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 4096];
        let masked = [0x11u8; RSA_MASKED_KEY_MIN_LEN];
        let y = [0x22u8; 256];
        let frame = TborRsaModExpReq::encode(&mut buf, (1, 1))
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .y(&y)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .op_type(RsaOp::Sign)
            .unwrap()
            .finish();
        assert_eq!(frame.op_type(), RsaOp::Sign);
        assert_eq!(frame.y(), &y[..]);
    }

    #[test]
    fn response_round_trips_x() {
        let mut buf = [0u8; 1024];
        let x = [0x33u8; RSA_MOD_EXP_MAX_LEN];
        let frame = TborRsaModExpResp::encode(&mut buf, (1, 1), 0, true)
            .unwrap()
            .x(&x)
            .unwrap()
            .finish();
        assert_eq!(frame.x(), &x[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        assert_eq!(RSA_MOD_EXP_MAX_LEN, 512);
        assert_eq!(RSA_MASKED_KEY_MAX_LEN, 3168);
        assert_eq!(RSA_MASKED_KEY_MIN_LEN, 264);
    }

    #[test]
    fn operation_discriminants_are_stable() {
        assert_eq!(RsaOp::Decrypt, RsaOp(1));
        assert_eq!(RsaOp::Sign, RsaOp(2));
        assert_eq!(RsaOp::Encrypt, RsaOp(3));
        assert_eq!(RsaOp::Verify, RsaOp(4));
        assert_eq!(RsaOp(5), RsaOp(5));
    }
}
