// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! Conversions between PAL crypto operands and big-endian encodings.
//!
//! PAL crypto operands are in the platform's operand order,
//! [`HsmCryptoOrder::BYTE_ORDER`](tsra_fw_hsm_pal_traits::HsmCryptoOrder).
//! Standard encodings — SEC1, X.509 / DER, COSE, HPKE KDF input — are
//! big-endian with exact-width ECC components. These helpers convert
//! between the two **in place**: on [`HsmByteOrder::Be`] platforms they
//! only check lengths, and on [`HsmByteOrder::Le`] platforms they reverse
//! bytes and move P-521 components between their padded slots and the
//! exact-width layout. Pass the PAL's const order so the branch folds.
//!
//! Shapes:
//!
//! - integer — a whole buffer: RSA operands, ECDH secrets, digests.
//! - coord — one ECC component in a `wire_coord_len(order)` slot.
//! - pair — two ECC components: a point `x || y` or a signature `r || s`.

use tsra_fw_hsm_pal_traits::HsmByteOrder;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

/// Converts an operand-order integer to big-endian in place.
#[inline]
#[allow(clippy::disallowed_methods, reason = "the one sanctioned reversal")]
pub fn int_to_be(order: HsmByteOrder, buf: &mut [u8]) {
    if !order.is_be() {
        buf.reverse();
    }
}

/// Converts a big-endian integer to operand order in place.
#[inline]
pub fn int_from_be(order: HsmByteOrder, buf: &mut [u8]) {
    int_to_be(order, buf);
}

/// Copies the operand-order integer `src` into `dst` as big-endian.
///
/// # Errors
/// [`HsmError::InvalidArg`] if the lengths differ.
#[inline]
pub fn int_copy_to_be(order: HsmByteOrder, dst: &mut [u8], src: &[u8]) -> HsmResult<()> {
    if dst.len() != src.len() {
        return Err(HsmError::InvalidArg);
    }
    if order.is_be() {
        dst.copy_from_slice(src);
    } else {
        for (d, s) in dst.iter_mut().zip(src.iter().rev()) {
            *d = *s;
        }
    }
    Ok(())
}

/// Copies the big-endian integer `src` into `dst` in operand order.
///
/// # Errors
/// [`HsmError::InvalidArg`] if the lengths differ.
#[inline]
pub fn int_copy_from_be(order: HsmByteOrder, dst: &mut [u8], src: &[u8]) -> HsmResult<()> {
    int_copy_to_be(order, dst, src)
}

/// Converts the operand-order ECC component in `slot` to big-endian in
/// place, returning the exact-width (`curve.priv_key_len()`) value at the
/// head of `slot`.
///
/// # Errors
/// [`HsmError::InvalidArg`] if `slot` is shorter than
/// `curve.wire_coord_len(order)`.
#[inline]
pub fn coord_to_be(
    order: HsmByteOrder,
    curve: HsmEccCurve,
    slot: &mut [u8],
) -> HsmResult<&mut [u8]> {
    if slot.len() < curve.wire_coord_len(order) {
        return Err(HsmError::InvalidArg);
    }
    let be = &mut slot[..curve.priv_key_len()];
    int_to_be(order, be);
    Ok(be)
}

/// Converts the big-endian ECC component at the head of `slot`
/// (`curve.priv_key_len()` bytes) to operand order in place, returning the
/// `curve.wire_coord_len(order)` operand; padding is zeroed.
///
/// # Errors
/// [`HsmError::InvalidArg`] if `slot` is shorter than
/// `curve.wire_coord_len(order)`.
#[inline]
pub fn coord_from_be(
    order: HsmByteOrder,
    curve: HsmEccCurve,
    slot: &mut [u8],
) -> HsmResult<&mut [u8]> {
    let raw = curve.priv_key_len();
    let wire = curve.wire_coord_len(order);
    if slot.len() < wire {
        return Err(HsmError::InvalidArg);
    }
    let operand = &mut slot[..wire];
    int_from_be(order, &mut operand[..raw]);
    operand[raw..].fill(0);
    Ok(operand)
}

/// Converts an operand-order component pair (`x || y` or `r || s`, each in
/// a `curve.wire_coord_len(order)` slot) at the head of `buf` to the
/// big-endian exact-width pair in place, returning the
/// `2 * curve.priv_key_len()` result at the head of `buf`.
///
/// # Errors
/// [`HsmError::InvalidArg`] if `buf` is shorter than
/// `2 * curve.wire_coord_len(order)`.
#[inline]
pub fn pair_to_be(order: HsmByteOrder, curve: HsmEccCurve, buf: &mut [u8]) -> HsmResult<&mut [u8]> {
    let raw = curve.priv_key_len();
    let wire = curve.wire_coord_len(order);
    if buf.len() < 2 * wire {
        return Err(HsmError::InvalidArg);
    }
    int_to_be(order, &mut buf[..raw]);
    int_to_be(order, &mut buf[wire..wire + raw]);
    if wire != raw {
        buf.copy_within(wire..wire + raw, raw);
    }
    Ok(&mut buf[..2 * raw])
}

/// Converts the big-endian exact-width component pair at the head of `buf`
/// (`2 * curve.priv_key_len()` bytes) to operand order in place, returning
/// the `2 * curve.wire_coord_len(order)` operand; padding is zeroed.
///
/// # Errors
/// [`HsmError::InvalidArg`] if `buf` is shorter than
/// `2 * curve.wire_coord_len(order)`.
#[inline]
pub fn pair_from_be(
    order: HsmByteOrder,
    curve: HsmEccCurve,
    buf: &mut [u8],
) -> HsmResult<&mut [u8]> {
    let raw = curve.priv_key_len();
    let wire = curve.wire_coord_len(order);
    if buf.len() < 2 * wire {
        return Err(HsmError::InvalidArg);
    }
    let operand = &mut buf[..2 * wire];
    if wire != raw {
        operand.copy_within(raw..2 * raw, wire);
        operand[raw..wire].fill(0);
        operand[wire + raw..].fill(0);
    }
    int_from_be(order, &mut operand[..raw]);
    int_from_be(order, &mut operand[wire..wire + raw]);
    Ok(operand)
}

#[cfg(test)]
mod tests;
