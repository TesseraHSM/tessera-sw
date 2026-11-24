// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signature wire-format helpers.

use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::HsmByteOrder;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

use crate::consts::SIGNATURE_LEN;

/// Convert ECDSA `r || s` in place between the PAL's operand order and
/// the big-endian COSE form, one half at a time. The conversion is its
/// own inverse and a no-op on big-endian PALs.
///
/// `sig` must be exactly [`SIGNATURE_LEN`] bytes.
pub(crate) fn sig_halves_swap(order: HsmByteOrder, sig: &mut [u8]) -> HsmResult<()> {
    if sig.len() != SIGNATURE_LEN {
        return Err(HsmError::InvalidArg);
    }
    let (r, s) = sig.split_at_mut(SIGNATURE_LEN / 2);
    byte_order::int_to_be(order, r);
    byte_order::int_to_be(order, s);
    Ok(())
}
