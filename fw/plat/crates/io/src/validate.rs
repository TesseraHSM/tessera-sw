// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Validation of the request transfer fields an SQE carries.

use tsra_fw_hsm_pal_traits::HsmDmaAddr;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

/// 4K page size.
const PAGE_4K: u32 = 4096;

/// Maximum source buffer length (two 4K pages).
///
/// The SQE carries a PRP *pair*, and the host driver populates PRP2
/// whenever the request exceeds 4K, so a request spans up to 8K — the
/// transport buffer the host and the TBOR schemas are built around.
pub const MAX_SRC_LEN: u32 = 2 * PAGE_4K;

/// Maximum destination buffer length (two 4K pages).
///
/// The host driver allocates an 8K (2-page) response buffer and advertises
/// its full size in the SQE; both PRP pages are programmed for the
/// outbound transfer.
pub const MAX_DST_LEN: u32 = 2 * PAGE_4K;

/// Size of one NVMe SGL Data Block descriptor in the OOB array.
pub const OOB_ENTRY_LEN: u32 = 16;

/// Maximum out-of-band descriptor-array length: one 4K descriptor page
/// (up to 256 SGL Data Block descriptors).
pub const MAX_OOB_LEN: u32 = PAGE_4K;

#[inline]
fn is_aligned_4k(addr: HsmDmaAddr) -> bool {
    addr.lo & (PAGE_4K - 1) == 0
}

/// Validates the transfer fields of a request-carrying SQE, independent of
/// the SQE format.
///
/// - Source and destination lengths must be 1..=8192.
/// - Source and destination PRP1 must be 4K-aligned.
/// - A present OOB array (`oob_len != 0`) is a whole number of 16-byte
///   descriptors, at most one 4K page, at a non-null 4K-aligned address.
///
/// # Errors
///
/// `IoChannelInvalid{Src,Dst,Oob}{Len,Alignment}` for the failing field;
/// `InvalidArg` for a null OOB address.
#[inline]
pub fn validate_io_fields(
    src_len: u32,
    dst_len: u32,
    src_prp1: HsmDmaAddr,
    dst_prp1: HsmDmaAddr,
    oob_len: u32,
    oob_prp: HsmDmaAddr,
) -> HsmResult<()> {
    if src_len == 0 || src_len > MAX_SRC_LEN {
        return Err(HsmError::IoChannelInvalidSrcLen);
    }
    if dst_len == 0 || dst_len > MAX_DST_LEN {
        return Err(HsmError::IoChannelInvalidDstLen);
    }
    if !is_aligned_4k(src_prp1) {
        return Err(HsmError::IoChannelInvalidSrcAlignment);
    }
    if !is_aligned_4k(dst_prp1) {
        return Err(HsmError::IoChannelInvalidDstAlignment);
    }
    if oob_len != 0 {
        if !oob_len.is_multiple_of(OOB_ENTRY_LEN) || oob_len > MAX_OOB_LEN {
            return Err(HsmError::IoChannelInvalidOobLen);
        }
        if !is_aligned_4k(oob_prp) {
            return Err(HsmError::IoChannelInvalidOobAlignment);
        }
        if oob_prp.is_null() {
            return Err(HsmError::InvalidArg);
        }
    }
    Ok(())
}

/// Host address of descriptor `index` in the OOB array of `oob_len` bytes
/// at `oob_prp`.
///
/// # Errors
///
/// `InvalidArg` when the descriptor lies outside the array.
#[inline]
pub fn oob_entry_addr(oob_prp: HsmDmaAddr, oob_len: u32, index: usize) -> HsmResult<HsmDmaAddr> {
    let off = u32::try_from(index)
        .ok()
        .and_then(|index| index.checked_mul(OOB_ENTRY_LEN))
        .filter(|off| {
            off.checked_add(OOB_ENTRY_LEN)
                .is_some_and(|end| end <= oob_len)
        })
        .ok_or(HsmError::InvalidArg)?;
    let addr = ((u64::from(oob_prp.hi) << 32) | u64::from(oob_prp.lo))
        .checked_add(u64::from(off))
        .ok_or(HsmError::InvalidArg)?;
    Ok(HsmDmaAddr {
        lo: addr as u32,
        hi: (addr >> 32) as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn addr(lo: u32, hi: u32) -> HsmDmaAddr {
        HsmDmaAddr { lo, hi }
    }

    #[test]
    fn oob_entry_addr_indexes_within_the_array() {
        assert_eq!(oob_entry_addr(addr(0x1000, 0), 48, 0), Ok(addr(0x1000, 0)));
        assert_eq!(oob_entry_addr(addr(0x1000, 0), 48, 2), Ok(addr(0x1020, 0)));
        assert_eq!(oob_entry_addr(addr(0xFFFF_FFF0, 0), 32, 1), Ok(addr(0, 1)));
    }

    #[test]
    fn oob_entry_addr_rejects_out_of_range() {
        assert_eq!(
            oob_entry_addr(addr(0x1000, 0), 48, 3),
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            oob_entry_addr(addr(0x1000, 0), 0, 0),
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            oob_entry_addr(addr(0x1000, 0), 48, usize::MAX),
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            oob_entry_addr(addr(u32::MAX, u32::MAX), 32, 1),
            Err(HsmError::InvalidArg)
        );
    }
}
