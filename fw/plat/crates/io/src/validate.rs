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

/// Validate an exact output SGL before publishing payload bytes.
///
/// `read` fetches one 16-byte descriptor from host memory. Segment lengths
/// describe descriptor bytes, not payload capacity. Nonempty Data Blocks
/// ensure even a cyclic chain exhausts the payload budget and is rejected.
///
/// # Errors
///
/// `InvalidArg` for malformed, short or oversized lists; host-read errors
/// are propagated unchanged.
pub async fn validate_exact_sgl(
    root: &[u8; 16],
    total: usize,
    mut read: impl core::ops::AsyncFnMut(u64) -> HsmResult<[u8; 16]>,
) -> HsmResult<()> {
    u32::try_from(total).map_err(|_| HsmError::InvalidArg)?;
    fn len(desc: &[u8; 16]) -> u32 {
        u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]])
    }

    if root[15] >> 4 == 0 {
        return if len(root) as usize == total {
            Ok(())
        } else {
            Err(HsmError::InvalidArg)
        };
    }
    let mut remaining = total;
    let mut segment = *root;
    loop {
        let ty = segment[15] >> 4;
        let last = ty == 3;
        let bytes = len(&segment);
        if !matches!(ty, 2 | 3)
            || bytes < if last { 16 } else { 32 }
            || bytes > PAGE_4K
            || !bytes.is_multiple_of(16)
            || remaining == 0
        {
            return Err(HsmError::InvalidArg);
        }
        let mut addr = u64::from_le_bytes([
            segment[0], segment[1], segment[2], segment[3], segment[4], segment[5], segment[6],
            segment[7],
        ]);
        for offset in (0..bytes).step_by(16) {
            let desc = read(addr).await?;
            addr = addr.checked_add(16).ok_or(HsmError::InvalidArg)?;
            let end = offset + 16 == bytes;
            match desc[15] >> 4 {
                0 => {
                    let payload = len(&desc) as usize;
                    if payload == 0 || payload > remaining || (end && !last) {
                        return Err(HsmError::InvalidArg);
                    }
                    remaining -= payload;
                    if remaining == 0 && !(end && last) {
                        return Err(HsmError::InvalidArg);
                    }
                    if end {
                        return if remaining == 0 {
                            Ok(())
                        } else {
                            Err(HsmError::InvalidArg)
                        };
                    }
                }
                2 | 3 if end && !last => segment = desc,
                _ => return Err(HsmError::InvalidArg),
            }
        }
    }
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

    fn sgl(ty: u8, addr: u64, len: u32) -> [u8; 16] {
        let mut desc = [0; 16];
        desc[..8].copy_from_slice(&addr.to_le_bytes());
        desc[8..12].copy_from_slice(&len.to_le_bytes());
        desc[15] = ty << 4;
        desc
    }

    fn check_sgl(root: [u8; 16], total: usize, descriptors: &[(u64, [u8; 16])]) -> HsmResult<()> {
        use core::future::Future;
        use core::task::Context;
        use core::task::Poll;
        use core::task::Waker;

        let mut reads = 0;
        let future = validate_exact_sgl(&root, total, async |addr| {
            reads += 1;
            assert!(reads <= 2 * total + 1, "cyclic list must terminate");
            descriptors
                .iter()
                .find(|(a, _)| *a == addr)
                .map(|(_, desc)| *desc)
                .ok_or(HsmError::FailedToStartDmaTransaction)
        });
        let mut future = core::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("descriptor fixture must be immediately ready"),
        }
    }

    #[test]
    fn exact_sgl_checks_payload_not_descriptor_bytes() {
        let root = sgl(3, 0x1000, 32);
        for (tail, expected) in [
            (531, Ok(())),
            (530, Err(HsmError::InvalidArg)),
            (532, Err(HsmError::InvalidArg)),
        ] {
            assert_eq!(
                check_sgl(
                    root,
                    4627,
                    &[
                        (0x1000, sgl(0, 0x2000, 4096)),
                        (0x1010, sgl(0, 0x3000, tail)),
                    ]
                ),
                expected
            );
        }
        assert_eq!(check_sgl(sgl(0, 0x2000, 4627), 4627, &[]), Ok(()));
        assert_eq!(
            check_sgl(sgl(0, 0x2000, 4628), 4627, &[]),
            Err(HsmError::InvalidArg)
        );
    }

    #[test]
    fn exact_sgl_validates_chains_and_rejects_trailing_entries() {
        let chain = [
            (0x1000, sgl(0, 0x2000, 4096)),
            (0x1010, sgl(3, 0x3000, 16)),
            (0x3000, sgl(0, 0x4000, 531)),
        ];
        assert_eq!(check_sgl(sgl(2, 0x1000, 32), 4627, &chain), Ok(()));
        assert_eq!(
            check_sgl(sgl(3, 0x1000, 32), 4627, &chain),
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            check_sgl(sgl(3, 0x1000, 48), 4096, &chain),
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            check_sgl(sgl(2, 0x1000, 16), 4627, &chain),
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            check_sgl(sgl(3, 0x1000, 17), 4627, &chain),
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            check_sgl(sgl(3, 0x1000, 4112), 4627, &chain),
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            check_sgl(sgl(3, 0x1000, 16), 1, &[(0x1000, sgl(0, 0x2000, 0))]),
            Err(HsmError::InvalidArg)
        );
    }

    #[test]
    fn exact_sgl_rejects_cycles_and_preserves_read_errors() {
        let root = sgl(2, 0x1000, 32);
        assert_eq!(
            check_sgl(root, 3, &[(0x1000, sgl(0, 0x2000, 1)), (0x1010, root),]),
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            check_sgl(root, 3, &[]),
            Err(HsmError::FailedToStartDmaTransaction)
        );
    }
}
