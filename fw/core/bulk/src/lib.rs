// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bulk (fast-path) AES-GCM / AES-XTS queue wire formats.
//!
//! Lion-compatible layouts shared by every component that touches a bulk
//! queue entry: the HSM PALs that execute bulk IOs, the core that posts
//! error completions, and host-side emulators and tests that build
//! submissions.
//!
//! - [`BulkSqe`] — the 32-dword (128-byte) submission entry (64-byte
//!   NVMe-style command followed by the 64-byte GCM / XTS command-specific
//!   fields), with [`BulkSqe::parse`] reading and validating it in place
//!   from the IO's [`HsmSqe`].
//! - [`BulkCqe`] — the 16-dword (64-byte) completion entry, written into
//!   the IO's [`HsmCqe`].
//!
//! Field offsets are byte offsets into the entry; byte `n` is bits
//! `8 * (n % 4)..` of dword `n / 4` (little-endian dwords).
//! - [`BulkStatus`] — the CQE status / error code pair, with
//!   [`BulkStatus::from_error`] mapping an [`HsmError`] onto it.

#![no_std]

mod cqe;
mod sqe;
mod status;

#[cfg(test)]
mod tests;

pub use cqe::*;
pub use sqe::*;
pub use status::*;
use tsra_fw_hsm_pal_traits::HsmCqe;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSqe;

/// Number of dwords in a bulk submission entry (command + GCM / XTS
/// fields).
pub const BULK_SQE_DWORDS: usize = 32;

/// Number of dwords in a bulk completion entry.
pub const BULK_CQE_DWORDS: usize = 16;

/// Owned bulk submission entry.
pub type RawBulkSqe = [u32; BULK_SQE_DWORDS];

/// Owned bulk completion entry.
pub type RawBulkCqe = [u32; BULK_CQE_DWORDS];

/// Maximum bytes moved through the source (and destination) SGL of one IO,
/// including the GCM AAD region.
pub const MAX_DATA_LEN: u32 = 16 * 1024;

/// AES block length; SGL data lengths must be a multiple of it.
pub const BLOCK_LEN: u32 = 16;

/// Alignment of the padded GCM AAD region at the start of the source data.
pub const GCM_AAD_ALIGN: u32 = 32;

/// Maximum GCM text tail carried outside the SGL (see [`GcmTail`]).
pub const GCM_MAX_TAIL_LEN: u8 = (BLOCK_LEN - 1) as u8;

/// AES-GCM tag length.
pub const GCM_TAG_LEN: usize = 16;

/// AES-GCM IV length.
pub const GCM_IV_LEN: usize = 12;

/// AES-XTS tweak length.
pub const XTS_TWEAK_LEN: usize = 16;

/// SQE command type of a bulk AES command.
pub const CMD_TYPE_AES: u8 = 5;

/// SQE frame type of a bulk AES command.
pub const FRAME_TYPE_AES: u8 = 1;

/// NVMe SGL descriptor length in bytes.
pub const SGL_DESC_LEN: u32 = 16;
/// Maximum descriptor-list size accepted from the host driver.
pub const SGL_MAX_SEGMENT_LEN: u32 = 4096;
/// NVMe SGL Data Block type.
pub const SGL_DATA_BLOCK: u8 = 0;
/// NVMe SGL Segment type.
pub const SGL_SEGMENT: u8 = 2;
/// NVMe SGL Last Segment type.
pub const SGL_LAST_SEGMENT: u8 = 3;

/// Validate a payload descriptor and describe its block-aligned prefix.
/// Segment descriptors retain their list length; the engine bounds the payload.
pub fn sgl_prefix(desc: &[u8; 16], len: u32, prefix: u32) -> HsmResult<[u8; 16]> {
    if prefix > len || len > MAX_DATA_LEN || !prefix.is_multiple_of(BLOCK_LEN) {
        return Err(HsmError::InvalidArg);
    }
    let desc_len = u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]);
    match desc[15] >> 4 {
        SGL_DATA_BLOCK if desc_len == len => sgl_data_block_range(desc, 0, prefix),
        kind @ (SGL_SEGMENT | SGL_LAST_SEGMENT) => {
            let min = if kind == SGL_SEGMENT {
                2 * SGL_DESC_LEN
            } else {
                SGL_DESC_LEN
            };
            let addr = u64::from_le_bytes(core::array::from_fn(|index| desc[index]));
            if desc[15] & 0xF != 0
                || desc[12..15] != [0; 3]
                || addr == 0
                || desc_len < min
                || desc_len > SGL_MAX_SEGMENT_LEN
                || !desc_len.is_multiple_of(SGL_DESC_LEN)
                || addr.checked_add(u64::from(desc_len)).is_none()
            {
                return Err(HsmError::InvalidArg);
            }
            Ok(*desc)
        }
        _ => Err(HsmError::InvalidArg),
    }
}

/// Describe a checked subrange of a flat NVMe SGL Data Block.
pub fn sgl_data_block_range(desc: &[u8; 16], offset: u32, len: u32) -> HsmResult<[u8; 16]> {
    let addr = u64::from_le_bytes(core::array::from_fn(|index| desc[index]));
    let available = u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]);
    if desc[15] != SGL_DATA_BLOCK
        || desc[12..15] != [0; 3]
        || (available != 0 && addr == 0)
        || addr.checked_add(u64::from(available)).is_none()
        || offset.checked_add(len).is_none_or(|end| end > available)
    {
        return Err(HsmError::InvalidArg);
    }
    let start = addr
        .checked_add(u64::from(offset))
        .ok_or(HsmError::InvalidArg)?;
    let mut result = *desc;
    result[..8].copy_from_slice(&start.to_le_bytes());
    result[8..12].copy_from_slice(&len.to_le_bytes());
    Ok(result)
}

/// One bounded SGL-range traversal action; all addresses remain host addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SglRangeStep {
    /// Fetch one descriptor from this address and supply it to the next step.
    Descriptor(u64),
    /// Transfer the bytes described by this checked flat Data Block.
    Data([u8; 16]),
    /// The requested range is complete.
    Done,
}

/// Bounded, allocation-free traversal of a range within a host SGL.
pub struct SglRangeCursor {
    current: Option<[u8; 16]>,
    offset: u32,
    remaining: u32,
    next: u64,
    end: u64,
    chained: bool,
    awaiting: bool,
    budget: u32,
}

impl SglRangeCursor {
    /// Start a traversal bounded by the maximum host-driver descriptor page.
    pub fn new(root: [u8; 16], offset: u32, len: u32) -> HsmResult<Self> {
        if offset.checked_add(len).is_none_or(|end| end > MAX_DATA_LEN) {
            return Err(HsmError::InvalidArg);
        }
        Ok(Self {
            current: Some(root),
            offset,
            remaining: len,
            next: 0,
            end: 0,
            chained: false,
            awaiting: false,
            budget: SGL_MAX_SEGMENT_LEN / SGL_DESC_LEN,
        })
    }

    /// Advance, supplying descriptor bytes only after a `Descriptor` action.
    pub fn step(&mut self, fetched: Option<[u8; 16]>) -> HsmResult<SglRangeStep> {
        if self.awaiting {
            let desc = fetched.ok_or(HsmError::InvalidArg)?;
            let is_chain = matches!(desc[15] >> 4, SGL_SEGMENT | SGL_LAST_SEGMENT);
            if is_chain != (self.chained && self.next == self.end) {
                return Err(HsmError::InvalidArg);
            }
            self.current = Some(desc);
            self.awaiting = false;
        } else if fetched.is_some() {
            return Err(HsmError::InvalidArg);
        }
        if self.remaining == 0 {
            return Ok(SglRangeStep::Done);
        }
        if let Some(desc) = self.current.take() {
            self.budget = self.budget.checked_sub(1).ok_or(HsmError::InvalidArg)?;
            let available = u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]);
            match desc[15] >> 4 {
                SGL_DATA_BLOCK => {
                    sgl_data_block_range(&desc, 0, 0)?;
                    if available == 0 {
                        return Err(HsmError::InvalidArg);
                    }
                    if self.offset >= available {
                        self.offset -= available;
                    } else {
                        let count = (available - self.offset).min(self.remaining);
                        let part = sgl_data_block_range(&desc, self.offset, count)?;
                        self.offset = 0;
                        self.remaining -= count;
                        return Ok(SglRangeStep::Data(part));
                    }
                }
                kind @ (SGL_SEGMENT | SGL_LAST_SEGMENT) => {
                    sgl_prefix(&desc, 0, 0)?;
                    if self.next != self.end {
                        return Err(HsmError::InvalidArg);
                    }
                    self.next = u64::from_le_bytes(core::array::from_fn(|index| desc[index]));
                    self.end = self
                        .next
                        .checked_add(u64::from(available))
                        .ok_or(HsmError::InvalidArg)?;
                    self.chained = kind == SGL_SEGMENT;
                }
                _ => return Err(HsmError::InvalidArg),
            }
        }
        if self.next >= self.end || self.budget == 0 {
            return Err(HsmError::InvalidArg);
        }
        let addr = self.next;
        self.next = self
            .next
            .checked_add(u64::from(SGL_DESC_LEN))
            .ok_or(HsmError::InvalidArg)?;
        self.awaiting = true;
        Ok(SglRangeStep::Descriptor(addr))
    }
}

fn rd_u8<const N: usize>(d: &[u32; N], off: usize) -> u8 {
    (d[off / 4] >> (8 * (off % 4))) as u8
}

fn rd_u16<const N: usize>(d: &[u32; N], off: usize) -> u16 {
    u16::from(rd_u8(d, off)) | (u16::from(rd_u8(d, off + 1)) << 8)
}

fn rd_u32<const N: usize>(d: &[u32; N], off: usize) -> u32 {
    u32::from(rd_u16(d, off)) | (u32::from(rd_u16(d, off + 2)) << 16)
}

fn rd_u64<const N: usize>(d: &[u32; N], off: usize) -> u64 {
    u64::from(rd_u32(d, off)) | (u64::from(rd_u32(d, off + 4)) << 32)
}

fn rd_arr<const N: usize, const M: usize>(d: &[u32; N], off: usize) -> [u8; M] {
    core::array::from_fn(|i| rd_u8(d, off + i))
}

fn wr<const N: usize>(d: &mut [u32; N], off: usize, v: &[u8]) {
    for (i, &b) in v.iter().enumerate() {
        let (w, sh) = ((off + i) / 4, 8 * ((off + i) % 4));
        d[w] = (d[w] & !(0xFF << sh)) | (u32::from(b) << sh);
    }
}
