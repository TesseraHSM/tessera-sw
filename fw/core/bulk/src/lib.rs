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
