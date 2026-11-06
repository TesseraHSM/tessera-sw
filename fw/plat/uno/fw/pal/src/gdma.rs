// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno GDMA controller implementation.
//!
//! Bridges the platform-agnostic [`HsmGdmaController`] trait to the
//! low-level [`GdmaDriver`](tsra_fw_uno_drivers_gdma::GdmaDriver)
//! by converting buffer addresses and [`HsmDmaAddr`] values into
//! [`DriverDmaBuf`] and [`MemInterface`] parameters.
//!
//! # Address model
//!
//! The Uno HSM is a Cortex-M core with a 32-bit address space, so
//! device-local pointers always fit in a single [`DmaAddr`] with
//! `hi = 0`. Host-side addresses arrive as [`HsmDmaAddr`] (a full
//! 64-bit address split into `hi`/`lo` halves) and are wrapped in a
//! [`DriverDmaBuf::Prp`] or [`DriverDmaBuf::Sgl`] depending on the caller's
//! `prp` flag.
//!
//! # Transfer direction helpers
//!
//! | Helper                   | Source interface    | Destination interface |
//! |--------------------------|---------------------|-----------------------|
//! | `copy_mem`               | Device              | Device                |
//! | `copy_mem_from_host`     | Host                | Device                |
//! | `copy_mem_from_host_raw` | Host (raw SGL desc) | Device                |
//! | `copy_mem_to_host`       | Device              | Host                  |
//! | `HostSgl::write_from`    | Device              | Host (raw SGL, cursor)|

use tsra_fw_hsm_pal_traits::HsmDmaAddr;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmGdmaController;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_uno_drivers_gdma::GdmaAddr;
use tsra_fw_uno_drivers_gdma::GdmaBuf;
use tsra_fw_uno_drivers_gdma::MemInterface;
use tsra_fw_uno_drivers_part_store::HsmPartId;
use tsra_fw_uno_reg_soc::zero::ZERO_BASE;
use tsra_fw_uno_reg_soc::zero::ZERO_SIZE;
use tsra_fw_uno_trace::tracing::*;
use zeroize::Zeroize;

use crate::UnoHsmPal;

/// Converts an [`HsmDmaAddr`] (the trait-level 64-bit address) into a
/// [`GdmaBuf`] suitable for a host-side DMA operand.
///
/// The `prp` flag selects the descriptor format written to the GDMA
/// submission queue:
///
/// - `true`  → [`GdmaBuf::Prp`] — Physical Region Page descriptor pair.
///   `prp0` holds the address; `prp1` is zeroed (single-page transfer).
/// - `false` → [`GdmaBuf::Sgl`] — Scatter-Gather List descriptor pair.
///   `sgl0` holds the address; `sgl1` is zeroed (inline data block).
#[inline(always)]
fn host_dma_buf(addr: HsmDmaAddr, addr2: HsmDmaAddr, prp: bool) -> GdmaBuf {
    let gdma_addr = GdmaAddr {
        lo: addr.lo,
        hi: addr.hi,
    };
    if prp {
        // `prp1` is the *second page*, not a length or a list pointer at
        // this size: a PRP pair covers up to two 4 KiB pages. Leaving it
        // zero silently truncates any transfer that crosses the first page
        // boundary, which is exactly how ML-DSA-87 signatures were being
        // cut at 4096 bytes and zero-filled after.
        GdmaBuf::Prp {
            prp0: gdma_addr,
            prp1: GdmaAddr {
                lo: addr2.lo,
                hi: addr2.hi,
            },
        }
    } else {
        GdmaBuf::Sgl {
            sgl0: gdma_addr,
            sgl1: GdmaAddr::ZERO,
        }
    }
}

/// Converts a device-local (DTCM / SRAM) raw pointer and length into
/// an SGL [`GdmaBuf`].
///
/// SGL Data Block descriptor: `sgl0` = address, `sgl1.lo` = length,
/// `sgl1.hi[31:24]` = type/subtype (0x00 = inline data block).
/// No 4K page-crossing restriction unlike PRP.
#[inline(always)]
fn device_dma_buf(ptr: *const u8, len: u32) -> GdmaBuf {
    GdmaBuf::Sgl {
        sgl0: GdmaAddr::from_u32(ptr as usize as u32),
        sgl1: GdmaAddr { lo: len, hi: 0 },
    }
}

/// Builds an inline SGL Data Block operand for `len` contiguous host
/// bytes at `addr`.
///
/// Unlike [`host_dma_buf`] with `prp = false`, the length is carried in
/// `sgl1.lo`: the GDMA takes an SGL operand's length from the
/// descriptor, and a zero length is rejected with `dma_error(1)`
/// (`0x08f08101`). No 4 KiB page-crossing limit, unlike a PRP pair.
#[inline(always)]
fn host_sgl_block(addr: u64, len: u32) -> GdmaBuf {
    GdmaBuf::Sgl {
        sgl0: GdmaAddr {
            lo: addr as u32,
            hi: (addr >> 32) as u32,
        },
        sgl1: GdmaAddr { lo: len, hi: 0 },
    }
}

/// Host memory page size assumed by a PRP operand.
const HOST_PAGE_SIZE: u64 = 4096;

/// Builds a single-page PRP operand for host bytes at `addr`. The
/// transfer must not cross the 4 KiB page containing `addr`.
#[inline(always)]
fn host_prp_page(addr: u64) -> GdmaBuf {
    GdmaBuf::Prp {
        prp0: GdmaAddr {
            lo: addr as u32,
            hi: (addr >> 32) as u32,
        },
        prp1: GdmaAddr::ZERO,
    }
}

/// Converts a raw 16-byte NVMe SGL Data Block descriptor into an SGL
/// [`GdmaBuf`] for a host-side DMA source.
///
/// The descriptor's two little-endian 8-byte dwords map directly onto
/// the GDMA SGL source pair: `desc[0..8]` → `sgl0` (address),
/// `desc[8..16]` → `sgl1` (the block's embedded length + type).
#[inline(always)]
fn sgl_desc_buf(desc: &[u8; 16]) -> GdmaBuf {
    GdmaBuf::Sgl {
        sgl0: GdmaAddr {
            lo: u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]),
            hi: u32::from_le_bytes([desc[4], desc[5], desc[6], desc[7]]),
        },
        sgl1: GdmaAddr {
            lo: u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]),
            hi: u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]),
        },
    }
}

/// Maps a partition ID to a GDMA host interface selector.
///
/// `IFC_SLCT` names the AXI port that owns the buffer: the PCIe
/// memory-location id of the function (PF `0x10`, VF `n` `0x20 + n`).
/// Partition ids use the dense PcieFunction numbering, so widen before
/// selecting the port; an id naming no function is rejected rather than
/// widened into a port that would alias another function. A valid id never
/// yields 0, which selects device memory.
#[inline(always)]
fn host_interface(part_id: HsmPartId) -> HsmResult<MemInterface> {
    let pfn = u8::from(part_id);
    let ctrl_id = crate::pal::pfn_to_axi_id(pfn).ok_or(HsmError::InvalidArg)?;
    Ok(MemInterface::Host { ctrl_id })
}

/// Validates a raw 16-byte NVMe SGL descriptor naming a host buffer of
/// `len` payload bytes and returns the GDMA transfer length.
///
/// Used by the gather path ([`HsmGdmaController::copy_mem_from_host_raw`]).
pub(crate) fn raw_sgl_len(desc: &[u8; 16], len: usize) -> HsmResult<u32> {
    // The descriptor's type is the high nibble of its last byte; the
    // low nibble is `sub_type`.
    //
    // A Data Block names the payload directly, so its embedded
    // length is the transfer length and must match the destination
    // exactly. A Segment / Last Segment descriptor instead names a
    // run of descriptors for the engine to walk, so its length field
    // is a count of *descriptor* bytes and says nothing about the
    // payload — the transfer length is what the caller asked for,
    // and the engine gathers that many bytes by following the
    // segment. Treating a segment descriptor as a data block would
    // reject the transfer outright and, if forced through, move the
    // 16-byte descriptor instead of the item.
    let desc_len = sgl_desc_len(desc);
    match sgl_desc_type(desc) {
        SGL_TYPE_DATA_BLOCK => {
            if desc_len as usize != len {
                return Err(HsmError::InvalidArg);
            }
            Ok(desc_len)
        }
        ty @ (SGL_TYPE_SEGMENT | SGL_TYPE_LAST_SEGMENT) => {
            // The descriptor is forwarded to the engine verbatim, and
            // the engine uses `desc_len` to bound how many descriptor
            // bytes it walks. It comes from host memory, so validate
            // its shape here rather than letting a malformed value
            // send the engine reading past the segment page.
            if !sgl_segment_shape_ok(ty, desc_len) {
                return Err(HsmError::InvalidArg);
            }
            u32::try_from(len).map_err(|_| HsmError::InvalidArg)
        }
        _ => Err(HsmError::InvalidArg),
    }
}

/// NVMe SGL descriptor types (high nibble of byte 15; the low nibble
/// is `sub_type`).
const SGL_TYPE_DATA_BLOCK: u8 = 0x0;
const SGL_TYPE_SEGMENT: u8 = 0x2;
const SGL_TYPE_LAST_SEGMENT: u8 = 0x3;

/// One NVMe SGL descriptor on the wire.
const SGL_DESC_LEN: u32 = 16;
/// The driver backs every SGL segment with whole pages
/// (`coh_mem_sz = seg_cnt * PAGE_SIZE`, `tsra_dma_io.c`) and
/// rejects an item needing more than one page of descriptors, so
/// a segment can never legitimately exceed this.
const SGL_SEGMENT_MAX_LEN: u32 = 4096;

#[inline(always)]
fn sgl_desc_type(desc: &[u8; 16]) -> u8 {
    desc[15] >> 4
}

#[inline(always)]
fn sgl_desc_len(desc: &[u8; 16]) -> u32 {
    u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]])
}

#[inline(always)]
fn sgl_desc_addr(desc: &[u8; 16]) -> u64 {
    u64::from_le_bytes([
        desc[0], desc[1], desc[2], desc[3], desc[4], desc[5], desc[6], desc[7],
    ])
}

/// Validates the descriptor-byte length of a `SEGMENT` /
/// `LAST_SEGMENT` descriptor.
///
/// A `SEGMENT` needs at least two descriptors: its last one chains to
/// the next segment rather than describing data, so a
/// single-descriptor segment would carry no payload and leave the
/// walker following a chain pointer that is really the only entry.
fn sgl_segment_shape_ok(ty: u8, desc_len: u32) -> bool {
    let min_len = if ty == SGL_TYPE_SEGMENT {
        2 * SGL_DESC_LEN
    } else {
        SGL_DESC_LEN
    };
    desc_len >= min_len && desc_len <= SGL_SEGMENT_MAX_LEN && desc_len.is_multiple_of(SGL_DESC_LEN)
}

/// Firmware-side cursor over a host NVMe SGL.
///
/// [`copy_mem_from_host_raw`](HsmGdmaController::copy_mem_from_host_raw)
/// hands the root descriptor to
/// the GDMA engine, which always transfers from the *start* of the
/// list. Streaming algorithms (chunked AES-GCM / AES-XTS over payloads
/// larger than the per-IO DMA slot) need to resume mid-list, so this
/// cursor walks the descriptors itself and issues one GDMA per
/// contiguous host Data Block piece.
///
/// Supports a Data Block root and `SEGMENT` / `LAST_SEGMENT` chains.
/// Every chain descriptor is validated with the same rules as
/// [`raw_sgl_len`]; zero-length Data Blocks are rejected, so each
/// segment makes forward progress and a cyclic host list cannot spin
/// the walker forever.
pub(crate) struct HostSgl {
    /// Host address of the next byte in the current Data Block.
    blk_addr: u64,
    /// Bytes left in the current Data Block (clamped to `remaining`).
    blk_rem: u32,
    /// Host address of the next descriptor in the current segment.
    seg_addr: u64,
    /// Descriptor bytes left in the current segment.
    seg_rem: u32,
    /// `true` if the current segment may not chain to another one.
    seg_last: bool,
    /// Payload bytes not yet transferred.
    remaining: usize,
}

impl HostSgl {
    /// Opens a cursor over the `total`-byte host buffer named by `desc`.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `desc` is malformed (see
    ///   [`raw_sgl_len`]).
    pub(crate) fn new(desc: &[u8; 16], total: usize) -> HsmResult<Self> {
        raw_sgl_len(desc, total)?;
        let ty = sgl_desc_type(desc);
        let addr = sgl_desc_addr(desc);
        let len = sgl_desc_len(desc);
        let mut sgl = Self {
            blk_addr: 0,
            blk_rem: 0,
            seg_addr: 0,
            seg_rem: 0,
            seg_last: true,
            remaining: total,
        };
        if ty == SGL_TYPE_DATA_BLOCK {
            sgl.blk_addr = addr;
            sgl.blk_rem = core::cmp::min(len as usize, total) as u32;
        } else {
            sgl.seg_addr = addr;
            sgl.seg_rem = len;
            sgl.seg_last = ty == SGL_TYPE_LAST_SEGMENT;
        }
        Ok(sgl)
    }

    /// Reads the next Data Block descriptor from host memory into the
    /// cursor, following at most one segment chain per non-last
    /// segment. `scratch` must be at least 16 bytes.
    async fn next_block(
        &mut self,
        pal: &UnoHsmPal,
        io: &crate::UnoHsmIo,
        scratch: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let ifc = host_interface(io.pid())?;
        loop {
            if self.seg_rem == 0 {
                return Err(HsmError::InvalidArg);
            }
            let slot = &mut scratch[..SGL_DESC_LEN as usize];
            let src = host_sgl_block(self.seg_addr, SGL_DESC_LEN);
            let dst = device_dma_buf(slot.as_mut_ptr(), SGL_DESC_LEN);
            pal.gdma
                .copy_mem(
                    src,
                    ifc,
                    SGL_DESC_LEN,
                    dst,
                    MemInterface::Device,
                    SGL_DESC_LEN,
                )?
                .await?;
            self.seg_addr = self
                .seg_addr
                .checked_add(SGL_DESC_LEN as u64)
                .ok_or(HsmError::InvalidArg)?;
            self.seg_rem -= SGL_DESC_LEN;

            let mut d = [0u8; 16];
            d.copy_from_slice(&slot[..]);
            let len = sgl_desc_len(&d);
            match sgl_desc_type(&d) {
                SGL_TYPE_DATA_BLOCK => {
                    if len == 0 {
                        return Err(HsmError::InvalidArg);
                    }
                    self.blk_addr = sgl_desc_addr(&d);
                    self.blk_rem = core::cmp::min(len as usize, self.remaining) as u32;
                    return Ok(());
                }
                ty @ (SGL_TYPE_SEGMENT | SGL_TYPE_LAST_SEGMENT) => {
                    // A chain pointer is only legal as the final entry
                    // of a non-last segment.
                    if self.seg_last || self.seg_rem != 0 || !sgl_segment_shape_ok(ty, len) {
                        return Err(HsmError::InvalidArg);
                    }
                    self.seg_addr = sgl_desc_addr(&d);
                    self.seg_rem = len;
                    self.seg_last = ty == SGL_TYPE_LAST_SEGMENT;
                }
                _ => return Err(HsmError::InvalidArg),
            }
        }
    }

    /// Gathers the next `dst.len()` payload bytes from the host into
    /// `dst`. `scratch` (≥ 16 bytes) holds fetched descriptors.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if fewer than `dst.len()` bytes remain
    ///   or the host list is malformed.
    /// * Any GDMA error.
    pub(crate) async fn read_into(
        &mut self,
        pal: &UnoHsmPal,
        io: &crate::UnoHsmIo,
        scratch: &mut HsmDmaBuf,
        dst: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let n = dst.len();
        if n > self.remaining {
            return Err(HsmError::InvalidArg);
        }
        let ifc = host_interface(io.pid())?;
        let mut off = 0usize;
        while off < n {
            if self.blk_rem == 0 {
                self.next_block(pal, io, scratch).await?;
            }
            let piece = core::cmp::min(n - off, self.blk_rem as usize);
            let part = &mut dst[off..off + piece];
            let src = host_sgl_block(self.blk_addr, piece as u32);
            let dst_addr = device_dma_buf(part.as_mut_ptr(), piece as u32);
            pal.gdma
                .copy_mem(
                    src,
                    ifc,
                    piece as u32,
                    dst_addr,
                    MemInterface::Device,
                    piece as u32,
                )?
                .await?;
            self.advance(piece)?;
            off += piece;
        }
        Ok(())
    }

    /// Scatters `src` into the next `src.len()` payload bytes of the
    /// host buffer. `scratch` (≥ 16 bytes) holds fetched descriptors.
    ///
    /// # Errors
    /// Same as [`HostSgl::read_into`].
    pub(crate) async fn write_from(
        &mut self,
        pal: &UnoHsmPal,
        io: &crate::UnoHsmIo,
        scratch: &mut HsmDmaBuf,
        src: &HsmDmaBuf,
    ) -> HsmResult<()> {
        let n = src.len();
        if n > self.remaining {
            return Err(HsmError::InvalidArg);
        }
        let ifc = host_interface(io.pid())?;
        let mut off = 0usize;
        while off < n {
            if self.blk_rem == 0 {
                self.next_block(pal, io, scratch).await?;
            }
            // Host writes use a single-page PRP destination (the proven
            // `copy_mem_to_host` form); the GDMA does not honor an SGL
            // Data Block as a host *destination*. Split at 4 KiB host
            // page boundaries so `prp1` is never needed.
            let page_rem = HOST_PAGE_SIZE - (self.blk_addr & (HOST_PAGE_SIZE - 1));
            let piece = core::cmp::min(n - off, self.blk_rem as usize);
            let piece = core::cmp::min(piece as u64, page_rem) as usize;
            let part = &src[off..off + piece];
            let src_addr = device_dma_buf(part.as_ptr(), piece as u32);
            let dst = host_prp_page(self.blk_addr);
            pal.gdma
                .copy_mem(
                    src_addr,
                    MemInterface::Device,
                    piece as u32,
                    dst,
                    ifc,
                    piece as u32,
                )?
                .await?;
            self.advance(piece)?;
            off += piece;
        }
        Ok(())
    }

    fn advance(&mut self, n: usize) -> HsmResult<()> {
        self.blk_addr = self
            .blk_addr
            .checked_add(n as u64)
            .ok_or(HsmError::InvalidArg)?;
        self.blk_rem -= n as u32;
        self.remaining -= n;
        Ok(())
    }
}

/// Uno platform implementation of [`HsmGdmaController`].
impl HsmGdmaController for UnoHsmPal {
    async fn copy_mem(
        &self,
        _io: &Self::Io,
        src: &HsmDmaBuf,
        dst: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let src_addr = device_dma_buf(src.as_ptr(), src.len() as u32);
        let dst_addr = device_dma_buf(dst.as_mut_ptr(), dst.len() as u32);
        self.gdma
            .copy_mem(
                src_addr,
                MemInterface::Device,
                src.len() as u32,
                dst_addr,
                MemInterface::Device,
                dst.len() as u32,
            )?
            .await
    }

    /// Zero an HSM-local buffer.
    ///
    /// Wipes off-CPU with the GDMA engine via
    /// [`gdma_zero_region`](UnoHsmPal::gdma_zero_region), which copies from
    /// the read-as-zero `ZERO` window — GDMA has no fill/memset opcode,
    /// so a wipe is a device-to-device copy out of that region. Every
    /// [`HsmDmaBuf`] is GSRAM-backed by construction (the DTCM heap hands out
    /// plain `&mut [u8]`, never a `HsmDmaBuf`), so the destination is always
    /// GDMA-reachable.
    ///
    /// Falls back to volatile CPU writes if the engine has no free tag or the
    /// transfer fails, so the buffer is scrubbed either way; both paths use
    /// writes that cannot be optimized away.
    async fn zero_mem(&self, _io: &Self::Io, dst: &mut HsmDmaBuf) -> HsmResult<()> {
        let len = dst.len();
        if len == 0 {
            return Ok(());
        }
        if self.gdma_zero_region(dst.as_mut_ptr(), len).await.is_err() {
            // SAFETY: the exclusive buffer view covers this writable region.
            unsafe { cpu_zeroize(dst.as_mut_ptr(), len) };
        }
        Ok(())
    }

    async fn copy_mem_from_host(
        &self,
        io: &Self::Io,
        src: HsmDmaAddr,
        src2: HsmDmaAddr,
        dst: &mut HsmDmaBuf,
        prp: bool,
    ) -> HsmResult<()> {
        let len = dst.len() as u32;
        let src_addr = host_dma_buf(src, src2, prp);
        let dst_addr = device_dma_buf(dst.as_mut_ptr(), len);
        self.gdma
            .copy_mem(
                src_addr,
                host_interface(io.pid())?,
                len,
                dst_addr,
                MemInterface::Device,
                len,
            )?
            .await
    }

    async fn copy_mem_from_host_raw(
        &self,
        io: &Self::Io,
        desc: &[u8; 16],
        dst: &mut HsmDmaBuf,
        prp: bool,
    ) -> HsmResult<()> {
        // The GDMA consumes the descriptor and interprets its SGL
        // format, so this path is SGL-only.
        if prp {
            return Err(HsmError::UnsupportedCmd);
        }

        let len = raw_sgl_len(desc, dst.len())?;

        let src_addr = sgl_desc_buf(desc);
        let dst_addr = device_dma_buf(dst.as_mut_ptr(), len);
        self.gdma
            .copy_mem(
                src_addr,
                host_interface(io.pid())?,
                len,
                dst_addr,
                MemInterface::Device,
                len,
            )?
            .await
    }

    async fn copy_mem_to_host(
        &self,
        io: &Self::Io,
        src: &HsmDmaBuf,
        dst: HsmDmaAddr,
        dst2: HsmDmaAddr,
        prp: bool,
    ) -> HsmResult<()> {
        let len = src.len() as u32;
        let src_addr = device_dma_buf(src.as_ptr(), len);
        let dst_addr = host_dma_buf(dst, dst2, prp);
        self.gdma
            .copy_mem(
                src_addr,
                MemInterface::Device,
                len,
                dst_addr,
                host_interface(io.pid())?,
                len,
            )?
            .await
    }
}

impl UnoHsmPal {
    /// GDMA-zero a GDMA-reachable device region `[dst_ptr, dst_ptr + len)`.
    ///
    /// Copies zeros from the [`ZERO_BASE`] window, chunked to its
    /// [`ZERO_SIZE`] so an arbitrarily large region can be wiped with a
    /// fixed 16 KiB zero source. Both operands use the device
    /// interface. Only valid for GDMA-reachable memory (GSRAM); the M7 TCM
    /// is not on the GDMA fabric and must be wiped by the CPU.
    async fn gdma_zero_region(&self, dst_ptr: *mut u8, len: usize) -> HsmResult<()> {
        let mut off = 0usize;
        while off < len {
            let chunk = core::cmp::min(len - off, ZERO_SIZE as usize);
            let src = device_dma_buf(ZERO_BASE as *const u8, chunk as u32);
            // SAFETY: `off < len`, so `dst_ptr + off` stays within the
            // caller-provided `[dst_ptr, dst_ptr + len)` region.
            let dst = device_dma_buf(unsafe { dst_ptr.add(off) }, chunk as u32);
            self.gdma
                .copy_mem(
                    src,
                    MemInterface::Device,
                    chunk as u32,
                    dst,
                    MemInterface::Device,
                    chunk as u32,
                )?
                .await?;
            off += chunk;
        }
        Ok(())
    }

    /// Securely scrub both per-IO scratch buffers for `io_index`.
    ///
    /// Called on IO teardown so no key material from one IO survives into
    /// the next IO that reuses the slot. On Uno every crypto operand lives
    /// in these bump-allocated buffers (no heap), so wiping them is what
    /// protects private keys / plaintext — the CPU-visible arena is the
    /// only place they exist.
    ///
    /// The SRAM (DMA) buffer is wiped off-CPU with the GDMA engine; the DTCM
    /// (NonDma) buffer sits in the M7 TCM, which GDMA cannot reach, so it is
    /// wiped by the CPU. If the GDMA wipe fails (e.g. no free tags under
    /// heavy concurrency), the SRAM buffer is scrubbed by the CPU as a
    /// fallback so secrets are never left resident.
    ///
    /// Only each heap's *high-water* region is wiped, not its full capacity.
    /// The bump watermark rewinds on every scope exit, but the peak bounds
    /// every byte written since the previous scrub, and everything past it is
    /// already zero from that scrub. Measured over ~1.7k host IOs the DMA peak
    /// averaged ~933 B of the 16 KiB slot (max ~3.3 KiB). The slot is sized to
    /// `ZERO`, so even a full-capacity wipe is a single GDMA transfer.
    /// A heap that was never touched is skipped entirely.
    pub(crate) async fn scrub_io_slot(&self, io_index: u16) {
        let (dma_ptr, dma_len) = crate::alloc::io_slot_dma_dirty(self, io_index);
        if dma_len != 0 && self.gdma_zero_region(dma_ptr, dma_len).await.is_err() {
            // Surface the fallback: a persistent GDMA fault would otherwise
            // silently degrade every wipe into a CPU loop with no signal.
            // Logged via the trace facade (as the iic/oic drivers do for
            // unexpected conditions); compiled out when no trace backend is
            // selected. Correctness is unaffected — the CPU wipe below still
            // fully scrubs the buffer.
            warn!(
                "gdma",
                "SRAM scrub for slot {} fell back to CPU (GDMA wipe failed)", io_index
            );
            // SAFETY: `(dma_ptr, dma_len)` is a prefix of the slot's SRAM
            // buffer, valid for writes over its whole length.
            unsafe { cpu_zeroize(dma_ptr, dma_len) };
        }
        // DTCM (NonDma) heap — not GDMA-reachable, so wipe with the CPU.
        let (nd_ptr, nd_len) = crate::alloc::io_slot_nondma_dirty(self, io_index);
        // SAFETY: `(nd_ptr, nd_len)` is a prefix of the slot's DTCM buffer,
        // valid for writes over its whole length.
        unsafe { cpu_zeroize(nd_ptr, nd_len) };

        // Both heaps are now zero up to their peaks; drop the high-water marks
        // so the next scrub covers only writes made after this point.
        crate::alloc::clear_io_peak(self, io_index);
    }
}

/// Volatile CPU zeroization of `[ptr, ptr + len)` that the optimizer cannot
/// elide, via the vetted [`zeroize`] crate. Used for the M7 TCM (which GDMA
/// cannot reach) and as the GDMA-failure fallback for SRAM.
///
/// Zeroes the widest naturally-aligned element the region supports: an
/// 8-byte-aligned `u64` (QWORD) body, framed by a byte-wise head/tail for
/// any unaligned edges. `[u64]::zeroize()` lowers to 64-bit volatile stores
/// (a single `STRD`/64-bit AXI transfer on Cortex-M7), so it issues half as
/// many stores as a 32-bit wipe and a quarter of a byte-wise one.
///
/// The **head** is normally empty: callers pass a per-IO region base, and
/// both regions are 8-byte aligned (`DTCM_IO_BUF` 0x600, `SRAM_IO_BUF`
/// 0x4000). The **tail** is not — `len` is the heap's dirty high-water
/// mark, not the region size, and the bump allocator aligns to each
/// value's `align_of`, so a watermark that is not a multiple of 8 is the
/// normal case and the tail path runs routinely.
///
/// `zeroize` emits the volatile writes plus a compiler+atomic fence, so
/// the wipe cannot be elided.
///
/// # Safety
///
/// `ptr` must be valid for writes of `len` bytes.
#[inline]
unsafe fn cpu_zeroize(ptr: *mut u8, len: usize) {
    // Byte-wise head up to the first 8-byte boundary (empty when the
    // caller passes an 8-aligned region base, which is the normal case).
    let head = ((8 - (ptr as usize & 7)) & 7).min(len);
    if head != 0 {
        // SAFETY: `head <= len`, so this stays within the caller's region.
        unsafe { core::slice::from_raw_parts_mut(ptr, head) }.zeroize();
    }
    // QWORD body: a whole number of `u64`s at an 8-byte-aligned address.
    let body_len = (len - head) & !7usize;
    if body_len != 0 {
        // SAFETY: `ptr + head` is 8-byte aligned by construction and
        // `body_len` is a `u64` multiple within the region, so the cast and
        // slice are valid for writes.
        let body_ptr = unsafe { ptr.add(head) } as *mut u64;
        // SAFETY: body_ptr is aligned and body_len bytes remain within the exclusive region.
        let body = unsafe { core::slice::from_raw_parts_mut(body_ptr, body_len / 8) };
        body.zeroize();
    }
    // Byte-wise tail (sub-`u64` remainder). Unlike the head this is
    // common: `len` is the dirty high-water mark, not the region size.
    let tail_off = head + body_len;
    if tail_off < len {
        // SAFETY: `tail_off < len`, so `ptr + tail_off` is within the region.
        unsafe { core::slice::from_raw_parts_mut(ptr.add(tail_off), len - tail_off) }.zeroize();
    }
}
