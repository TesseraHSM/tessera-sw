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
//! | Helper               | Source interface | Destination interface |
//! |----------------------|------------------|-----------------------|
//! | `copy_mem`           | Device           | Device                |
//! | `copy_mem_from_host` | Host             | Device                |
//! | `copy_mem_to_host`   | Device           | Host                  |

use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmCqe;
use tsra_fw_hsm_pal_traits::HsmDmaAddr;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmGdmaController;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmPartId;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::ReplyError;
use tsra_fw_uno_drivers_gdma::GdmaAddr;
use tsra_fw_uno_drivers_gdma::GdmaBuf;
use tsra_fw_uno_drivers_gdma::MemInterface;
use tsra_fw_uno_reg_soc::zero::ZERO_BASE;
use tsra_fw_uno_reg_soc::zero::ZERO_SIZE;
use tsra_fw_uno_trace::tracing::*;
use zeroize::Zeroize;

use crate::UnoHsmIo;
use crate::UnoHsmPal;
use crate::alloc::IO_SLOTS;

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
    let ctrl_id = crate::pal::pfn_to_axi_id(u8::from(part_id)).ok_or(HsmError::InvalidArg)?;
    Ok(MemInterface::Host { ctrl_id })
}

/// Uno platform implementation of [`HsmGdmaController`].
impl HsmGdmaController for UnoHsmPal {
    async fn copy_mem(&self, _io: &impl HsmIo, src: &DmaBuf, dst: &mut DmaBuf) -> HsmResult<()> {
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
    /// [`DmaBuf`] is GSRAM-backed by construction (the DTCM heap hands out
    /// plain `&mut [u8]`, never a `DmaBuf`), so the destination is always
    /// GDMA-reachable.
    ///
    /// Falls back to [`DmaBuf::zeroize`] if the engine has no free tag or the
    /// transfer fails, so the buffer is scrubbed either way; both paths use
    /// writes that cannot be optimized away.
    async fn zeroize_mem(&self, _io: &impl HsmIo, dst: &mut DmaBuf) -> HsmResult<()> {
        let len = dst.len();
        if len == 0 {
            return Ok(());
        }
        if self.gdma_zero_region(dst.as_mut_ptr(), len).await.is_err() {
            dst.zeroize();
        }
        Ok(())
    }

    async fn copy_mem_from_host(
        &self,
        io: &impl HsmIo,
        src: HsmDmaAddr,
        src2: HsmDmaAddr,
        dst: &mut DmaBuf,
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
        io: &impl HsmIo,
        desc: &[u8; 16],
        dst: &mut DmaBuf,
        prp: bool,
    ) -> HsmResult<()> {
        // The GDMA consumes the descriptor and interprets its SGL
        // format, so this path is SGL-only.
        if prp {
            return Err(HsmError::UnsupportedCmd);
        }

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

        let desc_len = u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]);
        let len = match desc[15] >> 4 {
            SGL_TYPE_DATA_BLOCK => {
                if desc_len as usize != dst.len() {
                    return Err(HsmError::InvalidArg);
                }
                desc_len
            }
            ty @ (SGL_TYPE_SEGMENT | SGL_TYPE_LAST_SEGMENT) => {
                // The descriptor is forwarded to the engine verbatim, and
                // the engine uses `desc_len` to bound how many descriptor
                // bytes it walks. It comes from host memory, so validate
                // its shape here rather than letting a malformed value
                // send the engine reading past the segment page.
                //
                // A `SEGMENT` needs at least two descriptors: its last one
                // chains to the next segment rather than describing data,
                // so a single-descriptor segment would carry no payload
                // and leave the engine following a chain pointer that is
                // really the only entry.
                let min_len = if ty == SGL_TYPE_SEGMENT {
                    2 * SGL_DESC_LEN
                } else {
                    SGL_DESC_LEN
                };
                if desc_len < min_len
                    || desc_len > SGL_SEGMENT_MAX_LEN
                    || !desc_len.is_multiple_of(SGL_DESC_LEN)
                {
                    return Err(HsmError::InvalidArg);
                }
                u32::try_from(dst.len()).map_err(|_| HsmError::InvalidArg)?
            }
            _ => return Err(HsmError::InvalidArg),
        };

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
        io: &impl HsmIo,
        src: &DmaBuf,
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
    /// [`HsmPal::reply_io`](tsra_fw_hsm_pal_traits::HsmPal::reply_io): the
    /// response copy is linked to the CQE post, which
    /// [`wake_gdma`](Self::wake_gdma) starts the moment the copy lands, so
    /// the IO's task is woken once, by the post's completion.
    pub(crate) async fn reply_linked(
        &self,
        io: &mut UnoHsmIo,
        resp: &DmaBuf,
        dst: HsmDmaAddr,
        dst2: HsmDmaAddr,
        prp: bool,
    ) -> Result<(), ReplyError> {
        let len = resp.len() as u32;
        let link = u32::from(io.index()) | u32::from(io.queue_id() as u8) << 16;
        let posted = self
            .gdma
            .copy_mem_linked(
                device_dma_buf(resp.as_ptr(), len),
                MemInterface::Device,
                len,
                host_dma_buf(dst, dst2, prp),
                host_interface(io.pid()).map_err(ReplyError::Copy)?,
                len,
                link,
            )
            .map_err(ReplyError::Copy)?
            .await
            .map_err(ReplyError::Copy)?;
        match posted {
            Some(tag) => self.oic.wait_send(tag).await,
            // The post could not start then (no free tag or a full ring):
            // post it now.
            None => self.complete_io(io).await,
        }
        .map_err(ReplyError::Complete)
    }

    /// [`HsmPal::finish_io`](tsra_fw_hsm_pal_traits::HsmPal::finish_io):
    /// the response copy is linked to the CQE post as in
    /// [`reply_linked`](Self::reply_linked), but no task awaits either:
    /// [`wake_gdma`](Self::wake_gdma) starts the post (of `copy_failed`
    /// if the copy failed), and [`wake_oic`](Self::wake_oic) drops the IO
    /// once it is done. Declines an IO whose dirty SRAM is too large for
    /// the CPU to scrub, as the drop cannot wait for the GDMA.
    pub(crate) fn reply_detached(
        &self,
        io: UnoHsmIo,
        resp: &DmaBuf,
        dst: HsmDmaAddr,
        dst2: HsmDmaAddr,
        prp: bool,
        copy_failed: fn(&mut HsmCqe),
    ) -> Result<(), UnoHsmIo> {
        let index = usize::from(io.index());
        if index >= IO_SLOTS || crate::alloc::io_slot_dma_dirty(self, io.index()).1 > CPU_SCRUB_MAX
        {
            return Err(io);
        }
        let Ok(ifc) = host_interface(io.pid()) else {
            return Err(io);
        };
        let queue_id = io.queue_id() as u8;
        self.detached.with(|d| {
            d.copy_failed[index] = copy_failed;
            d.queue[index] = queue_id;
        });
        let len = resp.len() as u32;
        let link = u32::from(io.index()) | u32::from(queue_id) << 16;
        match self.gdma.copy_mem_detached(
            device_dma_buf(resp.as_ptr(), len),
            MemInterface::Device,
            len,
            host_dma_buf(dst, dst2, prp),
            ifc,
            len,
            link,
        ) {
            Ok(()) => Ok(()),
            Err(_) => Err(io),
        }
    }

    /// GDMA completion handler: wakes each finished copy's task, first
    /// posting the CQE of each reply whose response has just landed (see
    /// [`reply_linked`](Self::reply_linked) and
    /// [`reply_detached`](Self::reply_detached)).
    pub(crate) fn wake_gdma(&self, irq: u16) {
        self.gdma.wake_with(
            irq,
            |link, waker| {
                self.oic
                    .start_send(link as u16, (link >> 16) as u8, waker)
                    .ok()
            },
            |link, copied| self.post_detached(link as u16, (link >> 16) as u8, copied),
        );
    }

    /// The response copy of the detached reply of IO slot `index` is done:
    /// post its CQE, first made to report the copy's failure if it failed.
    /// A post that cannot start now (no OIC tag or ring room) is retried by
    /// [`retry_detached`](Self::retry_detached).
    fn post_detached(&self, index: u16, queue_id: u8, copied: bool) {
        if !copied {
            let mark = self.detached.with(|d| d.copy_failed[usize::from(index)]);
            crate::io::update_cqe(index, mark);
        }
        if self.oic.send_detached(index, queue_id).is_err() {
            self.detached.with(|d| d.unposted |= 1 << index);
        }
    }

    /// Starts the detached posts [`post_detached`](Self::post_detached)
    /// could not, now that the OIC may have room. One DTCM read when there
    /// are none.
    pub(crate) fn retry_detached(&self) {
        let mut unposted = self.detached.with(|d| d.unposted);
        while unposted != 0 {
            let index = unposted.trailing_zeros() as u16;
            unposted &= unposted - 1;
            let queue_id = self.detached.with(|d| d.queue[usize::from(index)]);
            if self.oic.send_detached(index, queue_id).is_ok() {
                self.detached.with(|d| d.unposted &= !(1 << index));
            }
        }
    }

    /// OIC completion handler: wakes each finished post's task, and drops
    /// each detached IO whose CQE is now posted, as
    /// [`drop_io`](HsmIoController::drop_io) would.
    pub(crate) fn wake_oic(&self, irq: u16) {
        self.oic.wake_with(irq, |index, queue_id| {
            self.scrub_io_slot_cpu(index);
            self.iic.free_io(index, u16::from(queue_id));
        });
    }

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
    /// The SRAM (DMA) buffer is wiped off-CPU with the GDMA engine unless
    /// its dirty region is at most [`CPU_SCRUB_MAX`] bytes; the DTCM
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
        if dma_len != 0 && dma_len <= CPU_SCRUB_MAX {
            // SAFETY: `(dma_ptr, dma_len)` is a prefix of the slot's SRAM
            // buffer, valid for writes over its whole length.
            unsafe { cpu_zeroize(dma_ptr, dma_len) };
        } else if dma_len != 0 && self.gdma_zero_region(dma_ptr, dma_len).await.is_err() {
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

impl UnoHsmPal {
    /// [`scrub_io_slot`](Self::scrub_io_slot) all by the CPU, so nothing to
    /// await; meant for a slot whose dirty SRAM is at most
    /// [`CPU_SCRUB_MAX`].
    fn scrub_io_slot_cpu(&self, io_index: u16) {
        let (dma_ptr, dma_len) = crate::alloc::io_slot_dma_dirty(self, io_index);
        // SAFETY: `(dma_ptr, dma_len)` is a prefix of the slot's SRAM
        // buffer, valid for writes over its whole length.
        unsafe { cpu_zeroize(dma_ptr, dma_len) };
        let (nd_ptr, nd_len) = crate::alloc::io_slot_nondma_dirty(self, io_index);
        // SAFETY: `(nd_ptr, nd_len)` is a prefix of the slot's DTCM buffer,
        // valid for writes over its whole length.
        unsafe { cpu_zeroize(nd_ptr, nd_len) };
        crate::alloc::clear_io_peak(self, io_index);
    }
}

/// SRAM scrubs of at most this many bytes are done by the CPU: its stores
/// to SRAM are posted (about a cycle each), so a small wipe costs less CPU
/// than submitting a GDMA transfer and handling its completion, which also
/// costs the IO another poll. Most IOs' dirty region is well under this
/// (a 1 KiB AES-CBC request's is about 2.4 KiB); larger ones go to the
/// GDMA.
const CPU_SCRUB_MAX: usize = 4096;

/// Volatile CPU zeroization of `[ptr, ptr + len)` that the optimizer cannot
/// elide, via the vetted [`zeroize`] crate. Used for the M7 TCM (which GDMA
/// cannot reach), small SRAM scrubs, and as the GDMA-failure fallback for
/// SRAM.
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
