// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno I/O controller — bridges IIC/OIC drivers to HSM IO traits.
//!
//! Implements [`HsmIoController`] and [`HsmIo`] for the Uno SoC by
//! mapping the IIC driver's submission/completion queues to the
//! platform-agnostic HSM I/O traits.
//!
//! # Memory regions
//!
//! Each IO slot `index` has four associated regions in the IO GSRAM
//! address map:
//!
//! | Region          | Array             | Purpose                              |
//! |-----------------|-------------------|--------------------------------------|
//! | `IO_SQ[index]`  | 64B SQE           | Submission queue entry (read-only)   |
//! | `IO_CQ[index]`  | 16B CQE           | Completion queue entry (write)       |
//! | `IO_META[index]` | 8B metadata      | Controller/queue IDs from IIC recv   |
//! | `DTCM_IO_BUF[index]` | 1.5KB fmem   | Fast DTCM workspace buffer           |
//! | `SRAM_IO_BUF[index]` | 16KB smem    | Large SRAM workspace buffer          |
//!
//! The IIC controller DMAs incoming SQE data directly into `IO_SQ[index]`
//! (configured via `io_pool_base`). The firmware reads the SQE in-place
//! and writes the CQE into `IO_CQ[index]` for OIC to transmit.

use core::cell::Cell;
use core::cell::UnsafeCell;
use core::mem;
use core::ops::AsyncFnOnce;

use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;
use tsra_fw_hsm_io::CqeEntry;
use tsra_fw_hsm_io::OOB_ENTRY_LEN;
use tsra_fw_hsm_io::OP_TBOR;
use tsra_fw_hsm_io::RawCqe;
use tsra_fw_hsm_io::RawSqe;
use tsra_fw_hsm_io::SqeEntry;
use tsra_fw_hsm_io::oob_entry_addr;
use tsra_fw_hsm_io::sealed;
use tsra_fw_hsm_io::validate_io_fields;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmCqe;
use tsra_fw_hsm_pal_traits::HsmDmaAddr;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmGdmaController;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmIoTypes;
use tsra_fw_hsm_pal_traits::HsmRequest;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSqe;
use tsra_fw_static_ref::StaticRef;
use tsra_fw_uno_drivers_gdma::MemInterface;
use tsra_fw_uno_drivers_iic::Received;
use tsra_fw_uno_drivers_part_store::HsmPartId;
use tsra_fw_uno_reg_soc::io_gsram::IO_CQ_COUNT;
use tsra_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;
use tsra_fw_uno_reg_soc::io_gsram::IO_META_COUNT;
use tsra_fw_uno_reg_soc::io_gsram::IO_META_CTLR;
use tsra_fw_uno_reg_soc::io_gsram::IO_META_QUEUE;
use tsra_fw_uno_reg_soc::io_gsram::IO_SQ_COUNT;
use tsra_fw_uno_reg_soc::io_gsram::IoCqEntry;
use tsra_fw_uno_reg_soc::io_gsram::IoSqEntry;
use tsra_fw_uno_reg_soc::io_gsram::regs::IoGsramRegs;
use tsra_fw_uno_trace::tracing::*;

use crate::UnoHsmPal;
use crate::alloc::ADMIN_IO_INDEX;
use crate::alloc::SELF_TEST_IO_INDEX;
use crate::alloc::UnoScopedAlloc;
use crate::alloc::reset_io_alloc;

/// Typed overlay of the IO GSRAM region.
// SAFETY: IO_GSRAM_BASE is the aligned, permanently mapped IO queue region.
const IO_Q: StaticRef<IoGsramRegs> = unsafe { StaticRef::new(IO_GSRAM_BASE as *const IoGsramRegs) };

/// Each host IO slot's SQE, copied out of `IO_SQ` when its IO is accepted.
///
/// The SQE's fields are read many times per IO, and IO GSRAM is read
/// uncached: a load costs the interconnect's full latency, while two
/// eight-word bursts fetch the whole 64-byte entry for about the price of
/// two loads. The hardware writes `IO_SQ[index]` only while the slot is
/// free, so the copy stays valid until the IO is dropped.
struct SqeCopies(UnsafeCell<[SqeEntry; IO_SQ_COUNT as usize]>);

// SAFETY: single-core firmware with cooperative scheduling; a slot's copy
// is written only by `accept_io`, before its IO exists, and read only
// through that IO.
unsafe impl Sync for SqeCopies {}

static SQE_COPIES: SqeCopies =
    SqeCopies(UnsafeCell::new([SqeEntry([0; 16]); IO_SQ_COUNT as usize]));

/// Copies host slot `index`'s SQE out of `IO_SQ` with two eight-word bursts.
fn copy_sqe(index: usize) {
    let src = &IO_Q.io_sq[index] as *const IoSqEntry as *const u32;
    // SAFETY: `index` is a host slot, so its copy exists; nothing else
    // borrows it while the slot is free (see `SqeCopies`).
    let dst = unsafe { (*SQE_COPIES.0.get())[index].0.as_mut_ptr() };
    #[cfg(target_arch = "arm")]
    // SAFETY: both are 64-byte, word-aligned SQEs: the IO_SQ entry and its
    // DTCM copy.
    unsafe {
        core::arch::asm!(
            "ldm {s}!, {{r2, r3, r4, r5, r8, r9, r10, r11}}",
            "stm {d}!, {{r2, r3, r4, r5, r8, r9, r10, r11}}",
            "ldm {s}!, {{r2, r3, r4, r5, r8, r9, r10, r11}}",
            "stm {d}!, {{r2, r3, r4, r5, r8, r9, r10, r11}}",
            s = inout(reg) src => _,
            d = inout(reg) dst => _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(target_arch = "arm"))]
    // SAFETY: as above.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, 16);
    }
}

/// Each host IO slot's CQE, built here while its IO runs and written out to
/// `IO_CQ` whole, with one burst, by [`publish_cqe`] just before the OIC
/// posts it.
///
/// The CQE is filled in field by field (status, lengths, session fields,
/// queue id), and IO GSRAM is read uncached: in place, each update would
/// first read its word back over the interconnect.
struct CqeCopies(UnsafeCell<[CqeEntry; IO_CQ_COUNT as usize]>);

// SAFETY: single-core firmware with cooperative scheduling; a slot's copy
// is touched only by its IO, or by the platform finishing it once detached.
unsafe impl Sync for CqeCopies {}

static CQE_COPIES: CqeCopies = CqeCopies(UnsafeCell::new([CqeEntry([0; 4]); IO_CQ_COUNT as usize]));

/// Writes host slot `index`'s CQE out to `IO_CQ`, where the OIC reads it.
/// The OIC orders its descriptor writes, and so this one, ahead of its
/// doorbell.
fn publish_cqe(index: u16) {
    const { assert!(mem::size_of::<IoCqEntry>() == 16) };
    // SAFETY: indexing checks `index` is a host slot; only a pointer is
    // formed, no reference to the copy (see `CqeCopies`).
    let src = unsafe { (*CQE_COPIES.0.get())[index as usize].0.as_ptr() };
    let dst = core::ptr::addr_of!(IO_Q.io_cq[index as usize]) as *mut u32;
    #[cfg(target_arch = "arm")]
    // SAFETY: both are 16-byte, word-aligned CQEs: the DTCM copy and its
    // IO_CQ entry, which only this slot's completion uses.
    unsafe {
        core::arch::asm!(
            "ldm {s}, {{r2, r3, r4, r5}}",
            "stm {d}, {{r2, r3, r4, r5}}",
            s = in(reg) src,
            d = in(reg) dst,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(target_arch = "arm"))]
    // SAFETY: as above.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, 4);
    }
}

/// An in-flight IO identified by its IO_SQ slot index.
///
/// Holds the slot index for the lifetime of a single IO operation.
/// Metadata (controller_id, queue_id, queue_index) is stored in
/// `IO_META[index]`, written by the IIC driver at recv time; the IO reads
/// the partition and queue it needs from there once, when it is created,
/// since IO GSRAM is read uncached and both are wanted many times per IO.
#[derive(Debug)]
pub struct UnoHsmIo {
    /// IO_SQ slot index. Host IO uses `0..ADMIN_IO_INDEX`; the reserved
    /// admin slot (`ADMIN_IO_INDEX`, the last of `IO_SLOTS`) is used only
    /// for PAL-internal provisioning crypto. So the valid range is
    /// `0..=ADMIN_IO_INDEX`, not just the host range.
    index: u16,
    /// Partition the IO targets, from `IO_META[index]` (see [`Self::pid`]).
    pid: HsmPartId,
    /// Source queue, from `IO_META[index]` (see [`Self::queue_id`]).
    queue_id: u16,
    transport_binding: Cell<Option<sealed::SessionTransportBinding>>,
}

/// How the run loop brought an IO's request in ahead of the IO's task (see
/// [`Stage::Received`]).
pub(crate) enum RequestIn {
    /// Copied into the exchange buffer.
    Copied,
    /// The copy failed.
    Failed,
}

/// Takes a host IO the run loop received (see
/// [`UnoHsmPal::set_io_dispatch`]) to the task that serves its slot. It runs
/// inside the run loop's pass, so it must hand the IO on without waiting.
pub type IoDispatch = fn(UnoHsmIo);

impl UnoHsmIo {
    /// Returns the platform-private resource slot for this IO.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Returns the queue ID read from IO_META when the IO was created.
    fn queue_id(&self) -> u16 {
        self.queue_id
    }

    /// An IO over slot `index`, taking its partition and queue from the
    /// slot's `IO_META` entry.
    fn from_meta(index: u16) -> Self {
        if index as u32 >= IO_META_COUNT {
            return Self {
                index,
                pid: HsmPartId::from(crate::pal::NO_PARTITION),
                queue_id: 0,
                transport_binding: Cell::new(None),
            };
        }
        let meta = &IO_Q.io_meta[index as usize];
        Self::from_routing(
            index,
            meta.ctlr.read(IO_META_CTLR::CONTROLLER_ID) as u8,
            meta.queue.read(IO_META_QUEUE::QUEUE_ID) as u16,
        )
    }

    /// An IO over slot `index` from source controller `axi_id`'s queue
    /// `queue_id`.
    fn from_routing(index: u16, axi_id: u8, queue_id: u16) -> Self {
        Self {
            index,
            // The hardware reports the routing axi_id; partitions are
            // indexed by the dense PcieFunction id, so translate here. An
            // axi_id naming no function yields an out-of-range id, which
            // the partition lookup rejects with `InvalidArg` rather than
            // aliasing a valid slot.
            pid: HsmPartId::from(
                crate::pal::axi_id_to_pfn(axi_id).unwrap_or(crate::pal::NO_PARTITION),
            ),
            queue_id,
            transport_binding: Cell::new(None),
        }
    }

    /// Constructs a **bare, unscrubbed** IO handle over the dedicated admin
    /// slot ([`ADMIN_IO_INDEX`]), targeting partition `pid`.
    ///
    /// Internal provisioning (partition identity and enable-time keygen)
    /// runs without a host IO. Reusing the concrete [`UnoHsmIo`] /
    /// [`UnoScopedAlloc`] types — rather than a bespoke admin IO type —
    /// avoids re-monomorphizing the generic vault / crypto / DMA paths.
    /// The target `pid` is written into the admin slot's `IO_META` so
    /// [`pid`](Self::pid) resolves correctly.
    ///
    /// # Prefer [`with_admin_io`](UnoHsmPal::with_admin_io)
    ///
    /// This constructor performs **no scrub**: anything the caller writes to
    /// the admin slot's bump heaps stays resident until some later scrub.
    /// Its only caller is [`with_admin_io`](UnoHsmPal::with_admin_io), which
    /// wipes the slot on completion. The admin slot's `IO_META` is shared, so
    /// it must only be written from the IPC task that runs admin sessions
    /// sequentially; a host-IO path must use its own IO instead. The name is
    /// deliberately blunt so a new call site has to opt into the hazard
    /// explicitly.
    ///
    /// [`ADMIN_IO_INDEX`]: crate::alloc::ADMIN_IO_INDEX
    /// [`UnoScopedAlloc`]: crate::alloc::UnoScopedAlloc
    pub(crate) fn admin_no_scrub(pid: HsmPartId) -> Self {
        // CONTROLLER_ID holds the hardware axi_id (what IIC `recv` records for
        // a host IO), so an internally created admin IO stores the same
        // encoding for `pid()` to round-trip it back to `pid`.
        let axi_id = crate::pal::pfn_to_axi_id(u8::from(pid)).unwrap_or(crate::pal::NO_PARTITION);
        IO_Q.io_meta[ADMIN_IO_INDEX as usize]
            .ctlr
            .write(IO_META_CTLR::CONTROLLER_ID.val(axi_id as u32));
        Self::from_meta(ADMIN_IO_INDEX)
    }

    /// Constructs an IO handle over the dedicated self-test slot
    /// ([`SELF_TEST_IO_INDEX`]).
    ///
    /// Used by the cryptographic algorithm self-tests (CAST), which run
    /// without a host IO. KAT operands are allocated from this slot's
    /// `SRAM_IO_BUF` via the bump allocator. No partition context applies,
    /// so `IO_META` is left untouched ([`pid`](HsmIo::pid) is unused by the
    /// self-test path).
    ///
    /// # Restrictions
    ///
    /// This handle is for DMA allocation only. Its index ([`SELF_TEST_IO_INDEX`]) is outside the
    /// host queue ranges (`IO_SQ_COUNT`/`IO_CQ_COUNT`/`IO_META_COUNT`), so
    /// [`sqe`](HsmIo::sqe) and [`cqe`](HsmIo::cqe) have no backing entry and must not be
    /// called on it; the host-IO dispatch that reads them never runs for the self-test.
    ///
    /// [`SELF_TEST_IO_INDEX`]: crate::alloc::SELF_TEST_IO_INDEX
    pub(crate) fn self_test() -> Self {
        Self::from_meta(SELF_TEST_IO_INDEX)
    }

    /// Returns the partition ID for this IO, resolved from the axi_id in
    /// IO_META when the IO was created (see [`from_meta`](Self::from_meta)).
    ///
    /// The self-test slot ([`SELF_TEST_IO_INDEX`]) has no `IO_META` entry or
    /// partition context, so it returns the invalid `NO_PARTITION` sentinel
    /// rather than aliasing a real partition or indexing `IO_META`.
    pub(crate) fn pid(&self) -> HsmPartId {
        self.pid
    }
}

impl HsmIo for UnoHsmIo {
    type Sqe = SqeEntry;
    type Cqe = CqeEntry;

    /// Returns the SQE from `IO_SQ[index]`.
    ///
    /// IIC DMAs the host-side 64-byte SQE into `IO_SQ[index]`; a host IO
    /// reads the copy [`accept_io`](UnoHsmPal::accept_io) took of it.
    fn sqe(&self) -> &SqeEntry {
        const _ASSERT_SQE_SIZE: () =
            assert!(mem::size_of::<IoSqEntry>() == mem::size_of::<RawSqe>());
        const _ASSERT_SQE_ALIGN: () =
            assert!(mem::align_of::<IoSqEntry>() == mem::align_of::<RawSqe>());

        if (self.index as u32) < IO_SQ_COUNT {
            // SAFETY: `accept_io` filled this host slot's copy before the IO
            // existed, and it is not written again while the IO lives.
            return unsafe { &(*SQE_COPIES.0.get())[self.index as usize] };
        }
        let io_sq = &IO_Q.io_sq[self.index as usize];
        // SAFETY: The queue entry and RawSqe (and so the transparent
        // SqeEntry) share the asserted layout; this IO owns the slot.
        unsafe { &*(io_sq as *const IoSqEntry as *const SqeEntry) }
    }

    /// Returns a mutable reference to the slot's CQE, its DTCM copy (see
    /// [`CqeCopies`]): the HSM core writes completion status there, and the
    /// copy goes out to `IO_CQ[index]`, where the OIC driver reads it, when
    /// the completion is posted.
    fn cqe(&mut self) -> &mut CqeEntry {
        const _ASSERT_CQE_SIZE: () =
            assert!(mem::size_of::<IoCqEntry>() == mem::size_of::<RawCqe>());
        const _ASSERT_CQE_ALIGN: () =
            assert!(mem::align_of::<IoCqEntry>() == mem::align_of::<RawCqe>());

        slot_cqe(self.index)
    }
}

impl HsmIoTypes for UnoHsmPal {
    type Io = UnoHsmIo;
}

impl HsmIoController for UnoHsmPal {
    /// Awaits the next inbound IO from the IIC driver.
    ///
    /// Every IO handed out is counted in flight until
    /// [`drop_io`](HsmIoController::drop_io) returns its slot.
    async fn poll_io(&self) -> HsmResult<Self::Io> {
        loop {
            let io = self.accept_io(self.iic.recv().await);
            if !self.io_paused() {
                return Ok(io);
            }
            self.recycle_reset_io(io).await;
        }
    }

    /// Posts the completion (CQE) to the host via OIC.
    ///
    /// Posts the CQE only; the IO_SQ slot is returned to the ISQ
    /// separately by [`drop_io`](HsmIoController::drop_io) so the caller
    /// can run post-completion work over `io` first.
    async fn recv_request(&self, io: &UnoHsmIo) -> HsmResult<HsmRequest<'_>> {
        let plan = RequestPlan::of(io)?;
        let control = io.sqe().session_ctrl();
        let (len, headroom) = (plan.len, plan.headroom);
        let mut buf = match self.take_request_in(io) {
            None => {
                let mut buf = self.dma_alloc_exchange(io, plan.exchange_len())?;
                self.copy_mem_from_host(
                    io,
                    plan.src.0,
                    plan.src.1,
                    &mut buf.buffer_mut()[headroom..headroom + len],
                    true,
                )
                .await
                .map_err(|_| HsmError::FailedToStartDmaTransaction)?;
                buf
            }
            Some(RequestIn::Copied) => {
                crate::alloc::prefetched_exchange(self, io.index, plan.exchange_len())?
            }
            Some(RequestIn::Failed) => return Err(HsmError::FailedToStartDmaTransaction),
        };
        let resp_capacity = plan.resp_capacity;
        let Some(id) = plan.sealed_id else {
            return Ok(HsmRequest {
                buf,
                len,
                resp_capacity,
            });
        };
        let (len, binding) = sealed::sealed_open(
            self,
            io,
            id,
            control,
            &mut buf.buffer_mut()[..headroom + len],
        )
        .await?;
        io.transport_binding.set(Some(binding));
        let buf = buf.skip_prefix(headroom)?;
        Ok(HsmRequest {
            buf,
            len,
            resp_capacity: sealed::sealed_msg_capacity(resp_capacity),
        })
    }

    /// Copies the response to the host, sealing an in-session TBOR one
    /// (see [`sealed`]) and setting the CQE length to the frame's.
    async fn send_response(&self, io: &mut UnoHsmIo, resp: &HsmDmaBuf) -> HsmResult<()> {
        let resp = match sealed::sealed_session(io.sqe())? {
            Some(id) => {
                let binding = io
                    .transport_binding
                    .take()
                    .ok_or(HsmError::SessionTransportError)?;
                let frame = sealed::sealed_seal(self, io, id, binding, resp).await?;
                let frame_len = u16::try_from(frame.len()).map_err(|_| HsmError::InvalidArg)?;
                io.cqe().view().set_dst_len(frame_len);
                frame
            }
            None => resp,
        };
        let sqe = io.sqe().view();
        if resp.len() > sqe.dst_len() as usize {
            return Err(HsmError::InvalidArg);
        }
        self.copy_mem_to_host(io, resp, sqe.dst_prp1(), sqe.dst_prp2(), true)
            .await
            .map_err(|_| HsmError::FailedToStartDmaTransaction)
    }

    async fn recv_oob(&self, io: &UnoHsmIo, index: usize, dst: &mut HsmDmaBuf) -> HsmResult<()> {
        let desc = self.oob_desc(io, index).await?;
        self.copy_mem_from_host_raw(io, &desc, dst, false).await
    }

    /// Writes `src` to the host buffer of OOB descriptor `index`, which
    /// must be an SGL Data Block of exactly `src.len()` bytes.
    async fn send_oob(&self, io: &UnoHsmIo, index: usize, src: &HsmDmaBuf) -> HsmResult<()> {
        const SGL_TYPE_DATA_BLOCK: u8 = 0x0;

        let desc = self.oob_desc(io, index).await?;
        let len = u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]);
        if desc[15] >> 4 != SGL_TYPE_DATA_BLOCK || len as usize != src.len() {
            return Err(HsmError::InvalidArg);
        }
        self.gdma
            .copy_mem(
                crate::gdma::device_dma_buf(src.as_ptr(), len),
                MemInterface::Device,
                len,
                crate::gdma::sgl_desc_buf(&desc),
                crate::gdma::host_interface(io.pid())?,
                len,
            )?
            .await
    }

    async fn complete_io(&self, io: &mut Self::Io) -> HsmResult<()> {
        let queue_id = io.queue_id();
        io.cqe().view().set_sq_id(queue_id);
        publish_cqe(io.index);
        self.oic.send(io.index, queue_id as u8)?.await
    }

    /// Starts the reply copy as a detached GDMA transfer, whose completion
    /// [`finish_detached`](UnoHsmPal::finish_detached) turns into a detached
    /// CQE post, and that post's completion into the scrub and free of
    /// [`drop_io`](HsmIoController::drop_io). Declines admin and self-test
    /// IOs, sealed IOs (whose reply [`send_response`] must seal), and IOs
    /// whose dirty SRAM is too large to scrub with the CPU.
    ///
    /// [`send_response`]: HsmIoController::send_response
    fn finish_io(&self, io: Self::Io, resp: &HsmDmaBuf) -> Result<(), Self::Io> {
        let index = io.index;
        if sealed::sqe_is_sealed(io.sqe()) {
            return Err(io);
        }
        let sqe = io.sqe().view();
        let (dst, dst2) = (sqe.dst_prp1(), sqe.dst_prp2());
        if index as u32 >= IO_SQ_COUNT
            || resp.len() > sqe.dst_len() as usize
            || crate::alloc::io_slot_dma_dirty(self, index).1 > crate::gdma::CPU_SCRUB_MAX
        {
            return Err(io);
        }
        let Ok(ifc) = crate::gdma::host_interface(io.pid()) else {
            return Err(io);
        };
        let len = resp.len() as u32;
        if self
            .gdma
            .copy_mem_detached(
                crate::gdma::device_dma_buf(resp.as_ptr(), len),
                MemInterface::Device,
                len,
                crate::gdma::host_dma_buf(dst, dst2, true),
                ifc,
                len,
                index,
            )
            .is_err()
        {
            return Err(io);
        }
        self.stages[index as usize].set(Stage::Reply {
            queue_id: io.queue_id(),
        });
        Ok(())
    }

    /// Drops an IO without sending a completion (e.g. for disabled
    /// partitions). Scrubs the slot's scratch buffers, then returns the
    /// IO_SQ slot to the ISQ.
    ///
    /// This is the universal IO teardown point (the core dispatch loop
    /// calls it on both the completed and the dropped paths), so the
    /// per-IO buffer scrub lives here. See
    /// [`scrub_io_slot`](UnoHsmPal::scrub_io_slot). It also ends the IO's
    /// in-flight count, in the same step that returns the slot.
    async fn drop_io(&self, io: Self::Io) -> HsmResult<()> {
        let queue_id = io.queue_id();
        // Scrub both per-IO scratch buffers *before* returning the slot to
        // the ISQ, so no key material from this IO can be observed by the
        // next IO that reuses the slot.
        self.scrub_io_slot(io.index).await;
        self.iic.free_io(io.index, queue_id);
        self.io_in_flight_dec();
        Ok(())
    }
}

/// Where a host IO slot is in the work the run loop does for it: each
/// detached step's completion takes the slot to its next stage (see
/// [`UnoHsmPal::finish_detached`]).
#[derive(Default)]
pub(crate) enum Stage {
    /// Nothing: the slot is free, or its IO is with its task.
    #[default]
    Idle,
    /// Copying the request in (see [`UnoHsmPal::start_request`]); the IO
    /// waits here for it.
    Request(UnoHsmIo),
    /// The IO is with its task, its request brought in as given, for
    /// [`recv_request`](HsmIoController::recv_request) to take.
    Received(RequestIn),
    /// Copying the reply out (see [`HsmIoController::finish_io`]), then
    /// posting the completion to queue `queue_id`.
    Reply { queue_id: u16 },
    /// Posting the completion to queue `queue_id`.
    Post { queue_id: u16 },
}

/// Where an IO's request is and what receiving it takes, from the IO's
/// SQE, checked as receiving it requires.
struct RequestPlan {
    /// The session of a sealed request.
    sealed_id: Option<HsmSessId>,
    /// The request's length.
    len: usize,
    /// Room a sealed request leaves in front of it for its AAD.
    headroom: usize,
    /// The request's host buffer (PRP 1 and 2).
    src: (HsmDmaAddr, HsmDmaAddr),
    /// The host's response buffer length.
    resp_capacity: usize,
}

impl RequestPlan {
    fn of(io: &UnoHsmIo) -> HsmResult<Self> {
        let sealed_id = sealed::sealed_session(io.sqe())?;
        let sqe = io.sqe().view();
        if sqe.cmd().psdt() != 0 {
            return Err(HsmError::SqeInvalidPsdt);
        }
        validate_io_fields(
            sqe.src_len(),
            sqe.dst_len(),
            sqe.src_prp1(),
            sqe.dst_prp1(),
            sqe.oob_len(),
            sqe.oob_prp(),
        )?;
        Ok(Self {
            sealed_id,
            len: sqe.src_len() as usize,
            headroom: sealed_id.map_or(0, |_| sealed::TRANSPORT_AAD_LEN),
            src: (sqe.src_prp1(), sqe.src_prp2()),
            resp_capacity: sqe.dst_len() as usize,
        })
    }

    /// Length of the exchange buffer the request is received into.
    fn exchange_len(&self) -> usize {
        self.headroom + self.len.next_multiple_of(4)
    }
}

/// The CQE of IO slot `index`, as [`HsmIo::cqe`] exposes it.
fn slot_cqe(index: u16) -> &'static mut CqeEntry {
    // SAFETY: indexing checks `index` is a host slot, and only the slot's
    // owner -- its IO, or the platform finishing a detached IO -- touches
    // its copy (see `CqeCopies`).
    unsafe { &mut (*CQE_COPIES.0.get())[index as usize] }
}

impl UnoHsmPal {
    /// Reads OOB descriptor `index` of `io` from host memory.
    pub(crate) async fn oob_desc(
        &self,
        io: &UnoHsmIo,
        index: usize,
    ) -> HsmResult<[u8; OOB_ENTRY_LEN as usize]> {
        let sqe = io.sqe().view();
        let addr = oob_entry_addr(sqe.oob_prp(), sqe.oob_len(), index)?;
        self.alloc_scoped_async(io, async |scoped| {
            let entry = scoped.dma_alloc(OOB_ENTRY_LEN as usize)?;
            self.copy_mem_from_host(io, addr, HsmDmaAddr::ZERO, entry, true)
                .await?;
            let bytes: &[u8] = entry;
            bytes.try_into().map_err(|_| HsmError::InternalError)
        })
        .await
    }
}

impl UnoHsmPal {
    /// Advances the host IO slots the run loop works on (see [`Stage`]):
    /// hands on each IO whose request copy is done, posts the completion of
    /// each finished reply copy (marked failed first if the copy failed),
    /// retries posts the OIC had no room for, and scrubs and frees the slot
    /// of each posted completion. Called on every run-loop pass.
    pub(crate) fn finish_detached(&self) {
        while let Some((index, ok)) = self.gdma.take_detached() {
            match self.stages[index as usize].take() {
                Stage::Request(io) => {
                    self.stages[index as usize].set(Stage::Received(if ok {
                        RequestIn::Copied
                    } else {
                        RequestIn::Failed
                    }));
                    // Set before the first copy, and never cleared.
                    if let Some(dispatch) = self.io_dispatch.get() {
                        dispatch(io);
                    }
                }
                Stage::Reply { queue_id } => {
                    let cqe = slot_cqe(index);
                    if !ok {
                        cqe.set_err(HsmError::FailedToStartDmaTransaction);
                    }
                    cqe.view().set_sq_id(queue_id);
                    self.post_detached(index, queue_id);
                }
                stage => self.stages[index as usize].set(stage),
            }
        }
        let mut pending = self.detached_post_pending.get();
        if pending != 0 {
            self.detached_post_pending.set(0);
            while pending != 0 {
                let index = pending.trailing_zeros() as u16;
                pending &= !(1 << index);
                if let Stage::Post { queue_id } = self.stages[index as usize].take() {
                    self.post_detached(index, queue_id);
                }
            }
        }
        while let Some((index, _)) = self.oic.take_detached() {
            // As `drop_io`: wipe the slot's scratch before the slot can be
            // reused. A failed post is dropped like a failed `complete_io`.
            // The post granted the IO's queue credit back (see
            // `OicDriver::send_detached`), so only the buffer returns here.
            self.stages[index as usize].set(Stage::Idle);
            self.scrub_io_slot_cpu(index);
            self.iic.release_io(index);
            self.io_in_flight_dec();
        }
    }

    /// Posts slot `index`'s completion to queue `queue_id`, or leaves it
    /// for the next pass if the OIC has no room.
    #[inline]
    fn post_detached(&self, index: u16, queue_id: u16) {
        self.stages[index as usize].set(Stage::Post { queue_id });
        publish_cqe(index);
        if self.oic.send_detached(index, queue_id as u8).is_err() {
            self.detached_post_pending
                .set(self.detached_post_pending.get() | 1 << index);
        }
    }

    /// How the run loop brought `io`'s request in ahead of the IO's task, if
    /// it did. Leaves the slot idle: while a task holds the slot's IO, the
    /// slot is idle or [`Stage::Received`].
    #[inline]
    fn take_request_in(&self, io: &UnoHsmIo) -> Option<RequestIn> {
        match self.stages.get(usize::from(io.index))?.take() {
            Stage::Received(request_in) => Some(request_in),
            _ => None,
        }
    }

    /// Starts copying a TBOR IO's request in from the host as the run loop
    /// receives the IO, into the exchange buffer
    /// [`recv_request`](HsmIoController::recv_request) would copy it into,
    /// and parks the IO until the copy lands (see
    /// [`finish_detached`](Self::finish_detached)): the IO's task then wakes
    /// once, to its request. Returns the IO, to hand on now, if the copy
    /// does not start; `recv_request` then copies the request, or fails as
    /// it would have.
    fn start_request(&self, io: UnoHsmIo) -> Option<UnoHsmIo> {
        let index = io.index;
        if index as u32 >= IO_SQ_COUNT || io.sqe().opcode() != OP_TBOR {
            return Some(io);
        }
        let Ok(plan) = RequestPlan::of(&io) else {
            return Some(io);
        };
        let Ok(ifc) = crate::gdma::host_interface(io.pid) else {
            return Some(io);
        };
        let Ok(mut buf) = self.dma_alloc_exchange(&io, plan.exchange_len()) else {
            return Some(io);
        };
        let len = plan.len as u32;
        let dst = buf.buffer_mut()[plan.headroom..].as_mut_ptr();
        if self
            .gdma
            .copy_mem_detached(
                crate::gdma::host_dma_buf(plan.src.0, plan.src.1, true),
                ifc,
                len,
                crate::gdma::device_dma_buf(dst, len),
                MemInterface::Device,
                len,
                index,
            )
            .is_err()
        {
            reset_io_alloc(self, index);
            return Some(io);
        }
        self.stages[index as usize].set(Stage::Request(io));
        None
    }

    /// Turns IO_SQ slot `index` received from the IIC driver into an IO:
    /// counts it in flight (balanced by [`drop_io`](HsmIoController::drop_io))
    /// and resets the slot's scratch allocator.
    #[inline]
    pub(crate) fn accept_io(&self, rx: Received) -> UnoHsmIo {
        let index = rx.index;
        self.io_in_flight_inc();
        reset_io_alloc(self, index);
        if (index as u32) < IO_SQ_COUNT {
            // A request brought in for the slot's last IO, which ended
            // without taking it, is not this IO's.
            self.stages[index as usize].set(Stage::Idle);
            copy_sqe(index as usize);
            // SAFETY: as in `HsmIo::sqe`; `copy_sqe` just filled the copy.
            let sqe = unsafe { &(*SQE_COPIES.0.get())[index as usize] };
            let mut cqe = CqeEntry::default();
            cqe.view().set_cmd_id(sqe.view().cmd_id());
            *slot_cqe(index) = cqe;
        }
        // The routing comes with the IO, as the IIC driver read it from the
        // ICQ entry, rather than back out of IO_META.
        UnoHsmIo::from_routing(index, rx.axi_id, u16::from(rx.queue_id))
    }

    /// Has the run loop hand each host IO it receives to `dispatch`, rather
    /// than wake [`poll_io`](HsmIoController::poll_io) to receive it, so an
    /// IO reaches the task that serves it without a pass through a receive
    /// task. `poll_io` still receives the IO that comes while host IO is
    /// paused for a PCIe reset.
    pub fn set_io_dispatch(&self, dispatch: IoDispatch) {
        self.io_dispatch.set(Some(dispatch));
    }

    /// Run-loop wake for the IIC's ICQ interrupt: takes every IO waiting in
    /// the ICQ and hands it to the [`IoDispatch`] set, or, with none set or
    /// while host IO is paused, wakes `poll_io`'s receive.
    pub(crate) fn wake_iic(&self, irq: u16) {
        match self.io_dispatch.get() {
            Some(dispatch) if !self.io_paused() => {
                tsra_fw_uno_drivers_nvic::Nvic::unpend_raw(irq);
                while let Some(rx) = self.iic.try_recv() {
                    if let Some(io) = self.start_request(self.accept_io(rx)) {
                        dispatch(io);
                    }
                }
            }
            _ => self.iic.wake(irq),
        }
    }

    /// Recycles an IO received during a PCIe reset without dispatching it:
    /// the slot is scrubbed and returned, and no CQE is posted. Such an IO
    /// belongs to the host state being torn down. See
    /// [`handle_ipc_event`](UnoHsmPal::handle_ipc_event).
    pub(crate) async fn recycle_reset_io(&self, io: UnoHsmIo) {
        if let Err(_e) = self.drop_io(io).await {
            error!(
                "pcie",
                _e, "reset: failed to recycle IO received during reset"
            );
        }
    }
}

impl UnoHsmPal {
    /// All accepted host IOs have completed and no inbound IO remains unclaimed.
    pub(crate) fn host_io_drained(&self) -> bool {
        self.io_in_flight() == 0 && !self.iic.has_pending_io()
    }

    /// Runs `f` as an *admin session* over the dedicated admin IO slot
    /// ([`ADMIN_IO_INDEX`]), scrubbing that slot when `f` completes.
    ///
    /// This is the admin-side counterpart of
    /// [`drop_io`](HsmIoController::drop_io): internal provisioning
    /// (partition identity, enable-time keygen, boot-key masking, vault
    /// teardown) runs without a host IO, so it never reaches `drop_io` and
    /// its scratch would otherwise only be watermark-rewound, never wiped —
    /// leaving raw private-key material (e.g. the P-384 identity scalar)
    /// resident in the admin slot indefinitely.
    ///
    /// Binding the scrub to the session rather than to each caller means no
    /// admin path that dirties the slot can forget it. `f` also receives a
    /// [`UnoScopedAlloc`] rewound to the slot's base, so every admin sequence
    /// starts from a clean bump heap.
    ///
    /// Sessions must not nest — [`UnoScopedAlloc::for_admin`] rewinds the
    /// slot's watermarks, so an inner session would alias an outer one's
    /// live buffers. All current callers are strictly sequential.
    ///
    /// # Parameters
    /// - `pid`: partition the session targets; written into the admin
    ///   slot's `IO_META` so [`UnoHsmIo::pid`] resolves correctly.
    /// - `f`: async closure run with the admin IO handle and a rewound
    ///   scoped allocator.
    ///
    /// # Returns
    /// Whatever `f` returned. `R` cannot borrow anything the scrub will wipe:
    /// the higher-ranked bound stops it borrowing from the session's scoped
    /// allocator, and `R: 'static` additionally stops it returning a buffer
    /// obtained from the PAL-level allocator, whose lifetime is tied to the
    /// PAL and so outlives the session. Every current caller returns an owned
    /// value, so the bound costs nothing.
    pub(crate) async fn with_admin_io<R, F>(&self, pid: HsmPartId, f: F) -> R
    where
        R: 'static,
        F: for<'a> AsyncFnOnce(&'a UnoHsmIo, &'a UnoScopedAlloc<'a>) -> R,
    {
        let io = UnoHsmIo::admin_no_scrub(pid);
        let result = {
            let alloc = UnoScopedAlloc::for_admin(self);
            f(&io, &alloc).await
        };
        self.scrub_io_slot(ADMIN_IO_INDEX).await;
        result
    }
}
