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
//! and writes the CQE, built in DTCM, into `IO_CQ[index]` for OIC to
//! transmit.
//!
//! Bulk (fast-path) IOs arrive on the fast-path controller's FP1 and FP2
//! IIC/OIC channel pairs and use their own `BULK_IO_SQ` (128B),
//! `BULK_IO_CQ` (64B) and `BULK_IO_META` arrays, shared by both channels:
//! each posts its own range of the slots. They have no per-IO heaps; a bulk
//! IO's allocator slot (see [`UnoHsmIo::alloc_index`]) is a small DMA heap
//! over its `BULK_SCRATCH` slot, for core work before the bulk crypto.

use core::cell::Cell;
use core::cell::UnsafeCell;
use core::mem;
use core::ops::AsyncFnOnce;

use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_hsm_bulk::BulkCqe;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_hsm_bulk::BulkCqeEntry;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_hsm_bulk::BulkSqeEntry;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_hsm_bulk::RawBulkCqe;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_hsm_bulk::RawBulkSqe;
use tsra_fw_hsm_io::CqeEntry;
use tsra_fw_hsm_io::OOB_ENTRY_LEN;
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
use tsra_fw_hsm_pal_traits::HsmIoKind;
use tsra_fw_hsm_pal_traits::HsmIoTypes;
use tsra_fw_hsm_pal_traits::HsmRequest;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSqe;
use tsra_fw_static_ref::StaticRef;
use tsra_fw_uno_drivers_gdma::MemInterface;
use tsra_fw_uno_drivers_iic::Received;
use tsra_fw_uno_drivers_part_store::HsmPartId;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_uno_reg_soc::io_gsram::BULK_SCRATCH_OFFSET;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_uno_reg_soc::io_gsram::BULK_SCRATCH_SIZE;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_uno_reg_soc::io_gsram::BULK_SCRATCH_STRIDE;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_uno_reg_soc::io_gsram::BulkIoCqEntry;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_uno_reg_soc::io_gsram::BulkIoSqEntry;
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
    const { assert!(mem::size_of::<IoCqEntry>() == 16 && mem::size_of::<RawCqe>() == 16) };
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

/// An in-flight IO identified by its queue kind and slot index.
///
/// Holds the slot index for the lifetime of a single IO operation.
/// Metadata (controller_id, queue_id, queue_index) is stored in
/// `IO_META[index]` (or `BULK_IO_META[index]`), written by the IIC driver
/// at recv time; the IO keeps the partition and queue it needs from the
/// routing the driver returned, since IO GSRAM is read uncached and both
/// are wanted many times per IO.
#[derive(Debug)]
pub struct UnoHsmIo {
    /// Slot index. For a command IO this indexes `IO_SQ`: host IO uses
    /// `0..ADMIN_IO_INDEX`; the reserved admin slot (`ADMIN_IO_INDEX`, the
    /// last of `IO_SLOTS`) is used only for PAL-internal provisioning
    /// crypto. For a bulk IO it indexes `BULK_IO_SQ`.
    index: u16,

    /// Queue kind the IO arrived on.
    kind: HsmIoKind,
    /// Partition the IO targets, from its routing (see [`Self::pid`]).
    pid: HsmPartId,
    /// Source queue, from its routing (see [`Self::queue_id`]).
    queue_id: u16,
    transport_binding: Cell<Option<sealed::SessionTransportBinding>>,
}

/// Takes a command IO the run loop received (see
/// [`UnoHsmPal::set_io_dispatch`]) to the task that serves its slot. It runs
/// inside the run loop's pass, so it must hand the IO on without waiting.
pub type IoDispatch = fn(UnoHsmIo);

impl UnoHsmIo {
    /// Returns the platform-private resource slot for this IO.
    ///
    /// Command and bulk IOs index separate slot arrays (see
    /// [`kind`](HsmIo::kind)); only command slots own per-IO heaps.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Returns this IO's allocator slot: its slot index for a command IO,
    /// and one past the command slots for a bulk IO, whose heap is its
    /// `BULK_SCRATCH` slot (see [`crate::alloc`]).
    pub(crate) fn alloc_index(&self) -> u16 {
        match self.kind {
            HsmIoKind::Bulk => crate::alloc::IO_SLOTS as u16 + self.index,
            _ => self.index,
        }
    }

    /// Returns this bulk IO's scratch region (`BULK_SCRATCH[index]`), in
    /// GSRAM the AES, BCP and GDMA engines can reach.
    ///
    /// The region belongs to the IO until [`drop_io`] scrubs it; views of it
    /// must not overlap.
    ///
    /// [`drop_io`]: HsmIoController::drop_io
    #[cfg(not(feature = "bulk_crypto"))]
    pub(crate) fn bulk_scratch(&self) -> (*mut u8, usize) {
        debug_assert_eq!(self.kind, HsmIoKind::Bulk, "command IO has no bulk scratch");
        let addr = IO_GSRAM_BASE as usize
            + BULK_SCRATCH_OFFSET as usize
            + usize::from(self.index) * BULK_SCRATCH_STRIDE as usize;
        (addr as *mut u8, BULK_SCRATCH_SIZE as usize)
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
                kind: HsmIoKind::Cmd,
                pid: HsmPartId::from(crate::pal::NO_PARTITION),
                queue_id: 0,
                transport_binding: Cell::new(None),
            };
        }
        let meta = &IO_Q.io_meta[index as usize];
        Self::from_routing(
            index,
            HsmIoKind::Cmd,
            meta.ctlr.read(IO_META_CTLR::CONTROLLER_ID) as u8,
            meta.queue.read(IO_META_QUEUE::QUEUE_ID) as u16,
        )
    }

    /// A `kind` IO over slot `index` from source controller `axi_id`'s queue
    /// `queue_id`.
    fn from_routing(index: u16, kind: HsmIoKind, axi_id: u8, queue_id: u16) -> Self {
        Self {
            index,
            kind,
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

impl UnoHsmIo {
    /// Returns a command IO's SQE.
    ///
    /// IIC DMAs the host-side 64-byte SQE into `IO_SQ[index]`; a host IO
    /// reads the copy [`accept_io`](UnoHsmPal::accept_io) took of it.
    pub(crate) fn cmd_sqe(&self) -> &SqeEntry {
        const _ASSERT_SQE_SIZE: () =
            assert!(mem::size_of::<IoSqEntry>() == mem::size_of::<RawSqe>());
        const _ASSERT_SQE_ALIGN: () =
            assert!(mem::align_of::<IoSqEntry>() == mem::align_of::<RawSqe>());

        debug_assert_eq!(self.kind, HsmIoKind::Cmd, "bulk IO has no command SQE");
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

    /// Returns a bulk IO's SQE, at `BULK_IO_SQ[index]`.
    #[cfg(not(feature = "bulk_crypto"))]
    pub(crate) fn bulk_sqe(&self) -> &BulkSqeEntry {
        debug_assert_eq!(self.kind, HsmIoKind::Bulk, "command IO has no bulk SQE");
        slot_bulk_sqe(self.index)
    }

    /// Returns a bulk IO's CQE, at `BULK_IO_CQ[index]`.
    #[cfg(not(feature = "bulk_crypto"))]
    pub(crate) fn bulk_cqe(&mut self) -> &mut BulkCqeEntry {
        debug_assert_eq!(self.kind, HsmIoKind::Bulk, "command IO has no bulk CQE");
        slot_bulk_cqe(self.index)
    }
}

impl HsmIo for UnoHsmIo {
    // A command IO and a bulk IO have differently sized entries in their own
    // queues, so each is handed out behind the entry traits.
    type Sqe = dyn HsmSqe;
    type Cqe = dyn HsmCqe;

    /// Returns the IO's SQE: [`cmd_sqe`](Self::cmd_sqe) or
    /// [`bulk_sqe`](Self::bulk_sqe).
    fn sqe(&self) -> &Self::Sqe {
        #[cfg(not(feature = "bulk_crypto"))]
        if self.kind == HsmIoKind::Bulk {
            return self.bulk_sqe();
        }
        self.cmd_sqe()
    }

    /// Returns the IO's CQE: a command IO's DTCM copy, written out to
    /// `IO_CQ[index]` when the completion is posted (see [`CqeCopies`]), or
    /// `BULK_IO_CQ[index]`.
    ///
    /// The HSM core writes completion status here; the OIC driver
    /// reads it when sending the completion back to the host.
    fn cqe(&mut self) -> &mut Self::Cqe {
        #[cfg(not(feature = "bulk_crypto"))]
        if self.kind == HsmIoKind::Bulk {
            return self.bulk_cqe();
        }
        slot_cqe(self.index)
    }

    fn kind(&self) -> HsmIoKind {
        self.kind
    }
}

impl HsmIoTypes for UnoHsmPal {
    type Io = UnoHsmIo;
}

impl HsmIoController for UnoHsmPal {
    /// Awaits the next inbound IO from the command or a bulk IIC driver.
    ///
    /// When several have work, the queue polled first rotates per call so
    /// none can starve the others. Every IO handed out is counted in
    /// flight until [`drop_io`](HsmIoController::drop_io) returns its slot.
    async fn poll_io(&self) -> HsmResult<Self::Io> {
        loop {
            #[cfg(not(feature = "bulk_crypto"))]
            let (rx, kind) = {
                use embassy_futures::select::Either3;
                use embassy_futures::select::select3;

                fn first<T>(e: Either3<T, T, T>) -> T {
                    match e {
                        Either3::First(r) | Either3::Second(r) | Either3::Third(r) => r,
                    }
                }

                let turn = self.poll_turn.get();
                self.poll_turn.set((turn + 1) % 3);
                let cmd = async { (self.iic.recv().await, HsmIoKind::Cmd) };
                let fp1 = async { (self.bulk_iic.recv().await, HsmIoKind::Bulk) };
                let fp2 = async { (self.bulk_fp2_iic.recv().await, HsmIoKind::Bulk) };
                match turn {
                    0 => first(select3(cmd, fp1, fp2).await),
                    1 => first(select3(fp1, fp2, cmd).await),
                    _ => first(select3(fp2, cmd, fp1).await),
                }
            };
            #[cfg(feature = "bulk_crypto")]
            let (rx, kind) = (self.iic.recv().await, HsmIoKind::Cmd);
            let io = self.accept_io(rx, kind);
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
        let sealed_id = sealed::sealed_session(io.cmd_sqe())?;
        let control = io.cmd_sqe().session_ctrl();
        let sqe = io.cmd_sqe().view();
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
        let len = sqe.src_len() as usize;
        let headroom = sealed_id.map_or(0, |_| sealed::TRANSPORT_AAD_LEN);
        let mut buf = self.dma_alloc_exchange(io, headroom + len.next_multiple_of(4))?;
        self.copy_mem_from_host(
            io,
            sqe.src_prp1(),
            sqe.src_prp2(),
            &mut buf.buffer_mut()[headroom..headroom + len],
            true,
        )
        .await
        .map_err(|_| HsmError::FailedToStartDmaTransaction)?;
        let resp_capacity = sqe.dst_len() as usize;
        let Some(id) = sealed_id else {
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
        let resp = match sealed::sealed_session(io.cmd_sqe())? {
            Some(id) => {
                let binding = io
                    .transport_binding
                    .take()
                    .ok_or(HsmError::SessionTransportError)?;
                let frame = sealed::sealed_seal(self, io, id, binding, resp).await?;
                let frame_len = u16::try_from(frame.len()).map_err(|_| HsmError::InvalidArg)?;
                slot_cqe(io.index).view().set_dst_len(frame_len);
                frame
            }
            None => resp,
        };
        let sqe = io.cmd_sqe().view();
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
        match io.kind {
            HsmIoKind::Cmd => {
                slot_cqe(io.index).view().set_sq_id(queue_id);
                publish_cqe(io.index);
                self.oic.send(io.index, queue_id as u8)?.await
            }
            #[cfg(not(feature = "bulk_crypto"))]
            HsmIoKind::Bulk => {
                BulkCqe::set_sq_id(&mut slot_bulk_cqe(io.index).0, queue_id);
                // The OSQ entry carries the IO's inbound-queue credit
                // (`return_credit`).
                self.bulk_oic_for(io.index)
                    .send(io.index, queue_id as u8)?
                    .await
            }
            #[cfg(feature = "bulk_crypto")]
            HsmIoKind::Bulk => Err(HsmError::InternalError),
        }
    }

    /// Starts the reply copy as a detached GDMA transfer, whose completion
    /// [`finish_detached`](UnoHsmPal::finish_detached) turns into a detached
    /// CQE post, and that post's completion into the scrub and free of
    /// [`drop_io`](HsmIoController::drop_io). Declines bulk, admin and
    /// self-test IOs, sealed IOs (whose reply [`send_response`] must seal),
    /// and IOs whose dirty SRAM is too large to scrub with the CPU.
    ///
    /// [`send_response`]: HsmIoController::send_response
    fn finish_io(&self, io: Self::Io, resp: &HsmDmaBuf) -> Result<(), Self::Io> {
        let index = io.index;
        if io.kind != HsmIoKind::Cmd || sealed::sqe_is_sealed(io.cmd_sqe()) {
            return Err(io);
        }
        let sqe = io.cmd_sqe().view();
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
        self.detached[index as usize].set(DetachedIo {
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
        if io.kind == HsmIoKind::Bulk {
            // Bulk slots have no per-IO heaps; only their small scratch
            // (AES blocks, GCM tail) needs scrubbing.
            #[cfg(not(feature = "bulk_crypto"))]
            {
                let (ptr, len) = io.bulk_scratch();
                // SAFETY: the IO's own scratch region, writable over its
                // whole length, and no longer in use.
                unsafe { crate::gdma::cpu_zeroize(ptr, len) };
                crate::alloc::clear_io_peak(self, io.alloc_index());
                // Returns only the buffer: a bulk IO's credit comes back
                // with its completion, or, for an IO dropped without one,
                // when the SQ is recreated (see `grant_credit`).
                self.bulk_iic_for(io.index).free_io(io.index, queue_id);
            }
            self.io_in_flight_dec(HsmIoKind::Bulk);
            return Ok(());
        }
        // Scrub both per-IO scratch buffers *before* returning the slot to
        // the ISQ, so no key material from this IO can be observed by the
        // next IO that reuses the slot.
        self.scrub_io_slot(io.index).await;
        self.iic.free_io(io.index, queue_id);
        self.io_in_flight_dec(HsmIoKind::Cmd);
        Ok(())
    }
}

/// What finishing a detached host IO still needs (see
/// [`HsmIoController::finish_io`]).
#[derive(Clone, Copy)]
pub(crate) struct DetachedIo {
    queue_id: u16,
}

impl DetachedIo {
    pub(crate) const NONE: Self = Self { queue_id: 0 };
}

/// The CQE of IO slot `index`, as [`HsmIo::cqe`] exposes it: its DTCM copy
/// (see [`CqeCopies`]), which goes out to `IO_CQ[index]` when the
/// completion is posted.
fn slot_cqe(index: u16) -> &'static mut CqeEntry {
    // SAFETY: indexing checks `index` is a host slot, and only the slot's
    // owner -- its IO, or the platform finishing a detached IO -- touches
    // its copy (see `CqeCopies`).
    unsafe { &mut (*CQE_COPIES.0.get())[index as usize] }
}

/// The SQE of bulk slot `index`.
#[cfg(not(feature = "bulk_crypto"))]
fn slot_bulk_sqe(index: u16) -> &'static BulkSqeEntry {
    const _ASSERT_SIZE: () =
        assert!(mem::size_of::<BulkIoSqEntry>() == mem::size_of::<RawBulkSqe>());
    const _ASSERT_ALIGN: () =
        assert!(mem::align_of::<BulkIoSqEntry>() == mem::align_of::<RawBulkSqe>());
    let io_sq = &IO_Q.bulk_io_sq[index as usize];
    // SAFETY: the queue entry and RawBulkSqe (and so the transparent
    // BulkSqeEntry) share the asserted layout; the slot's IO owns it.
    unsafe { &*(io_sq as *const BulkIoSqEntry as *const BulkSqeEntry) }
}

/// The CQE of bulk slot `index`.
#[cfg(not(feature = "bulk_crypto"))]
fn slot_bulk_cqe(index: u16) -> &'static mut BulkCqeEntry {
    const _ASSERT_SIZE: () =
        assert!(mem::size_of::<BulkIoCqEntry>() == mem::size_of::<RawBulkCqe>());
    const _ASSERT_ALIGN: () =
        assert!(mem::align_of::<BulkIoCqEntry>() == mem::align_of::<RawBulkCqe>());
    // SAFETY: the queue entry and RawBulkCqe (and so the transparent
    // BulkCqeEntry) share the asserted layout, and only the slot's IO
    // touches it.
    unsafe {
        let ptr = core::ptr::addr_of!(IO_Q.bulk_io_cq[index as usize]) as *mut BulkCqeEntry;
        &mut *ptr
    }
}

#[cfg(not(feature = "bulk_crypto"))]
impl UnoHsmPal {
    /// The IIC driver that posts bulk slot `index`: FP1 below
    /// [`BULK_FP1_SLOTS`](crate::pal::BULK_FP1_SLOTS), FP2 above. The slot
    /// must go back to the channel that posted it.
    fn bulk_iic_for(&self, index: u16) -> &crate::pal::BulkIic {
        if index < crate::pal::BULK_FP1_SLOTS {
            self.bulk_iic
        } else {
            self.bulk_fp2_iic
        }
    }

    /// The OIC driver paired with [`bulk_iic_for`](Self::bulk_iic_for).
    fn bulk_oic_for(&self, index: u16) -> &crate::pal::BulkOic {
        if index < crate::pal::BULK_FP1_SLOTS {
            self.bulk_oic
        } else {
            self.bulk_fp2_oic
        }
    }
}

impl UnoHsmPal {
    /// Reads OOB descriptor `index` of `io` from host memory.
    pub(crate) async fn oob_desc(
        &self,
        io: &UnoHsmIo,
        index: usize,
    ) -> HsmResult<[u8; OOB_ENTRY_LEN as usize]> {
        let sqe = io.cmd_sqe().view();
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
    /// Advances detached IOs (see [`HsmIoController::finish_io`]): posts the
    /// completion of each finished reply copy (marked failed first if the
    /// copy failed), retries posts the OIC had no room for, and scrubs and
    /// frees the slot of each posted completion. Called on every run-loop
    /// pass.
    pub(crate) fn finish_detached(&self) {
        while let Some((index, ok)) = self.gdma.take_detached() {
            let d = self.detached[index as usize].get();
            let cqe = slot_cqe(index);
            if !ok {
                cqe.set_err(HsmError::FailedToStartDmaTransaction);
            }
            cqe.view().set_sq_id(d.queue_id);
            self.post_detached(index);
        }
        let mut pending = self.detached_post_pending.get();
        if pending != 0 {
            self.detached_post_pending.set(0);
            while pending != 0 {
                let index = pending.trailing_zeros() as u16;
                pending &= !(1 << index);
                self.post_detached(index);
            }
        }
        while let Some((index, _)) = self.oic.take_detached() {
            // As `drop_io`: wipe the slot's scratch before the slot can be
            // reused. A failed post is dropped like a failed `complete_io`.
            // The post granted the IO's queue credit back (see
            // `OicDriver::send_detached`), so only the buffer returns here.
            self.scrub_io_slot_cpu(index);
            self.iic.release_io(index);
            self.io_in_flight_dec(HsmIoKind::Cmd);
        }
    }

    /// Posts slot `index`'s completion, or leaves it for the next pass if
    /// the OIC has no room.
    #[inline]
    fn post_detached(&self, index: u16) {
        let queue_id = self.detached[index as usize].get().queue_id as u8;
        publish_cqe(index);
        if self.oic.send_detached(index, queue_id).is_err() {
            self.detached_post_pending
                .set(self.detached_post_pending.get() | 1 << index);
        }
    }

    /// Turns slot `rx.index` received from the `kind` IIC driver into an IO:
    /// counts it in flight (balanced by [`drop_io`](HsmIoController::drop_io)),
    /// and resets a command slot's scratch allocator and copies its SQE, or
    /// marks a bulk slot busy.
    #[inline]
    pub(crate) fn accept_io(&self, rx: Received, kind: HsmIoKind) -> UnoHsmIo {
        let index = rx.index;
        self.io_in_flight_inc(kind);
        match kind {
            HsmIoKind::Cmd => {
                reset_io_alloc(self, index);
                if (index as u32) < IO_SQ_COUNT {
                    self.io_session_key[index as usize].set(None);
                    copy_sqe(index as usize);
                    // SAFETY: as in `HsmIo::sqe`; `copy_sqe` just filled the copy.
                    let sqe = unsafe { &(*SQE_COPIES.0.get())[index as usize] };
                    let mut cqe = CqeEntry::default();
                    cqe.view().set_cmd_id(sqe.view().cmd_id());
                    *slot_cqe(index) = cqe;
                }
            }
            // Stamp the bulk CQE with the command's attributes and id, so a
            // failure can be recorded in it (`HsmCqe::set_err`).
            #[cfg(not(feature = "bulk_crypto"))]
            HsmIoKind::Bulk => {
                reset_io_alloc(self, crate::alloc::IO_SLOTS as u16 + index);
                *slot_bulk_cqe(index) = BulkCqeEntry::for_sqe(&slot_bulk_sqe(index).0)
            }
            #[cfg(feature = "bulk_crypto")]
            HsmIoKind::Bulk => {}
        }
        // The routing comes with the IO, as the IIC driver read it from the
        // ICQ entry, rather than back out of IO_META.
        UnoHsmIo::from_routing(index, kind, rx.axi_id, u16::from(rx.queue_id))
    }

    /// Has the run loop hand each command IO it receives to `dispatch`,
    /// rather than wake [`poll_io`](HsmIoController::poll_io) to receive it,
    /// so an IO reaches the task that serves it without a pass through a
    /// receive task. `poll_io` still receives bulk IOs, and the command IO
    /// that comes while host IO is paused for a PCIe reset.
    pub fn set_io_dispatch(&self, dispatch: IoDispatch) {
        self.io_dispatch.set(Some(dispatch));
    }

    /// Run-loop wake for the command IIC's ICQ interrupt: takes every IO
    /// waiting in the ICQ and hands it to the [`IoDispatch`] set, or, with
    /// none set or while host IO is paused, wakes `poll_io`'s receive.
    pub(crate) fn wake_iic(&self, irq: u16) {
        match self.io_dispatch.get() {
            Some(dispatch) if !self.io_paused() => {
                tsra_fw_uno_drivers_nvic::Nvic::unpend_raw(irq);
                while let Some(rx) = self.iic.try_recv() {
                    dispatch(self.accept_io(rx, HsmIoKind::Cmd));
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
    /// All accepted host command IOs have completed and no inbound command IO
    /// remains unclaimed.
    ///
    /// Bulk IOs are not counted: Admin quiesces only the command queues for
    /// the RNG self-test, so under steady bulk traffic some bulk IO is
    /// almost always in flight. They need not be: a bulk IO reads the DRBG
    /// only synchronously (its GCM IV), and the engines it waits on (BCP,
    /// GDMA, AES) do not draw from it.
    pub(crate) fn host_io_drained(&self) -> bool {
        self.cmd_io_in_flight() == 0 && !self.iic.has_pending_io()
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
