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

use core::cell::UnsafeCell;
use core::mem;
use core::ops::AsyncFnOnce;

use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::RawCqe;
use tsra_fw_hsm_io::RawSqe;
use tsra_fw_hsm_pal_traits::HsmCqe;
use tsra_fw_hsm_pal_traits::HsmDmaAddr;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmIoTypes;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSqe;
use tsra_fw_static_ref::StaticRef;
use tsra_fw_uno_drivers_gdma::MemInterface;
use tsra_fw_uno_drivers_part_store::HsmPartId;
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
struct SqeCopies(UnsafeCell<[RawSqe; IO_SQ_COUNT as usize]>);

// SAFETY: single-core firmware with cooperative scheduling; a slot's copy
// is written only by `accept_io`, before its IO exists, and read only
// through that IO.
unsafe impl Sync for SqeCopies {}

static SQE_COPIES: SqeCopies = SqeCopies(UnsafeCell::new([[0; 16]; IO_SQ_COUNT as usize]));

/// Copies host slot `index`'s SQE out of `IO_SQ` with two eight-word bursts.
fn copy_sqe(index: usize) {
    let src = &IO_Q.io_sq[index] as *const IoSqEntry as *const u32;
    // SAFETY: `index` is a host slot, so its copy exists; nothing else
    // borrows it while the slot is free (see `SqeCopies`).
    let dst = unsafe { (*SQE_COPIES.0.get())[index].as_mut_ptr() };
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
}

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
            };
        }
        let meta = &IO_Q.io_meta[index as usize];
        let axi_id = meta.ctlr.read(IO_META_CTLR::CONTROLLER_ID) as u8;
        Self {
            index,
            // IO_META records the routing axi_id the hardware reported;
            // partitions are indexed by the dense PcieFunction id, so
            // translate here. An axi_id naming no function yields an
            // out-of-range id, which the partition lookup rejects with
            // `InvalidArg` rather than aliasing a valid slot.
            pid: HsmPartId::from(
                crate::pal::axi_id_to_pfn(axi_id).unwrap_or(crate::pal::NO_PARTITION),
            ),
            queue_id: meta.queue.read(IO_META_QUEUE::QUEUE_ID) as u16,
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
    /// Returns the SQE from `IO_SQ[index]`.
    ///
    /// IIC DMAs the host-side 64-byte SQE into `IO_SQ[index]`; a host IO
    /// reads the copy [`accept_io`](UnoHsmPal::accept_io) took of it.
    fn sqe(&self) -> &HsmSqe {
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
        // SAFETY: The queue entry and RawSqe share the asserted layout; this IO owns the slot.
        unsafe { &*(io_sq as *const IoSqEntry as *const RawSqe) }
    }

    /// Returns a mutable reference to the CQE at `IO_CQ[index]`.
    ///
    /// The HSM core writes completion status here; the OIC driver
    /// reads it when sending the completion back to the host.
    fn cqe(&mut self) -> &mut HsmCqe {
        const _ASSERT_CQE_SIZE: () =
            assert!(mem::size_of::<IoCqEntry>() == mem::size_of::<RawCqe>());
        const _ASSERT_CQE_ALIGN: () =
            assert!(mem::align_of::<IoCqEntry>() == mem::align_of::<RawCqe>());

        // SAFETY: The asserted layout matches RawCqe; the mutable IO borrow owns its CQ slot.
        unsafe {
            let ptr = core::ptr::addr_of!(IO_Q.io_cq[self.index as usize]) as *mut RawCqe;
            &mut *ptr
        }
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
    async fn complete_io(&self, io: &mut Self::Io) -> HsmResult<()> {
        let queue_id = io.queue_id();
        Cqe::try_from(io.cqe())?.set_sq_id(queue_id);
        self.oic.send(io.index, queue_id as u8)?.await
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
    /// Starts the reply copy as a detached GDMA transfer, whose completion
    /// [`finish_detached`](UnoHsmPal::finish_detached) turns into a detached
    /// CQE post, and that post's completion into the scrub and free of
    /// [`drop_io`](HsmIoController::drop_io). Declines admin and self-test
    /// IOs, and IOs whose dirty SRAM is too large to scrub with the CPU.
    fn finish_io(
        &self,
        io: Self::Io,
        resp: &HsmDmaBuf,
        dst: HsmDmaAddr,
        dst2: HsmDmaAddr,
        copy_failed: fn(&mut HsmCqe),
    ) -> Result<(), Self::Io> {
        let index = io.index;
        if index as u32 >= IO_SQ_COUNT
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
            copy_failed,
        });
        Ok(())
    }

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

/// What finishing a detached host IO still needs (see
/// [`HsmIoController::finish_io`]).
#[derive(Clone, Copy)]
pub(crate) struct DetachedIo {
    queue_id: u16,
    copy_failed: fn(&mut HsmCqe),
}

impl DetachedIo {
    pub(crate) const NONE: Self = Self {
        queue_id: 0,
        copy_failed: |_| {},
    };
}

/// The CQE of host IO slot `index`, as [`HsmIo::cqe`] exposes it.
fn slot_cqe(index: u16) -> &'static mut HsmCqe {
    // SAFETY: as in `HsmIo::cqe`: the layouts match, and only the slot's
    // owner -- here the platform, finishing a detached IO -- touches it.
    unsafe {
        let ptr = core::ptr::addr_of!(IO_Q.io_cq[index as usize]) as *mut RawCqe;
        &mut *ptr
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
                (d.copy_failed)(cqe);
            }
            if let Ok(mut cqe) = Cqe::try_from(cqe) {
                cqe.set_sq_id(d.queue_id);
            }
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
            self.scrub_io_slot_cpu(index);
            self.iic
                .free_io(index, self.detached[index as usize].get().queue_id);
            self.io_in_flight_dec();
        }
    }

    /// Posts slot `index`'s completion, or leaves it for the next pass if
    /// the OIC has no room.
    fn post_detached(&self, index: u16) {
        let queue_id = self.detached[index as usize].get().queue_id as u8;
        if self.oic.send_detached(index, queue_id).is_err() {
            self.detached_post_pending
                .set(self.detached_post_pending.get() | 1 << index);
        }
    }

    /// Turns IO_SQ slot `index` received from the IIC driver into an IO:
    /// counts it in flight (balanced by [`drop_io`](HsmIoController::drop_io))
    /// and resets the slot's scratch allocator.
    pub(crate) fn accept_io(&self, index: u16) -> UnoHsmIo {
        self.io_in_flight_inc();
        reset_io_alloc(self, index);
        if (index as u32) < IO_SQ_COUNT {
            copy_sqe(index as usize);
        }
        UnoHsmIo::from_meta(index)
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
