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
//!
//! Bulk (fast-path) IOs arrive on the fast-path controller's FP1 and FP2
//! IIC/OIC channel pairs and use their own `BULK_IO_SQ` (128B),
//! `BULK_IO_CQ` (64B) and `BULK_IO_META` arrays, shared by both channels:
//! each posts its own range of the slots. They have no per-IO heaps: a bulk
//! IO must not reach the allocator, whose tables are indexed by command slot.

use core::mem;
use core::ops::AsyncFnOnce;

use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_hsm_bulk::BulkCqe;
use tsra_fw_hsm_bulk::RawBulkCqe;
use tsra_fw_hsm_bulk::RawBulkSqe;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::RawCqe;
use tsra_fw_hsm_io::RawSqe;
use tsra_fw_hsm_pal_traits::HsmCqe;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmIoKind;
use tsra_fw_hsm_pal_traits::HsmIoTypes;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSqe;
use tsra_fw_static_ref::StaticRef;
use tsra_fw_uno_drivers_part_store::HsmPartId;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_uno_reg_soc::io_gsram::BULK_IO_META_COUNT;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_uno_reg_soc::io_gsram::BULK_SCRATCH_OFFSET;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_uno_reg_soc::io_gsram::BULK_SCRATCH_SIZE;
#[cfg(not(feature = "bulk_crypto"))]
use tsra_fw_uno_reg_soc::io_gsram::BULK_SCRATCH_STRIDE;
use tsra_fw_uno_reg_soc::io_gsram::BulkIoCqEntry;
use tsra_fw_uno_reg_soc::io_gsram::BulkIoSqEntry;
use tsra_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;
use tsra_fw_uno_reg_soc::io_gsram::IO_META_COUNT;
use tsra_fw_uno_reg_soc::io_gsram::IO_META_CTLR;
use tsra_fw_uno_reg_soc::io_gsram::IO_META_QUEUE;
use tsra_fw_uno_reg_soc::io_gsram::IoCqEntry;
use tsra_fw_uno_reg_soc::io_gsram::IoMetaEntry;
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

/// An in-flight IO identified by its queue kind and slot index.
///
/// Holds the slot index for the lifetime of a single IO operation.
/// Metadata (controller_id, queue_id, queue_index) is stored in
/// `IO_META[index]` (or `BULK_IO_META[index]`), written by the IIC driver
/// at recv time.
#[derive(Debug)]
pub struct UnoHsmIo {
    /// Slot index. For a command IO this indexes `IO_SQ`: host IO uses
    /// `0..ADMIN_IO_INDEX`; the reserved admin slot (`ADMIN_IO_INDEX`, the
    /// last of `IO_SLOTS`) is used only for PAL-internal provisioning
    /// crypto. For a bulk IO it indexes `BULK_IO_SQ`.
    index: u16,

    /// Queue kind the IO arrived on.
    kind: HsmIoKind,

    /// The IO's completion was posted with its inbound-queue credit
    /// (bulk OIC `return_credit`), so `drop_io` returns only the buffer.
    #[cfg_attr(feature = "bulk_crypto", allow(dead_code))]
    credit_returned: bool,
}

impl UnoHsmIo {
    /// Returns the platform-private resource slot for this IO.
    ///
    /// Only command IOs own per-IO heaps; a bulk index would alias a
    /// command slot's heaps.
    pub(crate) fn index(&self) -> u16 {
        debug_assert_eq!(self.kind, HsmIoKind::Cmd, "bulk IO has no heap slot");
        self.index
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

    /// Returns the queue ID from IO_META.
    fn queue_id(&self) -> u16 {
        if self.index as u32 >= IO_META_COUNT {
            return 0;
        }
        self.io_meta().queue.read(IO_META_QUEUE::QUEUE_ID) as u16
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
        let io = Self {
            index: ADMIN_IO_INDEX,
            kind: HsmIoKind::Cmd,
            credit_returned: false,
        };
        // CONTROLLER_ID holds the hardware axi_id (what IIC `recv` records for
        // a host IO), so an internally created admin IO stores the same
        // encoding for `pid()` to round-trip it back to `pid`.
        let axi_id = crate::pal::pfn_to_axi_id(u8::from(pid)).unwrap_or(crate::pal::NO_PARTITION);
        io.io_meta()
            .ctlr
            .write(IO_META_CTLR::CONTROLLER_ID.val(axi_id as u32));
        io
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
        Self {
            index: SELF_TEST_IO_INDEX,
            kind: HsmIoKind::Cmd,
            credit_returned: false,
        }
    }

    /// Returns a reference to the IO_META entry for this slot.
    ///
    /// Only valid for host and admin slots — `IO_META` has
    /// [`IO_META_COUNT`] entries (host `0..32` plus [`ADMIN_IO_INDEX`]).
    /// The self-test slot ([`SELF_TEST_IO_INDEX`]) has no `IO_META` entry;
    /// callers must guard against it (see [`pid`](HsmIo::pid)).
    #[inline]
    fn io_meta(&self) -> &IoMetaEntry {
        match self.kind {
            HsmIoKind::Cmd => &IO_Q.io_meta[self.index as usize],
            HsmIoKind::Bulk => &IO_Q.bulk_io_meta[self.index as usize],
        }
    }

    /// Returns the partition ID for this IO.
    ///
    /// IO_META records the routing axi_id the hardware reported; partitions
    /// are indexed by the dense PcieFunction id, so translate here. An axi_id
    /// naming no function yields an out-of-range id, which the partition
    /// lookup rejects with `InvalidArg` rather than aliasing a valid slot.
    ///
    /// The self-test slot ([`SELF_TEST_IO_INDEX`]) has no `IO_META` entry or
    /// partition context, so it returns the invalid `NO_PARTITION` sentinel
    /// rather than aliasing a real partition or indexing `IO_META`.
    pub(crate) fn pid(&self) -> HsmPartId {
        if self.index as u32 >= IO_META_COUNT {
            return HsmPartId::from(crate::pal::NO_PARTITION);
        }
        let axi_id = self.io_meta().ctlr.read(IO_META_CTLR::CONTROLLER_ID) as u8;
        HsmPartId::from(crate::pal::axi_id_to_pfn(axi_id).unwrap_or(crate::pal::NO_PARTITION))
    }
}

impl HsmIo for UnoHsmIo {
    /// Returns the SQE from `IO_SQ[index]`.
    ///
    /// IIC DMAs the host-side 64-byte SQE directly into this slot, so it
    /// can be read in-place without a copy.
    fn sqe(&self) -> &HsmSqe {
        const _ASSERT_SQE_SIZE: () =
            assert!(mem::size_of::<IoSqEntry>() == mem::size_of::<RawSqe>());
        const _ASSERT_SQE_ALIGN: () =
            assert!(mem::align_of::<IoSqEntry>() == mem::align_of::<RawSqe>());
        const _ASSERT_BULK_SQE_SIZE: () =
            assert!(mem::size_of::<BulkIoSqEntry>() == mem::size_of::<RawBulkSqe>());
        const _ASSERT_BULK_SQE_ALIGN: () =
            assert!(mem::align_of::<BulkIoSqEntry>() == mem::align_of::<RawBulkSqe>());

        if self.kind == HsmIoKind::Bulk {
            let io_sq = &IO_Q.bulk_io_sq[self.index as usize];
            // SAFETY: The queue entry and RawBulkSqe share the asserted layout; this IO owns the slot.
            return unsafe { &*(io_sq as *const BulkIoSqEntry as *const RawBulkSqe) };
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
        const _ASSERT_BULK_CQE_SIZE: () =
            assert!(mem::size_of::<BulkIoCqEntry>() == mem::size_of::<RawBulkCqe>());
        const _ASSERT_BULK_CQE_ALIGN: () =
            assert!(mem::align_of::<BulkIoCqEntry>() == mem::align_of::<RawBulkCqe>());

        if self.kind == HsmIoKind::Bulk {
            // SAFETY: The asserted layout matches RawBulkCqe; the mutable IO borrow owns its CQ slot.
            return unsafe {
                let ptr =
                    core::ptr::addr_of!(IO_Q.bulk_io_cq[self.index as usize]) as *mut RawBulkCqe;
                &mut *ptr
            };
        }
        // SAFETY: The asserted layout matches RawCqe; the mutable IO borrow owns its CQ slot.
        unsafe {
            let ptr = core::ptr::addr_of!(IO_Q.io_cq[self.index as usize]) as *mut RawCqe;
            &mut *ptr
        }
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
            let (index, kind) = {
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
            let (index, kind) = (self.iic.recv().await, HsmIoKind::Cmd);
            let io = self.accept_io(index, kind);
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
        match io.kind {
            HsmIoKind::Cmd => {
                Cqe::try_from(io.cqe())?.set_sq_id(queue_id);
                self.oic.send(io.index)?.await
            }
            #[cfg(not(feature = "bulk_crypto"))]
            HsmIoKind::Bulk => {
                let cqe: &mut RawBulkCqe = io
                    .cqe()
                    .try_into()
                    .map_err(|_| tsra_fw_hsm_pal_traits::HsmError::InternalError)?;
                BulkCqe::set_sq_id(cqe, queue_id);
                let sent = self.bulk_oic_for(io.index).send(io.index)?;
                // The OSQ entry is posted with the IO's credit, which the
                // hardware returns even if the wait below fails.
                io.credit_returned = true;
                sent.await
            }
            #[cfg(feature = "bulk_crypto")]
            HsmIoKind::Bulk => Err(tsra_fw_hsm_pal_traits::HsmError::InternalError),
        }
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
                let iic = self.bulk_iic_for(io.index);
                if io.credit_returned {
                    iic.release_buffer(io.index);
                } else {
                    iic.free_io(io.index, queue_id);
                }
                let bit = bulk_bit(io.index);
                self.bulk_busy.set(self.bulk_busy.get() & !bit);
                self.bulk_freed.set(self.bulk_freed.get() | bit);
            }
            self.io_in_flight_dec();
            return Ok(());
        }
        // Scrub both per-IO scratch buffers *before* returning the slot to
        // the ISQ, so no key material from this IO can be observed by the
        // next IO that reuses the slot.
        self.scrub_io_slot(io.index).await;
        self.iic.free_io(io.index, queue_id);
        self.io_in_flight_dec();
        Ok(())
    }
}

/// Slot bit for bulk IO `index` in [`UnoHsmPal::bulk_busy`].
#[cfg(not(feature = "bulk_crypto"))]
#[inline]
fn bulk_bit(index: u16) -> u32 {
    const _: () = assert!(BULK_IO_META_COUNT <= u32::BITS);
    1u32.checked_shl(u32::from(index)).unwrap_or(0)
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

    /// Starts draining device SQ `sq` of the function at `axi_id`: returns
    /// the mask of bulk slots it has in flight, which are done once all of
    /// them are set in [`bulk_freed`](UnoHsmPal::bulk_freed).
    ///
    /// Only IOs already taken from the queue are waited for; IOs arriving
    /// during the drain do not extend it, so a host that keeps submitting
    /// cannot stall the Admin IPC.
    pub(crate) fn begin_bulk_sq_drain(&self, axi_id: u8, sq: u8) -> u32 {
        let busy = self.bulk_busy.get();
        let mut wait = 0;
        for (i, meta) in IO_Q.bulk_io_meta.iter().enumerate() {
            let bit = 1u32 << i;
            if busy & bit != 0
                && meta.ctlr.read(IO_META_CTLR::CONTROLLER_ID) == u32::from(axi_id)
                && meta.queue.read(IO_META_QUEUE::QUEUE_ID) == u32::from(sq)
            {
                wait |= bit;
            }
        }
        self.bulk_freed.set(self.bulk_freed.get() & !wait);
        wait
    }
}

impl UnoHsmPal {
    /// Turns slot `index` received from the `kind` IIC driver into an IO:
    /// counts it in flight (balanced by [`drop_io`](HsmIoController::drop_io)),
    /// and resets a command slot's scratch allocator or marks a bulk slot
    /// busy.
    pub(crate) fn accept_io(&self, index: u16, kind: HsmIoKind) -> UnoHsmIo {
        self.io_in_flight_inc();
        match kind {
            HsmIoKind::Cmd => reset_io_alloc(self, index),
            #[cfg(not(feature = "bulk_crypto"))]
            HsmIoKind::Bulk => self.bulk_busy.set(self.bulk_busy.get() | bulk_bit(index)),
            #[cfg(feature = "bulk_crypto")]
            HsmIoKind::Bulk => {}
        }
        UnoHsmIo {
            index,
            kind,
            credit_returned: false,
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
        #[cfg(not(feature = "bulk_crypto"))]
        if self.bulk_iic.has_pending_io() || self.bulk_fp2_iic.has_pending_io() {
            return false;
        }
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
