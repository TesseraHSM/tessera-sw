// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::future::poll_fn;
use core::task::Context;
use core::task::Poll;
use core::task::Waker;

use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;
use tock_registers::LocalRegisterCopy;
use tsra_fw_single_cell::SingleCell;
use tsra_fw_static_ref::StaticRef;
use tsra_fw_uno_error::HsmResult;
use tsra_fw_uno_reg_soc::gdma::regs::GdmaRegs;
use tsra_fw_uno_reg_soc::gdma::CQ_CHANNEL_HEAD;
use tsra_fw_uno_reg_soc::gdma::CQ_CTRL;
use tsra_fw_uno_reg_soc::gdma::GDMA_BASE;
use tsra_fw_uno_reg_soc::gdma::IRQ_ENABLE;
use tsra_fw_uno_reg_soc::gdma::SQ_CHANNEL_HEAD;
use tsra_fw_uno_reg_soc::gdma::SQ_CHANNEL_TAIL;
use tsra_fw_uno_reg_soc::gdma::SQ_CTRL;
use tsra_fw_uno_reg_soc::io_gsram::GdmaCqEntry;
use tsra_fw_uno_reg_soc::io_gsram::GdmaSqEntry;
use tsra_fw_uno_reg_soc::io_gsram::GDMA_CQ_COUNT;
use tsra_fw_uno_reg_soc::io_gsram::GDMA_CQ_STATUS;
use tsra_fw_uno_reg_soc::io_gsram::GDMA_SQ_COUNT;

use crate::ChannelConfig;
use crate::GdmaBuf;
use crate::GdmaError;
use crate::MemInterface;

struct TagSlot {
    /// The awaiting task. A plain `Option` rather than a
    /// `WakerRegistration` so a linked copy can hand it on (see
    /// [`GdmaDriver::wake_with`]).
    waker: Option<Waker>,
    completed: bool,
    status: u8,
    /// Work to start as soon as the copy succeeds; see
    /// [`GdmaDriver::copy_mem_linked`].
    link: Option<u32>,
    /// What starting `link` returned, for the copy's future.
    linked: Option<u16>,
    /// No future awaits the copy (see [`GdmaDriver::copy_mem_detached`]):
    /// its completion goes to `wake_with`'s `done`, and frees the tag.
    detached: bool,
}

impl TagSlot {
    fn register(&mut self, w: &Waker) {
        match &self.waker {
            Some(old) if old.will_wake(w) => {}
            _ => self.waker = Some(w.clone()),
        }
    }
}

struct GdmaState<const DEPTH: usize> {
    cq_head: u16,
    sq_tail: u16,
    /// Cached SQ head index. Updated lazily when the queue looks full.
    sq_head_cached: u16,
    tag_free: u32,
    tags: [TagSlot; DEPTH],
}

/// Async GDMA (General DMA Controller) driver.
///
/// One instance manages a single hardware channel. Queue ring addresses and
/// shadow pointers are supplied by [`ChannelConfig`], while the MMIO base comes
/// from the generated [`GDMA_BASE`] constant.
///
/// # Type Parameters
///
/// - `DEPTH`: Queue depth and max concurrent tags. Must be a power of 2, at
///   most 32.
pub struct GdmaDriver<const DEPTH: usize> {
    /// Physical channel index.
    channel: u8,

    /// Cached channel configuration used by [`init`](Self::init).
    config: ChannelConfig,

    /// Controller MMIO registers.
    regs: StaticRef<GdmaRegs>,

    /// SQ ring in DTCM (typed overlay).
    sq_ring: *mut GdmaSqEntry,

    /// CQ ring in DTCM (typed overlay).
    cq_ring: *const GdmaCqEntry,

    /// CQ tail shadow address (firmware reads this instead of MMIO).
    cq_tail_shadow: *const u32,

    /// SQ head shadow address used for the lazy full-queue check.
    sq_head_shadow: *const u32,

    /// Mutable state protected by single-threaded access.
    state: SingleCell<GdmaState<DEPTH>>,
}

// SAFETY: GdmaDriver is only used on single-core Cortex-M firmware with
// cooperative scheduling. The raw pointers reference MMIO or DTCM memory with
// a single owner in practice; Send/Sync are needed for Embassy's static tasks.
unsafe impl<const DEPTH: usize> Send for GdmaDriver<DEPTH> {}
unsafe impl<const DEPTH: usize> Sync for GdmaDriver<DEPTH> {}

impl<const DEPTH: usize> core::fmt::Debug for GdmaDriver<DEPTH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GdmaDriver")
            .field("DEPTH", &DEPTH)
            .field("channel", &self.channel)
            .finish()
    }
}

impl<const DEPTH: usize> GdmaDriver<DEPTH> {
    const MASK: u16 = (DEPTH - 1) as u16;

    const _ASSERT_DEPTH_POW2: () = assert!(DEPTH.is_power_of_two(), "DEPTH must be power of 2");
    const _ASSERT_DEPTH_MAX: () = assert!(DEPTH <= 32, "DEPTH must be <= 32 (u32 tag bitmap)");
    const _ASSERT_SQ_FIT: () =
        assert!(DEPTH <= GDMA_SQ_COUNT as usize, "DEPTH exceeds SQ capacity");
    const _ASSERT_CQ_FIT: () =
        assert!(DEPTH <= GDMA_CQ_COUNT as usize, "DEPTH exceeds CQ capacity");

    const _ASSERT_SQ_ENTRY_SIZE: () = assert!(
        core::mem::size_of::<GdmaSqEntry>() == 16 * 4,
        "GdmaSqEntry must be 64 bytes"
    );
    const _ASSERT_SQ_ENTRY_ALIGN: () = assert!(
        core::mem::align_of::<GdmaSqEntry>() == core::mem::align_of::<u32>(),
        "GdmaSqEntry must be u32-aligned"
    );

    /// Construct the driver for a specific channel without touching MMIO.
    ///
    /// Only stores configuration and initializes software state. Hardware
    /// registers and DTCM shadow words are programmed by [`init`](Self::init);
    /// the channel is then activated by [`enable`](Self::enable).
    ///
    /// Splitting construction from MMIO programming lets the firmware build
    /// the driver instance early while deferring any shared-register writes
    /// until after the boot handshake has completed.
    ///
    /// # Panics
    ///
    /// Compile-time panic if `DEPTH` is not a power of 2, exceeds 32, or is
    /// larger than the GDMA queue storage allocated in DTCM.
    pub fn new(config: ChannelConfig) -> Self {
        #[allow(clippy::let_unit_value)]
        {
            let _ = Self::_ASSERT_DEPTH_POW2;
            let _ = Self::_ASSERT_DEPTH_MAX;
            let _ = Self::_ASSERT_SQ_FIT;
            let _ = Self::_ASSERT_CQ_FIT;
            let _ = Self::_ASSERT_SQ_ENTRY_SIZE;
            let _ = Self::_ASSERT_SQ_ENTRY_ALIGN;
        }

        let regs = unsafe { StaticRef::new(GDMA_BASE as *const GdmaRegs) };

        let tags = core::array::from_fn(|_| TagSlot {
            waker: None,
            completed: false,
            status: 0,
            link: None,
            linked: None,
            detached: false,
        });

        let tag_free = if DEPTH >= 32 {
            u32::MAX
        } else {
            (1u32 << DEPTH) - 1
        };

        Self {
            channel: config.channel,
            config,
            regs,
            sq_ring: config.sq_base as *mut GdmaSqEntry,
            cq_ring: config.cq_base as *const GdmaCqEntry,
            cq_tail_shadow: config.cq_tail_shadow as *const u32,
            sq_head_shadow: config.sq_head_shadow as *const u32,
            state: SingleCell::new(GdmaState {
                cq_head: 0,
                sq_tail: 0,
                sq_head_cached: 0,
                tag_free,
                tags,
            }),
        }
    }

    /// Program the channelized SQ and CQ registers, clear DTCM shadows,
    /// and enable.
    ///
    /// Must only be called after any boot handshake completes.
    pub fn init(&self) {
        let ch = self.config.channel as usize;

        let sq = &self.regs.sq[ch];
        sq.base_lo.set(self.config.sq_base);
        sq.base_hi.set(0);
        sq.head_shadow.set(self.config.sq_head_shadow);
        sq.tail.write(SQ_CHANNEL_TAIL::TAIL.val(0));
        self.regs.sq_ctrl[ch].write(SQ_CTRL::DEPTH.val(DEPTH as u32));

        let cq = &self.regs.cq[ch];
        cq.base_lo.set(self.config.cq_base);
        cq.base_hi.set(0);
        cq.tail_shadow.set(self.config.cq_tail_shadow);
        cq.head.write(CQ_CHANNEL_HEAD::HEAD.val(0));
        self.regs.cq_ctrl[ch].write(CQ_CTRL::DEPTH.val(DEPTH as u32));

        unsafe { (self.config.cq_tail_shadow as *mut u32).write_volatile(0) };
        unsafe { (self.config.sq_head_shadow as *mut u32).write_volatile(0) };

        // Enable
        self.regs.cq_ctrl[ch].modify(CQ_CTRL::EN::SET + CQ_CTRL::TAIL_SHADOW_EN::SET);
        self.regs.sq_ctrl[ch].modify(SQ_CTRL::EN::SET + SQ_CTRL::HEAD_SHADOW_EN::SET);

        if self.config.interrupt {
            let val = self.regs.irq_enable.read(IRQ_ENABLE::IRQ_EN) | (1u32 << self.config.channel);
            self.regs.irq_enable.write(IRQ_ENABLE::IRQ_EN.val(val));
        }
    }

    /// Allocate a tag, write an SQE entry, and ring the doorbell.
    #[allow(clippy::too_many_arguments)]
    fn submit(
        &self,
        src_addr: GdmaBuf,
        src_ifc: MemInterface,
        src_len: u32,
        dst_addr: GdmaBuf,
        dst_ifc: MemInterface,
        dst_len: u32,
        link: Option<u32>,
    ) -> HsmResult<u16> {
        if src_len == 0 || dst_len == 0 {
            return Err(GdmaError::ZERO_LENGTH);
        }
        if src_ifc.is_invalid_host() || dst_ifc.is_invalid_host() {
            return Err(GdmaError::INVALID_HOST_IFC);
        }

        self.state.with(|s| {
            if s.tag_free == 0 {
                return Err(GdmaError::NO_FREE_TAGS);
            }
            let tag = s.tag_free.trailing_zeros() as u16;
            s.tag_free &= !(1u32 << tag);

            let next_tail = (s.sq_tail + 1) & Self::MASK;
            if next_tail == s.sq_head_cached {
                s.sq_head_cached = unsafe { self.sq_head_shadow.read_volatile() } as u16;
                if next_tail == s.sq_head_cached {
                    s.sq_head_cached = self.regs.sq[self.channel as usize]
                        .head
                        .read(SQ_CHANNEL_HEAD::HEAD) as u16;
                    if next_tail == s.sq_head_cached {
                        s.tag_free |= 1u32 << tag;
                        return Err(GdmaError::SQ_FULL);
                    }
                }
            }

            let slot = (s.sq_tail & Self::MASK) as usize;
            let sq = unsafe { &mut *self.sq_ring.add(slot) };

            // Build the 16-DW SQ entry locally, then bulk-copy to MMIO.
            // This replaces ~24 individual STR instructions with 4 STM
            // (LDM from stack + STM to MMIO).
            let (src_fst_lo, src_fst_hi, src_snd_lo, src_snd_hi) = src_addr.to_dwords();
            let (dst_fst_lo, dst_fst_hi, dst_snd_lo, dst_snd_hi) = dst_addr.to_dwords();

            let ctrl = (tag as u32) << 16 | (src_addr.fmt_bit() << 11) | (dst_addr.fmt_bit() << 12);
            let src_ifc_val = src_ifc.ifc_slct() as u32;
            let dst_ifc_val = dst_ifc.ifc_slct() as u32;
            let ifc = src_ifc_val | (dst_ifc_val << 8) | (src_ifc_val << 16) | (dst_ifc_val << 24);

            let entry: [u32; 16] = [
                ctrl,       // DW0: ctrl
                ifc,        // DW1: ifc
                0,          // DW2: rsvd
                0,          // DW3: rsvd
                src_len,    // DW4: src_len
                dst_len,    // DW5: dst_len
                0,          // DW6: rsvd
                0,          // DW7: rsvd
                src_fst_lo, // DW8
                src_fst_hi, // DW9
                src_snd_lo, // DW10
                src_snd_hi, // DW11
                dst_fst_lo, // DW12
                dst_fst_hi, // DW13
                dst_snd_lo, // DW14
                dst_snd_hi, // DW15
            ];

            let sq_ptr = sq as *mut GdmaSqEntry as *mut u32;
            let sq_words = unsafe { core::slice::from_raw_parts_mut(sq_ptr, entry.len()) };
            tsra_fw_bulk_copy::copy_slice(sq_words, &entry);
            s.tags[tag as usize].link = link;

            // Ensure SQ entry write is visible to HW before doorbell
            cortex_m::asm::dmb();

            s.sq_tail = next_tail;
            self.regs.sq[self.channel as usize]
                .tail
                .write(SQ_CHANNEL_TAIL::TAIL.val(s.sq_tail.into()));

            Ok(tag)
        })
    }

    /// Submit a DMA copy from `src` to `dst` and await completion.
    ///
    /// Submits on the first poll, then checks for completion on subsequent
    /// polls. This avoids constructing a separate submit + wait future.
    ///
    /// # Errors
    ///
    /// Returns immediately:
    /// - [`GdmaError::ZERO_LENGTH`] — `src_len` or `dst_len` is zero.
    /// - [`GdmaError::INVALID_HOST_IFC`] — `Host { ctrl_id: 0 }` used.
    /// - [`GdmaError::NO_FREE_TAGS`] — all tag slots are in use.
    /// - [`GdmaError::SQ_FULL`] — SQ ring buffer is full.
    ///
    /// Returns on await:
    /// - [`GdmaError::dma_error`] — hardware reported an error.
    pub fn copy_mem(
        &self,
        src_addr: GdmaBuf,
        src_ifc: MemInterface,
        src_len: u32,
        dst_addr: GdmaBuf,
        dst_ifc: MemInterface,
        dst_len: u32,
    ) -> HsmResult<impl core::future::Future<Output = HsmResult<()>> + '_> {
        let tag = self.submit(src_addr, src_ifc, src_len, dst_addr, dst_ifc, dst_len, None)?;
        Ok(poll_fn(move |cx| {
            self.poll_tag(tag, cx).map(|r| r.map(|_| ()))
        }))
    }

    /// [`copy_mem`](Self::copy_mem), then start the follow-on work `link`
    /// as soon as the copy succeeds, from [`wake_with`](Self::wake_with)
    /// rather than when the awaiting task next runs.
    ///
    /// `link` is opaque here: it is passed to `wake_with`'s `start`, and
    /// what that returns (`None` if it started nothing) is the future's
    /// output. The future resolves once the copy has completed; when the
    /// follow-on started, `start` was handed the awaiting task's waker, so
    /// the task is next woken by the follow-on's own completion.
    ///
    /// # Errors
    ///
    /// As [`copy_mem`](Self::copy_mem).
    #[allow(clippy::too_many_arguments)]
    pub fn copy_mem_linked(
        &self,
        src_addr: GdmaBuf,
        src_ifc: MemInterface,
        src_len: u32,
        dst_addr: GdmaBuf,
        dst_ifc: MemInterface,
        dst_len: u32,
        link: u32,
    ) -> HsmResult<impl core::future::Future<Output = HsmResult<Option<u16>>> + '_> {
        let tag = self.submit(
            src_addr,
            src_ifc,
            src_len,
            dst_addr,
            dst_ifc,
            dst_len,
            Some(link),
        )?;
        Ok(poll_fn(move |cx| self.poll_tag(tag, cx)))
    }

    /// [`copy_mem_linked`](Self::copy_mem_linked) that no future awaits:
    /// the copy's completion goes to [`wake_with`](Self::wake_with)'s
    /// `done`, which gets `link` and whether the copy succeeded, and the
    /// tag is freed there.
    ///
    /// # Errors
    ///
    /// As [`copy_mem`](Self::copy_mem), when submitting.
    #[allow(clippy::too_many_arguments)]
    pub fn copy_mem_detached(
        &self,
        src_addr: GdmaBuf,
        src_ifc: MemInterface,
        src_len: u32,
        dst_addr: GdmaBuf,
        dst_ifc: MemInterface,
        dst_len: u32,
        link: u32,
    ) -> HsmResult<()> {
        let tag = self.submit(
            src_addr,
            src_ifc,
            src_len,
            dst_addr,
            dst_ifc,
            dst_len,
            Some(link),
        )?;
        self.state.with(|s| s.tags[tag as usize].detached = true);
        Ok(())
    }

    /// Poll `tag` for completion, freeing it once complete.
    fn poll_tag(&self, tag: u16, cx: &mut Context<'_>) -> Poll<HsmResult<Option<u16>>> {
        self.state.with(|s| {
            let slot = &mut s.tags[tag as usize];
            if slot.completed {
                let status = slot.status;
                let linked = slot.linked.take();
                slot.completed = false;
                s.tag_free |= 1u32 << tag;
                return Poll::Ready(if status == 0 {
                    Ok(linked)
                } else {
                    Err(GdmaError::dma_error(status))
                });
            }
            slot.register(cx.waker());
            Poll::Pending
        })
    }

    /// Drain all available CQ entries and wake their awaiters.
    ///
    /// Processes every pending completion in one call, amortizing the
    /// SingleCell borrow and batching the MMIO head pointer write.
    /// Call from the GDMA_CQ IRQ handler or the main poll loop.
    pub fn wake(&self, irq: u16) {
        self.wake_with(irq, |_, _| None, |_, _| {});
    }

    /// [`wake`](Self::wake), first starting the follow-on of each
    /// successful [linked](Self::copy_mem_linked) copy:
    /// `start(link, waker)` gets the copy's `link` and the waker of the
    /// task awaiting it, and returns what it started. If it started
    /// something, it has taken over waking the task, so the copy's
    /// completion does not wake it. Each [detached](Self::copy_mem_detached)
    /// copy's completion goes to `done(link, succeeded)` instead.
    pub fn wake_with(
        &self,
        irq: u16,
        mut start: impl FnMut(u32, Option<&Waker>) -> Option<u16>,
        mut done: impl FnMut(u32, bool),
    ) {
        self.state.with(|s| {
            let tail = unsafe { self.cq_tail_shadow.read_volatile() } as u16;

            while s.cq_head != tail {
                let cq_slot = (s.cq_head & Self::MASK) as usize;
                // SAFETY: `cq_slot` is within the ring.
                let entry = unsafe { self.cq_ring.add(cq_slot) };
                // When the next entry is posted too and follows this one in
                // memory, one burst reads both status words.
                if (s.cq_head + 1) & Self::MASK != tail && cq_slot + 1 < DEPTH {
                    // SAFETY: `entry` and the entry after it lie in the ring.
                    let (first, second) = unsafe { read_status_pair(entry) };
                    Self::complete(s, first, &mut start, &mut done);
                    Self::complete(s, second, &mut start, &mut done);
                } else {
                    // SAFETY: `entry` lies in the ring.
                    let status = unsafe { &*entry }.status.get();
                    Self::complete(s, status, &mut start, &mut done);
                }
            }

            self.regs.cq[self.channel as usize]
                .head
                .write(CQ_CHANNEL_HEAD::HEAD.val(s.cq_head.into()));
            tsra_fw_uno_drivers_nvic::Nvic::unpend_raw(irq);
        });
    }

    /// Consume the CQ entry at the head, whose status word is `status`:
    /// record the copy's outcome, start its follow-on through `start` (see
    /// [`wake_with`](Self::wake_with)) and wake the task awaiting it.
    fn complete(
        s: &mut GdmaState<DEPTH>,
        status: u32,
        start: &mut impl FnMut(u32, Option<&Waker>) -> Option<u16>,
        done: &mut impl FnMut(u32, bool),
    ) {
        let st = LocalRegisterCopy::<u32, GDMA_CQ_STATUS::Register>::new(status);
        let tag = st.read(GDMA_CQ_STATUS::TAG) as u16;
        let status = if st.read(GDMA_CQ_STATUS::SUCCESS) != 0 {
            0u8
        } else {
            1u8
        };

        s.cq_head = (s.cq_head + 1) & Self::MASK;

        if (tag as usize) < DEPTH {
            let slot = &mut s.tags[tag as usize];
            if slot.detached {
                slot.detached = false;
                let link = slot.link.take().unwrap_or_default();
                s.tag_free |= 1u32 << tag;
                done(link, status == 0);
                return;
            }
            slot.status = status;
            slot.completed = true;
            if let Some(link) = slot.link.take() {
                if status == 0 {
                    slot.linked = start(link, slot.waker.as_ref());
                }
            }
            if slot.linked.is_some() {
                slot.waker = None;
            } else if let Some(waker) = slot.waker.take() {
                waker.wake();
            }
        }
    }
}

/// Reads the status words of the CQ entry at `p` and the one after it with
/// one five-word burst: the ring sits in memory CP1 reads uncached, where
/// each load costs tens of cycles whatever its width but a burst costs
/// little more than one.
///
/// # Safety
///
/// `p` and `p.add(1)` must point to CQ entries.
#[inline(always)]
unsafe fn read_status_pair(p: *const GdmaCqEntry) -> (u32, u32) {
    const _ASSERT_ENTRY_WORDS: () = assert!(core::mem::size_of::<GdmaCqEntry>() == 16);
    #[cfg(target_arch = "arm")]
    {
        let (first, second): (u32, u32);
        // SAFETY: per the function contract; a CQ entry is four words, so
        // the next entry's status is the fifth word.
        unsafe {
            core::arch::asm!(
                "ldm {p}, {{r0, r1, r2, r3, r4}}",
                p = in(reg) p,
                out("r0") first,
                out("r1") _,
                out("r2") _,
                out("r3") _,
                out("r4") second,
                options(nostack, readonly, preserves_flags),
            );
        }
        (first, second)
    }
    #[cfg(not(target_arch = "arm"))]
    {
        // SAFETY: per the function contract.
        unsafe { ((*p).status.get(), (*p.add(1)).status.get()) }
    }
}
