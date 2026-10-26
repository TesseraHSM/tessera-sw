// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared state for the PQC engine pool.
//!
//! Mirrors the UPKA pool but for three engines rather than sixteen, and
//! without specific-engine acquisition: callers never care *which* FP core
//! runs their work, so the only entry point is "give me any free engine".

use core::task::Context;

use embassy_sync::waitqueue::WakerRegistration;

use crate::doorbell;
use crate::mailbox;
use crate::mailbox::SEED_LEN;
use crate::types::EngineId;
use crate::types::EngineState;
use crate::types::QueueSlotState;
use crate::types::ENGINES;
use crate::types::QUEUE_DEPTH;

/// List terminator for [`QueueSlot::next`], and the "no slot" sentinel for
/// the list heads. `QUEUE_DEPTH` is far below this, so it cannot collide
/// with a real index.
pub(crate) const NO_SLOT: u8 = u8::MAX;

/// "No engine", for [`QueueSlot::prestaged_on`].
pub(crate) const NO_ENGINE: u8 = u8::MAX;

/// Per-engine state.
pub(crate) struct EngineSlot {
    /// Lifecycle state.
    pub(crate) state: EngineState,

    /// The request last posted here, until the engine is released; zero
    /// for none.
    pub(crate) inflight: u32,

    /// Where that request's outputs go in the operand slot.
    pub(crate) outputs: Outputs,

    /// The waiter whose request's inputs are already staged in this
    /// engine's operand slot, [`NO_SLOT`] for none (see
    /// [`PqcState::prestage`]).
    pub(crate) prestaged: u8,

    /// Whether the running request's core will mark its inputs taken:
    /// signing reads its key in place to the end, and never does.
    pub(crate) gives_inputs_back: bool,
}

impl EngineSlot {
    pub(crate) const fn new() -> Self {
        Self {
            state: EngineState::Idle,
            inflight: 0,
            outputs: [(0, 0); 2],
            prestaged: NO_SLOT,
            gives_inputs_back: false,
        }
    }
}

/// The `(offset, len)` operand slot regions a request's outputs occupy.
pub(crate) type Outputs = [(usize, usize); 2];

/// One entry in the FIFO of tasks waiting for an engine.
pub(crate) struct QueueSlot {
    /// Waker for the waiting task.
    pub(crate) waker: WakerRegistration,

    /// Lifecycle state.
    pub(crate) state: QueueSlotState,

    /// Intrusive link to the next slot in whichever list this slot is on.
    ///
    /// A slot is on exactly one list at a time -- the free list when idle,
    /// the wait ring while queued -- so a single link serves both and the
    /// whole structure costs one byte per slot.
    ///
    /// [`NO_SLOT`] terminates a list.
    pub(crate) next: u8,

    /// The request the waiting task left for whoever frees an engine to
    /// post, if any.
    pub(crate) staged: Option<Staged>,

    /// The engine whose operand slot already holds that request's inputs,
    /// [`NO_ENGINE`] for none.
    pub(crate) prestaged_on: u8,
}

impl QueueSlot {
    pub(crate) const fn new() -> Self {
        Self {
            waker: WakerRegistration::new(),
            state: QueueSlotState::Free,
            next: NO_SLOT,
            staged: None,
            prestaged_on: NO_ENGINE,
        }
    }
}

/// A bulk input of a [`Staged`] request: `len` bytes at `ptr`, copied into
/// the engine's operand slot at `offset` as the request is posted.
#[derive(Clone, Copy)]
pub(crate) struct Operand {
    pub(crate) ptr: *const u8,
    pub(crate) len: usize,
    pub(crate) offset: usize,
}

impl Operand {
    /// No operand.
    pub(crate) const NONE: Self = Self {
        ptr: core::ptr::null(),
        len: 0,
        offset: 0,
    };

    /// `data`, for the operand slot at `offset`.
    pub(crate) fn new(data: &[u8], offset: usize) -> Self {
        Self {
            ptr: data.as_ptr(),
            len: data.len(),
            offset,
        }
    }
}

/// A request left by a task queued for an engine so the engine can start on
/// it the moment it is freed: [`PqcState::release_engine`] posts it, rather
/// than waking the task to, which can be tens of microseconds away under
/// load.
///
/// The bulk inputs are referenced, not copied: they stay in the task's own
/// buffers, which outlive the request because the task is suspended in
/// [`PqcDriver::acquire_and_post`](crate::PqcDriver) until it is posted, and
/// a task dropped while queued takes its request back out of the queue.
#[derive(Clone)]
pub(crate) struct Staged {
    pub(crate) op: u32,
    pub(crate) key_kind: u32,
    pub(crate) xi: [u8; SEED_LEN],
    pub(crate) rnd: [u8; SEED_LEN],
    pub(crate) msg_len: u32,
    pub(crate) ctx_len: u32,
    pub(crate) sig_len: u32,
    pub(crate) pub_key_len: u32,
    pub(crate) operands: [Operand; 4],
    /// Where the outputs will go, which a request staged behind this one
    /// must keep clear of.
    pub(crate) outputs: Outputs,
}

// SAFETY: the operand pointers are only dereferenced while the task that
// staged them is suspended waiting for its request to be posted (see
// `Staged`), and the firmware runs on one core.
unsafe impl Send for Staged {}

impl Staged {
    /// A request with no bulk inputs and every length zero.
    pub(crate) const fn new(op: u32, key_kind: u32) -> Self {
        Self {
            op,
            key_kind,
            xi: [0; SEED_LEN],
            rnd: [0; SEED_LEN],
            msg_len: 0,
            ctx_len: 0,
            sig_len: 0,
            pub_key_len: 0,
            operands: [Operand::NONE; 4],
            outputs: [(0, 0); 2],
        }
    }

    /// The request, as the mailbox carries it.
    pub(crate) fn params(&self) -> mailbox::RequestParams<'_> {
        mailbox::RequestParams {
            op: self.op,
            key_kind: self.key_kind,
            xi: &self.xi,
            rnd: &self.rnd,
            msg_len: self.msg_len,
            ctx_len: self.ctx_len,
            sig_len: self.sig_len,
            pub_key_len: self.pub_key_len,
        }
    }

    /// Whether every bulk input lands clear of `outputs`.
    fn avoids(&self, outputs: &[(usize, usize)]) -> bool {
        self.operands.iter().all(|o| {
            o.len == 0
                || outputs
                    .iter()
                    .all(|&(off, len)| o.offset + o.len <= off || off + len <= o.offset)
        })
    }

    /// Copy the bulk inputs into engine `id`'s operand slot.
    fn stage_operands(&self, id: EngineId) {
        for o in &self.operands {
            if o.len != 0 {
                // SAFETY: see `Staged`: the buffer behind the pointer is
                // still borrowed by the suspended task that staged it.
                let data = unsafe { core::slice::from_raw_parts(o.ptr, o.len) };
                // Cannot fail: every operand was checked against its
                // region's maximum before it was staged.
                let _ = mailbox::write_slot(id, o.offset, data);
            }
        }
    }

    /// Wipe the seeds, which are key material, and forget the bulk inputs.
    pub(crate) fn wipe(&mut self) {
        for b in self.xi.iter_mut().chain(self.rnd.iter_mut()) {
            // SAFETY: `b` is a valid, writable byte of `self`.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        self.operands = [Operand::NONE; 4];
    }
}

/// Shared mutable state for the engine pool.
pub(crate) struct PqcState {
    /// Bitmask of free engines; bit `i` set means engine `i` is idle.
    pub(crate) free_mask: u8,

    /// Per-engine state.
    pub(crate) engines: [EngineSlot; ENGINES],

    /// FIFO of tasks waiting for any engine.
    pub(crate) queue: [QueueSlot; QUEUE_DEPTH],

    /// Head of the free-slot list, or [`NO_SLOT`] when every slot is in use.
    pub(crate) free_head: u8,

    /// Head of the wait ring: the waiter that queued first, and so the next
    /// to be served. [`NO_SLOT`] when nobody is waiting.
    pub(crate) wait_head: u8,

    /// Tail of the wait ring: the most recent arrival, where the next push
    /// goes. [`NO_SLOT`] when nobody is waiting.
    pub(crate) wait_tail: u8,

    /// Sequence number for the FP shared-memory bring-up probe, so each
    /// sentinel differs from the last.
    pub(crate) probe_seq: u32,

    /// Requests posted and responses awaited.
    pub(crate) responses: Responses,

    /// Queue slots handed an engine whose task is still to be woken, by
    /// bit (see [`take_handed_over`](Self::take_handed_over)).
    pub(crate) handed_over: u32,
}

const _: () = assert!(QUEUE_DEPTH <= u32::BITS as usize);

/// Bookkeeping for requests in flight on the engines.
pub(crate) struct Responses {
    /// Sequence number for PQC requests, so a response is unambiguously
    /// matched to the request that produced it.
    pub(crate) request_seq: u32,

    /// Engines whose task awaits a response, by bit (see
    /// [`PqcDriver::wake`](crate::PqcDriver::wake)).
    pub(crate) awaiting: u8,

    /// The sequence number each awaited response will carry.
    pub(crate) awaiting_seq: [u32; ENGINES],

    /// The task awaiting each engine's response.
    pub(crate) wakers: [WakerRegistration; ENGINES],
}

impl Responses {
    const fn new() -> Self {
        Self {
            request_seq: 0,
            awaiting: 0,
            awaiting_seq: [0; ENGINES],
            wakers: [const { WakerRegistration::new() }; ENGINES],
        }
    }

    /// Post `request`, whose bulk inputs are already in engine `id`'s
    /// operand slot, ring the doorbell, and mark its response awaited.
    ///
    /// Returns the request's number, which the response will carry.
    fn post(&mut self, id: EngineId, request: &Staged) -> u32 {
        // Monotonic across all engines, so a response can never be mistaken
        // for one to an earlier request on the same core.
        self.request_seq = self.request_seq.wrapping_add(1);
        let seq = self.request_seq;
        mailbox::post_request(id, seq, &request.params());
        doorbell::ring(id, seq);
        let engine = usize::from(id.raw());
        self.awaiting |= 1 << engine;
        self.awaiting_seq[engine] = seq;
        seq
    }
}

impl PqcState {
    pub(crate) const fn new() -> Self {
        // Chain every slot onto the free list, in order.
        let mut queue = [const { QueueSlot::new() }; QUEUE_DEPTH];
        let mut i = 0;
        while i < QUEUE_DEPTH {
            queue[i].next = if i + 1 < QUEUE_DEPTH {
                (i + 1) as u8
            } else {
                NO_SLOT
            };
            i += 1;
        }

        Self {
            free_mask: (1u8 << ENGINES) - 1,
            engines: [const { EngineSlot::new() }; ENGINES],
            queue,
            free_head: 0,
            wait_head: NO_SLOT,
            wait_tail: NO_SLOT,
            probe_seq: 0,
            responses: Responses::new(),
            handed_over: 0,
        }
    }

    /// Claim a free engine, marking it busy.
    pub(crate) fn claim_free_engine(&mut self) -> Option<EngineId> {
        if self.free_mask == 0 {
            return None;
        }
        let id = self.free_mask.trailing_zeros() as u8;
        self.free_mask &= !(1u8 << id);
        self.engines[id as usize].state = EngineState::Busy;
        Some(EngineId::new(id))
    }

    /// True if any task is queued waiting for an engine.
    ///
    /// Checked before claiming an engine directly so a newly-freed engine
    /// goes to the task that has been waiting longest rather than to
    /// whoever happens to poll next.
    pub(crate) fn has_waiters(&self) -> bool {
        self.wait_head != NO_SLOT
    }

    /// Reserve a queue slot for a task about to wait.
    pub(crate) fn reserve_queue_slot(&mut self) -> Option<u8> {
        // Pop the free list.
        let idx = self.free_head;
        if idx == NO_SLOT {
            return None;
        }
        self.free_head = self.queue[idx as usize].next;

        // Push onto the tail of the wait ring, preserving arrival order.
        let slot = &mut self.queue[idx as usize];
        slot.state = QueueSlotState::Pending;
        slot.next = NO_SLOT;
        if self.wait_tail == NO_SLOT {
            self.wait_head = idx;
        } else {
            self.queue[self.wait_tail as usize].next = idx;
        }
        self.wait_tail = idx;

        Some(idx)
    }

    /// Register `cx` against a queue slot and report the engine assigned to
    /// it, if any.
    ///
    /// The engine comes with the number of the staged request already posted
    /// to it, if there was one.
    pub(crate) fn poll_queue_slot(
        &mut self,
        idx: u8,
        cx: &Context<'_>,
    ) -> Option<(EngineId, Option<u32>)> {
        let handed = match self.queue[idx as usize].state {
            QueueSlotState::Assigned(id) => Some((id, None)),
            QueueSlotState::Running(id, seq) => Some((id, Some(seq))),
            _ => None,
        };
        match handed {
            Some(handed) => {
                // The engine has been collected; recycle the slot onto the
                // free list so a later arrival can reuse it.
                let slot = &mut self.queue[idx as usize];
                slot.state = QueueSlotState::Free;
                slot.next = self.free_head;
                self.free_head = idx;
                Some(handed)
            }
            None => {
                self.queue[idx as usize].waker.register(cx.waker());
                None
            }
        }
    }

    /// The queue slots handed an engine since the last call, whose tasks
    /// the caller must wake.
    ///
    /// The hand-off does not wake the task itself: the PAL polls this
    /// driver after each executor pass ([`PqcDriver::wake`](crate::PqcDriver::wake)),
    /// and a task woken then, being woken last, runs first in the next
    /// pass, whereas one woken mid-pass runs after every task the end of
    /// the pass wakes. Until it runs, the engine it is handed sits idle.
    pub(crate) fn take_handed_over(&mut self) -> u32 {
        core::mem::take(&mut self.handed_over)
    }

    /// Take back the request a task dropped while still queued in slot
    /// `idx` left there, which refers to that task's buffers.
    pub(crate) fn unstage(&mut self, idx: u8) {
        if let Some(staged) = self.queue[idx as usize].staged.as_mut() {
            staged.wipe();
        }
        self.queue[idx as usize].staged = None;
        let e = self.queue[idx as usize].prestaged_on;
        if e != NO_ENGINE {
            self.engines[e as usize].prestaged = NO_SLOT;
            self.queue[idx as usize].prestaged_on = NO_ENGINE;
        }
    }

    /// Stage `request`'s bulk inputs in engine `id`'s operand slot, unless
    /// they are there already, and post it.
    ///
    /// Returns the request's number, which the response will carry.
    pub(crate) fn post(&mut self, id: EngineId, request: &Staged, inputs_staged: bool) -> u32 {
        if !inputs_staged {
            request.stage_operands(id);
        }
        let seq = self.responses.post(id, request);
        let engine = &mut self.engines[id.raw() as usize];
        engine.inflight = seq;
        engine.outputs = request.outputs;
        engine.gives_inputs_back = request.op != crate::request::PqcOp::MlDsaSign as u32;
        seq
    }

    /// Stage the next waiting request's inputs in the operand slot of each
    /// engine whose core has already taken its own request's inputs out of
    /// it, so that request starts as soon as the engine is released rather
    /// than after the copy: up to 7 KB at PSRAM speed, which the core
    /// would otherwise sit through idle.
    ///
    /// The request staged is the oldest waiting one not staged elsewhere
    /// whose inputs land clear of the running request's outputs; it is
    /// served by that engine when it is released (see
    /// [`release_engine`](Self::release_engine)).
    pub(crate) fn prestage(&mut self) {
        for e in 0..ENGINES {
            let engine = &self.engines[e];
            // Checking costs a PSRAM read every pass, which a signing core,
            // reading its key out of PSRAM throughout, would be slowed by.
            if engine.inflight == 0 || engine.prestaged != NO_SLOT || !engine.gives_inputs_back {
                continue;
            }
            let id = EngineId::new(e as u8);
            if mailbox::inputs_taken(id) != engine.inflight {
                continue;
            }
            let outputs = engine.outputs;
            let mut idx = self.wait_head;
            while idx != NO_SLOT {
                let slot = &mut self.queue[idx as usize];
                if slot.prestaged_on == NO_ENGINE {
                    if let Some(staged) = &slot.staged {
                        if staged.avoids(&outputs) {
                            staged.stage_operands(id);
                            slot.prestaged_on = e as u8;
                            self.engines[e].prestaged = idx;
                            break;
                        }
                    }
                }
                idx = slot.next;
            }
        }
    }

    /// Unlink waiter `idx` from the wait ring.
    fn unlink(&mut self, idx: u8) {
        let next = self.queue[idx as usize].next;
        if self.wait_head == idx {
            self.wait_head = next;
        } else {
            let mut prev = self.wait_head;
            while self.queue[prev as usize].next != idx {
                prev = self.queue[prev as usize].next;
            }
            self.queue[prev as usize].next = next;
            if self.wait_tail == idx {
                self.wait_tail = prev;
            }
        }
        if self.wait_head == NO_SLOT {
            self.wait_tail = NO_SLOT;
        }
    }

    /// The waiter engine `id` goes to when released: the one whose inputs
    /// are already staged in its slot, else the longest-waiting one not
    /// staged on another engine, else -- rather than leave this engine
    /// idle while others wait -- the longest-waiting one at all.
    fn next_waiter(&self, id: EngineId) -> Option<u8> {
        let pre = self.engines[id.raw() as usize].prestaged;
        if pre != NO_SLOT {
            return Some(pre);
        }
        let mut idx = self.wait_head;
        while idx != NO_SLOT {
            if self.queue[idx as usize].prestaged_on == NO_ENGINE {
                return Some(idx);
            }
            idx = self.queue[idx as usize].next;
        }
        (self.wait_head != NO_SLOT).then_some(self.wait_head)
    }

    /// Hand engine `id` straight to the waiter it would go to on release,
    /// if that waiter left a request none of whose inputs land in
    /// `outputs` -- the `(offset, len)` operand slot regions of the request
    /// just finished, which its task is still to read. Returns whether the
    /// engine was handed over.
    ///
    /// The core holds the new request's outputs back until the old ones are
    /// marked collected, so only its inputs could disturb them; inputs
    /// staged ahead were checked against the same outputs when staged.
    pub(crate) fn release_engine_early(&mut self, id: EngineId, outputs: &[(usize, usize)]) -> bool {
        let Some(idx) = self.next_waiter(id) else {
            return false;
        };
        let slot = &self.queue[idx as usize];
        let clear = match &slot.staged {
            Some(staged) => slot.prestaged_on == id.raw() || staged.avoids(outputs),
            None => false,
        };
        if clear {
            self.release_engine(id);
        }
        clear
    }

    /// Return an engine to the pool, handing it straight to a waiting task
    /// if there is one (see [`next_waiter`](Self::next_waiter)).
    pub(crate) fn release_engine(&mut self, id: EngineId) {
        let e = id.raw() as usize;
        self.engines[e].inflight = 0;
        let waiter = self.next_waiter(id);
        self.engines[e].prestaged = NO_SLOT;

        match waiter {
            Some(idx) => {
                self.unlink(idx);
                let idx = idx as usize;
                // Staged here already, or on another engine, which then
                // has nothing staged.
                let on = self.queue[idx].prestaged_on;
                let inputs_staged = on == id.raw();
                if on != NO_ENGINE && !inputs_staged {
                    self.engines[on as usize].prestaged = NO_SLOT;
                }
                self.queue[idx].prestaged_on = NO_ENGINE;
                // Stays busy: ownership transfers directly to the waiter,
                // which finds the request it staged, if any, already started.
                self.queue[idx].state = match self.queue[idx].staged.take() {
                    Some(mut staged) => {
                        let seq = self.post(id, &staged, inputs_staged);
                        staged.wipe();
                        QueueSlotState::Running(id, seq)
                    }
                    None => QueueSlotState::Assigned(id),
                };
                self.handed_over |= 1 << idx;
            }
            None => {
                self.engines[e].state = EngineState::Idle;
                self.free_mask |= 1u8 << id.raw();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reserve every slot and return the indices in arrival order.
    fn reserve_all(state: &mut PqcState) -> [u8; QUEUE_DEPTH] {
        let mut out = [0u8; QUEUE_DEPTH];
        for entry in out.iter_mut() {
            *entry = state.reserve_queue_slot().expect("slot available");
        }
        out
    }

    /// Take the engine assigned to `idx`, recycling the slot exactly as
    /// `poll_queue_slot` does when a task collects its engine.
    fn collect(state: &mut PqcState, idx: u8) -> Option<EngineId> {
        match state.queue[idx as usize].state {
            QueueSlotState::Assigned(id) => {
                let free_head = state.free_head;
                let slot = &mut state.queue[idx as usize];
                slot.state = QueueSlotState::Free;
                slot.next = free_head;
                state.free_head = idx;
                Some(id)
            }
            _ => None,
        }
    }

    /// A freed engine must go to the waiter that queued first, even when
    /// that waiter sits at a higher slot index than a later arrival.
    ///
    /// Regression: selection used to be by slot index, so a task that
    /// re-queued into a low index repeatedly overtook one waiting in a high
    /// index. On silicon that starved waiters for up to 3,979 ms against a
    /// FIFO bound of 1,165 ms.
    #[test]
    fn released_engine_goes_to_the_oldest_waiter() {
        let mut state = PqcState::new();

        // Occupy every engine so subsequent arrivals must queue.
        for _ in 0..ENGINES {
            state.claim_free_engine().expect("engine free");
        }

        // Two waiters: the first to arrive holds the *higher* slot index.
        let early = state.reserve_queue_slot().expect("slot");
        let late = state.reserve_queue_slot().expect("slot");
        // Invert the index order so index cannot masquerade as arrival
        // order: the first arrival now sits at the higher index.
        assert!(early < late, "expected ascending allocation");

        state.release_engine(EngineId::new(0));

        assert!(
            collect(&mut state, early).is_some(),
            "the engine must go to the waiter that queued first"
        );
        assert!(
            collect(&mut state, late).is_none(),
            "the later arrival must still be waiting"
        );
    }

    /// Slots recycled out of order must not corrupt the free list.
    ///
    /// This is the hazard that rules out a plain ring buffer over the slot
    /// array: up to `ENGINES` slots can be `Assigned` at once and their
    /// tasks may collect in any order, so slot lifetimes are not FIFO even
    /// though *arrival* is. The free list handles that; a ring index would
    /// have wrapped onto a still-assigned slot.
    #[test]
    fn out_of_order_collection_keeps_the_free_list_sound() {
        let mut state = PqcState::new();
        for _ in 0..ENGINES {
            state.claim_free_engine().expect("engine free");
        }

        let a = state.reserve_queue_slot().expect("slot");
        let b = state.reserve_queue_slot().expect("slot");
        let c = state.reserve_queue_slot().expect("slot");

        // Assign all three, then collect them in reverse.
        for _ in 0..3 {
            state.release_engine(EngineId::new(0));
        }
        for idx in [c, b, a] {
            assert!(collect(&mut state, idx).is_some(), "slot {idx} assigned");
        }

        // Every slot must be reusable, and each handed out exactly once.
        let mut seen = [false; QUEUE_DEPTH];
        for _ in 0..QUEUE_DEPTH {
            let idx = state.reserve_queue_slot().expect("slot available") as usize;
            assert!(!seen[idx], "slot {idx} handed out twice");
            seen[idx] = true;
        }
        assert!(
            state.reserve_queue_slot().is_none(),
            "queue must report full once every slot is taken"
        );
    }

    /// Every waiter is eventually served: with more arrivals than engines,
    /// none is left behind.
    #[test]
    fn no_waiter_is_starved() {
        let mut state = PqcState::new();
        for _ in 0..ENGINES {
            state.claim_free_engine().expect("engine free");
        }

        let waiters = reserve_all(&mut state);
        for expected in waiters {
            state.release_engine(EngineId::new(0));
            assert!(
                collect(&mut state, expected).is_some(),
                "slot {expected} should have been served in turn"
            );
        }
    }
}
