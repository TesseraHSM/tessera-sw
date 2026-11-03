// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared state for the PQC engine pool.
//!
//! Mirrors the UPKA pool but for three engines rather than sixteen, and
//! without specific-engine acquisition: callers never care *which* FP core
//! runs their work, so the only entry point is "give me any free engine".

use core::task::Context;
use core::task::Poll;

use embassy_sync::waitqueue::WakerRegistration;
use tsra_fw_hsm_pal_traits::HsmResult;

use crate::error::PqcError;
use crate::types::EngineId;
use crate::types::EngineState;
use crate::types::QueueSlotState;
use crate::types::ENGINES;
use crate::types::QUEUE_DEPTH;

/// List terminator for [`QueueSlot::next`], and the "no slot" sentinel for
/// the list heads. `QUEUE_DEPTH` is far below this, so it cannot collide
/// with a real index.
pub(crate) const NO_SLOT: u8 = u8::MAX;

/// Per-engine state.
pub(crate) struct EngineSlot {
    /// Lifecycle state.
    pub(crate) state: EngineState,
}

impl EngineSlot {
    pub(crate) const fn new() -> Self {
        Self {
            state: EngineState::Idle,
        }
    }
}

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
}

impl QueueSlot {
    pub(crate) const fn new() -> Self {
        Self {
            waker: WakerRegistration::new(),
            state: QueueSlotState::Free,
            next: NO_SLOT,
        }
    }
}

/// Shared mutable state for the engine pool.
/// Outcome of one [`PqcState::poll_acquire`].
pub(crate) enum Acquire {
    /// Finished: the engine claimed, or why none can be.
    Done(HsmResult<EngineId>),

    /// Still queued, at the head while an engine drains: look again after a
    /// pause. Nothing signals a core's late answer, and polling on every
    /// executor pass would spin.
    Reap,
}

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

    /// Sequence number for PQC requests, so a response is unambiguously
    /// matched to the request that produced it.
    pub(crate) request_seq: u32,
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
            request_seq: 0,
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
    pub(crate) fn poll_queue_slot(&mut self, idx: u8, cx: &Context<'_>) -> Option<EngineId> {
        match self.queue[idx as usize].state {
            QueueSlotState::Assigned(id) => {
                // The engine has been collected; recycle the slot onto the
                // free list so a later arrival can reuse it.
                let slot = &mut self.queue[idx as usize];
                slot.state = QueueSlotState::Free;
                slot.next = self.free_head;
                self.free_head = idx;
                Some(id)
            }
            _ => {
                self.queue[idx as usize].waker.register(cx.waker());
                None
            }
        }
    }

    /// Return an engine to the pool, handing it straight to the
    /// longest-waiting task if there is one.
    pub(crate) fn release_engine(&mut self, id: EngineId) {
        // The head of the wait ring is by construction the waiter that
        // queued first, so serving it is both fair and O(1).
        let waiter = if self.wait_head == NO_SLOT {
            None
        } else {
            let idx = self.wait_head;
            self.wait_head = self.queue[idx as usize].next;
            if self.wait_head == NO_SLOT {
                self.wait_tail = NO_SLOT;
            }
            Some(idx as usize)
        };

        match waiter {
            Some(idx) => {
                // Ownership transfers directly to the waiter. Marked busy
                // explicitly: a reclaimed engine arrives here draining.
                self.engines[id.raw() as usize].state = EngineState::Busy;
                self.queue[idx].state = QueueSlotState::Assigned(id);
                self.queue[idx].waker.wake();
                self.wake_head_if_draining();
            }
            None => {
                self.engines[id.raw() as usize].state = EngineState::Idle;
                self.free_mask |= 1u8 << id.raw();
            }
        }
    }

    /// Withhold an engine released while request `seq` may still be running
    /// on its core; see [`EngineState::Draining`].
    ///
    /// Wakes every waiter: the head starts watching for the core's answer,
    /// and if no engine is left that will ever be released, all give up
    /// (see [`poll_acquire`](Self::poll_acquire)).
    pub(crate) fn quarantine_engine(&mut self, id: EngineId, seq: u32) {
        self.engines[id.raw() as usize].state = EngineState::Draining(seq);
        let mut idx = self.wait_head;
        while idx != NO_SLOT {
            self.queue[idx as usize].waker.wake();
            idx = self.queue[idx as usize].next;
        }
    }

    /// True if any engine is draining.
    pub(crate) fn has_draining(&self) -> bool {
        self.engines
            .iter()
            .any(|e| matches!(e.state, EngineState::Draining(_)))
    }

    /// True if every engine is draining, so none is idle and none will be
    /// released until a core answers a request it has already missed the
    /// deadline for.
    pub(crate) fn all_draining(&self) -> bool {
        self.engines
            .iter()
            .all(|e| matches!(e.state, EngineState::Draining(_)))
    }

    /// Return draining engines whose cores have since answered.
    ///
    /// `answered(id, seq)` reports whether core `id` has answered request
    /// `seq`; `scrub(id)` wipes what the request left in shared memory and
    /// runs before the engine is handed on.
    pub(crate) fn reclaim_drained(
        &mut self,
        mut answered: impl FnMut(EngineId, u32) -> bool,
        mut scrub: impl FnMut(EngineId),
    ) {
        for i in 0..ENGINES {
            if let EngineState::Draining(seq) = self.engines[i].state {
                let id = EngineId::new(i as u8);
                if answered(id, seq) {
                    scrub(id);
                    self.release_engine(id);
                }
            }
        }
    }

    /// Withdraw the waiter in queue slot `idx`, which has stopped waiting.
    ///
    /// An engine already handed to it goes to the next waiter instead, so a
    /// waiter that leaves cannot strand one.
    pub(crate) fn cancel_wait(&mut self, idx: u8) {
        match self.queue[idx as usize].state {
            QueueSlotState::Free => return,
            QueueSlotState::Pending => {
                let was_head = self.wait_head == idx;
                self.unlink_waiter(idx);
                if was_head {
                    self.wake_head_if_draining();
                }
            }
            // Left the wait ring when it was assigned.
            QueueSlotState::Assigned(id) => self.release_engine(id),
        }
        let slot = &mut self.queue[idx as usize];
        slot.state = QueueSlotState::Free;
        slot.next = self.free_head;
        self.free_head = idx;
    }

    /// One poll of [`PqcDriver::acquire_any`](crate::PqcDriver::acquire_any)
    /// for the waiter whose queue slot is `slot` (`None` until it queues).
    ///
    /// `answered` and `scrub` are as for [`reclaim_drained`](Self::reclaim_drained).
    pub(crate) fn poll_acquire(
        &mut self,
        slot: &mut Option<u8>,
        cx: &Context<'_>,
        answered: impl FnMut(EngineId, u32) -> bool,
        scrub: impl FnMut(EngineId),
    ) -> Poll<Acquire> {
        self.reclaim_drained(answered, scrub);

        let idx = match *slot {
            // Already queued: take the engine if one has been handed over.
            Some(idx) => {
                if let Some(id) = self.poll_queue_slot(idx, cx) {
                    *slot = None;
                    return Poll::Ready(Acquire::Done(Ok(id)));
                }
                idx
            }
            None => {
                // Fast path, but only when nobody is waiting -- otherwise a
                // task arriving now would jump the queue.
                if !self.has_waiters() {
                    if let Some(id) = self.claim_free_engine() {
                        return Poll::Ready(Acquire::Done(Ok(id)));
                    }
                }
                if self.all_draining() {
                    return Poll::Ready(Acquire::Done(Err(PqcError::FP_NOT_READY)));
                }
                let Some(idx) = self.reserve_queue_slot() else {
                    return Poll::Ready(Acquire::Done(Err(PqcError::QUEUE_FULL)));
                };
                *slot = Some(idx);
                self.poll_queue_slot(idx, cx);
                idx
            }
        };

        // No engine will be released until a core answers a request it has
        // already missed its deadline for: give up rather than wait forever.
        if self.all_draining() {
            self.cancel_wait(idx);
            *slot = None;
            return Poll::Ready(Acquire::Done(Err(PqcError::FP_NOT_READY)));
        }
        // Only the head waiter watches draining engines; the rest sleep until
        // an engine is handed over or the head moves on.
        if self.wait_head == idx && self.has_draining() {
            return Poll::Ready(Acquire::Reap);
        }
        Poll::Pending
    }

    /// Wake the head waiter if an engine is draining, so it takes over
    /// watching it from a waiter that has just left the head.
    fn wake_head_if_draining(&mut self) {
        if self.wait_head != NO_SLOT && self.has_draining() {
            self.queue[self.wait_head as usize].waker.wake();
        }
    }

    /// Remove `idx` from the wait ring.
    fn unlink_waiter(&mut self, idx: u8) {
        let mut prev = NO_SLOT;
        let mut cur = self.wait_head;
        while cur != NO_SLOT && cur != idx {
            prev = cur;
            cur = self.queue[cur as usize].next;
        }
        if cur != idx {
            return;
        }
        let next = self.queue[idx as usize].next;
        if prev == NO_SLOT {
            self.wait_head = next;
        } else {
            self.queue[prev as usize].next = next;
        }
        if self.wait_tail == idx {
            self.wait_tail = prev;
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

    /// An engine released with a request still running stays out of the
    /// pool until its core answers, and is scrubbed before anyone gets it.
    #[test]
    fn draining_engine_waits_for_its_core_and_is_scrubbed() {
        let mut state = PqcState::new();
        for _ in 0..ENGINES {
            state.claim_free_engine().expect("engine free");
        }
        let waiter = state.reserve_queue_slot().expect("slot");

        state.quarantine_engine(EngineId::new(1), 7);
        state.reclaim_drained(
            |_, _| false,
            |_| panic!("scrubbed before the core answered"),
        );
        assert!(state.has_draining());
        assert!(
            collect(&mut state, waiter).is_none(),
            "a draining engine must not be handed out"
        );

        let mut scrubbed = None;
        state.reclaim_drained(
            |id, seq| id == EngineId::new(1) && seq == 7,
            |id| scrubbed = Some(id),
        );
        assert_eq!(scrubbed, Some(EngineId::new(1)));
        assert!(!state.has_draining());
        assert_eq!(collect(&mut state, waiter), Some(EngineId::new(1)));
        assert_eq!(state.engines[1].state, EngineState::Busy);
    }

    /// Only when every engine is draining is there nothing left to wait for.
    #[test]
    fn all_draining_only_when_every_engine_is() {
        let mut state = PqcState::new();
        for _ in 0..ENGINES {
            state.claim_free_engine().expect("engine free");
        }
        for i in 0..ENGINES as u8 - 1 {
            state.quarantine_engine(EngineId::new(i), u32::from(i));
        }
        assert!(!state.all_draining());
        state.quarantine_engine(EngineId::new(ENGINES as u8 - 1), 9);
        assert!(state.all_draining());
    }

    /// A waiter that leaves is skipped, and one that leaves after being
    /// handed an engine passes it on instead of stranding it.
    #[test]
    fn cancelled_waiters_leave_the_queue_and_pass_on_engines() {
        let mut state = PqcState::new();
        for _ in 0..ENGINES {
            state.claim_free_engine().expect("engine free");
        }

        let a = state.reserve_queue_slot().expect("slot");
        let b = state.reserve_queue_slot().expect("slot");
        let c = state.reserve_queue_slot().expect("slot");
        state.cancel_wait(b);
        state.release_engine(EngineId::new(0));
        assert_eq!(collect(&mut state, a), Some(EngineId::new(0)));
        state.release_engine(EngineId::new(1));
        assert_eq!(collect(&mut state, c), Some(EngineId::new(1)));
        assert!(!state.has_waiters());

        let d = state.reserve_queue_slot().expect("slot");
        let e = state.reserve_queue_slot().expect("slot");
        state.release_engine(EngineId::new(2));
        state.cancel_wait(d);
        assert_eq!(collect(&mut state, e), Some(EngineId::new(2)));

        // Every slot is back on the free list.
        reserve_all(&mut state);
    }

    /// A context whose waker does nothing, for driving `poll_acquire`.
    fn noop_cx() -> Context<'static> {
        Context::from_waker(core::task::Waker::noop())
    }

    /// Only the head waiter watches a draining engine; once the head is
    /// served the next waiter takes over, and stops when nothing drains.
    #[test]
    fn only_the_head_waiter_watches_draining_engines() {
        let mut state = PqcState::new();
        for _ in 0..ENGINES {
            state.claim_free_engine().expect("engine free");
        }
        state.quarantine_engine(EngineId::new(0), 1);
        let cx = noop_cx();
        let never = |_: EngineId, _: u32| false;

        let mut head = None;
        let mut next = None;
        let first = state.poll_acquire(&mut head, &cx, never, |_| {});
        assert!(matches!(first, Poll::Ready(Acquire::Reap)));
        assert!(state
            .poll_acquire(&mut next, &cx, never, |_| {})
            .is_pending());

        // The core answers: the head collects the scrubbed engine, and with
        // nothing left draining the next waiter simply waits.
        let got = state.poll_acquire(&mut head, &cx, |_, seq| seq == 1, |_| {});
        assert!(matches!(got, Poll::Ready(Acquire::Done(Ok(id))) if id == EngineId::new(0)));
        assert!(state
            .poll_acquire(&mut next, &cx, never, |_| {})
            .is_pending());

        // Another engine drains: the waiter now at the head watches it.
        state.quarantine_engine(EngineId::new(1), 2);
        let watch = state.poll_acquire(&mut next, &cx, never, |_| {});
        assert!(matches!(watch, Poll::Ready(Acquire::Reap)));
    }

    /// With every engine draining, queued and arriving waiters give up
    /// rather than wait for cores that may never answer.
    #[test]
    fn waiters_give_up_when_every_engine_is_draining() {
        let mut state = PqcState::new();
        for _ in 0..ENGINES {
            state.claim_free_engine().expect("engine free");
        }
        let cx = noop_cx();
        let never = |_: EngineId, _: u32| false;

        let mut queued = None;
        assert!(state
            .poll_acquire(&mut queued, &cx, never, |_| {})
            .is_pending());
        for i in 0..ENGINES as u8 {
            state.quarantine_engine(EngineId::new(i), u32::from(i));
        }

        let gave_up = state.poll_acquire(&mut queued, &cx, never, |_| {});
        assert!(
            matches!(gave_up, Poll::Ready(Acquire::Done(Err(e))) if e == PqcError::FP_NOT_READY)
        );
        assert_eq!(queued, None);
        assert!(!state.has_waiters());

        let mut late = None;
        let refused = state.poll_acquire(&mut late, &cx, never, |_| {});
        assert!(
            matches!(refused, Poll::Ready(Acquire::Done(Err(e))) if e == PqcError::FP_NOT_READY)
        );
    }
}
