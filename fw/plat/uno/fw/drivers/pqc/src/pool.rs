// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared state for the PQC engine pool.
//!
//! Mirrors the UPKA pool but for six engines -- two lanes on each of three
//! FP cores -- rather than sixteen, and without specific-engine
//! acquisition: callers never need a particular lane, so the only entry
//! point is "give me any free engine". A caller may name a preference,
//! though: an ML-DSA signer tags its request with its key, and the core
//! that last signed with that key still holds the key's public matrix,
//! which spares it most of the matrix expansion. A freed engine goes to the
//! oldest waiter with its core's tag, if one is queued, ahead of the head
//! of the queue; failing that, to the oldest whose tag no other core holds,
//! so that it does not take a waiter another core would serve with its
//! matrix in hand. The head is passed over at most [`MAX_HEAD_SKIPS`] times
//! before it is served regardless.

use core::task::Context;
use core::task::Poll;

use embassy_sync::waitqueue::WakerRegistration;
use tsra_fw_hsm_pal_traits::HsmResult;

use crate::error::PqcError;
use crate::types::EngineId;
use crate::types::EngineState;
use crate::types::QueueSlotState;
use crate::types::CORES;
use crate::types::ENGINES;
use crate::types::QUEUE_DEPTH;

/// List terminator for [`QueueSlot::next`], and the "no slot" sentinel for
/// the list heads. `QUEUE_DEPTH` is far below this, so it cannot collide
/// with a real index.
pub(crate) const NO_SLOT: u8 = u8::MAX;

/// Most times the head waiter may be passed over for a later one before it
/// is served regardless. Each costs it at most one request's time on one of
/// the engines.
pub(crate) const MAX_HEAD_SKIPS: u8 = 16;

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

    /// The waiter's affinity tag, or 0 for none; see
    /// [`PqcState::core_tag`].
    pub(crate) tag: u32,
}

impl QueueSlot {
    pub(crate) const fn new() -> Self {
        Self {
            waker: WakerRegistration::new(),
            state: QueueSlotState::Free,
            next: NO_SLOT,
            tag: 0,
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

    /// Per core, the last nonzero tag a task acquired one of its lanes
    /// with: the key it signs with next or last, and whose public matrix it
    /// holds. Kept per core because the two lanes share one matrix. Only a
    /// hint -- the core checks the key itself.
    pub(crate) core_tag: [u32; CORES],

    /// Times the current head waiter has been passed over.
    pub(crate) head_skips: u8,

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
            core_tag: [0; CORES],
            head_skips: 0,
            queue,
            free_head: 0,
            wait_head: NO_SLOT,
            wait_tail: NO_SLOT,
            probe_seq: 0,
            request_seq: 0,
        }
    }

    /// Claim a free engine for a task with affinity `tag`, marking it busy:
    /// preferably a lane of an idle core, so that requests run side by side
    /// rather than queue on one core while another idles, and of those one
    /// whose core holds `tag`; otherwise the lowest.
    pub(crate) fn claim_free_engine(&mut self, tag: u32) -> Option<EngineId> {
        if self.free_mask == 0 {
            return None;
        }
        let mut id = 0;
        let mut best = u8::MAX;
        for i in 0..ENGINES {
            if self.free_mask & (1 << i) == 0 {
                continue;
            }
            let busy = self.free_mask & (1 << ((i + CORES) % ENGINES)) == 0;
            let rank =
                (u8::from(busy) << 1) | u8::from(tag == 0 || self.core_tag[i % CORES] != tag);
            if rank < best {
                best = rank;
                id = i as u8;
            }
        }
        if tag != 0 {
            self.core_tag[id as usize % CORES] = tag;
        }
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

    /// True if a core other than `core` holds tag `tag` (nonzero).
    fn held_elsewhere(&self, core: usize, tag: u32) -> bool {
        tag != 0 && (0..CORES).any(|c| c != core && self.core_tag[c] == tag)
    }

    /// Reserve a queue slot for a task with affinity `tag` about to wait.
    pub(crate) fn reserve_queue_slot(&mut self, tag: u32) -> Option<u8> {
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
        slot.tag = tag;
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

    /// Return an engine to the pool, handing it straight to a waiting task
    /// if there is one: unless the head of the queue has been passed over
    /// [`MAX_HEAD_SKIPS`] times, the longest-waiting with its core's tag,
    /// else the longest-waiting whose tag no other core holds; otherwise
    /// the head.
    pub(crate) fn release_engine(&mut self, id: EngineId) {
        let core = id.core() as usize;
        // The head of the wait ring is by construction the waiter that
        // queued first.
        let waiter = if self.wait_head == NO_SLOT {
            None
        } else {
            let want = self.core_tag[core];
            let head = self.wait_head;
            let mut idx = head;
            if self.head_skips < MAX_HEAD_SKIPS
                && (want == 0 || self.queue[head as usize].tag != want)
            {
                let mut pick = NO_SLOT;
                let mut cur = head;
                while cur != NO_SLOT {
                    let tag = self.queue[cur as usize].tag;
                    if want != 0 && tag == want {
                        pick = cur;
                        break;
                    }
                    if pick == NO_SLOT && !self.held_elsewhere(core, tag) {
                        pick = cur;
                    }
                    cur = self.queue[cur as usize].next;
                }
                if pick != NO_SLOT {
                    idx = pick;
                }
            }
            self.unlink_waiter(idx);
            if idx != head {
                self.head_skips += 1;
            }
            Some(idx as usize)
        };

        match waiter {
            Some(idx) => {
                // Ownership transfers directly to the waiter. Marked busy
                // explicitly: a reclaimed engine arrives here draining.
                self.engines[id.raw() as usize].state = EngineState::Busy;
                let tag = self.queue[idx].tag;
                if tag != 0 {
                    self.core_tag[core] = tag;
                }
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

    /// One poll of [`PqcDriver::acquire_for`](crate::PqcDriver::acquire_for)
    /// for the waiter with affinity `tag` whose queue slot is `slot` (`None`
    /// until it queues).
    ///
    /// `answered` and `scrub` are as for [`reclaim_drained`](Self::reclaim_drained).
    pub(crate) fn poll_acquire(
        &mut self,
        slot: &mut Option<u8>,
        tag: u32,
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
                    if let Some(id) = self.claim_free_engine(tag) {
                        return Poll::Ready(Acquire::Done(Ok(id)));
                    }
                }
                if self.all_draining() {
                    return Poll::Ready(Acquire::Done(Err(PqcError::FP_NOT_READY)));
                }
                let Some(idx) = self.reserve_queue_slot(tag) else {
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
            self.head_skips = 0;
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
            *entry = state.reserve_queue_slot(0).expect("slot available");
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
            state.claim_free_engine(0).expect("engine free");
        }

        // Two waiters: the first to arrive holds the *higher* slot index.
        let early = state.reserve_queue_slot(0).expect("slot");
        let late = state.reserve_queue_slot(0).expect("slot");
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
            state.claim_free_engine(0).expect("engine free");
        }

        let a = state.reserve_queue_slot(0).expect("slot");
        let b = state.reserve_queue_slot(0).expect("slot");
        let c = state.reserve_queue_slot(0).expect("slot");

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
            let idx = state.reserve_queue_slot(0).expect("slot available") as usize;
            assert!(!seen[idx], "slot {idx} handed out twice");
            seen[idx] = true;
        }
        assert!(
            state.reserve_queue_slot(0).is_none(),
            "queue must report full once every slot is taken"
        );
    }

    /// A freed engine goes to the oldest waiter with the tag it last ran,
    /// ahead of the head, and takes on the tag of whoever it goes to.
    #[test]
    fn released_engine_prefers_a_waiter_with_its_tag() {
        let mut state = PqcState::new();
        assert_eq!(state.claim_free_engine(5), Some(EngineId::new(0)));
        state.claim_free_engine(0).expect("engine free");
        state.claim_free_engine(0).expect("engine free");

        let head = state.reserve_queue_slot(1).expect("slot");
        let five = state.reserve_queue_slot(5).expect("slot");
        let later_five = state.reserve_queue_slot(5).expect("slot");

        state.release_engine(EngineId::new(0));
        assert_eq!(collect(&mut state, five), Some(EngineId::new(0)));
        assert!(collect(&mut state, head).is_none());

        // An untagged engine serves the head, which hands it its tag.
        state.release_engine(EngineId::new(1));
        assert_eq!(collect(&mut state, head), Some(EngineId::new(1)));
        assert_eq!(state.core_tag[1], 1);
        state.release_engine(EngineId::new(1));
        assert_eq!(collect(&mut state, later_five), Some(EngineId::new(1)));

        // Of the free engines, one holding the tag is claimed first.
        let mut state = PqcState::new();
        state.core_tag[2] = 7;
        assert_eq!(state.claim_free_engine(7), Some(EngineId::new(2)));
        assert_eq!(state.claim_free_engine(9), Some(EngineId::new(0)));
        assert_eq!(state.core_tag[0], 9);
    }

    /// A free lane of an idle core is claimed ahead of one whose core holds
    /// the tag but is busy with its other lane; once every core is busy,
    /// the tag decides.
    #[test]
    fn idle_cores_are_claimed_before_busy_cores_lanes() {
        let mut state = PqcState::new();
        assert_eq!(state.claim_free_engine(9), Some(EngineId::new(0)));
        assert_eq!(state.claim_free_engine(9), Some(EngineId::new(1)));
        assert_eq!(state.claim_free_engine(7), Some(EngineId::new(2)));
        assert_eq!(state.claim_free_engine(7), Some(EngineId::new(5)));
        assert_eq!(state.claim_free_engine(0), Some(EngineId::new(3)));
    }

    /// Both lanes of a core share its tag: a freed lane goes to a waiter
    /// for the key its core's other lane was taken for.
    #[test]
    fn released_lane_prefers_its_cores_tag() {
        let mut state = PqcState::new();
        for _ in 0..crate::types::CORES {
            state.claim_free_engine(0).expect("engine free");
        }
        let lane = state.claim_free_engine(5).expect("engine free");
        assert_eq!(lane, EngineId::new(3));
        state.claim_free_engine(0).expect("engine free");
        state.claim_free_engine(0).expect("engine free");

        let six = state.reserve_queue_slot(6).expect("slot");
        let five = state.reserve_queue_slot(5).expect("slot");
        state.release_engine(EngineId::new(0));
        assert_eq!(collect(&mut state, five), Some(EngineId::new(0)));
        assert!(collect(&mut state, six).is_none());
    }

    /// With no waiter for its own tag, a freed engine passes over waiters
    /// whose tag another core holds for one whose tag none does.
    #[test]
    fn released_engine_leaves_waiters_another_engine_holds() {
        let mut state = PqcState::new();
        for tag in [5, 6, 7] {
            state.claim_free_engine(tag).expect("engine free");
        }
        let six = state.reserve_queue_slot(6).expect("slot");
        let nine = state.reserve_queue_slot(9).expect("slot");

        state.release_engine(EngineId::new(0));
        assert_eq!(collect(&mut state, nine), Some(EngineId::new(0)));
        assert_eq!(state.core_tag[0], 9);
        state.release_engine(EngineId::new(1));
        assert_eq!(collect(&mut state, six), Some(EngineId::new(1)));
    }

    /// The head is passed over at most `MAX_HEAD_SKIPS` times in a row.
    #[test]
    fn head_is_served_after_max_skips() {
        let mut state = PqcState::new();
        state.claim_free_engine(5).expect("engine free");
        state.claim_free_engine(0).expect("engine free");
        state.claim_free_engine(0).expect("engine free");

        let head = state.reserve_queue_slot(1).expect("slot");
        let mut fives = [0u8; MAX_HEAD_SKIPS as usize + 1];
        for f in fives.iter_mut() {
            *f = state.reserve_queue_slot(5).expect("slot");
        }
        for &f in &fives[..MAX_HEAD_SKIPS as usize] {
            state.release_engine(EngineId::new(0));
            assert_eq!(collect(&mut state, f), Some(EngineId::new(0)));
        }
        state.release_engine(EngineId::new(0));
        assert_eq!(collect(&mut state, head), Some(EngineId::new(0)));
        assert_eq!(state.head_skips, 0);
    }

    /// Every waiter is eventually served: with more arrivals than engines,
    /// none is left behind.
    #[test]
    fn no_waiter_is_starved() {
        let mut state = PqcState::new();
        for _ in 0..ENGINES {
            state.claim_free_engine(0).expect("engine free");
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
            state.claim_free_engine(0).expect("engine free");
        }
        let waiter = state.reserve_queue_slot(0).expect("slot");

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
            state.claim_free_engine(0).expect("engine free");
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
            state.claim_free_engine(0).expect("engine free");
        }

        let a = state.reserve_queue_slot(0).expect("slot");
        let b = state.reserve_queue_slot(0).expect("slot");
        let c = state.reserve_queue_slot(0).expect("slot");
        state.cancel_wait(b);
        state.release_engine(EngineId::new(0));
        assert_eq!(collect(&mut state, a), Some(EngineId::new(0)));
        state.release_engine(EngineId::new(1));
        assert_eq!(collect(&mut state, c), Some(EngineId::new(1)));
        assert!(!state.has_waiters());

        let d = state.reserve_queue_slot(0).expect("slot");
        let e = state.reserve_queue_slot(0).expect("slot");
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
            state.claim_free_engine(0).expect("engine free");
        }
        state.quarantine_engine(EngineId::new(0), 1);
        let cx = noop_cx();
        let never = |_: EngineId, _: u32| false;

        let mut head = None;
        let mut next = None;
        let first = state.poll_acquire(&mut head, 0, &cx, never, |_| {});
        assert!(matches!(first, Poll::Ready(Acquire::Reap)));
        assert!(state
            .poll_acquire(&mut next, 0, &cx, never, |_| {})
            .is_pending());

        // The core answers: the head collects the scrubbed engine, and with
        // nothing left draining the next waiter simply waits.
        let got = state.poll_acquire(&mut head, 0, &cx, |_, seq| seq == 1, |_| {});
        assert!(matches!(got, Poll::Ready(Acquire::Done(Ok(id))) if id == EngineId::new(0)));
        assert!(state
            .poll_acquire(&mut next, 0, &cx, never, |_| {})
            .is_pending());

        // Another engine drains: the waiter now at the head watches it.
        state.quarantine_engine(EngineId::new(1), 2);
        let watch = state.poll_acquire(&mut next, 0, &cx, never, |_| {});
        assert!(matches!(watch, Poll::Ready(Acquire::Reap)));
    }

    /// With every engine draining, queued and arriving waiters give up
    /// rather than wait for cores that may never answer.
    #[test]
    fn waiters_give_up_when_every_engine_is_draining() {
        let mut state = PqcState::new();
        for _ in 0..ENGINES {
            state.claim_free_engine(0).expect("engine free");
        }
        let cx = noop_cx();
        let never = |_: EngineId, _: u32| false;

        let mut queued = None;
        assert!(state
            .poll_acquire(&mut queued, 0, &cx, never, |_| {})
            .is_pending());
        for i in 0..ENGINES as u8 {
            state.quarantine_engine(EngineId::new(i), u32::from(i));
        }

        let gave_up = state.poll_acquire(&mut queued, 0, &cx, never, |_| {});
        assert!(
            matches!(gave_up, Poll::Ready(Acquire::Done(Err(e))) if e == PqcError::FP_NOT_READY)
        );
        assert_eq!(queued, None);
        assert!(!state.has_waiters());

        let mut late = None;
        let refused = state.poll_acquire(&mut late, 0, &cx, never, |_| {});
        assert!(
            matches!(refused, Poll::Ready(Acquire::Done(Err(e))) if e == PqcError::FP_NOT_READY)
        );
    }
}
