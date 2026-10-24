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

    /// The request the waiting task left for whoever frees an engine to
    /// post, if any.
    pub(crate) staged: Option<Staged>,
}

impl QueueSlot {
    pub(crate) const fn new() -> Self {
        Self {
            waker: WakerRegistration::new(),
            state: QueueSlotState::Free,
            next: NO_SLOT,
            staged: None,
        }
    }
}

/// A request whose inputs all travel in the mailbox (key generation's), left
/// by a task queued for an engine so the engine can start on it the moment
/// it is freed: [`PqcState::release_engine`] posts it, rather than waking the
/// task to, which can be tens of microseconds away under load.
#[derive(Clone)]
pub(crate) struct Staged {
    pub(crate) op: u32,
    pub(crate) key_kind: u32,
    pub(crate) xi: [u8; SEED_LEN],
    pub(crate) rnd: [u8; SEED_LEN],
}

impl Staged {
    /// The request, as the mailbox carries it.
    pub(crate) fn params(&self) -> mailbox::RequestParams<'_> {
        mailbox::RequestParams {
            op: self.op,
            key_kind: self.key_kind,
            xi: &self.xi,
            rnd: &self.rnd,
            msg_len: 0,
            ctx_len: 0,
            sig_len: 0,
            pub_key_len: 0,
        }
    }

    /// Wipe the seeds, which are key material.
    pub(crate) fn wipe(&mut self) {
        for b in self.xi.iter_mut().chain(self.rnd.iter_mut()) {
            // SAFETY: `b` is a valid, writable byte of `self`.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
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
}

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

    /// Post `request` to engine `id`, ring its doorbell, and mark its
    /// response awaited.
    ///
    /// Returns the request's number, which the response will carry.
    pub(crate) fn post(&mut self, id: EngineId, request: &mailbox::RequestParams<'_>) -> u32 {
        // Monotonic across all engines, so a response can never be mistaken
        // for one to an earlier request on the same core.
        self.request_seq = self.request_seq.wrapping_add(1);
        let seq = self.request_seq;
        mailbox::post_request(id, seq, request);
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
                // Stays busy: ownership transfers directly to the waiter,
                // which finds the request it staged, if any, already started.
                let slot = &mut self.queue[idx];
                slot.state = match &mut slot.staged {
                    Some(staged) => {
                        let seq = self.responses.post(id, &staged.params());
                        staged.wipe();
                        QueueSlotState::Running(id, seq)
                    }
                    None => QueueSlotState::Assigned(id),
                };
                slot.staged = None;
                slot.waker.wake();
            }
            None => {
                self.engines[id.raw() as usize].state = EngineState::Idle;
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
