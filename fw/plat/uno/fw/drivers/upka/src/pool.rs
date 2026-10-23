// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::task::Context;

use embassy_sync::waitqueue::WakerRegistration;

use crate::executor::EngineExecutor;
use crate::EngineId;
use crate::EngineState;
use crate::QueueSlotState;
use crate::RequestId;

const LEGACY_REQUEST_ID: RequestId = RequestId::new(0);

/// Tracks waiter state for one hardware PKA engine.
pub(crate) struct EngineSlot {
    /// Waker for the task waiting on this engine's completion.
    pub(crate) waker: WakerRegistration,

    /// Raw status bits captured when the engine completes a command.
    pub(crate) status: u8,

    /// Explicit lifecycle state of this engine.
    pub(crate) state: EngineState,

    /// Indicates whether the engine should produce a completion wake-up.
    pub(crate) completion_armed: bool,

    /// A post-operation wipe is running; its completion releases the
    /// engine (see `UpkaEngine::release_after_wipe`).
    pub(crate) wiping: bool,

    /// Ticket of the staged command running on this engine (see
    /// [`UpkaState::submit_staged`]).
    pub(crate) ticket: Option<u8>,
}

impl EngineSlot {
    pub(crate) fn clear(&mut self) {
        self.status = 0;
        self.state = EngineState::Idle;
        self.completion_armed = false;
        self.wiping = false;
        self.ticket = None;
    }

    pub(crate) fn mark_in_use(&mut self, awaiting_completion: bool) {
        self.state = EngineState::Running {
            req: LEGACY_REQUEST_ID,
        };
        self.completion_armed = awaiting_completion;
        self.status = 0;
    }

    pub(crate) fn take_completion_status(&mut self) -> Option<u8> {
        if self.status == 0 {
            return None;
        }

        let status = self.status;
        self.status = 0;
        self.completion_armed = false;
        Some(status)
    }

    pub(crate) fn register_waiter(&mut self, cx: &Context<'_>) {
        self.waker.register(cx.waker());
    }

    pub(crate) fn arm_completion_wait(&mut self) {
        self.status = 0;
        self.completion_armed = true;
        if self.state == EngineState::Idle {
            self.state = EngineState::Running {
                req: LEGACY_REQUEST_ID,
            };
        }
    }

    pub(crate) fn is_in_use(&self) -> bool {
        self.state != EngineState::Idle
    }

    pub(crate) fn is_completion_armed(&self) -> bool {
        self.completion_armed
    }

    pub(crate) fn has_completion_status(&self) -> bool {
        self.status != 0
    }

    pub(crate) fn capture_completion_status(&mut self, status: u8) {
        self.status = status;
    }

    pub(crate) fn wake_waiter(&mut self) {
        self.waker.wake();
    }
}

/// Tracks a waiter that requested a specific engine.
pub(crate) struct SpecificWaiter {
    /// Waker for the task waiting on a specific engine ID.
    pub(crate) waker: WakerRegistration,

    /// Indicates whether a task is currently waiting on this engine ID.
    pub(crate) waiting: bool,

    /// Indicates whether the engine has been assigned to the waiter.
    pub(crate) assigned: bool,
}

impl SpecificWaiter {
    pub(crate) fn register_waiter(&mut self, cx: &Context<'_>) {
        self.waker.register(cx.waker());
    }
}

/// Tracks one entry in the shared engine-acquisition queue.
pub(crate) struct QueueSlot {
    /// Waker for the task associated with this queue entry.
    pub(crate) waker: WakerRegistration,

    /// Explicit lifecycle state for this queue slot.
    pub(crate) state: QueueSlotState,

    /// Ticket of the staged command waiting here, when the slot is
    /// pre-staged.
    pub(crate) ticket: u8,
}

impl QueueSlot {
    pub(crate) fn occupy(&mut self, pre_staged: bool) {
        self.state = QueueSlotState::Pending {
            req: LEGACY_REQUEST_ID,
            pre_staged,
        };
    }

    pub(crate) fn clear(&mut self) {
        self.state = QueueSlotState::Free;
    }

    pub(crate) fn assign_engine(&mut self, id: u8) {
        self.state = match self.state {
            QueueSlotState::Pending { req, pre_staged } => QueueSlotState::Assigned {
                req,
                engine: EngineId::new(id),
                pre_staged,
            },
            QueueSlotState::Assigned {
                req,
                engine: _,
                pre_staged,
            } => QueueSlotState::Assigned {
                req,
                engine: EngineId::new(id),
                pre_staged,
            },
            QueueSlotState::Completing { req, .. } => QueueSlotState::Completing {
                req,
                engine: EngineId::new(id),
            },
            QueueSlotState::Free => QueueSlotState::Assigned {
                req: LEGACY_REQUEST_ID,
                engine: EngineId::new(id),
                pre_staged: false,
            },
        };
    }

    pub(crate) fn assigned_engine(&self) -> Option<u8> {
        match self.state {
            QueueSlotState::Assigned { engine, .. } => Some(engine.raw()),
            QueueSlotState::Completing { engine, .. } => Some(engine.raw()),
            QueueSlotState::Free | QueueSlotState::Pending { .. } => None,
        }
    }

    pub(crate) fn is_unassigned_waiter(&self) -> bool {
        matches!(self.state, QueueSlotState::Pending { .. })
    }

    pub(crate) fn is_occupied(&self) -> bool {
        !matches!(self.state, QueueSlotState::Free)
    }

    pub(crate) fn pre_staged(&self) -> bool {
        match self.state {
            QueueSlotState::Pending { pre_staged, .. }
            | QueueSlotState::Assigned { pre_staged, .. } => pre_staged,
            QueueSlotState::Completing { .. } | QueueSlotState::Free => false,
        }
    }

    pub(crate) fn register_waiter(&mut self, cx: &Context<'_>) {
        self.waker.register(cx.waker());
    }
}

/// Staged commands one driver tracks at once (see
/// [`UpkaState::submit_staged`]). A caller holds its ticket from submission
/// until it collects the result, so this covers every task that can run a
/// PKA command at once (one per IO slot, plus the admin and boot paths)
/// with room to spare.
pub(crate) const TICKETS: usize = 64;

/// One PKA command: its opcode, result operand and argument operands.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StagedCmd {
    pub(crate) opcode: u32,
    pub(crate) result: u32,
    pub(crate) arg1: u32,
    pub(crate) arg2: u32,
    pub(crate) arg3: u32,
}

/// Where a staged command is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TicketState {
    Free,
    /// Waiting for an engine at this queue slot.
    Queued(u8),
    /// Running on an engine.
    Running,
    /// Finished with this engine status, which its caller has yet to take.
    Done(u8),
    /// Running, but its caller has gone: freed when the command finishes.
    Abandoned,
}

/// A staged command and its caller's waker.
pub(crate) struct Ticket {
    pub(crate) waker: WakerRegistration,
    pub(crate) state: TicketState,
    pub(crate) cmd: StagedCmd,
}

/// Shared mutable state for the async PKA engine pool.
pub(crate) struct UpkaState<const DEPTH: usize, const ENGINES: usize> {
    /// Bitmask of currently free engines.
    pub(crate) free_mask: u16,

    /// Per-engine completion state and wakers.
    pub(crate) engine_slots: [EngineSlot; ENGINES],

    /// Waiters blocked on a specific engine ID.
    pub(crate) specific_waiters: [SpecificWaiter; ENGINES],

    /// FIFO queue of tasks waiting for any engine.
    pub(crate) queue_slots: [QueueSlot; DEPTH],

    /// Monotonic head index of the waiter queue.
    pub(crate) queue_head: u8,

    /// Monotonic tail index of the waiter queue.
    pub(crate) queue_tail: u8,

    /// Staged commands, by ticket.
    pub(crate) tickets: [Ticket; TICKETS],

    /// Bitmask of free tickets.
    pub(crate) ticket_free: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueueDispatchAction {
    pub(crate) queue_slot: u8,
    pub(crate) pre_staged: bool,
}

impl<const DEPTH: usize, const ENGINES: usize> UpkaState<DEPTH, ENGINES> {
    /// Return the ring-buffer index for a monotonic queue cursor.
    pub(crate) fn queue_index(cursor: u8) -> usize {
        (cursor & ((DEPTH - 1) as u8)) as usize
    }

    /// Return whether the waiter queue has reached capacity.
    pub(crate) fn queue_is_full(&self) -> bool {
        self.queue_tail.wrapping_sub(self.queue_head) as usize >= DEPTH
    }

    /// Return whether the queue contains any waiter still awaiting engine assignment.
    pub(crate) fn has_any_waiters(&self) -> bool {
        let mut cursor = self.queue_head;
        while cursor != self.queue_tail {
            let idx = Self::queue_index(cursor);
            let slot = &self.queue_slots[idx];
            if slot.is_unassigned_waiter() {
                return true;
            }
            cursor = cursor.wrapping_add(1);
        }
        false
    }

    pub(crate) fn try_claim_free_engine(&mut self, awaiting_completion: bool) -> Option<u8> {
        if self.free_mask == 0 {
            return None;
        }

        let id = self.free_mask.trailing_zeros() as u8;
        self.free_mask &= !(1u16 << id);
        self.engine_slots[id as usize].mark_in_use(awaiting_completion);
        Some(id)
    }

    pub(crate) fn reserve_queue_slot(&mut self, pre_staged: bool) -> Option<u8> {
        if self.queue_is_full() {
            return None;
        }

        let q = Self::queue_index(self.queue_tail) as u8;
        self.queue_slots[q as usize].occupy(pre_staged);
        self.queue_tail = self.queue_tail.wrapping_add(1);
        Some(q)
    }

    pub(crate) fn wait_for_assigned_engine(&mut self, q: u8, cx: &Context<'_>) -> Option<u8> {
        let slot = &mut self.queue_slots[q as usize];
        if let Some(id) = slot.assigned_engine() {
            Some(id)
        } else {
            slot.register_waiter(cx);
            None
        }
    }

    pub(crate) fn clear_queue_entry(&mut self, q: u8) {
        self.queue_slots[q as usize].clear();
        while self.queue_head != self.queue_tail {
            let idx = Self::queue_index(self.queue_head);
            if self.queue_slots[idx].is_occupied() {
                break;
            }
            self.queue_head = self.queue_head.wrapping_add(1);
        }
    }

    pub(crate) fn release_engine_and_dispatch(&mut self, id: u8) -> Option<QueueDispatchAction> {
        self.engine_slots[id as usize].clear();

        if self.specific_waiters[id as usize].waiting {
            self.specific_waiters[id as usize].waiting = false;
            self.specific_waiters[id as usize].assigned = true;
            self.engine_slots[id as usize].mark_in_use(false);
            self.specific_waiters[id as usize].waker.wake();
            return None;
        }

        self.free_mask |= 1u16 << id;

        let mut cursor = self.queue_head;
        while cursor != self.queue_tail {
            let idx = Self::queue_index(cursor);
            if self.queue_slots[idx].is_unassigned_waiter() {
                let pre_staged = self.queue_slots[idx].pre_staged();
                self.free_mask &= !(1u16 << id);
                if pre_staged {
                    // A staged command: start it here, without waking its
                    // caller, which waits for the command's completion.
                    let t = self.queue_slots[idx].ticket;
                    self.clear_queue_entry(idx as u8);
                    self.start_ticket(id, t);
                    return Some(QueueDispatchAction {
                        queue_slot: idx as u8,
                        pre_staged,
                    });
                }
                self.engine_slots[id as usize].mark_in_use(pre_staged);
                self.queue_slots[idx].assign_engine(id);
                self.queue_slots[idx].waker.wake();
                return Some(QueueDispatchAction {
                    queue_slot: idx as u8,
                    pre_staged,
                });
            }
            cursor = cursor.wrapping_add(1);
        }

        None
    }

    /// Run `cmd` on any engine: start it now if one is free and nothing is
    /// queued ahead of it, else queue it to start, in order, on an engine
    /// as it is released (see
    /// [`release_engine_and_dispatch`](Self::release_engine_and_dispatch)).
    /// Its completion wipes the engine at once (see
    /// [`finish_staged`](Self::finish_staged)).
    ///
    /// Returns the command's ticket, or `None` if no ticket or queue slot
    /// is free.
    pub(crate) fn submit_staged(&mut self, cmd: StagedCmd) -> Option<u8> {
        if self.ticket_free == 0 {
            return None;
        }
        let t = self.ticket_free.trailing_zeros() as u8;
        let engine = if self.has_any_waiters() {
            None
        } else {
            self.try_claim_free_engine(false)
        };
        match engine {
            Some(id) => {
                self.ticket_free &= !(1u64 << t);
                self.tickets[t as usize].cmd = cmd;
                self.start_ticket(id, t);
            }
            None => {
                let q = self.reserve_queue_slot(true)?;
                self.ticket_free &= !(1u64 << t);
                self.tickets[t as usize].cmd = cmd;
                self.tickets[t as usize].state = TicketState::Queued(q);
                self.queue_slots[q as usize].ticket = t;
            }
        }
        Some(t)
    }

    /// Start ticket `t`'s command on engine `id`, which the caller holds.
    fn start_ticket(&mut self, id: u8, t: u8) {
        let cmd = self.tickets[t as usize].cmd;
        self.tickets[t as usize].state = TicketState::Running;
        let slot = &mut self.engine_slots[id as usize];
        slot.arm_completion_wait();
        slot.ticket = Some(t);
        EngineExecutor::submit_engine_command(
            id, cmd.opcode, cmd.result, cmd.arg1, cmd.arg2, cmd.arg3,
        );
    }

    /// Engine `id` finished ticket `t`'s command with `status`: hand the
    /// status to the ticket, waking its caller, and start wiping the
    /// engine, whose completion releases it.
    pub(crate) fn finish_staged(&mut self, id: u8, t: u8, status: u8) {
        let ticket = &mut self.tickets[t as usize];
        if ticket.state == TicketState::Abandoned {
            ticket.state = TicketState::Free;
            self.ticket_free |= 1u64 << t;
        } else {
            ticket.state = TicketState::Done(status);
            ticket.waker.wake();
        }
        let slot = &mut self.engine_slots[id as usize];
        slot.ticket = None;
        slot.arm_completion_wait();
        slot.wiping = true;
        EngineExecutor::submit_engine_command(id, crate::opcode::UPKA_MEM_WIPE, 0, 0, 0, 0);
    }

    /// Ticket `t`'s status, freeing the ticket, once its command has
    /// finished; until then registers the caller's waker.
    pub(crate) fn take_staged(&mut self, t: u8, cx: &Context<'_>) -> Option<u8> {
        let ticket = &mut self.tickets[t as usize];
        if let TicketState::Done(status) = ticket.state {
            ticket.state = TicketState::Free;
            self.ticket_free |= 1u64 << t;
            Some(status)
        } else {
            ticket.waker.register(cx.waker());
            None
        }
    }

    /// Give up ticket `t`, whose caller has gone. A queued command is
    /// dropped; a running one is left to finish (it is freed then), and the
    /// engine running it is returned so the caller can wait for the engine
    /// to stop using its buffers.
    pub(crate) fn abandon_staged(&mut self, t: u8) -> Option<u8> {
        match self.tickets[t as usize].state {
            TicketState::Queued(q) => {
                self.clear_queue_entry(q);
                self.tickets[t as usize].state = TicketState::Free;
                self.ticket_free |= 1u64 << t;
                None
            }
            TicketState::Running => {
                self.tickets[t as usize].state = TicketState::Abandoned;
                self.engine_slots
                    .iter()
                    .position(|e| e.ticket == Some(t))
                    .map(|id| id as u8)
            }
            TicketState::Done(_) => {
                self.tickets[t as usize].state = TicketState::Free;
                self.ticket_free |= 1u64 << t;
                None
            }
            TicketState::Free | TicketState::Abandoned => None,
        }
    }
}
