// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::future::poll_fn;
use core::task::Poll;

use tsra_fw_uno_error::HsmResult;

use crate::api::UpkaDriver;
use crate::engine::UpkaEngine;
use crate::executor::EngineExecutor;
use crate::opcode::map_status;
use crate::pool::StagedCmd;
use crate::pool::UpkaState;
use crate::UpkaError;

/// The ticket of a [`Scheduler::run_staged`] call, given up if the call is
/// dropped before it has the result.
struct TicketGuard<'a, const DEPTH: usize, const ENGINES: usize> {
    driver: &'a UpkaDriver<DEPTH, ENGINES>,
    ticket: Option<u8>,
}

impl<const DEPTH: usize, const ENGINES: usize> Drop for TicketGuard<'_, DEPTH, ENGINES> {
    fn drop(&mut self) {
        if let Some(t) = self.ticket {
            if self.driver.with_state(|s| s.abandon_staged(t)) {
                // The command still uses the caller's buffers: wait for it
                // to complete, which the engine's interrupt handles, freeing
                // the ticket. Waiting for the engine to idle could take as
                // long as the commands the handler starts on it after this.
                while self.driver.with_state(|s| s.is_abandoned(t)) {
                    core::hint::spin_loop();
                }
            }
        }
    }
}

/// Schedules queue/engine assignment and completion handling for UPKA commands.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Scheduler<'a, const DEPTH: usize, const ENGINES: usize> {
    driver: &'a UpkaDriver<DEPTH, ENGINES>,
}

impl<'a, const DEPTH: usize, const ENGINES: usize> Scheduler<'a, DEPTH, ENGINES> {
    /// Create a scheduler view over a driver instance.
    pub(crate) const fn new(driver: &'a UpkaDriver<DEPTH, ENGINES>) -> Self {
        Self { driver }
    }

    fn make_engine(&self, id: u8) -> UpkaEngine<'a, DEPTH, ENGINES> {
        UpkaEngine {
            driver: self.driver,
            id,
            released: false,
        }
    }

    fn assign_engine(state: &mut UpkaState<DEPTH, ENGINES>, id: u8, awaiting_completion: bool) {
        state.free_mask &= !(1u16 << id);
        state.engine_slots[id as usize].mark_in_use(awaiting_completion);
    }

    fn claim_free_engine(state: &mut UpkaState<DEPTH, ENGINES>) -> Option<u8> {
        state.try_claim_free_engine(false)
    }

    /// Acquire any free engine.
    pub(crate) async fn acquire_any(&self) -> HsmResult<UpkaEngine<'a, DEPTH, ENGINES>> {
        let mut queue_idx: Option<u8> = None;

        poll_fn(move |cx| {
            self.driver.with_state(|s| {
                if let Some(idx) = queue_idx {
                    let assigned = {
                        if let Some(id) = s.wait_for_assigned_engine(idx, cx) {
                            s.clear_queue_entry(idx);
                            Some(id)
                        } else {
                            None
                        }
                    };

                    if let Some(id) = assigned {
                        return Poll::Ready(Ok(self.make_engine(id)));
                    }

                    return Poll::Pending;
                }

                if !s.has_any_waiters() {
                    if let Some(id) = Self::claim_free_engine(s) {
                        return Poll::Ready(Ok(self.make_engine(id)));
                    }
                }

                if s.queue_is_full() {
                    return Poll::Ready(Err(UpkaError::QUEUE_FULL));
                }

                let Some(idx) = s.reserve_queue_slot(false) else {
                    return Poll::Ready(Err(UpkaError::QUEUE_FULL));
                };
                s.queue_slots[idx as usize].register_waiter(cx);
                queue_idx = Some(idx);
                Poll::Pending
            })
        })
        .await
    }

    /// Acquire a specific engine by ID.
    pub(crate) async fn acquire_engine(
        &self,
        target: u8,
    ) -> HsmResult<UpkaEngine<'a, DEPTH, ENGINES>> {
        if usize::from(target) >= ENGINES {
            return Err(UpkaError::CMD_ERROR);
        }

        let mut registered = false;

        poll_fn(move |cx| {
            self.driver.with_state(|s| {
                let waiter = &mut s.specific_waiters[target as usize];
                if waiter.assigned {
                    waiter.assigned = false;
                    registered = false;
                    return Poll::Ready(Ok(self.make_engine(target)));
                }

                let bit = 1u16 << target;
                if s.free_mask & bit != 0 {
                    Self::assign_engine(s, target, false);
                    return Poll::Ready(Ok(self.make_engine(target)));
                }

                if !registered {
                    if waiter.waiting {
                        return Poll::Ready(Err(UpkaError::QUEUE_FULL));
                    }
                    waiter.waiting = true;
                    registered = true;
                }

                waiter.register_waiter(cx);
                Poll::Pending
            })
        })
        .await
    }

    /// Poll one engine and wake waiters if completed. Called only from the
    /// engines' interrupt handler (see
    /// [`UpkaDriver::wake_engine`](crate::UpkaDriver::wake_engine)).
    pub(crate) fn wake_engine(&self, id: u8) {
        self.driver
            .with_state_in_handler(|s| Self::wake_engine_inner(s, id as usize));
    }

    fn wake_engine_inner(s: &mut UpkaState<DEPTH, ENGINES>, id: usize) {
        // The engine posts its status before it raises its done or its error
        // interrupt (one per command), and entering the handler cleared it.
        // No flags: the engine has not finished (it is busy, or idle), so
        // the interrupt is spurious.
        let flags = EngineExecutor::completion_flags(id as u8);
        if flags == 0 {
            return;
        }
        let slot = &mut s.engine_slots[id];
        // A wipe or a staged command was started with the slot armed, in use
        // and its status clear (see `arm_completion_wait`), so only a held
        // engine's completion needs the checks.
        if slot.wiping {
            Self::finish_wipe(s, id, flags as u8);
        } else if let Some(t) = slot.ticket {
            s.finish_staged(id as u8, t, flags as u8);
        } else if slot.is_in_use() && slot.is_completion_armed() && !slot.has_completion_status() {
            slot.capture_completion_status(flags as u8);
            slot.wake_waiter();
        }
    }

    /// Run one command on any engine without holding the engine across
    /// awaits: the command is started now if an engine is free, or else
    /// queued in the driver and started by whichever completion frees the
    /// next engine, and its own completion starts the engine's wipe. So the
    /// caller is woken once, with the result, and an engine never idles
    /// waiting for a task to run.
    ///
    /// # Errors
    ///
    /// [`UpkaError::QUEUE_FULL`] if the driver cannot take the command;
    /// otherwise the command's status.
    pub(crate) async fn run_staged(&self, cmd: StagedCmd) -> HsmResult<()> {
        let mut ticket = TicketGuard {
            driver: self.driver,
            ticket: None,
        };
        poll_fn(|cx| {
            self.driver.with_state(|s| match ticket.ticket {
                None => match s.submit_staged(cmd) {
                    Some(t) => {
                        ticket.ticket = Some(t);
                        s.tickets[t as usize].waker.register(cx.waker());
                        Poll::Pending
                    }
                    None => Poll::Ready(Err(UpkaError::QUEUE_FULL)),
                },
                Some(t) => match s.take_staged(t, cx) {
                    Some(status) => {
                        ticket.ticket = None;
                        Poll::Ready(map_status(status))
                    }
                    None => Poll::Pending,
                },
            })
        })
        .await
    }

    /// Complete a post-operation wipe started by
    /// [`UpkaEngine::release_after_wipe`]: return the engine to the pool (or
    /// hand it to the next waiter) if the wipe succeeded, or issue the wipe
    /// again if it did not, so that an engine that may still hold key
    /// material never returns to the pool.
    fn finish_wipe(s: &mut UpkaState<DEPTH, ENGINES>, id: usize, status: u8) {
        if map_status(status).is_ok() {
            let _ = s.release_engine_and_dispatch(id as u8);
        } else {
            s.engine_slots[id].arm_completion_wait();
            EngineExecutor::submit_wipe(id as u8);
        }
    }

    /// Release an engine and dispatch next queued waiter if available.
    pub(crate) fn release_engine(&self, id: u8) {
        self.driver.with_state(|s| {
            let _ = s.release_engine_and_dispatch(id);
        });
    }
}
