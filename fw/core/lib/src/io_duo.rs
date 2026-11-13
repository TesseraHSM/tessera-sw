// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Duo IO dispatch and opcode handling for [`Hsm`] (128 B SQE / 64 B CQE).
//!
//! Duo speaks api_rev 2.0 only and carries TBOR only (no MBOR). The SQE
//! names one of three [`DuoOp`]s:
//!
//! - [`DuoOp::Tbor`] — plaintext TBOR. Only session-less commands and
//!   `SessionOpenInit` may use it.
//! - [`DuoOp::TborSecure`] — TBOR protected by the session transport keys.
//!   `SessionOpenFinish`, in-session commands and `SessionClose` must use
//!   it, and the SQE `session_id` must name the body's session.
//! - [`DuoOp::FlushSession`] — tears down the SQE's session; no payload.
//!
//! The platform owns the transport: [`HsmIoController::recv_request`]
//! fetches (and, on the secure channel, decrypts) the request, and
//! [`HsmIoController::send_response`] encrypts and returns the reply and
//! fills the secure CQE fields. Core only records the outcome with
//! [`HsmCqe::set_ok`] / [`HsmCqe::set_err`].
//!
//! This pipeline is deliberately independent of the Uno one (`io_uno`):
//! each is tuned for its own wire format rather than sharing code.

use tsra_fw_ddi_tbor::RequestView as TborRequestView;
use tsra_fw_hsm_undo::UndoLog;
use tsra_fw_hsm_undo::WalkOutcome;
use tsra_fw_hsm_undo::UNDO_LOG_SIZE;

use super::*;

const OP_DUO_TBOR: u16 = DuoOp::Tbor as u16;
const OP_DUO_TBOR_SECURE: u16 = DuoOp::TborSecure as u16;
const OP_DUO_FLUSH: u16 = DuoOp::FlushSession as u16;

impl<P: HsmPal> Hsm<P> {
    /// Duo IO pipeline, run by [`handle_io`](Self::handle_io).
    pub(crate) async fn duo_io(&self, mut io: P::Io) {
        if !self.duo_partition_enabled(&io) {
            debug!("core", "dropping IO for disabled partition");
            if let Err(_e) = self.pal().drop_io(io).await {
                error!("core", HsmError::DropIoFailure, "drop_io failed: {:?}", _e);
            }
            return;
        }

        // The per-command undo log, owned here so it outlives `complete_io`
        // and the post-completion walk.
        let mut undo: Option<UndoLog<'_>> = None;
        // Partition credential lock, held through the post-completion walk.
        let mut credential_guard = None;

        let op_result = match io.sqe().opcode() {
            OP_DUO_TBOR => {
                self.handle_duo_tbor_op(&mut io, DuoOp::Tbor, &mut undo, &mut credential_guard)
                    .await
            }
            OP_DUO_TBOR_SECURE => {
                self.handle_duo_tbor_op(
                    &mut io,
                    DuoOp::TborSecure,
                    &mut undo,
                    &mut credential_guard,
                )
                .await
            }
            OP_DUO_FLUSH => self.handle_duo_flush_op(&io).await,
            _ => Err(HsmError::UnsupportedCmd),
        };

        // Record the success and send the reply. With nothing to walk once
        // the completion is posted, the platform can do that, post the CQE
        // and drop the IO on its own, freeing this task at once.
        let op_result = match op_result {
            Ok(reply) => {
                let len = reply.resp.map_or(0, |r| r.len());
                io.cqe().set_ok(len as u32);
                match reply.resp {
                    Some(resp) => {
                        if credential_guard.is_none() && undo.as_ref().is_none_or(UndoLog::is_empty)
                        {
                            match self.pal().finish_io(io, resp) {
                                Ok(()) => return,
                                Err(back) => io = back,
                            }
                        }
                        self.pal()
                            .send_response(&mut io, resp)
                            .await
                            .map(|()| reply.ddi_failed)
                    }
                    None => Ok(reply.ddi_failed),
                }
            }
            Err(e) => Err(e),
        };
        let handler_ok = match op_result {
            Ok(ddi_failed) => !ddi_failed,
            Err(e) => {
                error!("core", e, "handle_op failed");
                io.cqe().set_err(e);
                false
            }
        };

        let cqe_ok = match self.pal().complete_io(&mut io).await {
            Ok(()) => true,
            Err(_e) => {
                error!(
                    "core",
                    HsmError::CompleteIoFailure,
                    "completion failed: {:?}",
                    _e
                );
                false
            }
        };

        // Commit iff the handler succeeded *and* the CQE posted; otherwise
        // revert. A poisoned walk quarantines the partition.
        if let Some(log) = undo {
            let outcome = if handler_ok && cqe_ok {
                log.apply_commit(self.pal(), &io).await
            } else {
                log.apply_undo(self.pal(), &io).await
            };
            if outcome == WalkOutcome::Poisoned {
                error!(
                    "core",
                    HsmError::InternalError,
                    "undo walk poisoned the IO's partition"
                );
                if crate::part_state::part_set_faulted(self.pal(), &io).is_err() {
                    error!(
                        "core",
                        HsmError::InternalError,
                        "failed to fault the IO's poisoned partition"
                    );
                }
            }
        }

        drop(credential_guard);
        if let Err(_e) = self.pal().drop_io(io).await {
            error!("core", HsmError::DropIoFailure, "drop_io failed: {:?}", _e);
        }
    }

    /// Returns `true` if the partition for this IO can accept host traffic.
    #[inline]
    fn duo_partition_enabled(&self, io: &P::Io) -> bool {
        crate::part_state::part_state(self.pal(), io)
            .map(|s| {
                matches!(
                    s,
                    HsmPartState::Enabled | HsmPartState::Initializing | HsmPartState::Initialized
                )
            })
            .unwrap_or(false)
    }

    /// Handles a [`DuoOp::Tbor`] or [`DuoOp::TborSecure`] command.
    ///
    /// Same two-phase model as Uno: pre-decode errors fail the IO (the
    /// CQE carries the host status); post-decode errors are encoded into
    /// the TBOR response. On the secure channel the platform has already
    /// decrypted the request and checked its GCM tag, so a request that
    /// fails it is never parsed. A command on the wrong channel (see
    /// [`duo_channel_policy`]) is answered with a DDI error and never
    /// takes the partition credential lock.
    async fn handle_duo_tbor_op<'s>(
        &'s self,
        io: &mut P::Io,
        channel: DuoOp,
        undo: &mut Option<UndoLog<'s>>,
        credential_guard: &mut Option<P::PartitionGuard<'s>>,
    ) -> HsmResult<DuoReply<'s>> {
        let HsmRequest {
            buf: mut allocation,
            len: src_len,
            resp_capacity: dst_len,
        } = self.pal().recv_request(io).await?;
        let sqe_session_id = io.sqe().session_id().unwrap_or(0);

        let (opcode, body_sess_id) = {
            let req_view = TborRequestView::parse(&allocation.buffer_mut()[..src_len])
                .log_as("core", HsmError::DdiDecodeFailed)?;
            let op = req_view.opcode();
            let sid = if ddi::tbor::needs_body_session_id(op) {
                ddi::tbor::peek_session_id(&req_view)
            } else {
                None
            };
            (op, sid)
        };
        let policy = duo_channel_policy(
            channel,
            sess_ctrl_from_tbor_opcode(opcode),
            sqe_session_id,
            body_sess_id,
        );

        if policy.is_ok()
            && matches!(
                opcode,
                ddi::tbor::opcode::PSK_CHANGE
                    | ddi::tbor::opcode::SESSION_OPEN_FINISH
                    | ddi::tbor::opcode::KEY_REPORT
            )
        {
            *credential_guard = Some(
                self.pal()
                    .partition_lock(io)
                    .await
                    .log_as("core", HsmError::InternalError)?,
            );
        }

        let capacity = ddi::tbor::exchange_capacity(opcode, src_len, dst_len);
        if capacity > allocation.len() {
            self.pal()
                .dma_grow(io, &mut allocation, capacity)
                .log_as("core", HsmError::NotEnoughSpace)?;
        }
        let undo = undo.insert(if policy.is_ok() && ddi::tbor::records_undo(opcode) {
            self.duo_bind_undo(io)?
        } else {
            UndoLog::new(
                self.pal()
                    .dma_alloc(io, 0)
                    .log_as("core", HsmError::NotEnoughSpace)?,
            )
        });
        let mut exchange = HsmCmdBuf::new(allocation.buffer_mut(), src_len, dst_len)
            .log_as("core", HsmError::InternalError)?;
        let dispatch_result = match policy {
            Ok(()) => {
                ddi::tbor::dispatch(
                    self.pal(),
                    io,
                    &mut exchange,
                    opcode,
                    sqe_session_id,
                    body_sess_id,
                    undo,
                )
                .await
            }
            Err(e) => Err(e),
        };
        let ddi_failed = dispatch_result.is_err();
        let resp_len = match dispatch_result {
            Ok(out) => exchange
                .response(out.response_len)
                .log_as("core", HsmError::InternalError)?
                .len(),
            Err(err) => {
                let len = ddi::tbor::encode_exchange_err(opcode, err, &mut exchange)
                    .log_as("core", HsmError::InternalError)?;
                exchange
                    .response(len)
                    .log_as("core", HsmError::InternalError)?
                    .len()
            }
        };
        let resp = &allocation.into_buffer()[..resp_len];

        Ok(DuoReply {
            resp: Some(resp),
            ddi_failed,
        })
    }

    /// Binds the per-command undo log, carved from `io`'s DMA heap. Fails
    /// (`NotEnoughSpace`) before any partition state is mutated.
    fn duo_bind_undo<'s>(&'s self, io: &P::Io) -> HsmResult<UndoLog<'s>> {
        let buf = self
            .pal()
            .dma_alloc(io, UNDO_LOG_SIZE)
            .log_as("core", HsmError::NotEnoughSpace)?;
        Ok(UndoLog::new(buf))
    }

    /// Handles [`DuoOp::FlushSession`]: tears down the SQE's session. An
    /// already-free slot is an idempotent cleanup.
    async fn handle_duo_flush_op(&self, io: &P::Io) -> HsmResult<DuoReply<'static>> {
        let sess_id = io.sqe().session_id().ok_or(HsmError::InvalidArg)?;
        let _lock = self
            .pal()
            .partition_lock(io)
            .await
            .log_as("core", HsmError::InternalError)?;
        let result = self
            .pal()
            .session_destroy(io, HsmSessId::from(sess_id))
            .await;
        duo_flush_completion(result)
    }
}

/// Checks that a TBOR command arrived on the channel its session control
/// requires.
///
/// - [`DuoOp::Tbor`] carries only `NoSession` and `Open` commands.
/// - [`DuoOp::TborSecure`] carries only `InSession` and `Close` commands,
///   and the SQE `session_id` must equal the body's session id.
fn duo_channel_policy(
    op: DuoOp,
    ctrl: HsmSessCtrl,
    sqe_session_id: u16,
    body_sess_id: Option<HsmSessId>,
) -> HsmResult<()> {
    match (op, ctrl) {
        (DuoOp::Tbor, HsmSessCtrl::NoSession | HsmSessCtrl::Open) => Ok(()),
        (DuoOp::TborSecure, HsmSessCtrl::InSession | HsmSessCtrl::Close) => match body_sess_id {
            Some(id) if u16::from(id) == sqe_session_id => Ok(()),
            Some(_) => Err(HsmError::InvalidArg),
            None => Err(HsmError::SessionExpected),
        },
        _ => Err(HsmError::InvalidSessionControlOpcode),
    }
}

fn duo_flush_completion(result: HsmResult<()>) -> HsmResult<DuoReply<'static>> {
    match result {
        Ok(()) | Err(HsmError::SessionNotFound) => Ok(DuoReply {
            resp: None,
            ddi_failed: false,
        }),
        Err(err) => Err(err).log_as("core", HsmError::InternalError),
    }
}

/// Result of a Duo opcode handler.
struct DuoReply<'s> {
    /// TBOR response to return to the host, if any.
    resp: Option<&'s HsmDmaBuf>,
    /// A valid transport response carried a failed DDI command; undo, not commit.
    ddi_failed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: u16 = 3;

    #[test]
    fn plain_channel_accepts_only_sessionless_and_open() {
        for ctrl in [HsmSessCtrl::NoSession, HsmSessCtrl::Open] {
            assert_eq!(duo_channel_policy(DuoOp::Tbor, ctrl, 0, None), Ok(()));
        }
        for ctrl in [HsmSessCtrl::InSession, HsmSessCtrl::Close] {
            assert_eq!(
                duo_channel_policy(DuoOp::Tbor, ctrl, SID, Some(HsmSessId::from(SID))),
                Err(HsmError::InvalidSessionControlOpcode)
            );
        }
    }

    #[test]
    fn secure_channel_accepts_only_in_session_and_close() {
        for ctrl in [HsmSessCtrl::InSession, HsmSessCtrl::Close] {
            assert_eq!(
                duo_channel_policy(DuoOp::TborSecure, ctrl, SID, Some(HsmSessId::from(SID))),
                Ok(())
            );
        }
        for ctrl in [HsmSessCtrl::NoSession, HsmSessCtrl::Open] {
            assert_eq!(
                duo_channel_policy(DuoOp::TborSecure, ctrl, SID, Some(HsmSessId::from(SID))),
                Err(HsmError::InvalidSessionControlOpcode)
            );
        }
    }

    #[test]
    fn secure_channel_requires_matching_body_session() {
        for ctrl in [HsmSessCtrl::InSession, HsmSessCtrl::Close] {
            assert_eq!(
                duo_channel_policy(DuoOp::TborSecure, ctrl, SID, Some(HsmSessId::from(SID + 1))),
                Err(HsmError::InvalidArg)
            );
            assert_eq!(
                duo_channel_policy(DuoOp::TborSecure, ctrl, SID, None),
                Err(HsmError::SessionExpected)
            );
        }
    }

    #[test]
    fn flush_success_and_absent_session_complete_without_payload() {
        for result in [Ok(()), Err(HsmError::SessionNotFound)] {
            let reply = duo_flush_completion(result).expect("flush completes");
            assert!(reply.resp.is_none());
            assert!(!reply.ddi_failed);
        }
        for err in [HsmError::KeyNotFound, HsmError::InternalError] {
            assert!(matches!(
                duo_flush_completion(Err(err)),
                Err(HsmError::InternalError)
            ));
        }
    }
}
