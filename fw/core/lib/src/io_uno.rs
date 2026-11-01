// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno IO dispatch and opcode handling for [`Hsm`] (64 B SQE / 16 B CQE).
//!
//! The Duo pipeline lives in `io_duo`; the two are deliberately kept
//! separate so each can be tuned for its own wire format.
//!
//! # Pipeline
//!
//! ```text
//!  poll_io ──► uno_io ──► handle_{mbor,tbor,flush}_op
//!                │              │
//!                │         recv_request (SQE validation, inbound DMA)
//!                │         session validate
//!                │         DDI dispatch
//!            set_ok_ex / set_err
//!            send_response (or finish_io)
//!            complete_io
//! ```
//!
//! # Error handling
//!
//! Two-tier model:
//!
//! - **Pre-decode** (SQE validation, inbound DMA, header decode): the
//!   handler fails with a canonical [`HsmError`], which the CQE maps to a
//!   host status; no DDI body.
//!
//! - **Post-decode** (session validation, DDI dispatch, command exec):
//!   Errors encode a [`DdiErrCmdResp`] into the response, which is sent as
//!   a success; the host reads the error from the DDI response body.
//!
//! # Session control
//!
//! Each MBOR DDI op maps to an [`HsmSessCtrl`] kind (NoSession, Open,
//! InSession, Close). Session hijack protection validates the SQE
//! session fields against the decoded DDI header before dispatch.
//! Session state flows back via [`HsmCqeSession`] into the CQE.
//!
//! TBOR commands derive their [`HsmSessCtrl`] from the wire opcode
//! via [`sess_ctrl_from_tbor_opcode`]: `GetApiRev` and
//! `OpenSessionInit` are session-less; `OpenSessionFinish` and
//! `ChangePsk` require the SQE to carry the targeted slot's
//! `session_id`; `CloseSession` is classified as `Close` so the CQE
//! reflects the slot teardown.

use tsra_fw_ddi_mbor_api::DdiDecoder;
use tsra_fw_ddi_mbor_types::DdiOp;
use tsra_fw_ddi_mbor_types::DdiReqHdr;
use tsra_fw_ddi_tbor::RequestView as TborRequestView;
use tsra_fw_hsm_undo::UndoLog;
use tsra_fw_hsm_undo::WalkOutcome;
use tsra_fw_hsm_undo::UNDO_LOG_SIZE;

use super::*;

impl<P: HsmPal> Hsm<P> {
    /// Uno IO pipeline, run by [`handle_io`](Self::handle_io).
    pub(crate) async fn uno_io(&self, mut io: P::Io) {
        // Gate on partition state — drop IOs for non-enabled partitions.
        if !self.partition_enabled(&io) {
            debug!("core", "dropping IO for disabled partition");
            if let Err(_e) = self.pal().drop_io(io).await {
                error!("core", HsmError::DropIoFailure, "drop_io failed: {:?}", _e);
            }
            return;
        }

        if io.kind() == HsmIoKind::Bulk {
            self.handle_bulk_io(io).await;
            return;
        }

        // The per-command undo log (TBOR only), owned here so it outlives
        // `complete_io` and the post-completion walk.  Stays `None` for
        // MBOR / flush / failed requests; a TBOR command binds it once
        // parsed and **fails before mutating** if its DMA buffer can't be
        // carved.
        let mut undo: Option<UndoLog<'_>> = None;
        let mut credential_guard = None;

        let op_result = match io.sqe().opcode() {
            OP_MBOR => self.handle_mbor_op(&mut io).await,
            OP_TBOR => {
                self.handle_tbor_op(&mut io, &mut undo, &mut credential_guard)
                    .await
            }
            OP_FLUSH => self.handle_flush_op(&io).await,
            _ => Err(HsmError::UnsupportedCmd),
        };

        // Record the success and send the reply. With nothing to walk once
        // the completion is posted, the platform can do that, post the CQE
        // and drop the IO on its own, freeing this task at once.
        let op_result = match op_result {
            Ok(reply) => {
                let len = reply.resp.map_or(0, |r| r.len());
                io.cqe().set_ok_ex(len as u32, reply.sess);
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

        // Post the completion (CQE) to the host, then run the undo/commit
        // walk, then free the slot.  Splitting `complete_io` from
        // `drop_io` lets the walk run over `io` *after* the CQE post, so a
        // failed post reverts too.
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

        // Walk the undo log (TBOR only): commit iff the handler succeeded
        // *and* the CQE posted; otherwise revert unconditionally.  Safe
        // against admin teardown, which cannot race an in-flight IO.
        // Credential mutations retain their partition guard through this walk
        // so another rotation cannot observe or overwrite uncommitted state.
        if let Some(log) = undo {
            let outcome = if handler_ok && cqe_ok {
                log.apply_commit(self.pal(), &io).await
            } else {
                log.apply_undo(self.pal(), &io).await
            };
            if outcome == WalkOutcome::Poisoned {
                // A consistency-critical restore failed: the partition's
                // in-memory state is incoherent.  Quarantine it (Faulted) so
                // the enable gate drops all further host IO until a
                // free/realloc (or reboot) clears the fault.
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

    /// Runs a bulk (fast-path) IO and posts its CQE.
    ///
    /// The PAL writes the success CQE into the IO's CQE; on error the
    /// core records the failure in it. The SQ id is stamped by
    /// [`complete_io`](HsmIoController::complete_io).
    async fn handle_bulk_io(&self, mut io: P::Io) {
        if let Err(e) = self.pal().bulk_crypt(&mut io).await {
            debug!("core", "bulk IO failed: {:?}", e);
            io.cqe().set_err(e);
        }

        if let Err(_e) = self.pal().complete_io(&mut io).await {
            error!(
                "core",
                HsmError::CompleteIoFailure,
                "bulk completion failed: {:?}",
                _e
            );
        }
        if let Err(_e) = self.pal().drop_io(io).await {
            error!("core", HsmError::DropIoFailure, "drop_io failed: {:?}", _e);
        }
    }

    /// Bind the per-command undo log for a TBOR command that can record undo
    /// entries ([`ddi::tbor::records_undo`]), carved from `io`'s DMA heap.
    ///
    /// [`UNDO_LOG_SIZE`] bytes are taken from `io`'s DMA heap so the byte
    /// pre-images the undo walk restores are DMA-accessible.  The undo log
    /// is **mandatory**: if the buffer can't be carved, the command fails
    /// here (`NotEnoughSpace`) *before* mutating any partition state,
    /// rather than running with no rollback.
    fn bind_undo<'s>(&'s self, io: &P::Io) -> HsmResult<UndoLog<'s>> {
        let buf = self
            .pal()
            .dma_alloc(io, UNDO_LOG_SIZE)
            .log_as("core", HsmError::NotEnoughSpace)?;
        Ok(UndoLog::new(buf))
    }

    /// Returns `true` if the partition for this IO can accept host traffic.
    #[inline]
    fn partition_enabled(&self, io: &P::Io) -> bool {
        crate::part_state::part_state(self.pal(), io)
            .map(|s| {
                matches!(
                    s,
                    HsmPartState::Enabled | HsmPartState::Initializing | HsmPartState::Initialized
                )
            })
            .unwrap_or(false)
    }

    /// Handles an [`OP_MBOR`] IO command.
    ///
    /// **Phase 1 (pre-decode)** — request receive, header decode. Errors
    /// fail the command with a CQE host status, no DDI body.
    ///
    /// **Phase 2 (post-decode)** — Session validation, DDI dispatch.
    /// Errors → DDI error response sent to the host, CQE Success.
    ///
    /// Returns the reply for the caller to send to the host.
    async fn handle_mbor_op<'s>(&'s self, io: &mut P::Io) -> HsmResult<UnoReply<'s>> {
        let req = self.pal().recv_request(io).await?;
        let req_len = req.len;
        let req_buf = &mut req.buf.into_buffer()[..req_len];
        let sqe_ctrl = io.sqe().session_ctrl();
        let sqe_session_id = io.sqe().session_id();

        let mut decoder = DdiDecoder::new(req_buf);
        let hdr: DdiReqHdr = decoder
            .decode_hdr()
            .log_as("core", HsmError::DdiDecodeFailed)?;

        let session_ctrl = sess_ctrl_from_mbor_op(hdr.op);

        // The decoder borrows the request buffer, so it is scoped: the
        // borrow has to end before the buffer can be handed to the
        // platform below.
        let core_result = {
            let mut decoder = decoder;
            match Self::validate_session(&hdr, session_ctrl, sqe_ctrl, sqe_session_id)
                .and_then(|()| self.validate_session_live(io, &hdr, session_ctrl))
            {
                Ok(()) => ddi::mbor::dispatch(self.pal(), io, &mut decoder, &hdr).await,
                Err(e) => Err(e),
            }
        };
        // `UnsupportedCmd` means no core handler claimed this opcode.
        // Offer the untouched request to the platform before giving up;
        // its answer, including its own `UnsupportedCmd`, is what the host
        // sees.
        //
        // A handler for a *known* opcode can also return this status —
        // `rsa_unwrap` does for an unsupported key type — so the hook may
        // occasionally be offered a request the core did recognise. That
        // is harmless as long as a platform claims only opcodes the core
        // has no handler for, which is the documented contract; the
        // alternative, duplicating the opcode table here to distinguish
        // the two, would rot.
        let dispatch_result = match core_result {
            Err(HsmError::UnsupportedCmd) => self
                .pal()
                .mbor_dispatch(io, req_buf)
                .await
                .map(ddi::mbor::DispatchResult::from_resp),
            other => other,
        };

        // Fill the CQE session fields so the host can track the session per
        // file handle: a successful OpenSession carries the newly allocated
        // id (which sets `session_id_valid`), and a successful CloseSession
        // additionally sets `session_closed`. Both are left cleared on any
        // dispatch failure so the fields are only populated on success.
        let sess = match &dispatch_result {
            Ok(out) => match session_ctrl {
                HsmSessCtrl::Open => HsmCqeSession {
                    ctrl: session_ctrl,
                    id: out.session_id,
                    vault_id: Some(ddi::mbor::open_session::SESSION_SHORT_APP_ID),
                    closed: false,
                },
                HsmSessCtrl::Close => HsmCqeSession {
                    ctrl: session_ctrl,
                    id: hdr.sess_id,
                    vault_id: None,
                    closed: true,
                },
                _ => HsmCqeSession {
                    ctrl: session_ctrl,
                    ..HsmCqeSession::default()
                },
            },
            Err(_) => HsmCqeSession {
                ctrl: session_ctrl,
                ..HsmCqeSession::default()
            },
        };

        let resp: &HsmDmaBuf = match dispatch_result {
            Ok(out) => out.resp,
            Err(status) => self
                .pal()
                .dma_alloc_var(io, |buf| ddi::mbor::encode_ddi_err(hdr.op, status, buf))
                .log_as("core", HsmError::InternalError)?,
        };

        Ok(UnoReply {
            resp: Some(resp),
            sess,
            ddi_failed: false,
        })
    }

    /// Handles an [`OP_TBOR`] IO command.
    ///
    /// Parses TBOR framing and dispatches by raw `u8` opcode, using the
    /// opcode's session policy and a shared exchange allocation.
    ///
    /// **Phase 1 (pre-decode)** — request receive, TBOR
    /// `RequestView::parse`. Errors fail the command with a CQE host
    /// status.
    ///
    /// **Phase 2 (post-decode)** — Dispatch by opcode. Errors are
    /// encoded into the exchange as a non-zero TBOR `status`. The undo
    /// log is independent and remains live through outbound DMA and CQE.
    ///
    /// Returns the reply for the caller to send to the host.
    async fn handle_tbor_op<'s>(
        &'s self,
        io: &mut P::Io,
        undo: &mut Option<UndoLog<'s>>,
        credential_guard: &mut Option<P::PartitionGuard<'s>>,
    ) -> HsmResult<UnoReply<'s>> {
        let HsmRequest {
            buf: mut allocation,
            len: src_len,
            resp_capacity: dst_len,
        } = self.pal().recv_request(io).await?;
        let sqe_ctrl = io.sqe().session_ctrl();
        let sqe_session_id = io.sqe().session_id();

        // Parse once before growing or reborrowing the request storage.
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

        if matches!(
            opcode,
            ddi::tbor::opcode::PSK_CHANGE
                | ddi::tbor::opcode::SESSION_OPEN_FINISH
                | ddi::tbor::opcode::SESSION_REOPEN_FINISH
                | ddi::tbor::opcode::KEY_REPORT
        ) {
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
        // A command that can record undo entries gets its log now, before
        // it can mutate anything; any other gets an empty one over no
        // storage, which leaves teardown nothing of it to scrub.
        let undo = undo.insert(if ddi::tbor::records_undo::<P>(opcode) {
            self.bind_undo(io)?
        } else {
            UndoLog::new(
                self.pal()
                    .dma_alloc(io, 0)
                    .log_as("core", HsmError::NotEnoughSpace)?,
            )
        });
        let mut exchange = HsmCmdBuf::new(allocation.buffer_mut(), src_len, dst_len)
            .log_as("core", HsmError::InternalError)?;
        let session_ctrl = sess_ctrl_from_tbor_opcode(opcode);
        let dispatch_result =
            if Self::validate_tbor_session_flags(session_ctrl, sqe_ctrl, sqe_session_id).is_err() {
                Err(HsmError::InvalidArg)
            } else {
                ddi::tbor::dispatch(
                    self.pal(),
                    io,
                    &mut exchange,
                    opcode,
                    sqe_session_id.unwrap_or(0),
                    body_sess_id,
                    undo,
                )
                .await
            };
        // Session ids are exposed only after successful dispatch and response
        // validation. Preserve the existing close/open CQE semantics.
        let ddi_failed = dispatch_result.is_err();
        let (id, closed) = match &dispatch_result {
            Ok(out) => match session_ctrl {
                HsmSessCtrl::Open => (out.session_id, false),
                HsmSessCtrl::Close => (sqe_session_id, true),
                _ => (None, false),
            },
            Err(_) => (None, false),
        };
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

        Ok(UnoReply {
            resp: Some(resp),
            sess: HsmCqeSession {
                ctrl: session_ctrl,
                id,
                vault_id: None,
                closed,
            },
            ddi_failed,
        })
    }

    /// Validate SQE session fields against the decoded DDI header.
    #[inline(always)]
    fn validate_session(
        hdr: &DdiReqHdr,
        expected: HsmSessCtrl,
        sqe_ctrl: HsmSessCtrl,
        sqe_session_id: Option<u16>,
    ) -> HsmResult<()> {
        // Rules 1 and 2: SQE ctrl must match DDI op, and carry a session
        // id exactly when the op names a session.
        Self::validate_tbor_session_flags(expected, sqe_ctrl, sqe_session_id)?;

        // Rule 3: SQE session_id must match DDI header sess_id
        match sqe_session_id {
            Some(sqe_id) => match hdr.sess_id {
                Some(id) if id == sqe_id => Ok(()),
                _ => Err(HsmError::InvalidArg),
            },
            None if hdr.sess_id.is_some() => Err(HsmError::InvalidArg),
            None => Ok(()),
        }
    }

    /// Central session-liveness gate for session-referencing MBOR
    /// commands.
    ///
    /// [`Self::validate_session`] only checks the SQE flag / id *shape*;
    /// it does not confirm that `sess_id` names a live session.  The FW
    /// is the trust boundary — the host is untrusted and can bypass the
    /// host-side file-handle ↔ session binding — so every command that
    /// operates on an existing session must confirm the referenced slot
    /// is usable, or a forged `sess_id` would grant unauthenticated use
    /// of a victim partition's keys and credential.
    ///
    /// The decision is split into two pure helpers so the policy is unit
    /// testable without a PAL (the host layer rejects a mismatched
    /// `sess_id` before it ever reaches the device, so this gate cannot
    /// be exercised end-to-end with a forged id):
    /// [`session_ctrl_requires_live_session`] selects which commands need
    /// a live slot, and [`classify_session_state`] maps the slot state to
    /// the protocol status.
    ///
    /// Mirrors the central check in `validate_req_hdr`.
    fn validate_session_live(
        &self,
        io: &P::Io,
        hdr: &DdiReqHdr,
        session_ctrl: HsmSessCtrl,
    ) -> HsmResult<()> {
        if !session_ctrl_requires_live_session(session_ctrl, hdr.op) {
            return Ok(());
        }
        let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
        let state = self.pal().session_state(io, HsmSessId::from(sess_id));
        classify_session_state(session_ctrl, state)
    }

    /// Checks the SQE session fields' shape against the opcode's expected
    /// [`HsmSessCtrl`].
    ///
    /// Cross-checking the SQE `session_id` against the inline body
    /// `session_id` TOC entry happens in [`ddi::tbor::dispatch`] for
    /// every in-session / close opcode (i.e. every opcode whose
    /// [`HsmSessCtrl`] requires a session id).  This validator only
    /// enforces the `ctrl` / session-id consistency.
    #[inline(always)]
    fn validate_tbor_session_flags(
        expected: HsmSessCtrl,
        sqe_ctrl: HsmSessCtrl,
        sqe_session_id: Option<u16>,
    ) -> HsmResult<()> {
        if sqe_ctrl != expected {
            return Err(HsmError::InvalidArg);
        }
        match (expected, sqe_session_id.is_some()) {
            (HsmSessCtrl::NoSession, true) => Err(HsmError::InvalidArg),
            (HsmSessCtrl::Open, true) => Err(HsmError::SessionNotExpected),
            (HsmSessCtrl::Close | HsmSessCtrl::InSession, false) => Err(HsmError::InvalidArg),
            _ => Ok(()),
        }
    }

    /// Handles an [`OP_FLUSH`] IO command.
    ///
    /// Tears down the SQE's session without DMA or a DDI response body.
    /// An already-free slot is an idempotent cleanup.
    async fn handle_flush_op<'s>(&'s self, io: &P::Io) -> HsmResult<UnoReply<'s>> {
        let sess_id = flush_session_id(io.sqe()).log_as("core", HsmError::InvalidArg)?;
        let _lock = self
            .pal()
            .partition_lock(io)
            .await
            .log_as("core", HsmError::InternalError)?;
        let result = self
            .pal()
            .session_destroy(io, HsmSessId::from(sess_id))
            .await;
        flush_session_completion(sess_id, result)
    }
}

fn flush_session_completion<'s>(sess_id: u16, result: HsmResult<()>) -> HsmResult<UnoReply<'s>> {
    match result {
        Ok(()) | Err(HsmError::SessionNotFound) => Ok(UnoReply {
            resp: None,
            sess: HsmCqeSession {
                ctrl: HsmSessCtrl::Close,
                id: Some(sess_id),
                vault_id: None,
                closed: true,
            },
            ddi_failed: false,
        }),
        Err(err) => Err(err).log_as("core", HsmError::InternalError),
    }
}

fn flush_session_id<S: HsmSqe + ?Sized>(sqe: &S) -> HsmResult<u16> {
    if sqe.session_ctrl() != HsmSessCtrl::Close {
        return Err(HsmError::InvalidSessionControlOpcode);
    }
    sqe.session_id().ok_or(HsmError::SessionExpected)
}

/// A handler's successful outcome, ready to send to the host.
struct UnoReply<'s> {
    /// Response to send; `None` for a command without one (flush).
    resp: Option<&'s HsmDmaBuf>,
    /// CQE session fields.
    sess: HsmCqeSession,
    /// A valid transport response carried a failed DDI command; undo, not
    /// commit.
    ddi_failed: bool,
}

/// Whether an MBOR command referenced by `session_ctrl` / `op` requires
/// a usable (live) session slot before dispatch.
///
/// - `NoSession` / `Open` reference no existing slot → `false`.
/// - `Close` tears down an existing slot → `true`.
/// - `InSession` operates within a slot → `true`, **except**
///   [`DdiOp::ReopenSession`], which is classified `InSession` but by
///   design re-keys a renegotiation-pending (non-Active) slot and
///   validates that state in its own handler.
fn session_ctrl_requires_live_session(session_ctrl: HsmSessCtrl, op: DdiOp) -> bool {
    match session_ctrl {
        HsmSessCtrl::InSession => op != DdiOp::ReopenSession,
        HsmSessCtrl::Close => true,
        HsmSessCtrl::Unspecified | HsmSessCtrl::NoSession | HsmSessCtrl::Open => false,
    }
}

/// Maps a referenced slot's [`HsmSessionState`] to the protocol status,
/// mirroring the `validate_req_hdr` gate:
///
/// - `Active` → proceed.
/// - `NeedsRenegotiation` → `CloseSession` may still tear the slot down
///   (post-migration cleanup); any other in-session op must renegotiate
///   first ([`HsmError::SessionNeedsRenegotiation`]).
/// - `Pending` / `Invalid` → [`HsmError::SessionNotFound`] (the slot is
///   free, destroyed, forged, or mid-handshake — not a usable session).
fn classify_session_state(session_ctrl: HsmSessCtrl, state: HsmSessionState) -> HsmResult<()> {
    match state {
        HsmSessionState::Active => Ok(()),
        HsmSessionState::NeedsRenegotiation if session_ctrl == HsmSessCtrl::Close => Ok(()),
        HsmSessionState::NeedsRenegotiation => Err(HsmError::SessionNeedsRenegotiation),
        HsmSessionState::Pending | HsmSessionState::Invalid => Err(HsmError::SessionNotFound),
    }
}

#[cfg(test)]
mod session_gate_tests {
    use super::*;

    #[test]
    fn flush_success_and_absent_session_report_closed_completion() {
        for sess_id in [0, 7, u16::MAX] {
            for result in [Ok(()), Err(HsmError::SessionNotFound)] {
                let reply = flush_session_completion(sess_id, result).unwrap();
                assert!(reply.resp.is_none());
                assert!(!reply.ddi_failed);
                assert_eq!(
                    reply.sess,
                    HsmCqeSession {
                        ctrl: HsmSessCtrl::Close,
                        id: Some(sess_id),
                        vault_id: None,
                        closed: true,
                    }
                );
            }
        }
    }

    #[test]
    fn flush_maps_other_teardown_errors_to_internal() {
        for err in [
            HsmError::KeyNotFound,
            HsmError::InvalidArg,
            HsmError::InternalError,
        ] {
            let Err(e) = flush_session_completion(7, Err(err)) else {
                unreachable!()
            };
            assert_eq!(e, HsmError::InternalError);
        }
    }

    struct TestSqe {
        ctrl: HsmSessCtrl,
        id: Option<u16>,
    }

    impl HsmSqe for TestSqe {
        fn opcode(&self) -> u16 {
            OP_FLUSH
        }

        fn session_id(&self) -> Option<u16> {
            self.id
        }

        fn session_ctrl(&self) -> HsmSessCtrl {
            self.ctrl
        }
    }

    fn flush_sqe(ctrl: HsmSessCtrl, id: Option<u16>) -> TestSqe {
        TestSqe { ctrl, id }
    }

    #[test]
    fn flush_uses_sqe_session_without_dma_buffers() {
        for sess_id in [0, 7, u16::MAX] {
            let sqe = flush_sqe(HsmSessCtrl::Close, Some(sess_id));
            assert_eq!(flush_session_id(&sqe), Ok(sess_id));
        }
    }

    #[test]
    fn flush_rejects_wrong_session_control() {
        for ctrl in [
            HsmSessCtrl::NoSession,
            HsmSessCtrl::Open,
            HsmSessCtrl::InSession,
        ] {
            assert_eq!(
                flush_session_id(&flush_sqe(ctrl, Some(1))),
                Err(HsmError::InvalidSessionControlOpcode)
            );
        }
    }

    #[test]
    fn flush_requires_session_id_valid() {
        assert_eq!(
            flush_session_id(&flush_sqe(HsmSessCtrl::Close, None)),
            Err(HsmError::SessionExpected)
        );
    }

    #[test]
    fn no_session_and_open_never_require_a_live_slot() {
        for op in [DdiOp::GetApiRev, DdiOp::OpenSession, DdiOp::EccSign] {
            assert!(!session_ctrl_requires_live_session(
                HsmSessCtrl::NoSession,
                op
            ));
            assert!(!session_ctrl_requires_live_session(HsmSessCtrl::Open, op));
        }
    }

    #[test]
    fn in_session_requires_live_slot_except_reopen() {
        assert!(session_ctrl_requires_live_session(
            HsmSessCtrl::InSession,
            DdiOp::EcdhKeyExchange
        ));
        assert!(session_ctrl_requires_live_session(
            HsmSessCtrl::InSession,
            DdiOp::ChangePin
        ));
        // ReopenSession re-keys a renegotiation-pending slot; it is not
        // gated centrally.
        assert!(!session_ctrl_requires_live_session(
            HsmSessCtrl::InSession,
            DdiOp::ReopenSession
        ));
    }

    #[test]
    fn close_always_requires_the_slot_to_be_checked() {
        assert!(session_ctrl_requires_live_session(
            HsmSessCtrl::Close,
            DdiOp::CloseSession
        ));
    }

    #[test]
    fn active_slot_is_accepted_for_every_gated_ctrl() {
        for ctrl in [HsmSessCtrl::InSession, HsmSessCtrl::Close] {
            assert!(classify_session_state(ctrl, HsmSessionState::Active).is_ok());
        }
    }

    #[test]
    fn in_session_on_renego_slot_must_renegotiate() {
        assert_eq!(
            classify_session_state(HsmSessCtrl::InSession, HsmSessionState::NeedsRenegotiation),
            Err(HsmError::SessionNeedsRenegotiation)
        );
    }

    #[test]
    fn close_on_renego_slot_is_allowed() {
        // A renegotiation-pending slot can still be torn down without a
        // prior reopen (the reopen/close carve-out).
        assert!(
            classify_session_state(HsmSessCtrl::Close, HsmSessionState::NeedsRenegotiation).is_ok()
        );
    }

    #[test]
    fn pending_and_invalid_slots_are_not_found_for_every_gated_ctrl() {
        for ctrl in [HsmSessCtrl::InSession, HsmSessCtrl::Close] {
            for state in [HsmSessionState::Pending, HsmSessionState::Invalid] {
                assert_eq!(
                    classify_session_state(ctrl, state),
                    Err(HsmError::SessionNotFound)
                );
            }
        }
    }
}
