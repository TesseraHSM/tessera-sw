// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IO dispatch and opcode handling for [`Hsm`].
//!
//! # Pipeline
//!
//! ```text
//!  poll_io ──► handle_io ──► handle_{mbor,tbor,flush}_op
//!                  │              │                    │
//!                  │         validate SQE         validate op
//!                  │         dispatch opcode      in-DMA
//!                  │                              session validate
//!                  │                              DDI dispatch
//!                  │                              out-DMA
//!              populate CQE
//!              complete_io
//! ```
//!
//! # Error handling
//!
//! Two-tier model:
//!
//! - **Pre-decode** (SQE validation, inbound DMA, header decode):
//!   Errors return [`OpError`] → CQE gets host status code, no DDI body.
//!
//! - **Post-decode** (session validation, DDI dispatch, command exec):
//!   Errors encode a [`DdiErrCmdResp`] into smem and continue to outbound
//!   DMA. CQE status = Success; host reads error from DDI response body.
//!
//! # Session control
//!
//! Each MBOR DDI op maps to a [`SessionCtrl`] kind (NoSession, Open,
//! InSession, Close). Session hijack protection validates the SQE
//! session flags against the decoded DDI header before dispatch.
//! Session state flows back via [`HsmOpStatus`] → CQE DW0/DW1.
//!
//! TBOR commands derive their [`SessionCtrl`] from the wire opcode
//! via [`SessionCtrl::from_tbor_opcode`]: `GetApiRev` and
//! `OpenSessionInit` are session-less; `OpenSessionFinish` and
//! `ChangePsk` require the SQE to carry the targeted slot's
//! `session_id`; `CloseSession` is classified as `Close` so the CQE
//! reflects the slot teardown.

use tsra_fw_ddi_mbor_api::DdiDecoder;
use tsra_fw_ddi_mbor_types::DdiOp;
use tsra_fw_ddi_mbor_types::DdiReqHdr;
use tsra_fw_ddi_tbor::RequestView as TborRequestView;
use tsra_fw_hsm_oob::OobPtr;
use tsra_fw_hsm_undo::UndoLog;
use tsra_fw_hsm_undo::WalkOutcome;
use tsra_fw_hsm_undo::UNDO_LOG_SIZE;

use super::*;

impl<P: HsmPal> Hsm<P> {
    /// Top-level IO handler invoked by each Embassy send-task.
    ///
    /// Populates CQE header fields, runs the command pipeline, then
    /// writes session fields and status to the CQE before completion.
    pub async fn handle_io(&self, mut io: P::Io) {
        // Gate on partition state — drop IOs for non-enabled partitions.
        if !self.partition_enabled(&io) {
            debug!("core", "dropping IO for disabled partition");
            if let Err(_e) = self.pal().drop_io(io).await {
                error!("core", HsmError::DropIoFailure, "drop_io failed: {:?}", _e);
            }
            return;
        }

        // Single SQE parse — extract all fields once, populate CQE, validate,
        // and dispatch.
        let (op, validated) = match Self::init_cqe_from_sqe(&mut io) {
            Ok(decoded) => decoded,
            Err(_e) => {
                error!("core", _e, "unsupported SQE or CQE length");
                if let Err(_e) = self.pal().drop_io(io).await {
                    error!("core", HsmError::DropIoFailure, "drop_io failed: {:?}", _e);
                }
                return;
            }
        };

        // The per-command undo log (TBOR only), owned here so it outlives
        // `complete_io` and the post-completion walk.  Stays `None` for
        // MBOR / flush / invalid SQEs; a TBOR command binds it on entry and
        // **fails before mutating** if its DMA buffer can't be carved.
        let mut undo: Option<UndoLog<'_>> = None;

        let op_result = match validated {
            Err(e) => Err(e),
            Ok(()) => match op {
                OP_MBOR => self.handle_mbor_op(&mut io).await,
                OP_TBOR => match self.bind_undo(&io) {
                    Ok(log) => self.handle_tbor_op(&mut io, undo.insert(log)).await,
                    Err(e) => Err(e),
                },
                OP_FLUSH => self.handle_flush_op(&mut io).await,
                _ => Err(OpError::new(
                    HsmError::UnsupportedCmd,
                    HostStatus::INVALID_COMMAND_OPCODE,
                )),
            },
        };
        let handler_ok = op_result.as_ref().is_ok_and(|status| !status.ddi_failed);

        // Post the completion (CQE) to the host, then run the undo/commit
        // walk, then free the slot.  Splitting `complete_io` from
        // `drop_io` lets the walk run over `io` *after* the CQE post, so a
        // failed post reverts too.
        let completion = match Self::finalize_cqe(&mut io, op_result) {
            Ok(()) => self.pal().complete_io(&mut io).await,
            Err(e) => Err(e),
        };
        let cqe_ok = match completion {
            Ok(()) => true,
            Err(_e) => {
                error!(
                    "core",
                    HsmError::CompleteIoFailure,
                    "CQE finalization or completion failed: {:?}",
                    _e
                );
                false
            }
        };

        // Walk the undo log (TBOR only): commit iff the handler succeeded
        // *and* the CQE posted; otherwise revert unconditionally.  Safe
        // without a lock or generation check — admin teardown can't race an
        // in-flight IO, and this walk runs before `drop_io` frees the slot.
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

        if let Err(_e) = self.pal().drop_io(io).await {
            error!("core", HsmError::DropIoFailure, "drop_io failed: {:?}", _e);
        }
    }

    /// Bind the per-command undo log for a TBOR command, carved from `io`'s
    /// DMA heap.
    ///
    /// [`UNDO_LOG_SIZE`] bytes are taken from `io`'s DMA heap so the byte
    /// pre-images the undo walk restores are DMA-accessible.  The undo log
    /// is **mandatory**: if the buffer can't be carved, the command fails
    /// here (`ALLOC_ERR`) *before* mutating any partition state, rather than
    /// running with no rollback.
    fn bind_undo<'s>(&'s self, io: &P::Io) -> Result<UndoLog<'s>, OpError> {
        let buf = self
            .pal()
            .dma_alloc(io, UNDO_LOG_SIZE)
            .op_status(HostStatus::ALLOC_ERR)?;
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

    /// Parses the SQE once, populates the CQE header, and returns the
    /// op code along with the SQE-validation result.
    #[inline]
    fn init_cqe_from_sqe(io: &mut P::Io) -> HsmResult<(u16, Result<(), OpError>)> {
        let (cmd_id, op, validated) = {
            let sqe = Sqe::try_from(io.sqe())?;
            (sqe.cmd_id(), sqe.op(), sqe.validate())
        };
        let mut cqe = Cqe::try_from(io.cqe())?;
        cqe.clear();
        cqe.set_cmd_id(cmd_id);
        Ok((op, validated))
    }

    /// Writes the final CQE status from the dispatch result.
    #[inline]
    fn finalize_cqe(io: &mut P::Io, op_result: Result<HsmOpStatus, OpError>) -> HsmResult<()> {
        let mut cqe = Cqe::try_from(io.cqe())?;
        match op_result {
            Ok(status) => {
                cqe.set_dw0(CqeDw0::from(status.cqe_dw0_session).with_dst_len(status.resp_len));
                cqe.set_dw1(CqeDw1::from(status.cqe_dw1));
            }
            Err(e) => {
                cqe.set_status(e.status);
                error!("core", e.err, "handle_op failed");
            }
        }
        Ok(())
    }

    /// Handles an [`OP_MBOR`] IO command.
    ///
    /// **Phase 1 (pre-decode)** — SQE validation, inbound DMA, header
    /// decode. Errors → [`OpError`] → CQE host status, no DDI body.
    ///
    /// **Phase 2 (post-decode)** — Session validation, DDI dispatch.
    /// Errors → DDI error response DMA'd to host, CQE Success.
    async fn handle_mbor_op(&self, io: &mut P::Io) -> Result<HsmOpStatus, OpError> {
        let params = Self::decode_io_sqe(io)?;
        let split = params.src_len.next_multiple_of(4);
        let req_buf = self
            .pal()
            .dma_alloc(io, split)
            .op_status(HostStatus::ALLOC_ERR)?;

        // ── Phase 1: inbound DMA (yield 1) ─────────────────────────
        self.pal()
            .copy_mem_from_host(
                io,
                params.src_addr,
                params.src_addr2,
                &mut req_buf[..params.src_len],
                true,
            )
            .await
            .op_err(
                "core",
                HsmError::FailedToStartDmaTransaction,
                HostStatus::DMA_TXN_ERROR,
            )?;

        // ── Phase 2: decode + validate + dispatch (no yield) ───────
        let (resp, session_ctrl, cqe_sess_id, cqe_app_vault_id, cqe_closed) = {
            let req = &mut req_buf[..params.src_len];
            let mut decoder = DdiDecoder::new(req);
            let hdr: DdiReqHdr = decoder.decode_hdr().op_err(
                "core",
                HsmError::DdiDecodeFailed,
                HostStatus::REQ_HDR_DECODE_ERR,
            )?;

            let session_ctrl = SessionCtrl::from_op(hdr.op);

            // The decoder borrows the request buffer, so it is scoped:
            // the borrow has to end before the buffer can be handed to
            // the platform below.
            let core_result = {
                let mut decoder = decoder;
                match Self::validate_session(
                    &hdr,
                    session_ctrl,
                    params.session_flags,
                    params.sqe_session_id,
                )
                .and_then(|()| self.validate_session_live(io, &hdr, session_ctrl))
                {
                    Ok(()) => ddi::mbor::dispatch(self.pal(), io, &mut decoder, &hdr).await,
                    Err(e) => Err(e),
                }
            };
            // `UnsupportedCmd` means no core handler claimed this
            // opcode. Offer the untouched request to the platform before
            // giving up; its answer, including its own `UnsupportedCmd`,
            // is what the host sees.
            //
            // A handler for a *known* opcode can also return this status
            // — `rsa_unwrap` does for an unsupported key type — so the
            // hook may occasionally be offered a request the core did
            // recognise. That is harmless as long as a platform claims
            // only opcodes the core has no handler for, which is the
            // documented contract; the alternative, duplicating the
            // opcode table here to distinguish the two, would rot.
            let dispatch_result = match core_result {
                Err(HsmError::UnsupportedCmd) => self
                    .pal()
                    .mbor_dispatch(io, &mut req_buf[..params.src_len])
                    .await
                    .map(ddi::mbor::DispatchResult::from_resp),
                other => other,
            };

            // Fill the CQE session fields so the host can track the session
            // per file handle: a successful OpenSession carries the newly
            // allocated id in `session_id` (which sets `session_id_valid`), and
            // a successful CloseSession additionally sets `session_closed`.
            // Both are left cleared on any dispatch failure so the fields are
            // only populated on success.
            let (cqe_sess_id, cqe_app_vault_id, cqe_closed) = match &dispatch_result {
                Ok(out) => match session_ctrl {
                    SessionCtrl::Open => (
                        out.session_id,
                        Some(ddi::mbor::open_session::SESSION_SHORT_APP_ID),
                        false,
                    ),
                    SessionCtrl::Close => (hdr.sess_id, None, true),
                    _ => (None, None, false),
                },
                Err(_) => (None, None, false),
            };

            let resp: &HsmDmaBuf = dispatch_result.map(|out| out.resp).or_else(|status| {
                self.pal()
                    .dma_alloc_var(io, |buf| ddi::mbor::encode_ddi_err(hdr.op, status, buf))
                    .op_status(HostStatus::INTERNAL_ERROR)
                    .map(|b| &*b)
            })?;

            (
                resp,
                session_ctrl,
                cqe_sess_id,
                cqe_app_vault_id,
                cqe_closed,
            )
        };

        let resp_len = resp.len();

        // ── Outbound DMA (yield 2) ─────────────────────────────────
        self.pal()
            .copy_mem_to_host(io, resp, params.dst_addr, params.dst_addr2, true)
            .await
            .op_err(
                "core",
                HsmError::FailedToStartDmaTransaction,
                HostStatus::DMA_TXN_ERROR,
            )?;

        Ok(HsmOpStatus::new(
            resp_len,
            session_ctrl,
            cqe_sess_id,
            cqe_app_vault_id,
            cqe_closed,
        ))
    }

    /// Handles an [`OP_TBOR`] IO command.
    ///
    /// Parses TBOR framing and dispatches by raw `u8` opcode, using the
    /// opcode's session policy and a shared exchange allocation.
    ///
    /// **Phase 1 (pre-decode)** — SQE validation, inbound DMA, TBOR
    /// `RequestView::parse`. Errors → [`OpError`] → CQE host status.
    ///
    /// **Phase 2 (post-decode)** — Dispatch by opcode. Errors are
    /// encoded into the exchange as a non-zero TBOR `status`. The undo
    /// log is independent and remains live through outbound DMA and CQE.
    async fn handle_tbor_op<'s>(
        &'s self,
        io: &mut P::Io,
        undo: &mut UndoLog<'s>,
    ) -> Result<HsmOpStatus, OpError> {
        let params = Self::decode_io_sqe(io)?;
        let split = params.src_len.next_multiple_of(4);
        let mut allocation = self
            .pal()
            .dma_alloc_exchange(io, split)
            .op_status(HostStatus::ALLOC_ERR)?;

        // ── Phase 1: inbound DMA (yield 1) ─────────────────────────
        self.pal()
            .copy_mem_from_host(
                io,
                params.src_addr,
                params.src_addr2,
                &mut allocation.buffer_mut()[..params.src_len],
                true,
            )
            .await
            .op_err(
                "core",
                HsmError::FailedToStartDmaTransaction,
                HostStatus::DMA_TXN_ERROR,
            )?;

        // Parse once before growing or reborrowing the request storage.
        let (opcode, body_sess_id) = {
            let req_view = TborRequestView::parse(&allocation.buffer_mut()[..params.src_len])
                .op_err(
                    "core",
                    HsmError::DdiDecodeFailed,
                    HostStatus::REQ_HDR_DECODE_ERR,
                )?;
            let op = req_view.opcode();
            let sid = if ddi::tbor::needs_body_session_id(op) {
                ddi::tbor::peek_session_id(&req_view)
            } else {
                None
            };
            (op, sid)
        };

        let capacity = ddi::tbor::exchange_capacity(opcode, params.src_len, params.dst_len);
        if capacity > allocation.len() {
            self.pal()
                .dma_grow(io, &mut allocation, capacity)
                .op_status(HostStatus::ALLOC_ERR)?;
        }
        let mut exchange = HsmCmdBuf::new(allocation.buffer_mut(), params.src_len, params.dst_len)
            .op_status(HostStatus::INTERNAL_ERROR)?;
        let session_ctrl = SessionCtrl::from_tbor_opcode(opcode);
        let dispatch_result =
            if Self::validate_tbor_session_flags(session_ctrl, params.session_flags).is_err() {
                Err(HsmError::InvalidArg)
            } else {
                ddi::tbor::dispatch(
                    self.pal(),
                    io,
                    &mut exchange,
                    opcode,
                    params.sqe_session_id,
                    body_sess_id,
                    params.oob,
                    undo,
                )
                .await
            };
        // Session ids are exposed only after successful dispatch and response
        // validation. Preserve the existing close/open CQE semantics.
        let ddi_failed = dispatch_result.is_err();
        let (cqe_sess_id, cqe_closed) = match &dispatch_result {
            Ok(out) => match session_ctrl {
                SessionCtrl::Open => (out.session_id, false),
                SessionCtrl::Close => (Some(params.sqe_session_id), true),
                _ => (None, false),
            },
            Err(_) => (None, false),
        };
        let resp = match dispatch_result {
            Ok(out) => exchange
                .response(out.response_len)
                .op_status(HostStatus::INTERNAL_ERROR)?,
            Err(err) => {
                let len = ddi::tbor::encode_exchange_err(opcode, err, &mut exchange)
                    .op_status(HostStatus::INTERNAL_ERROR)?;
                exchange
                    .response(len)
                    .op_status(HostStatus::INTERNAL_ERROR)?
            }
        };
        let resp_len = resp.len();

        // ── Outbound DMA (yield 2) ─────────────────────────────────
        self.pal()
            .copy_mem_to_host(io, resp, params.dst_addr, params.dst_addr2, true)
            .await
            .op_err(
                "core",
                HsmError::FailedToStartDmaTransaction,
                HostStatus::DMA_TXN_ERROR,
            )?;

        let mut status = HsmOpStatus::new(resp_len, session_ctrl, cqe_sess_id, None, cqe_closed);
        status.ddi_failed = ddi_failed;
        Ok(status)
    }

    /// Validates the SQE for an MBOR / TBOR IO command and extracts the
    /// fields used by [`Self::handle_mbor_op`] / [`Self::handle_tbor_op`].
    #[inline]
    fn decode_io_sqe(io: &P::Io) -> Result<IoSqeParams, OpError> {
        let sqe = Sqe::try_from(io.sqe()).op_status(HostStatus::INVALID_FIELD_IN_COMMAND)?;
        sqe.validate_io_op()?;
        // Out-of-band SGL descriptor array (side-band bulk transfers such
        // as PartFinal's PTA cert chain); `None` when the SQE carries no
        // OOB region.  A non-zero `oob_len` with a null `oob_prp` is
        // rejected up front: `validate_io_op` only bounds the OOB length,
        // so without this a later OOB read would DMA from a null address.
        let oob_len = sqe.oob_len();
        let oob_prp = sqe.oob_prp();
        let oob = match (oob_len != 0, oob_prp.is_null()) {
            (false, _) => None,
            (true, false) => Some(OobPtr {
                prp: oob_prp,
                len: oob_len,
            }),
            (true, true) => {
                return Err(OpError::new(
                    HsmError::InvalidArg,
                    HostStatus::INVALID_FIELD_IN_COMMAND,
                ));
            }
        };
        Ok(IoSqeParams {
            src_len: sqe.src_len() as usize,
            dst_len: sqe.dst_len() as usize,
            src_addr: sqe.src_prp1(),
            src_addr2: sqe.src_prp2(),
            dst_addr: sqe.dst_prp1(),
            dst_addr2: sqe.dst_prp2(),
            session_flags: sqe.session_flags(),
            sqe_session_id: sqe.session_id(),
            oob,
        })
    }

    /// Validate SQE session flags against the decoded DDI header.
    #[inline(always)]
    fn validate_session(
        hdr: &DdiReqHdr,
        expected: SessionCtrl,
        flags: SessionFlags,
        sqe_session_id: u16,
    ) -> HsmResult<()> {
        // Rule 1: SQE ctrl must match DDI op
        if flags.ctrl() != expected as u8 {
            return Err(HsmError::InvalidArg);
        }

        // Rule 2: ctrl/id_valid combinations
        match (expected, flags.id_valid()) {
            (SessionCtrl::NoSession, true) => return Err(HsmError::InvalidArg),
            (SessionCtrl::Open, true) => return Err(HsmError::SessionNotExpected),
            (SessionCtrl::Close, false) => return Err(HsmError::InvalidArg),
            (SessionCtrl::InSession, false) => return Err(HsmError::InvalidArg),
            _ => {}
        }

        // Rule 3: SQE session_id must match DDI header sess_id
        if flags.id_valid() {
            match hdr.sess_id {
                Some(id) if id == sqe_session_id => {}
                _ => return Err(HsmError::InvalidArg),
            }
        } else if hdr.sess_id.is_some() {
            return Err(HsmError::InvalidArg);
        }

        Ok(())
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
        session_ctrl: SessionCtrl,
    ) -> HsmResult<()> {
        if !session_ctrl_requires_live_session(session_ctrl, hdr.op) {
            return Ok(());
        }
        let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
        let state = self.pal().session_state(io, HsmSessId::from(sess_id));
        classify_session_state(session_ctrl, state)
    }

    /// TBOR-side analogue of [`Self::validate_session`] that checks
    /// only the SQE-flag shape against the opcode's expected
    /// [`SessionCtrl`].
    ///
    /// Cross-checking the SQE `session_id` against the inline body
    /// `session_id` TOC entry happens in [`ddi::tbor::dispatch`] for
    /// every in-session / close opcode (i.e. every opcode whose
    /// [`SessionCtrl`] requires `id_valid = true`).  This validator
    /// only enforces the `ctrl` / `id_valid` consistency.
    #[inline(always)]
    fn validate_tbor_session_flags(expected: SessionCtrl, flags: SessionFlags) -> HsmResult<()> {
        if flags.ctrl() != expected as u8 {
            return Err(HsmError::InvalidArg);
        }
        match (expected, flags.id_valid()) {
            (SessionCtrl::NoSession, true) => Err(HsmError::InvalidArg),
            (SessionCtrl::Open, true) => Err(HsmError::SessionNotExpected),
            (SessionCtrl::Close, false) => Err(HsmError::InvalidArg),
            (SessionCtrl::InSession, false) => Err(HsmError::InvalidArg),
            _ => Ok(()),
        }
    }

    /// Handles an [`OP_FLUSH`] IO command.
    ///
    /// Tears down the SQE's session without DMA or a DDI response body.
    /// An already-free slot is an idempotent cleanup.
    async fn handle_flush_op(&self, io: &mut P::Io) -> Result<HsmOpStatus, OpError> {
        let sqe = Sqe::try_from(io.sqe()).op_status(HostStatus::INVALID_FIELD_IN_COMMAND)?;
        let sess_id = flush_session_id(&sqe).op_status(HostStatus::INVALID_FIELD_IN_COMMAND)?;
        let _lock = self
            .pal()
            .partition_lock(io)
            .await
            .op_status(HostStatus::INTERNAL_ERROR)?;
        let result = self
            .pal()
            .session_destroy(io, HsmSessId::from(sess_id))
            .await;
        flush_session_completion(sess_id, result)
    }
}

fn flush_session_completion(sess_id: u16, result: HsmResult<()>) -> Result<HsmOpStatus, OpError> {
    match result {
        Ok(()) | Err(HsmError::SessionNotFound) => Ok(HsmOpStatus::new(
            0,
            SessionCtrl::Close,
            Some(sess_id),
            None,
            true,
        )),
        Err(err) => Err(err).op_status(HostStatus::INTERNAL_ERROR),
    }
}

fn flush_session_id(sqe: &Sqe<'_>) -> HsmResult<u16> {
    let flags = sqe.session_flags();
    if flags.ctrl() != SessionCtrl::Close as u8 {
        return Err(HsmError::InvalidSessionControlOpcode);
    }
    if !flags.id_valid() {
        return Err(HsmError::SessionExpected);
    }
    Ok(sqe.session_id())
}

/// Fields extracted from a validated MBOR / TBOR IO SQE.
struct IoSqeParams {
    src_len: usize,
    dst_len: usize,
    src_addr: HsmDmaAddr,
    /// Second host source page (SQE PRP2). Required once the request
    /// crosses the first 4 KiB page; the two host pages are separately
    /// allocated and not physically contiguous.
    src_addr2: HsmDmaAddr,
    dst_addr: HsmDmaAddr,
    /// Second host destination page (SQE PRP2). Required once the
    /// response crosses the first 4 KiB page.
    dst_addr2: HsmDmaAddr,
    session_flags: SessionFlags,
    sqe_session_id: u16,
    /// Optional out-of-band SGL descriptor array (`oob_prp`/`oob_len`);
    /// `None` when `oob_len == 0`.  Threaded to TBOR handlers that pull
    /// bulk side-band data (e.g. PartFinal's PTA cert chain).
    oob: Option<OobPtr>,
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
fn session_ctrl_requires_live_session(session_ctrl: SessionCtrl, op: DdiOp) -> bool {
    match session_ctrl {
        SessionCtrl::InSession => op != DdiOp::ReopenSession,
        SessionCtrl::Close => true,
        SessionCtrl::NoSession | SessionCtrl::Open => false,
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
fn classify_session_state(session_ctrl: SessionCtrl, state: HsmSessionState) -> HsmResult<()> {
    match state {
        HsmSessionState::Active => Ok(()),
        HsmSessionState::NeedsRenegotiation if session_ctrl == SessionCtrl::Close => Ok(()),
        HsmSessionState::NeedsRenegotiation => Err(HsmError::SessionNeedsRenegotiation),
        HsmSessionState::Pending | HsmSessionState::Invalid => Err(HsmError::SessionNotFound),
    }
}

#[cfg(test)]
mod session_gate_tests {
    use tsra_fw_ddi_tbor_types as types;
    use tsra_fw_hsm_pal_std::HsmIoRequest;
    use tsra_fw_hsm_pal_std::HsmPartId;
    use tsra_fw_hsm_pal_std::StdHsmPal;

    use super::*;

    #[repr(align(4096))]
    struct HostPage([u8; 4096]);

    #[allow(unsafe_code)]
    fn response_bytes(bytes: &[u8]) -> &HsmDmaBuf {
        // SAFETY: the std PAL uses ordinary process memory, without device DMA.
        unsafe { HsmDmaBuf::from_raw(bytes) }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn tbor_errors_and_failed_completions_rollback_pending_sessions() {
        std::thread::Builder::new()
            // Match the std firmware executor's stack for the unoptimized IO future.
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(check_tbor_rollback());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[allow(clippy::unwrap_used)]
    async fn check_tbor_rollback() {
        let (tx, rx) = async_channel::bounded(1);
        let hsm = Hsm::new(StdHsmPal::new(rx, tokio::runtime::Handle::current()));
        hsm.pal().part_alloc_internal(0, 1).await.unwrap();
        hsm.pal().part_enable_internal(0).await.unwrap();
        let mut committed_session = None;

        for attempt in 0..10 {
            let short_response = attempt < 8;
            let fail_completion = attempt == 8;
            let mut request = HostPage([0; 4096]);
            let mut response = HostPage([0xA5; 4096]);
            let request_len = types::TborSessionOpenInitReq::encode(&mut request.0)
                .unwrap()
                .psk_id(types::PskId::CryptoUser)
                .unwrap()
                .session_type(types::SessionKind(0))
                .unwrap()
                .suite_id(types::SuiteId(1))
                .unwrap()
                .pk_init(&[0; 97])
                .unwrap()
                .finish()
                .len();
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            tx.send(HsmIoRequest {
                pid: HsmPartId::from(0u8),
                qid: 0,
                qidx: 0,
                sqe: SqeBuilder::new()
                    .cmd(CmdDword::new().with_op(OP_TBOR))
                    .buf_lens(request_len as u32, if short_response { 12 } else { 4096 })
                    .src_prp1(request.0.as_ptr() as u64)
                    .dst_prp1(response.0.as_mut_ptr() as u64)
                    .session_flags(SessionFlags::new().with_ctrl(SessionCtrl::Open as u8))
                    .build(),
                tx: reply_tx,
            })
            .await
            .unwrap();
            let io = hsm.pal().poll_io().await.unwrap();
            if attempt > 0 {
                hsm.pal()
                    .alloc_scoped(&io, |alloc| -> HsmResult<()> {
                        let reused =
                            alloc.dma_alloc(UNDO_LOG_SIZE + request_len.next_multiple_of(4))?;
                        assert!(
                            reused.iter().all(|&b| b == 0),
                            "previous IO was not scrubbed"
                        );
                        Ok(())
                    })
                    .unwrap();
            }
            for id in 0u16..8 {
                assert!(
                    matches!(
                        hsm.pal().session_state(&io, HsmSessId::from(id)),
                        HsmSessionState::Invalid
                    ),
                    "session {id} remained live before attempt {attempt}"
                );
            }
            if attempt == 0 {
                hsm.pal()
                    .dma_alloc(&io, 16384 - UNDO_LOG_SIZE - 100)
                    .unwrap()
                    .fill(0xA5);
            }
            let mut pk_init = [0; 97];
            pk_init[0] = 4;
            pk_init[1..]
                .copy_from_slice(&crate::part_state::part_id_pub_key(hsm.pal(), &io).unwrap()[..]);
            types::TborSessionOpenInitReq::encode(&mut request.0)
                .unwrap()
                .psk_id(types::PskId::CryptoUser)
                .unwrap()
                .session_type(types::SessionKind(0))
                .unwrap()
                .suite_id(types::SuiteId(1))
                .unwrap()
                .pk_init(&pk_init)
                .unwrap()
                .finish();
            let reply_rx = if fail_completion {
                drop(reply_rx);
                None
            } else {
                Some(reply_rx)
            };
            hsm.handle_io(io).await;
            if let Some(reply_rx) = reply_rx {
                let mut raw = reply_rx.await.unwrap();
                let cqe = Cqe::from(&mut raw);
                if attempt == 0 {
                    assert_eq!(cqe.status(), HostStatus::ALLOC_ERR);
                    assert!(response.0.iter().all(|&b| b == 0xA5));
                    continue;
                }
                assert_eq!(cqe.status(), 0, "attempt {attempt}");
                let len = usize::from(cqe.dst_len());
                assert!(response.0[len..].iter().all(|&b| b == 0xA5));
                if short_response {
                    let frame =
                        tsra_fw_ddi_tbor::ResponseView::parse(response_bytes(&response.0[..len]))
                            .unwrap();
                    assert_eq!(
                        frame.status(),
                        HsmError::TborBufferTooSmall.0,
                        "attempt {attempt}"
                    );
                    assert_eq!(len, 12);
                    assert!(!cqe.dw0().session_id_valid());
                } else {
                    let frame =
                        types::TborSessionOpenInitResp::decode(response_bytes(&response.0[..len]))
                            .unwrap();
                    assert!(cqe.dw0().session_id_valid());
                    assert_eq!(cqe.dw1().session_id(), u16::from(frame.session_id()));
                    committed_session = Some(HsmSessId::from(u16::from(frame.session_id())));
                }
            } else {
                types::TborSessionOpenInitResp::decode(response_bytes(&response.0)).unwrap();
            }
        }

        let (reply_tx, _) = tokio::sync::oneshot::channel();
        tx.send(HsmIoRequest {
            pid: HsmPartId::from(0u8),
            qid: 0,
            qidx: 0,
            sqe: [0; tsra_fw_hsm_io::SQE_DWORDS],
            tx: reply_tx,
        })
        .await
        .unwrap();
        let io = hsm.pal().poll_io().await.unwrap();
        let id = committed_session.unwrap();
        assert!(matches!(
            hsm.pal().session_state(&io, id),
            HsmSessionState::Pending
        ));
        hsm.pal().session_destroy(&io, id).await.unwrap();
        hsm.pal().drop_io(io).await.unwrap();
    }

    #[test]
    fn flush_success_and_absent_session_report_closed_completion() {
        for sess_id in [0, 7, u16::MAX] {
            for result in [Ok(()), Err(HsmError::SessionNotFound)] {
                let status = flush_session_completion(sess_id, result).unwrap();
                let flags = CqeDw0::from(status.cqe_dw0_session);
                let ids = CqeDw1::from(status.cqe_dw1);
                assert_eq!(status.resp_len, 0);
                assert_eq!(flags.dst_len(), 0);
                assert_eq!(flags.session_ctrl(), SessionCtrl::Close as u8);
                assert!(flags.session_id_valid());
                assert!(flags.session_closed());
                assert!(!flags.app_vault_id_valid());
                assert_eq!(ids.session_id(), sess_id);
                assert_eq!(ids.app_vault_id(), 0);
            }
        }
    }

    #[test]
    fn flush_preserves_other_teardown_errors() {
        for err in [
            HsmError::KeyNotFound,
            HsmError::InvalidArg,
            HsmError::InternalError,
        ] {
            let result = flush_session_completion(7, Err(err)).unwrap_err();
            assert_eq!(result.err, err);
            assert_eq!(result.status, HostStatus::INTERNAL_ERROR);
        }
    }

    #[test]
    fn flush_uses_sqe_session_without_dma_buffers() {
        for sess_id in [0, 7, u16::MAX] {
            let sqe = SqeBuilder::new()
                .cmd(CmdDword::new().with_op(OP_FLUSH))
                .session_flags(
                    SessionFlags::new()
                        .with_ctrl(SessionCtrl::Close as u8)
                        .with_id_valid(true),
                )
                .session_id(sess_id)
                .build();
            assert_eq!(flush_session_id(&Sqe::from(&sqe)), Ok(sess_id));
        }
    }

    #[test]
    fn flush_rejects_wrong_session_control() {
        for ctrl in [
            SessionCtrl::NoSession,
            SessionCtrl::Open,
            SessionCtrl::InSession,
        ] {
            let sqe = SqeBuilder::new()
                .session_flags(
                    SessionFlags::new()
                        .with_ctrl(ctrl as u8)
                        .with_id_valid(true),
                )
                .build();
            assert_eq!(
                flush_session_id(&Sqe::from(&sqe)),
                Err(HsmError::InvalidSessionControlOpcode)
            );
        }
    }

    #[test]
    fn flush_requires_session_id_valid() {
        let sqe = SqeBuilder::new()
            .session_flags(SessionFlags::new().with_ctrl(SessionCtrl::Close as u8))
            .build();
        assert_eq!(
            flush_session_id(&Sqe::from(&sqe)),
            Err(HsmError::SessionExpected)
        );
    }

    #[test]
    fn no_session_and_open_never_require_a_live_slot() {
        for op in [DdiOp::GetApiRev, DdiOp::OpenSession, DdiOp::EccSign] {
            assert!(!session_ctrl_requires_live_session(
                SessionCtrl::NoSession,
                op
            ));
            assert!(!session_ctrl_requires_live_session(SessionCtrl::Open, op));
        }
    }

    #[test]
    fn in_session_requires_live_slot_except_reopen() {
        assert!(session_ctrl_requires_live_session(
            SessionCtrl::InSession,
            DdiOp::EcdhKeyExchange
        ));
        assert!(session_ctrl_requires_live_session(
            SessionCtrl::InSession,
            DdiOp::ChangePin
        ));
        // ReopenSession re-keys a renegotiation-pending slot; it is not
        // gated centrally.
        assert!(!session_ctrl_requires_live_session(
            SessionCtrl::InSession,
            DdiOp::ReopenSession
        ));
    }

    #[test]
    fn close_always_requires_the_slot_to_be_checked() {
        assert!(session_ctrl_requires_live_session(
            SessionCtrl::Close,
            DdiOp::CloseSession
        ));
    }

    #[test]
    fn active_slot_is_accepted_for_every_gated_ctrl() {
        for ctrl in [SessionCtrl::InSession, SessionCtrl::Close] {
            assert!(classify_session_state(ctrl, HsmSessionState::Active).is_ok());
        }
    }

    #[test]
    fn in_session_on_renego_slot_must_renegotiate() {
        assert_eq!(
            classify_session_state(SessionCtrl::InSession, HsmSessionState::NeedsRenegotiation),
            Err(HsmError::SessionNeedsRenegotiation)
        );
    }

    #[test]
    fn close_on_renego_slot_is_allowed() {
        // A renegotiation-pending slot can still be torn down without a
        // prior reopen (the reopen/close carve-out).
        assert!(
            classify_session_state(SessionCtrl::Close, HsmSessionState::NeedsRenegotiation).is_ok()
        );
    }

    #[test]
    fn pending_and_invalid_slots_are_not_found_for_every_gated_ctrl() {
        for ctrl in [SessionCtrl::InSession, SessionCtrl::Close] {
            for state in [HsmSessionState::Pending, HsmSessionState::Invalid] {
                assert_eq!(
                    classify_session_state(ctrl, state),
                    Err(HsmError::SessionNotFound)
                );
            }
        }
    }
}
