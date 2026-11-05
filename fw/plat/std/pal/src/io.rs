// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IO work item and [`HsmIoController`] implementation for the std PAL.
//!
//! Defines the request/response types and the IO work item that flows
//! through the core. The [`HsmIoController`] implementation delegates
//! to [`StdIic`](crate::drivers::iic::StdIic) for receiving and
//! [`StdOic`](crate::drivers::oic::StdOic) for completing IOs.

use tokio::sync::oneshot::Sender as ReplySender;
use tsra_fw_hsm_bulk::BulkCqe;
use tsra_fw_hsm_bulk::RawBulkCqe;
use tsra_fw_hsm_bulk::RawBulkSqe;
use tsra_fw_hsm_bulk::BULK_CQE_DWORDS;
use tsra_fw_hsm_bulk::BULK_SQE_DWORDS;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::RawSqe;
use tsra_fw_hsm_io::CQE_DWORDS;
use tsra_fw_hsm_io::SQE_DWORDS;
use tsra_fw_hsm_pal_traits::*;

use crate::HsmPartId;
use crate::StdHsmPal;

/// An IO submit request sent from the user thread to the Embassy thread.
///
/// Contains the SQE, metadata, and a oneshot reply channel. Entries are
/// stored at the largest (bulk) size; `kind` selects how many dwords are
/// used (see [`StdHsmIo`]). Host buffers are referenced by address in the
/// SQE — the caller must keep them alive until the response is received.
pub struct HsmIoRequest {
    /// Source partition identifier.
    pub pid: HsmPartId,

    /// Source queue identifier.
    pub qid: u16,

    /// Index within the source queue.
    pub qidx: u16,

    /// Queue kind of the IO.
    pub kind: HsmIoKind,

    /// The submission queue entry; a command SQE uses the first
    /// [`SQE_DWORDS`] dwords.
    pub sqe: RawBulkSqe,

    /// Oneshot channel for sending the CQE back to the submitter; a
    /// command CQE is the first [`CQE_DWORDS`] dwords.
    pub tx: ReplySender<RawBulkCqe>,
}

impl HsmIoRequest {
    /// Builds a command IO request from a command SQE.
    pub fn cmd(
        pid: HsmPartId,
        qid: u16,
        qidx: u16,
        sqe: RawSqe,
        tx: ReplySender<RawBulkCqe>,
    ) -> Self {
        let mut req = Self {
            pid,
            qid,
            qidx,
            kind: HsmIoKind::Cmd,
            sqe: [0; BULK_SQE_DWORDS],
            tx,
        };
        if let Some(head) = req.sqe.first_chunk_mut::<SQE_DWORDS>() {
            *head = sqe;
        }
        req
    }
}

/// An IO work item backed by a pool-allocated buffer slot.
///
/// Created by [`poll_io`](HsmIoController::poll_io) and consumed by
/// [`complete_io`](HsmIoController::complete_io). Flows through the
/// core's `recv_task` → `send_task` pipeline unchanged.
///
/// # Buffers
///
/// `StdHsmIo` holds the index of its slot in the
/// [`BufferPool`](crate::buf_pool::BufferPool); the
/// [`HsmAlloc`](tsra_fw_hsm_pal_traits::HsmAlloc) implementation on
/// [`StdHsmPal`] uses the private slot to address per-slot bump
/// allocators backed by the pool's pre-allocated NonDma + Dma buffers.
pub struct StdHsmIo {
    /// Source partition identifier.
    pub(crate) pid: HsmPartId,

    /// Source queue identifier.
    pub(crate) qid: u16,

    /// Index within the source queue.
    pub(crate) qidx: u16,

    /// Index into the buffer pool, used by
    /// [`HsmAlloc`](tsra_fw_hsm_pal_traits::HsmAlloc) to address per-IO bump heaps.
    pub(crate) slot: u16,

    /// Oneshot channel for the reply.
    ///
    /// `Option` so [`complete_io`](HsmIoController::complete_io) can
    /// `take()` the oneshot sender (which is consumed on send) through a
    /// `&mut` borrow, leaving the rest of `io` intact for the
    /// post-completion walk.
    pub(crate) tx: Option<ReplySender<RawBulkCqe>>,

    /// Queue kind of the IO.
    pub(crate) kind: HsmIoKind,

    /// Submission entry storage, sized for the largest (bulk) entry;
    /// [`sqe`](HsmIo::sqe) exposes the first `sqe_len` dwords.
    pub(crate) sqe: RawBulkSqe,

    /// Completion entry storage, sized for the largest (bulk) entry;
    /// [`cqe`](HsmIo::cqe) exposes the first `cqe_len` dwords.
    pub(crate) cqe: RawBulkCqe,

    /// Submission entry length in dwords.
    pub(crate) sqe_len: usize,

    /// Completion entry length in dwords.
    pub(crate) cqe_len: usize,
}

// SAFETY: StdHsmIo is only used on the single-threaded Embassy executor.
unsafe impl Send for StdHsmIo {}

impl StdHsmIo {
    pub(crate) fn pid(&self) -> HsmPartId {
        self.pid
    }

    /// Construct a new IO work item from a request and an allocated slot.
    pub(crate) fn new(req: HsmIoRequest, slot: u16) -> Self {
        let (sqe_len, cqe_len) = match req.kind {
            HsmIoKind::Cmd => (SQE_DWORDS, CQE_DWORDS),
            HsmIoKind::Bulk => (BULK_SQE_DWORDS, BULK_CQE_DWORDS),
        };
        Self {
            pid: req.pid,
            qid: req.qid,
            qidx: req.qidx,
            slot,
            tx: Some(req.tx),
            kind: req.kind,
            sqe: req.sqe,
            cqe: [0; BULK_CQE_DWORDS],
            sqe_len,
            cqe_len,
        }
    }

    /// Construct a transient admin IO for internal provisioning crypto
    /// (e.g. masking `BK_BOOT` at partition allocation), backed by a
    /// caller-borrowed buffer-pool `slot`.  `tx` is a throwaway reply
    /// channel — no host awaits the completion.
    pub(crate) fn admin(pid: HsmPartId, slot: u16, tx: ReplySender<RawBulkCqe>) -> Self {
        Self::new(HsmIoRequest::cmd(pid, 0, 0, [0; SQE_DWORDS], tx), slot)
    }
}

impl core::fmt::Debug for StdHsmIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StdHsmIo")
            .field("partition_id", &self.pid)
            .field("queue_id", &self.qid)
            .field("queue_index", &self.qidx)
            .field("slot", &self.slot)
            .finish()
    }
}

impl HsmIo for StdHsmIo {
    fn sqe(&self) -> &HsmSqe {
        &self.sqe[..self.sqe_len]
    }

    fn cqe(&mut self) -> &mut HsmCqe {
        &mut self.cqe[..self.cqe_len]
    }

    fn kind(&self) -> HsmIoKind {
        self.kind
    }
}

impl HsmIoTypes for StdHsmPal {
    type Io = StdHsmIo;
}

impl HsmIoController for StdHsmPal {
    /// Wait for the next IO request and allocate a buffer slot.
    ///
    /// Delegates to [`StdIic::recv`](crate::drivers::iic::StdIic::recv)
    /// which receives from the submit channel and allocates a pool slot.
    /// The pool resets the slot's bump-allocator watermarks before
    /// returning, so the new IO starts with empty NonDma/Dma heaps.
    ///
    /// Suspends if no requests are available or if the buffer pool is
    /// exhausted.
    async fn poll_io(&self) -> HsmResult<StdHsmIo> {
        let (req, slot) = self.iic.recv().await?;
        Ok(StdHsmIo::new(req, slot))
    }

    /// Complete an IO: post the response CQE via the OIC driver.
    ///
    /// Posts the CQE only; the buffer slot is freed separately by
    /// [`drop_io`](HsmIoController::drop_io) so the caller can run
    /// post-completion work over `io` first.
    ///
    /// Propagates [`HsmError::CompleteIoFailure`] from the OIC driver when
    /// the CQE cannot be posted (dropped receiver or double-complete) so
    /// core can treat it as `cqe_ok = false` and roll back.
    async fn complete_io(&self, io: &mut Self::Io) -> HsmResult<()> {
        match io.kind {
            HsmIoKind::Cmd => {
                if let Some(cqe) = io.cqe.first_chunk_mut::<CQE_DWORDS>() {
                    Cqe::from(cqe).set_sq_id(io.qid);
                }
            }
            HsmIoKind::Bulk => BulkCqe::set_sq_id(&mut io.cqe, io.qid),
        }
        self.oic.send(io)
    }

    /// Drop an IO without sending a CQE — frees the buffer slot only.
    async fn drop_io(&self, io: Self::Io) -> HsmResult<()> {
        let slot = io.slot;
        drop(io);
        self.iic.free(slot);
        Ok(())
    }
}
