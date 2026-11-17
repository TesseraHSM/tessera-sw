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
use tsra_fw_hsm_bulk::BulkCqeEntry;
use tsra_fw_hsm_bulk::BulkSqeEntry;
use tsra_fw_hsm_bulk::RawBulkCqe;
use tsra_fw_hsm_bulk::RawBulkSqe;
use tsra_fw_hsm_bulk::BULK_CQE_DWORDS;
use tsra_fw_hsm_bulk::BULK_SQE_DWORDS;
use tsra_fw_hsm_io::oob_entry_addr;
use tsra_fw_hsm_io::OOB_ENTRY_LEN;
use tsra_fw_hsm_pal_traits::*;

use crate::cmd::Cqe;
use crate::cmd::CqeEntry;
use crate::cmd::RawSqe;
use crate::cmd::SqeEntry;
use crate::cmd::SQE_DWORDS;
use crate::transport;
use crate::HsmPartId;
use crate::StdHsmPal;

/// Length of one OOB descriptor (an NVMe SGL descriptor).
const OOB_DESC_LEN: usize = OOB_ENTRY_LEN as usize;

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

    /// Submission entry.
    pub(crate) sqe: StdSqe,

    /// Completion entry.
    pub(crate) cqe: StdCqe,
}

// SAFETY: StdHsmIo is only used on the single-threaded Embassy executor.
unsafe impl Send for StdHsmIo {}

impl StdHsmIo {
    pub(crate) fn pid(&self) -> HsmPartId {
        self.pid
    }

    /// Construct a new IO work item from a request and an allocated slot.
    pub(crate) fn new(req: HsmIoRequest, slot: u16) -> Self {
        let (sqe, cqe) = match req.kind {
            HsmIoKind::Cmd => {
                let sqe = SqeEntry(
                    *req.sqe
                        .first_chunk::<SQE_DWORDS>()
                        .unwrap_or(&[0; SQE_DWORDS]),
                );
                let cqe = transport::stamp_cqe(&sqe);
                (StdSqe::Cmd(sqe), StdCqe::Cmd(cqe))
            }
            HsmIoKind::Bulk => (
                StdSqe::Bulk(BulkSqeEntry(req.sqe)),
                StdCqe::Bulk(BulkCqeEntry::for_sqe(&req.sqe)),
            ),
        };
        Self {
            pid: req.pid,
            qid: req.qid,
            qidx: req.qidx,
            slot,
            tx: Some(req.tx),
            kind: req.kind,
            sqe,
            cqe,
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

/// A submission entry of either queue kind.
pub enum StdSqe {
    /// A command-queue entry.
    Cmd(SqeEntry),

    /// A bulk-queue entry.
    Bulk(BulkSqeEntry),
}

impl HsmSqe for StdSqe {
    fn opcode(&self) -> u16 {
        match self {
            Self::Cmd(e) => e.opcode(),
            Self::Bulk(e) => e.opcode(),
        }
    }

    fn session_id(&self) -> Option<u16> {
        match self {
            Self::Cmd(e) => e.session_id(),
            Self::Bulk(e) => e.session_id(),
        }
    }

    fn session_ctrl(&self) -> HsmSessCtrl {
        match self {
            Self::Cmd(e) => e.session_ctrl(),
            Self::Bulk(e) => e.session_ctrl(),
        }
    }
}

/// A completion entry of either queue kind.
pub enum StdCqe {
    /// A command-queue entry.
    Cmd(CqeEntry),

    /// A bulk-queue entry.
    Bulk(BulkCqeEntry),
}

impl StdCqe {
    /// The entry as posted to the submitter: a command CQE occupies the
    /// head of a zeroed bulk-sized array.
    pub(crate) fn to_raw(&self) -> RawBulkCqe {
        match self {
            Self::Cmd(e) => {
                let mut raw = [0; BULK_CQE_DWORDS];
                for (dst, src) in raw.iter_mut().zip(e.0.iter()) {
                    *dst = *src;
                }
                raw
            }
            Self::Bulk(e) => e.0,
        }
    }
}

impl HsmCqe for StdCqe {
    fn set_ok(&mut self, dst_len: u32) {
        match self {
            Self::Cmd(e) => e.set_ok(dst_len),
            Self::Bulk(e) => e.set_ok(dst_len),
        }
    }

    fn set_ok_ex(&mut self, dst_len: u32, sess: HsmCqeSession) {
        match self {
            Self::Cmd(e) => e.set_ok_ex(dst_len, sess),
            Self::Bulk(e) => e.set_ok_ex(dst_len, sess),
        }
    }

    fn set_err(&mut self, err: HsmError) {
        match self {
            Self::Cmd(e) => e.set_err(err),
            Self::Bulk(e) => e.set_err(err),
        }
    }
}

impl HsmIo for StdHsmIo {
    type Sqe = StdSqe;
    type Cqe = StdCqe;

    fn sqe(&self) -> &StdSqe {
        &self.sqe
    }

    fn cqe(&mut self) -> &mut StdCqe {
        &mut self.cqe
    }

    fn kind(&self) -> HsmIoKind {
        self.kind
    }
}

impl HsmIoTypes for StdHsmPal {
    type Io = StdHsmIo;
}

impl StdHsmPal {
    /// Reads OOB descriptor `index` of a command IO from host memory.
    pub(crate) async fn oob_desc(
        &self,
        io: &StdHsmIo,
        index: usize,
    ) -> HsmResult<[u8; OOB_DESC_LEN]> {
        let StdSqe::Cmd(sqe) = &io.sqe else {
            return Err(HsmError::InvalidArg);
        };
        let (base, len) = transport::oob_region(sqe);
        let addr = oob_entry_addr(base, len, index)?;
        self.alloc_scoped_async(io, async |scoped| {
            let entry = scoped.dma_alloc(OOB_DESC_LEN)?;
            self.copy_mem_from_host(io, addr, HsmDmaAddr::ZERO, entry, true)
                .await?;
            let bytes: &[u8] = entry;
            bytes.try_into().map_err(|_| HsmError::InternalError)
        })
        .await
    }

    /// Writes `buf` to the host buffer described by OOB descriptor `index`.
    pub(crate) async fn oob_write(&self, io: &StdHsmIo, index: usize, buf: &[u8]) -> HsmResult<()> {
        let desc = self.oob_desc(io, index).await?;
        crate::drivers::gdma::validate_raw_src(&desc, buf.len())?;
        // SAFETY: std host addresses are raw host-process pointers the
        // submitter keeps valid; `validate_raw_src` checked length and null.
        unsafe { self.gdma.copy_mem_to_host_raw(buf, &desc) };
        Ok(())
    }
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

    async fn recv_request(&self, io: &StdHsmIo) -> HsmResult<HsmRequest<'_>> {
        match &io.sqe {
            StdSqe::Cmd(sqe) => self.transport_recv(io, sqe).await,
            StdSqe::Bulk(_) => Err(HsmError::InvalidArg),
        }
    }

    async fn send_response(&self, io: &mut StdHsmIo, resp: &HsmDmaBuf) -> HsmResult<()> {
        let StdSqe::Cmd(sqe) = io.sqe else {
            return Err(HsmError::InvalidArg);
        };
        self.transport_send(io, sqe, resp).await
    }

    async fn recv_oob(&self, io: &StdHsmIo, index: usize, dst: &mut HsmDmaBuf) -> HsmResult<()> {
        let desc = self.oob_desc(io, index).await?;
        self.copy_mem_from_host_raw(io, &desc, dst, false).await
    }

    async fn send_oob(&self, io: &StdHsmIo, index: usize, src: &HsmDmaBuf) -> HsmResult<()> {
        self.oob_write(io, index, src).await
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
        match &mut io.cqe {
            StdCqe::Cmd(cqe) => Cqe::from(&mut cqe.0).set_sq_id(io.qid),
            StdCqe::Bulk(cqe) => BulkCqe::set_sq_id(&mut cqe.0, io.qid),
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

    /// Never takes `io`: there is no detached transfer engine, so core
    /// sends, completes and drops it itself.
    fn finish_io(&self, io: Self::Io, _resp: &HsmDmaBuf) -> Result<(), Self::Io> {
        Err(io)
    }
}
