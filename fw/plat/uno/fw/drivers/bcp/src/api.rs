// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(unsafe_code)]

use core::future::Future;
use core::pin::Pin;
use core::task::Context;
use core::task::Poll;

use bitfield_struct::bitfield;
use embassy_sync::waitqueue::MultiWakerRegistration;
use embassy_sync::waitqueue::WakerRegistration;
use embassy_time::Duration;
use embassy_time::Instant;
use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_single_cell::SingleCell;
use tsra_fw_static_ref::StaticRef;
use tsra_fw_uno_error::HsmResult;
use tsra_fw_uno_reg_soc::bcp::regs::BcpRegs;
use tsra_fw_uno_reg_soc::bcp::BCP_BASE;
use tsra_fw_uno_reg_soc::bcp::CONTROL;
use tsra_fw_uno_reg_soc::bcp::CQ_CFG;
use tsra_fw_uno_reg_soc::bcp::CQ_CI;
use tsra_fw_uno_reg_soc::bcp::LIST0_CFG;
use tsra_fw_uno_reg_soc::bcp::SQ_CFG;
use tsra_fw_uno_reg_soc::bcp::SQ_PI;
use tsra_fw_uno_reg_soc::bcp::STATUS;
use tsra_fw_uno_reg_soc::io_gsram::regs::IoGsramRegs;
use tsra_fw_uno_reg_soc::io_gsram::BCP_CQ_COUNT;
use tsra_fw_uno_reg_soc::io_gsram::BCP_CQ_OFFSET;
use tsra_fw_uno_reg_soc::io_gsram::BCP_CQ_PI_SHADOW_OFFSET;
use tsra_fw_uno_reg_soc::io_gsram::BCP_DFL_COUNT;
use tsra_fw_uno_reg_soc::io_gsram::BCP_DFL_OFFSET;
use tsra_fw_uno_reg_soc::io_gsram::BCP_DFL_STRIDE;
use tsra_fw_uno_reg_soc::io_gsram::BCP_SQ_CI_SHADOW_OFFSET;
use tsra_fw_uno_reg_soc::io_gsram::BCP_SQ_COUNT;
use tsra_fw_uno_reg_soc::io_gsram::BCP_SQ_OFFSET;
use tsra_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;
use tsra_fw_uno_reg_soc::zero::ZERO_BASE;

use crate::BcpError;

/// BCP MMIO registers.
// SAFETY: BCP_BASE is the aligned, permanently mapped BCP register block.
const BCP: StaticRef<BcpRegs> = unsafe { StaticRef::new(BCP_BASE as *const BcpRegs) };

/// GSRAM overlay holding the BCP rings.
// SAFETY: IO_GSRAM_BASE is the aligned, permanently mapped ring storage.
const GSRAM: StaticRef<IoGsramRegs> =
    unsafe { StaticRef::new(IO_GSRAM_BASE as *const IoGsramRegs) };

/// Ring depth.
const DEPTH: usize = BCP_SQ_COUNT as usize;

/// Ring index mask.
const MASK: u16 = (DEPTH - 1) as u16;

/// `NUM_ELEMENTS` encoding of [`DEPTH`] (0 = 8 entries, 1 = 16, ...).
const NUM_ELEMENTS: u32 = DEPTH.trailing_zeros() - 3;

/// Chunks one command may span; see [`BCP_MAX_SRC_LEN`].
const MAX_CHUNKS: usize = 2;

/// SQEs the commands in flight may have outstanding. Each command reserves
/// one per chunk from submission until it completes: the engine may not
/// have fetched them yet, and the abort that frees a failed command's
/// engine slot (sent only after the command's CQE, so after its chunks
/// were fetched) reuses the reservation. A ring must stay one short of
/// full so it never looks empty (`PI == CI`).
const SQE_BUDGET: usize = DEPTH - 1;

/// Command IDs: as many as single-chunk commands fit [`SQE_BUDGET`]. Each
/// command has at most one CQE not yet reaped.
const IDS: usize = SQE_BUDGET;

/// Tasks that can wait for a command ID before the oldest waiters are
/// woken early to make room (they then register again): every task that
/// can run a command, so a busy engine does not churn the waiters.
const ID_WAITERS: usize = 32;

/// `free` bitmap with every command ID free.
const ALL_FREE: u8 = ((1u16 << IDS) - 1) as u8;

/// Command deadline. One chunk takes microseconds; past this the engine is
/// presumed stuck, reset, and the commands in flight fail. Well inside the
/// host's 6 s command timeout.
const CMD_TIMEOUT: Duration = Duration::from_millis(2000);

/// Bound on the wait for a soft reset to complete and the engine to stop.
const RESET_SPIN: u32 = 100_000;

/// Driver-internal status for a command abandoned by a reset.
const STATUS_STALLED: u8 = 0xFF;

const _: () = assert!(DEPTH.is_power_of_two() && DEPTH >= 8 && DEPTH <= 64);
const _: () = assert!(BCP_CQ_COUNT as usize == DEPTH && BCP_DFL_COUNT as usize == DEPTH);

/// AES-256 key length; the engine has no other key size.
pub const BCP_KEY_LEN: usize = 32;

/// GCM IV length.
pub const BCP_IV_LEN: usize = 12;

/// GCM tag length.
pub const BCP_TAG_LEN: usize = 16;

/// Bytes per SQE (chunk), as the FP firmware chunked host commands. The
/// engine mis-processes a single chunk larger than this, so longer
/// commands span several SQEs.
pub const BCP_CHUNK_LEN: usize = 4096;

/// Largest source (padded AAD + text) one command may carry.
pub const BCP_MAX_SRC_LEN: usize = BCP_CHUNK_LEN * MAX_CHUNKS;

/// Buffer address alignment the engine is given. The PAL bounces buffers
/// that are not aligned.
pub const BCP_ADDR_ALIGN: usize = 4;

/// AAD padding granularity the engine requires.
pub const BCP_AAD_ALIGN: usize = 32;

/// Text granularity the engine requires.
pub const BCP_TEXT_ALIGN: usize = 16;

/// CQE status: command completed.
pub const BCP_STATUS_COMPLETED: u8 = 1 << 0;

/// CQE status: command failed (on GCM decrypt, includes a tag mismatch).
pub const BCP_STATUS_ERROR: u8 = 1 << 4;

/// `CMD_SLOT_ERR_STATUS1`: GCM tag mismatch (non-fatal).
pub const BCP_ERR1_TAG_MISMATCH: u32 = 1 << 13;

/// Key-vault words per key slot.
const KEY_WORDS: usize = BCP_KEY_LEN / 4;

/// DFL element size in DWORDs (host command + GCM/XTS aux command).
const DFL_DWORDS: usize = 32;

/// DFL DWORD holding the source length; the SGL descriptors follow.
const DFL_DESCR_DW: u32 = 6;

/// DFL DWORD where the crypto input (tag / tweak, IV, AAD length) starts.
const DFL_CRYPTO_IN_DW: u32 = 19;

/// DFL DWORD the engine writes the tag back to.
const DFL_CRYPTO_OUT_DW: usize = 1;

/// SQE `CmdState`: a single NEW|LAST chunk.
const CMD_STATE_NEW_LAST: u8 = 0b101;

/// SQE command state: first chunk of a command with more to follow.
const CMD_STATE_NEW: u8 = 0b001;

/// SQE command state: a middle chunk.
const CMD_STATE_CONTINUE: u8 = 0b010;

/// SQE `CmdState`: CONTINUE|LAST, as an abort is sent.
const CMD_STATE_CONTINUE_LAST: u8 = 0b110;

/// SQE `CmdOpcode`: data transfer.
const OPCODE_DATA_TRANSFER: u8 = 0;

/// SQE `CmdOpcode`: abort the command (frees a failed command's slot).
const OPCODE_ABORT: u8 = 2;

/// SQE `DataProcessType` for GCM encrypt (decrypt is one more).
const PROCESS_GCM_ENCRYPT: u8 = 3;

/// Global error checks the FP firmware enabled: key-vault ECC (16), AXI
/// write response (20), and AXI read response (25).
const GLOBAL_ERR_CHECKS: u32 = (1 << 16) | (1 << 20) | (1 << 25);

// ── Queue entry layouts (silicon `CdmaSqCmdDescr_t` / `CdmaCqCmdDescr_t`) ──

#[bitfield(u32)]
struct SqeDw0 {
    /// Command ID, echoed in the CQE.
    #[bits(10)]
    cmd_id: u16,
    /// 1 = NEW, 2 = CONTINUE, 4 = LAST.
    #[bits(3)]
    cmd_state: u8,
    #[bits(3)]
    opcode: u8,
    #[bits(4)]
    _rsvd0: u8,
    /// DFL element index within the list.
    #[bits(10)]
    dfl_idx: u16,
    /// DFL list number.
    #[bits(2)]
    dfl_num: u8,
}

#[bitfield(u32)]
struct SqeDw1 {
    /// 1/2 = XTS encrypt/decrypt, 3/4 = GCM encrypt/decrypt.
    #[bits(3)]
    process_type: u8,
    /// Data descriptors are SGL (`true`) or PRP (`false`).
    #[bits(1)]
    sgl: bool,
    #[bits(1)]
    continuation: bool,
    #[bits(2)]
    xts_data_unit_len: u8,
    #[bits(1)]
    _rsvd0: bool,
    /// Bytes in this chunk.
    #[bits(13)]
    chunk_byte_cnt: u16,
    #[bits(3)]
    _rsvd1: u8,
    #[bits(8)]
    ucd_iq_id: u8,
}

#[bitfield(u32)]
struct SqeDw2 {
    #[bits(10)]
    key1_idx: u16,
    #[bits(10)]
    key2_idx: u16,
    #[bits(12)]
    _rsvd0: u16,
}

#[bitfield(u32)]
struct CqeDw1 {
    #[bits(16)]
    cmd_chunk: u16,
    /// Internal command slot (0..68) the engine ran the command in.
    #[bits(8)]
    cmd_slot: u8,
    #[bits(8)]
    ucd_iq_id: u8,
}

#[bitfield(u32)]
struct CqeDw0 {
    #[bits(10)]
    cmd_id: u16,
    #[bits(1)]
    _rsvd0: bool,
    /// [`BCP_STATUS_COMPLETED`], [`BCP_STATUS_ERROR`], ...
    #[bits(5)]
    status: u8,
    #[bits(4)]
    _rsvd1: u8,
    #[bits(10)]
    dfl_idx: u16,
    #[bits(2)]
    dfl_num: u8,
}

/// GCM direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcmOp {
    Encrypt,
    Decrypt,
}

/// Source and destination of a GCM command: `[padded_AAD | text]`, which
/// the engine writes back whole, copying the padded AAD through. Buffers
/// must be [`BCP_ADDR_ALIGN`]-aligned and live in GSRAM the CDMA may
/// master (the PAL DMA heap does).
#[derive(Debug)]
pub enum GcmData<'a> {
    /// Read `src`, write `dst`, which is at least as long.
    Copy {
        src: &'a DmaBuf,
        dst: &'a mut DmaBuf,
    },
    /// Transform in place.
    InPlace(&'a mut DmaBuf),
}

impl GcmData<'_> {
    /// Source address and length.
    fn src(&self) -> (u32, usize) {
        match self {
            Self::Copy { src, .. } => (src.as_ptr() as u32, src.len()),
            Self::InPlace(buf) => (buf.as_ptr() as u32, buf.len()),
        }
    }

    /// Destination address and length.
    fn dst(&self) -> (u32, usize) {
        match self {
            Self::Copy { dst, .. } => (dst.as_ptr() as u32, dst.len()),
            Self::InPlace(buf) => (buf.as_ptr() as u32, buf.len()),
        }
    }
}

/// One AES-256-GCM command.
#[derive(Debug)]
pub struct GcmRequest<'a> {
    pub op: GcmOp,
    /// AES-256 key ([`BCP_KEY_LEN`] bytes).
    pub key: &'a [u8],
    pub iv: &'a [u8; BCP_IV_LEN],
    /// Padded AAD length at the start of `src`; a multiple of
    /// [`BCP_AAD_ALIGN`].
    pub aad_len: usize,
    /// Unpadded AAD length.
    pub unpadded_aad_len: usize,
    /// Expected tag for a decrypt: the engine's tag, which covers the
    /// padded AAD length. Ignored on encrypt.
    pub tag: &'a [u8; BCP_TAG_LEN],
    /// `[padded_AAD | text]`; the text is a non-empty multiple of
    /// [`BCP_TEXT_ALIGN`], and the whole source at most
    /// [`BCP_MAX_SRC_LEN`] bytes.
    pub data: GcmData<'a>,
}

/// Engine completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcmCompletion {
    /// CQE status bits.
    pub status: u8,
    /// Tag the engine computed over the padded AAD and the text it was
    /// given (on a decrypt tag mismatch too).
    pub tag: [u8; BCP_TAG_LEN],
    /// `CMD_SLOT_ERR_STATUS0/1` of the command's internal slot; zero
    /// unless [`BCP_STATUS_ERROR`] is set.
    pub err: [u32; 2],
}

impl GcmCompletion {
    /// Completed without error.
    pub fn ok(&self) -> bool {
        self.status & BCP_STATUS_COMPLETED != 0 && self.status & BCP_STATUS_ERROR == 0
    }

    /// Failed only because the tag did not match the expected tag.
    pub fn tag_mismatch_only(&self) -> bool {
        self.status & BCP_STATUS_ERROR != 0 && self.err == [0, BCP_ERR1_TAG_MISMATCH]
    }
}

struct Slot {
    waker: WakerRegistration,
    done: bool,
    /// Failed; waiting for the completion of the abort that frees its
    /// engine slot.
    aborting: bool,
    status: u8,
    tag: [u8; BCP_TAG_LEN],
    err: [u32; 2],
    deadline: Instant,
    /// SQEs reserved against [`SQE_BUDGET`] until the command completes.
    chunks: u8,
}

struct BcpState {
    /// Engine and rings configured.
    up: bool,
    /// The reset of a stuck engine is not confirmed yet: the commands in
    /// flight stay in flight, and new commands fail. Cleared once the
    /// reset is confirmed, or once the engine has reported every command
    /// in flight; either way the next command brings the engine up afresh.
    stalled: bool,
    /// Next submission ring index.
    sq_pi: u16,
    /// Next completion ring index.
    cq_ci: u16,
    /// Free command IDs (bit N = ID N free).
    free: u8,
    /// SQEs reserved by the commands in flight (at most [`SQE_BUDGET`]).
    reserved: usize,
    /// Tasks waiting for a free command ID.
    id_waiters: MultiWakerRegistration<ID_WAITERS>,
    /// Per command ID; IDs index the key-vault slots and DFL elements.
    slots: [Slot; IDS],
}

/// Async BCP driver.
///
/// Up to `IDS` commands may be outstanding while their chunks fit
/// [`SQE_BUDGET`], and further callers
/// wait for a command ID; each command owns the key-vault slot and DFL
/// element numbered by its ID.
pub struct BcpDriver {
    state: SingleCell<BcpState>,
}

impl core::fmt::Debug for BcpDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BcpDriver").finish()
    }
}

impl BcpDriver {
    /// Create the driver. Does not touch the hardware; the engine is
    /// brought up by the first command.
    pub fn new() -> Self {
        Self {
            state: SingleCell::new(BcpState {
                up: false,
                stalled: false,
                sq_pi: 0,
                cq_ci: 0,
                free: ALL_FREE,
                reserved: 0,
                id_waiters: MultiWakerRegistration::new(),
                slots: core::array::from_fn(|_| Slot {
                    waker: WakerRegistration::new(),
                    done: false,
                    aborting: false,
                    status: 0,
                    tag: [0; BCP_TAG_LEN],
                    err: [0; 2],
                    deadline: Instant::from_ticks(0),
                    chunks: 0,
                }),
            }),
        }
    }

    /// Submit an AES-256-GCM command and await its completion.
    ///
    /// Waits for a command ID when all are in use. Returns the raw
    /// completion; the caller decides what the status means. Fails with
    /// [`BcpError::TIMEOUT`] if the engine had to be reset (or a reset is
    /// still pending), or [`BcpError::RESET_FAILED`] if it could not be
    /// brought up.
    ///
    /// # Cancellation safety
    ///
    /// Once submitted, the engine reads `src` and writes `dst` until the
    /// command completes. Dropping the future before then blocks until the
    /// engine is done with them, or has been reset past the command's
    /// deadline, and then releases the command, so the buffers are never
    /// freed while the engine may still use them.
    pub fn gcm<'a>(
        &'a self,
        req: GcmRequest<'a>,
    ) -> impl Future<Output = HsmResult<GcmCompletion>> + 'a {
        GcmFuture {
            bcp: self,
            req,
            id: None,
        }
    }

    /// Reap completions and wake their awaiters; reset the engine if a
    /// command is past its deadline.
    ///
    /// The engine raises no HSM interrupt, so the PAL calls this from its
    /// poll loop. With no command in flight it touches no register: the
    /// poll loop runs for every host command, so even one GSRAM read per
    /// pass shows up in the latency of trivial commands.
    pub fn wake(&self) {
        self.state.with(|s| {
            if !s.up || s.free == ALL_FREE {
                return;
            }
            let pi = (GSRAM.bcp_cq_pi_shadow.get() as u16) & MASK;
            if pi != s.cq_ci {
                reap(s, pi);
            }
            // Checked after reaping as well, so that other commands
            // completing on every pass cannot hold off the reset of one
            // that is stuck.
            let now = Instant::now();
            let late = s
                .slots
                .iter()
                .enumerate()
                .any(|(i, slot)| s.free & (1 << i) == 0 && !slot.done && now > slot.deadline);
            if late {
                recover(s);
            }
        });
    }
}

/// The future [`BcpDriver::gcm`] returns. It owns its command from
/// submission until the completion is consumed, so that dropping it
/// mid-flight can wait for the engine before the buffers go.
struct GcmFuture<'a> {
    bcp: &'a BcpDriver,
    req: GcmRequest<'a>,
    /// Command ID while submitted and not yet consumed.
    id: Option<usize>,
}

impl Future for GcmFuture<'_> {
    type Output = HsmResult<GcmCompletion>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let bcp = this.bcp;
        bcp.state.with(|s| {
            let id = match this.id {
                Some(id) => id,
                None => {
                    let req = &this.req;
                    if let Err(e) = validate(req) {
                        return Poll::Ready(Err(e));
                    }
                    if s.stalled {
                        return Poll::Ready(Err(BcpError::TIMEOUT));
                    }
                    let chunks = req.data.src().1.div_ceil(BCP_CHUNK_LEN);
                    if s.free == 0 || s.reserved + chunks > SQE_BUDGET {
                        s.id_waiters.register(cx.waker());
                        return Poll::Pending;
                    }
                    if !s.up {
                        if !bring_up() {
                            return Poll::Ready(Err(BcpError::RESET_FAILED));
                        }
                        s.up = true;
                        s.sq_pi = 0;
                        s.cq_ci = 0;
                    }

                    let id = s.free.trailing_zeros() as usize;
                    s.free &= !(1 << id);
                    s.slots[id].done = false;
                    s.slots[id].aborting = false;
                    s.slots[id].deadline = Instant::now() + CMD_TIMEOUT;
                    s.slots[id].chunks = chunks as u8;
                    s.reserved += chunks;
                    this.id = Some(id);

                    load_key(id, req.key);
                    write_dfl(id, req);
                    submit(s, id, req.op, req.data.src().1);
                    id
                }
            };

            if !s.slots[id].done {
                s.slots[id].waker.register(cx.waker());
                return Poll::Pending;
            }
            this.id = None;
            let done = release(s, id);
            if done.status == STATUS_STALLED {
                return Poll::Ready(Err(BcpError::TIMEOUT));
            }
            Poll::Ready(Ok(done))
        })
    }
}

impl Drop for GcmFuture<'_> {
    /// Dropped with its command in flight, and the caller is about to free
    /// the command's buffers: wait for the engine to finish with them (or
    /// to be reset past the command's deadline), then release the command.
    /// While a reset cannot be confirmed this waits on, since returning
    /// would hand the caller buffers the engine may still use.
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        while !self.bcp.state.with(|s| s.slots[id].done) {
            self.bcp.wake();
        }
        self.bcp.state.with(|s| {
            release(s, id);
        });
    }
}

/// Release the completed command `id`: free its ID and SQE reservation,
/// wipe its key, and return its completion.
fn release(s: &mut BcpState, id: usize) -> GcmCompletion {
    let slot = &mut s.slots[id];
    slot.done = false;
    let done = GcmCompletion {
        status: slot.status,
        tag: slot.tag,
        err: slot.err,
    };
    slot.tag = [0; BCP_TAG_LEN];
    s.reserved -= usize::from(slot.chunks);
    clear_key(id);
    s.free |= 1 << id;
    if s.stalled && s.free == ALL_FREE {
        // The engine reported every command in flight before its reset was
        // confirmed. The next command brings it up again, which resets it
        // and refuses to run if that is not confirmed either.
        s.stalled = false;
        s.up = false;
    }
    s.id_waiters.wake();
    done
}

/// Advance the submission ring past the SQE just written at `sq_pi` and
/// ring the doorbell.
fn ring(s: &mut BcpState) {
    s.sq_pi = (s.sq_pi + 1) & MASK;
    // The descriptors must be visible before the doorbell starts the
    // engine's fetch.
    cortex_m::asm::dmb();
    BCP.sq_pi.write(SQ_PI::INDEX.val(s.sq_pi.into()));
}

/// Consume completions up to `pi`.
fn reap(s: &mut BcpState, pi: u16) {
    // Read the entries only after the index that published them.
    cortex_m::asm::dmb();

    while s.cq_ci != pi {
        let (dw0, dw1) = read_cqe(s.cq_ci as usize);
        s.cq_ci = (s.cq_ci + 1) & MASK;

        let id = dw0.cmd_id() as usize;
        if id >= IDS || s.free & (1 << id) != 0 {
            continue;
        }

        if s.slots[id].aborting {
            // The abort freeing a failed command's engine slot is done; the
            // command completes with its original status.
            let slot = &mut s.slots[id];
            slot.aborting = false;
            slot.done = true;
            slot.waker.wake();
            continue;
        }

        let status = dw0.status();
        let mut err = [0u32; 2];
        if status & BCP_STATUS_ERROR != 0 {
            // As the FP firmware does for every failed command: read the
            // failing slot's error status, then abort the command, which
            // frees the slot. Otherwise each failure (every decrypt tag
            // mismatch included) strands one of the engine's 68 slots.
            BCP.diag_control.set(dw1.cmd_slot().into());
            err = [
                BCP.cmd_slot_err_status0.get(),
                BCP.cmd_slot_err_status1.get(),
            ];
            write_abort(s.sq_pi as usize, id);
            ring(s);
        }

        let slot = &mut s.slots[id];
        slot.status = status;
        slot.err = err;
        slot.tag = read_tag(id);
        if status & BCP_STATUS_ERROR != 0 {
            slot.aborting = true;
        } else {
            slot.done = true;
            slot.waker.wake();
        }
    }

    BCP.cq_ci.write(CQ_CI::INDEX.val(s.cq_ci.into()));
}

/// Reset a stuck engine and fail every command in flight. The commands
/// complete only once the reset is confirmed to have stopped the engine,
/// which until then may still be reading and writing their buffers; if it
/// is not, they stay in flight, new commands fail, and the next pass tries
/// again. The next command brings the engine back up.
fn recover(s: &mut BcpState) {
    if !reset() {
        if !s.stalled {
            s.stalled = true;
            // Commands waiting for an ID fail instead.
            s.id_waiters.wake();
        }
        return;
    }
    s.stalled = false;
    s.up = false;

    let free = s.free;
    for (i, slot) in s.slots.iter_mut().enumerate() {
        if free & (1 << i) == 0 && !slot.done {
            slot.status = STATUS_STALLED;
            slot.aborting = false;
            slot.done = true;
            slot.waker.wake();
        }
    }
}

/// Soft-reset the engine and confirm that it has stopped: the reset bit
/// has self-cleared, no command is active and both AXI channels are idle.
/// Returns `false` if that is not seen within [`RESET_SPIN`] polls.
fn reset() -> bool {
    // The reset leaves the engine disabled, so it starts no new transfer.
    BCP.control.write(CONTROL::CDMA_RST::SET);
    for _ in 0..RESET_SPIN {
        let status = BCP.status.extract();
        if !BCP.control.is_set(CONTROL::CDMA_RST)
            && !status.is_set(STATUS::ACTIVE)
            && status.is_set(STATUS::AXI_RD_IDLE)
            && status.is_set(STATUS::AXI_WR_IDLE)
        {
            return true;
        }
    }
    false
}

/// Check a request.
fn validate(req: &GcmRequest<'_>) -> HsmResult<()> {
    if req.key.len() != BCP_KEY_LEN {
        return Err(BcpError::INVALID_KEY_LEN);
    }
    let (src, src_len) = req.data.src();
    let (dst, dst_len) = req.data.dst();
    let text_len = src_len
        .checked_sub(req.aad_len)
        .ok_or(BcpError::INVALID_DATA_LEN)?;
    if !req.aad_len.is_multiple_of(BCP_AAD_ALIGN)
        || req.unpadded_aad_len > req.aad_len
        || text_len == 0
        || !text_len.is_multiple_of(BCP_TEXT_ALIGN)
        || src_len > BCP_MAX_SRC_LEN
        || dst_len < src_len
        || !(src as usize).is_multiple_of(BCP_ADDR_ALIGN)
        || !(dst as usize).is_multiple_of(BCP_ADDR_ALIGN)
    {
        return Err(BcpError::INVALID_DATA_LEN);
    }
    Ok(())
}

/// Bring the engine up, following the FP firmware's `CDMAInit`: soft
/// reset, one queue pair and DFL list 0 in GSRAM over the SoC AXI
/// interface, error checks, tag write-back, then enable. Returns `false`,
/// leaving the engine alone, if the reset cannot be confirmed.
fn bring_up() -> bool {
    if !reset() {
        return false;
    }

    for e in GSRAM.bcp_sq.iter() {
        e.dw0.set(0);
        e.dw1.set(0);
        e.dw2.set(0);
        e.dw3.set(0);
    }
    for e in GSRAM.bcp_cq.iter() {
        e.dw0.set(0);
        e.dw1.set(0);
    }
    GSRAM.bcp_sq_ci_shadow.set(0);
    GSRAM.bcp_cq_pi_shadow.set(0);

    BCP.sq_pi.set(0);
    BCP.sq_ci_shadow_addr
        .set(IO_GSRAM_BASE + BCP_SQ_CI_SHADOW_OFFSET);
    BCP.sq_cfg
        .write(SQ_CFG::NUM_ELEMENTS.val(NUM_ELEMENTS) + SQ_CFG::SHADOW_EN::SET);
    BCP.sq_base_lo.set(IO_GSRAM_BASE + BCP_SQ_OFFSET);
    BCP.sq_base_hi.set(0);
    BCP.sq_cfg.modify(SQ_CFG::EN::SET);

    BCP.cq_ci.set(0);
    BCP.cq_pi_shadow_addr
        .set(IO_GSRAM_BASE + BCP_CQ_PI_SHADOW_OFFSET);
    BCP.cq_cfg
        .write(CQ_CFG::NUM_ELEMENTS.val(NUM_ELEMENTS) + CQ_CFG::SHADOW_EN::SET);
    BCP.cq_base_lo.set(IO_GSRAM_BASE + BCP_CQ_OFFSET);
    BCP.cq_base_hi.set(0);
    BCP.cq_cfg.modify(CQ_CFG::EN::SET);

    BCP.list0_cfg.write(
        LIST0_CFG::ELEMENT_DWORD_SZ.val(DFL_DWORDS as u32)
            + LIST0_CFG::DESCR_DWORD_OFFSET.val(DFL_DESCR_DW)
            + LIST0_CFG::CRYPTO_IN_DWORD_OFFSET.val(DFL_CRYPTO_IN_DW)
            + LIST0_CFG::CRYPTO_OUT_DWORD_OFFSET.val(DFL_CRYPTO_OUT_DW as u32),
    );
    BCP.list0_base_lo.set(IO_GSRAM_BASE + BCP_DFL_OFFSET);
    BCP.list0_base_hi.set(0);

    BCP.cmd_slot_err_check_en0.set(u32::MAX);
    BCP.cmd_slot_err_check_en1.set(u32::MAX);
    BCP.global_err_check_en.set(GLOBAL_ERR_CHECKS);

    BCP.dummy_port_base_lo.set(ZERO_BASE);
    BCP.dummy_port_base_hi.set(0);

    BCP.control.write(
        CONTROL::AXI_RD_EN::SET
            + CONTROL::AXI_WR_EN::SET
            + CONTROL::CQE_CRYPTO_UPDT_EN::SET
            + CONTROL::CQE_NVME_UPDT_EN::SET,
    );
    BCP.control.modify(CONTROL::CDMA_EN::SET);
    true
}

/// Write a key into the vault slot of command `id`, as little-endian words.
fn load_key(id: usize, key: &[u8]) {
    let (words, _) = key.as_chunks::<4>();
    for (i, word) in words.iter().enumerate() {
        BCP.key_vault[id * KEY_WORDS + i].set(u32::from_le_bytes(*word));
    }
}

/// Wipe the vault slot of command `id`.
fn clear_key(id: usize) {
    for i in 0..KEY_WORDS {
        BCP.key_vault[id * KEY_WORDS + i].set(0);
    }
}

/// DFL element of command `id`.
fn dfl_ptr(id: usize) -> *mut u32 {
    (IO_GSRAM_BASE + BCP_DFL_OFFSET + id as u32 * BCP_DFL_STRIDE) as *mut u32
}

/// Pack bytes into little-endian words at `dw[start..]`.
fn put_bytes(dw: &mut [u32; DFL_DWORDS], start: usize, bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        dw[start + i] = u32::from_le_bytes(word);
    }
}

/// Fill the DFL element of command `id`: the 64-byte host command with
/// SGL data-block descriptors (DW6-15), then the GCM aux command (key
/// index, unpadded AAD length, expected tag, IV, padded AAD length).
///
/// The destination is as long as the source: the engine writes the padded
/// AAD through ahead of the text, as the host fast path expected.
fn write_dfl(id: usize, req: &GcmRequest<'_>) {
    let mut dw = [0u32; DFL_DWORDS];
    let (src, src_len) = req.data.src();
    let (dst, _) = req.data.dst();
    let len = src_len as u32;

    // Source: length, then an SGL data-block descriptor {addr, len, type 0}.
    dw[6] = len;
    dw[7] = src;
    dw[9] = len;
    // Destination: likewise, as long as the source.
    dw[11] = len;
    dw[12] = dst;
    dw[14] = len;

    dw[17] = id as u32;
    dw[18] = req.unpadded_aad_len as u32;
    if req.op == GcmOp::Decrypt {
        put_bytes(&mut dw, 19, req.tag);
    }
    put_bytes(&mut dw, 23, req.iv);
    dw[26] = req.aad_len as u32;

    // Burst-write the element: the ring sits in memory the CPU writes
    // uncached, one bus transaction per store, while a store-multiple
    // writes several words in one.
    // SAFETY: `dfl_ptr(id)` is DFL element `id` of the GSRAM ring
    // (`id < DEPTH`), `DFL_DWORDS` words long and word-aligned, and only
    // this command uses it.
    let dst = unsafe { core::slice::from_raw_parts_mut(dfl_ptr(id), DFL_DWORDS) };
    tsra_fw_bulk_copy::copy_slice(dst, &dw);
}

/// Read the completion-ring entry at `ci`.
fn read_cqe(ci: usize) -> (CqeDw0, CqeDw1) {
    let entry = &GSRAM.bcp_cq[ci];
    (CqeDw0::from(entry.dw0.get()), CqeDw1::from(entry.dw1.get()))
}

/// Read the tag the engine wrote back into the DFL element of command `id`.
fn read_tag(id: usize) -> [u8; BCP_TAG_LEN] {
    let mut tag = [0u8; BCP_TAG_LEN];
    for (i, word) in tag.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        // SAFETY: see `write_dfl`; DW1-4 lie within the element, and the
        // engine finished writing them before the CQE that got us here.
        *word = unsafe { dfl_ptr(id).add(DFL_CRYPTO_OUT_DW + i).read_volatile() }.to_le_bytes();
    }
    tag
}

/// Write an abort for command `id` at ring index `sq_idx`.
fn write_abort(sq_idx: usize, id: usize) {
    let dw0 = SqeDw0::new()
        .with_cmd_id(id as u16)
        .with_cmd_state(CMD_STATE_CONTINUE_LAST)
        .with_opcode(OPCODE_ABORT)
        .with_dfl_idx(id as u16)
        .with_dfl_num(0);
    let e = &GSRAM.bcp_sq[sq_idx];
    e.dw0.set(dw0.into());
    e.dw1.set(0);
    e.dw2.set(0);
    e.dw3.set(0);
}

/// Queue command `id`: one SQE per [`BCP_CHUNK_LEN`] chunk of its
/// `len`-byte source, the first NEW and the last LAST, as the FP firmware
/// chunked host commands. Later chunks carry only their byte count; the
/// engine keeps the rest from the first.
fn submit(s: &mut BcpState, id: usize, op: GcmOp, len: usize) {
    let process_type = match op {
        GcmOp::Encrypt => PROCESS_GCM_ENCRYPT,
        GcmOp::Decrypt => PROCESS_GCM_ENCRYPT + 1,
    };
    let mut off = 0;
    while off < len {
        let chunk = (len - off).min(BCP_CHUNK_LEN);
        let first = off == 0;
        off += chunk;
        let state = match (first, off == len) {
            (true, true) => CMD_STATE_NEW_LAST,
            (true, false) => CMD_STATE_NEW,
            (false, true) => CMD_STATE_CONTINUE_LAST,
            (false, false) => CMD_STATE_CONTINUE,
        };
        let dw0 = SqeDw0::new()
            .with_cmd_id(id as u16)
            .with_cmd_state(state)
            .with_opcode(OPCODE_DATA_TRANSFER)
            .with_dfl_idx(id as u16)
            .with_dfl_num(0);
        let dw1 = if first {
            SqeDw1::new().with_process_type(process_type).with_sgl(true)
        } else {
            SqeDw1::new()
        }
        .with_chunk_byte_cnt(chunk as u16);
        let dw2 = SqeDw2::new().with_key1_idx(id as u16);

        let e = &GSRAM.bcp_sq[s.sq_pi as usize];
        e.dw0.set(dw0.into());
        e.dw1.set(dw1.into());
        e.dw2.set(dw2.into());
        // DW3: interface selects, all 0 = SoC AXI.
        e.dw3.set(0);
        ring(s);
    }
}
