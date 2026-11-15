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
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
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
use tsra_fw_uno_reg_soc::io_gsram::BcpCqe;
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
const MAX_CHUNKS: usize = 4;

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
const ALL_FREE: u64 = (1 << IDS) - 1;

/// Command deadline. One chunk takes microseconds; past this the engine is
/// presumed stuck, reset, and the commands in flight fail. Well inside the
/// host's 6 s command timeout. Counted from the first deadline check that
/// finds the command in flight, at most [`DEADLINE_CHECK_PASSES`] passes
/// after its submission.
const CMD_TIMEOUT: Duration = Duration::from_millis(2000);

/// Bound on the wait for a soft reset to complete and the engine to stop.
const RESET_SPIN: u32 = 100_000;

/// [`BcpDriver::wake`] passes between checks of the command deadlines.
const DEADLINE_CHECK_PASSES: u16 = 64;

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

/// XTS tweak length.
pub const BCP_TWEAK_LEN: usize = 16;

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

/// Key-vault slots per command ID: the data key, and the XTS tweak key.
const KEYS_PER_ID: usize = 2;

const _: () = assert!(IDS * KEYS_PER_ID * KEY_WORDS <= 4096);

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

/// SQE `DataProcessType` for XTS encrypt (decrypt is one more).
const PROCESS_XTS_ENCRYPT: u8 = 1;

/// SQE `DataProcessType` for GCM encrypt (decrypt is one more).
const PROCESS_GCM_ENCRYPT: u8 = 3;

/// SGL descriptor type (high nibble of byte 15): data block.
const SGL_TYPE_DATA_BLOCK: u8 = 0;

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

/// Cipher direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BcpOp {
    Encrypt,
    Decrypt,
}

/// GCM direction.
pub type GcmOp = BcpOp;

/// Source and destination of a command on GSRAM buffers. For a GCM they
/// hold `[padded_AAD | text]`, which the engine writes back whole, copying
/// the padded AAD through. Buffers must be [`BCP_ADDR_ALIGN`]-aligned and
/// live in GSRAM the CDMA may master (the PAL DMA heap does).
#[derive(Debug)]
pub enum BcpData<'a> {
    /// Read `src`, write `dst`, which is at least as long.
    Copy {
        src: &'a HsmDmaBuf,
        dst: &'a mut HsmDmaBuf,
    },
    /// Transform in place.
    InPlace(&'a mut HsmDmaBuf),
}

impl BcpData<'_> {
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
    pub data: BcpData<'a>,
}

/// One AES-256-XTS command on GSRAM buffers.
#[derive(Debug)]
pub struct XtsRequest<'a> {
    pub op: BcpOp,
    /// Data key ([`BCP_KEY_LEN`] bytes).
    pub key1: &'a [u8],
    /// Tweak key ([`BCP_KEY_LEN`] bytes).
    pub key2: &'a [u8],
    /// Initial tweak.
    pub tweak: &'a [u8; BCP_TWEAK_LEN],
    /// Data unit length encoding, as in [`HostCipher::Xts`].
    pub dul: u8,
    /// The text: a non-zero multiple of [`BCP_TEXT_ALIGN`], at most
    /// [`BCP_MAX_SRC_LEN`] bytes, with the same alignment and placement
    /// rules as [`BcpData`].
    pub data: BcpData<'a>,
}

/// Cipher of a [`HostRequest`].
pub enum HostCipher<'a> {
    /// AES-256-GCM over `[padded_AAD | text]`, as in [`GcmRequest`], except
    /// that the text may be empty: an AAD-only command yields the tag over
    /// the padded AAD and copies the AAD through, as on the FP engine.
    Gcm {
        /// AES-256 key ([`BCP_KEY_LEN`] bytes).
        key: &'a [u8],
        iv: &'a [u8; BCP_IV_LEN],
        /// Padded AAD length; a multiple of [`BCP_AAD_ALIGN`] no longer
        /// than the whole length.
        aad_len: usize,
        /// Unpadded AAD length.
        unpadded_aad_len: usize,
        /// Expected (engine) tag of a decrypt; ignored on encrypt.
        tag: &'a [u8; BCP_TAG_LEN],
    },
    /// AES-256-XTS.
    Xts {
        /// Data key ([`BCP_KEY_LEN`] bytes).
        key1: &'a [u8],
        /// Tweak key ([`BCP_KEY_LEN`] bytes).
        key2: &'a [u8],
        /// Initial tweak.
        tweak: &'a [u8; BCP_TWEAK_LEN],
        /// Data unit length encoding (0 = whole transfer, 1 = 512 B,
        /// 2 = 4 KiB, 3 = 8 KiB), as in the host submission entry.
        dul: u8,
    },
}

/// One command on host memory: the engine walks the host's SGL
/// descriptors itself, over the host interface `if_sel`. The source and
/// destination are both `len` bytes.
///
/// The caller validates the descriptors' shape; the engine bounds its
/// accesses by them and by `len`.
pub struct HostRequest<'a> {
    pub op: BcpOp,
    pub cipher: HostCipher<'a>,
    /// Bytes to process: a non-zero multiple of [`BCP_TEXT_ALIGN`], at
    /// most [`BCP_MAX_SRC_LEN`].
    pub len: usize,
    /// Source SGL descriptor, as the host wrote it.
    pub src: &'a [u8; 16],
    /// Destination SGL descriptor, as the host wrote it.
    pub dst: &'a [u8; 16],
    /// AXI interface select of the host function owning the buffers
    /// (PF `0x10`, VF `n` `0x20 + n`); never 0, which is the SoC.
    pub if_sel: u8,
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
    /// Stamped by the first deadline check that finds the command in
    /// flight, [`Instant::MAX`] until then: submitting a command reads no
    /// timer.
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
    free: u64,
    /// SQEs reserved by the commands in flight (at most [`SQE_BUDGET`]).
    reserved: usize,
    /// [`BcpDriver::wake`] passes with commands in flight, counted to space
    /// out the deadline checks.
    passes: u16,
    /// SQEs were written since the doorbell last rang: the next
    /// [`BcpDriver::wake`] rings it once for all of them.
    bell: bool,
    /// Tasks waiting for a free command ID.
    id_waiters: MultiWakerRegistration<ID_WAITERS>,
    /// Per command ID; IDs index the key-vault slots and DFL elements.
    slots: [Slot; IDS],
    /// The DFL element [`write_dfl`] builds before writing it out: words it
    /// does not set stay zero, so a command need not clear it first.
    dfl: [u32; DFL_DWORDS],
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
                passes: 0,
                bell: false,
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
                dfl: [0; DFL_DWORDS],
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
        CmdFuture {
            bcp: self,
            cmd: Cmd::local(req),
            id: None,
        }
    }

    /// Submit an AES-256-XTS command on GSRAM buffers and await its
    /// completion. Behaves as [`gcm`](Self::gcm) otherwise, cancellation
    /// included.
    pub fn xts<'a>(
        &'a self,
        req: XtsRequest<'a>,
    ) -> impl Future<Output = HsmResult<GcmCompletion>> + 'a {
        CmdFuture {
            bcp: self,
            cmd: Cmd::local_xts(req),
            id: None,
        }
    }

    /// Submit an AES-256-GCM or AES-256-XTS command on host memory and
    /// await its completion; see [`HostRequest`]. Behaves as
    /// [`gcm`](Self::gcm) otherwise, cancellation included.
    pub fn host<'a>(
        &'a self,
        req: HostRequest<'a>,
    ) -> impl Future<Output = HsmResult<GcmCompletion>> + 'a {
        CmdFuture {
            bcp: self,
            cmd: Cmd::host(req),
            id: None,
        }
    }

    /// Ring the doorbell for the commands submitted since the last call,
    /// reap completions and wake their awaiters; reset the engine if a
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
            if s.bell {
                doorbell(s);
            }
            let shadow = GSRAM.bcp_cq_pi_shadow.get();
            let pi = (shadow as u16) & MASK;
            if pi != s.cq_ci {
                reap(s, pi, shadow);
            }
            // Checked after reaping as well, so that other commands
            // completing on every pass cannot hold off the reset of one
            // that is stuck; but only every few passes, since deadlines
            // are seconds away and the check reads the timer and every
            // command's slot.
            s.passes = s.passes.wrapping_add(1);
            if !s.passes.is_multiple_of(DEADLINE_CHECK_PASSES) {
                return;
            }
            let now = Instant::now();
            let free = s.free;
            let mut late = false;
            for (i, slot) in s.slots.iter_mut().enumerate() {
                if free & (1 << i) != 0 || slot.done {
                    continue;
                }
                if slot.deadline == Instant::MAX {
                    slot.deadline = now + CMD_TIMEOUT;
                } else if now > slot.deadline {
                    late = true;
                }
            }
            if late {
                recover(s);
            }
        });
    }
}

/// Crypto input of a [`Cmd`].
enum Aux<'a> {
    Gcm {
        iv: &'a [u8; BCP_IV_LEN],
        aad_len: usize,
        unpadded_aad_len: usize,
        /// Expected tag (decrypt only).
        tag: Option<&'a [u8; BCP_TAG_LEN]>,
    },
    Xts {
        tweak: &'a [u8; BCP_TWEAK_LEN],
    },
}

/// A validated command, as the DFL element and SQEs carry it.
struct Cmd<'a> {
    process_type: u8,
    /// XTS data unit length encoding.
    dul: u8,
    key1: &'a [u8],
    key2: Option<&'a [u8]>,
    /// Source (and destination) length.
    len: usize,
    src: [u8; 16],
    dst: [u8; 16],
    /// Interface select of all four data / descriptor accesses.
    if_sel: u8,
    aux: Aux<'a>,
}

impl<'a> Cmd<'a> {
    /// A GCM command on GSRAM buffers, described by data-block descriptors
    /// over the SoC interface.
    fn local(req: GcmRequest<'a>) -> HsmResult<Self> {
        validate(&req)?;
        let (src, len) = req.data.src();
        let (dst, _) = req.data.dst();
        let process_type = match req.op {
            BcpOp::Encrypt => PROCESS_GCM_ENCRYPT,
            BcpOp::Decrypt => PROCESS_GCM_ENCRYPT + 1,
        };
        Ok(Self {
            process_type,
            dul: 0,
            key1: req.key,
            key2: None,
            len,
            src: data_block(src, len),
            dst: data_block(dst, len),
            if_sel: 0,
            aux: Aux::Gcm {
                iv: req.iv,
                aad_len: req.aad_len,
                unpadded_aad_len: req.unpadded_aad_len,
                tag: (req.op == BcpOp::Decrypt).then_some(req.tag),
            },
        })
    }

    /// An XTS command on GSRAM buffers, described as in
    /// [`local`](Self::local).
    fn local_xts(req: XtsRequest<'a>) -> HsmResult<Self> {
        let (src, len) = req.data.src();
        let (dst, dst_len) = req.data.dst();
        if req.key1.len() != BCP_KEY_LEN || req.key2.len() != BCP_KEY_LEN {
            return Err(BcpError::INVALID_KEY_LEN);
        }
        if len == 0
            || !len.is_multiple_of(BCP_TEXT_ALIGN)
            || len > BCP_MAX_SRC_LEN
            || dst_len < len
            || req.dul > 3
            || !(src as usize).is_multiple_of(BCP_ADDR_ALIGN)
            || !(dst as usize).is_multiple_of(BCP_ADDR_ALIGN)
        {
            return Err(BcpError::INVALID_DATA_LEN);
        }
        Ok(Self {
            process_type: PROCESS_XTS_ENCRYPT + u8::from(req.op == BcpOp::Decrypt),
            dul: req.dul,
            key1: req.key1,
            key2: Some(req.key2),
            len,
            src: data_block(src, len),
            dst: data_block(dst, len),
            if_sel: 0,
            aux: Aux::Xts { tweak: req.tweak },
        })
    }

    /// A command on host memory.
    fn host(req: HostRequest<'a>) -> HsmResult<Self> {
        if req.len == 0
            || !req.len.is_multiple_of(BCP_TEXT_ALIGN)
            || req.len > BCP_MAX_SRC_LEN
            || req.if_sel == 0
        {
            return Err(BcpError::INVALID_DATA_LEN);
        }
        let dir = u8::from(req.op == BcpOp::Decrypt);
        let (process_type, dul, key1, key2, aux) = match req.cipher {
            HostCipher::Gcm {
                key,
                iv,
                aad_len,
                unpadded_aad_len,
                tag,
            } => {
                if !aad_len.is_multiple_of(BCP_AAD_ALIGN)
                    || unpadded_aad_len > aad_len
                    || aad_len > req.len
                {
                    return Err(BcpError::INVALID_DATA_LEN);
                }
                let aux = Aux::Gcm {
                    iv,
                    aad_len,
                    unpadded_aad_len,
                    tag: (req.op == BcpOp::Decrypt).then_some(tag),
                };
                (PROCESS_GCM_ENCRYPT + dir, 0, key, None, aux)
            }
            HostCipher::Xts {
                key1,
                key2,
                tweak,
                dul,
            } => {
                if dul > 3 || key2.len() != BCP_KEY_LEN {
                    return Err(BcpError::INVALID_DATA_LEN);
                }
                let aux = Aux::Xts { tweak };
                (PROCESS_XTS_ENCRYPT + dir, dul, key1, Some(key2), aux)
            }
        };
        if key1.len() != BCP_KEY_LEN {
            return Err(BcpError::INVALID_KEY_LEN);
        }
        Ok(Self {
            process_type,
            dul,
            key1,
            key2,
            len: req.len,
            src: *req.src,
            dst: *req.dst,
            if_sel: req.if_sel,
            aux,
        })
    }
}

/// SGL data-block descriptor for `len` bytes at the GSRAM address `addr`.
fn data_block(addr: u32, len: usize) -> [u8; 16] {
    let mut d = [0u8; 16];
    d[..4].copy_from_slice(&addr.to_le_bytes());
    d[8..12].copy_from_slice(&(len as u32).to_le_bytes());
    d[15] = SGL_TYPE_DATA_BLOCK << 4;
    d
}

/// The future [`BcpDriver::gcm`], [`BcpDriver::xts`] and [`BcpDriver::host`]
/// return. It owns its command from submission until the completion is
/// consumed, so that dropping it mid-flight can wait for the engine before
/// the buffers go.
struct CmdFuture<'a> {
    bcp: &'a BcpDriver,
    /// The command, or why it is invalid.
    cmd: HsmResult<Cmd<'a>>,
    /// Command ID while submitted and not yet consumed.
    id: Option<usize>,
}

impl Future for CmdFuture<'_> {
    type Output = HsmResult<GcmCompletion>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let bcp = this.bcp;
        bcp.state.with(|s| {
            let id = match this.id {
                Some(id) => id,
                None => {
                    let cmd = match &this.cmd {
                        Ok(cmd) => cmd,
                        Err(e) => return Poll::Ready(Err(*e)),
                    };
                    if s.stalled {
                        return Poll::Ready(Err(BcpError::TIMEOUT));
                    }
                    let chunks = cmd.len.div_ceil(BCP_CHUNK_LEN);
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
                    s.slots[id].deadline = Instant::MAX;
                    s.slots[id].chunks = chunks as u8;
                    s.reserved += chunks;
                    this.id = Some(id);

                    load_key(key_slot(id, 0), cmd.key1);
                    if let Some(key2) = cmd.key2 {
                        load_key(key_slot(id, 1), key2);
                    }
                    write_dfl(&mut s.dfl, id, cmd);
                    submit(s, id, cmd);
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

impl Drop for CmdFuture<'_> {
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
#[inline]
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
    doorbell(s);
}

/// Hand the engine every SQE written before `sq_pi`.
fn doorbell(s: &mut BcpState) {
    s.bell = false;
    // The descriptors must be visible before the doorbell starts the
    // engine's fetch.
    cortex_m::asm::dmb();
    BCP.sq_pi.write(SQ_PI::INDEX.val(s.sq_pi.into()));
}

/// Consume completions up to `pi`, read from the index shadow as `shadow`.
fn reap(s: &mut BcpState, pi: u16, shadow: u32) {
    // Read the entries only after the index that published them.
    let cq = cq_ring_after(shadow);

    while s.cq_ci != pi {
        let (dw0, dw1) = read_cqe(cq, s.cq_ci as usize);
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
    // SQEs not handed over yet must not start on the engine being reset;
    // their commands fail with the others once the reset is confirmed.
    s.bell = false;
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

/// Key-vault slot `n` (0 = data key, 1 = XTS tweak key) of command `id`.
fn key_slot(id: usize, n: usize) -> usize {
    id * KEYS_PER_ID + n
}

/// Write a key into vault slot `slot`, as little-endian words.
///
/// A word-aligned key (vault keys are) is read in one burst: it sits in DMA
/// memory, which the CPU reads uncached, where a burst of eight words costs
/// about as much as a single byte load. The vault registers take one
/// single-beat store each; they do not accept a burst.
fn load_key(slot: usize, key: &[u8]) {
    const _: () = assert!(KEY_WORDS == 8);
    let (words, _) = key.as_chunks::<4>();
    #[cfg(target_arch = "arm")]
    if words.len() == KEY_WORDS && key.as_ptr().align_offset(4) == 0 {
        let dst: *const _ = &BCP.key_vault[slot * KEY_WORDS];
        // SAFETY: `key` is eight readable, word-aligned words, and vault slot
        // `slot` is eight consecutive word registers that only its command
        // uses. Little-endian words are the CPU's native order.
        unsafe {
            core::arch::asm!(
                "ldm {src}, {{r2, r3, r4, r5, r8, r9, r10, r11}}",
                "str r2, [{dst}]",
                "str r3, [{dst}, #4]",
                "str r4, [{dst}, #8]",
                "str r5, [{dst}, #12]",
                "str r8, [{dst}, #16]",
                "str r9, [{dst}, #20]",
                "str r10, [{dst}, #24]",
                "str r11, [{dst}, #28]",
                src = in(reg) key.as_ptr(),
                dst = in(reg) dst,
                out("r2") _,
                out("r3") _,
                out("r4") _,
                out("r5") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                options(nostack, preserves_flags),
            );
        }
        return;
    }
    for (i, word) in words.iter().enumerate() {
        BCP.key_vault[slot * KEY_WORDS + i].set(u32::from_le_bytes(*word));
    }
}

/// Wipe the vault slots of command `id`.
fn clear_key(id: usize) {
    for i in 0..KEYS_PER_ID * KEY_WORDS {
        BCP.key_vault[key_slot(id, 0) * KEY_WORDS + i].set(0);
    }
}

/// DFL element of command `id`.
fn dfl_ptr(id: usize) -> *mut u32 {
    (IO_GSRAM_BASE + BCP_DFL_OFFSET + id as u32 * BCP_DFL_STRIDE) as *mut u32
}

/// Read `N` (2 to 4) words at `src` with one LDM burst: out of memory the
/// CPU reads uncached (DMA memory, the GSRAM rings), a burst costs about as
/// much as a single load.
///
/// # Safety
///
/// `src` must be word-aligned and valid for reads of `N` words.
#[inline(always)]
unsafe fn burst_read<const N: usize>(src: *const u32) -> [u32; N] {
    const { assert!(N >= 2 && N <= 4) };
    let (a, b, c, d): (u32, u32, u32, u32);
    #[cfg(target_arch = "arm")]
    // SAFETY: per the function contract, for the words loaded.
    unsafe {
        match N {
            2 => {
                core::arch::asm!(
                    "ldm {s}, {{r2, r3}}",
                    s = in(reg) src,
                    out("r2") a,
                    out("r3") b,
                    options(nostack, preserves_flags, readonly),
                );
                (c, d) = (0, 0);
            }
            3 => {
                core::arch::asm!(
                    "ldm {s}, {{r2, r3, r4}}",
                    s = in(reg) src,
                    out("r2") a,
                    out("r3") b,
                    out("r4") c,
                    options(nostack, preserves_flags, readonly),
                );
                d = 0;
            }
            _ => core::arch::asm!(
                "ldm {s}, {{r2, r3, r4, r5}}",
                s = in(reg) src,
                out("r2") a,
                out("r3") b,
                out("r4") c,
                out("r5") d,
                options(nostack, preserves_flags, readonly),
            ),
        }
    }
    #[cfg(not(target_arch = "arm"))]
    // SAFETY: per the function contract, for the words loaded.
    unsafe {
        let word = |i: usize| if i < N { src.add(i).read_volatile() } else { 0 };
        (a, b, c, d) = (word(0), word(1), word(2), word(3));
    }
    let words = [a, b, c, d];
    core::array::from_fn(|i| words[i])
}

/// Pack a 12-byte IV, or a 16-byte tag, tweak or SGL descriptor, into
/// little-endian words at `dw[start..]`.
///
/// Inlined at its call sites, where `N` and `start` are constants.
/// Word-aligned bytes are read with one burst: they may sit in DMA memory
/// (a frame's trailer, a masked blob), which the CPU reads uncached.
#[inline(always)]
fn put_bytes<const N: usize>(dw: &mut [u32; DFL_DWORDS], start: usize, bytes: &[u8; N]) {
    const { assert!(N == BCP_IV_LEN || N == BCP_TAG_LEN) };
    if bytes.as_ptr().align_offset(4) != 0 {
        put_unaligned(dw, start, bytes);
        return;
    }
    if N == BCP_IV_LEN {
        // SAFETY: `bytes` is 12 readable bytes at a 4-aligned address.
        let words: [u32; 3] = unsafe { burst_read(bytes.as_ptr().cast()) };
        dw[start..start + 3].copy_from_slice(&words);
    } else {
        // SAFETY: `bytes` is 16 readable bytes at a 4-aligned address.
        let words: [u32; 4] = unsafe { burst_read(bytes.as_ptr().cast()) };
        dw[start..start + 4].copy_from_slice(&words);
    }
}

/// [`put_bytes`] for bytes that are not word-aligned.
#[inline(never)]
fn put_unaligned(dw: &mut [u32; DFL_DWORDS], start: usize, bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        dw[start + i] = u32::from_le_bytes(word);
    }
}

/// Fill the DFL element of command `id`, laid out as the host submission
/// entry the FP firmware handed the engine: the source length and SGL
/// descriptor (DW6-10), the destination's (DW11-15), then the crypto
/// input: for GCM the key slot, unpadded AAD length, expected tag, IV and
/// padded AAD length; for XTS the tweak.
///
/// The element is built in `dw`, whose other words are zero, and then
/// written out: every word set here is set on every command.
///
/// The destination is as long as the source: for GCM the engine writes
/// the padded AAD through ahead of the text, as the host fast path
/// expected.
fn write_dfl(dw: &mut [u32; DFL_DWORDS], id: usize, cmd: &Cmd<'_>) {
    let len = cmd.len as u32;

    dw[6] = len;
    put_bytes(dw, 7, &cmd.src);
    dw[11] = len;
    put_bytes(dw, 12, &cmd.dst);

    match cmd.aux {
        Aux::Gcm {
            iv,
            aad_len,
            unpadded_aad_len,
            tag,
        } => {
            dw[17] = key_slot(id, 0) as u32;
            dw[18] = unpadded_aad_len as u32;
            match tag {
                Some(tag) => put_bytes(dw, 19, tag),
                None => dw[19..23].fill(0),
            }
            put_bytes(dw, 23, iv);
            dw[26] = aad_len as u32;
        }
        Aux::Xts { tweak } => {
            dw[17..19].fill(0);
            put_bytes(dw, DFL_CRYPTO_IN_DW as usize, tweak);
            dw[23..27].fill(0);
        }
    }

    // Burst-write the element: the ring sits in memory the CPU writes
    // uncached, one bus transaction per store, while a store-multiple
    // writes several words in one.
    // SAFETY: `dfl_ptr(id)` is DFL element `id` of the GSRAM ring
    // (`id < DEPTH`), `DFL_DWORDS` words long and word-aligned, and only
    // this command uses it.
    let out = unsafe { core::slice::from_raw_parts_mut(dfl_ptr(id), DFL_DWORDS) };
    tsra_fw_bulk_copy::copy_slice(out, dw);
}

/// The completion ring, at an address computed from `loaded`, a value just
/// loaded: entries read through it are read after that load. The address
/// dependency orders the loads without a barrier, which would also wait for
/// every store before it to complete.
#[inline(always)]
fn cq_ring_after(loaded: u32) -> *const BcpCqe {
    let zero: usize;
    #[cfg(target_arch = "arm")]
    // SAFETY: computes `loaded ^ loaded` in a register; touches no memory.
    unsafe {
        core::arch::asm!(
            "eor {z}, {v}, {v}",
            z = lateout(reg) zero,
            v = in(reg) loaded,
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    #[cfg(not(target_arch = "arm"))]
    {
        let _ = loaded;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        zero = 0;
    }
    GSRAM.bcp_cq.as_ptr().wrapping_byte_add(zero)
}

/// Read the completion-ring entry at `ci` of `ring` (see
/// [`cq_ring_after`]), with one burst.
fn read_cqe(ring: *const BcpCqe, ci: usize) -> (CqeDw0, CqeDw1) {
    let entry = ring.wrapping_add(ci).cast::<u32>();
    // SAFETY: the entry is two words of the GSRAM ring (`ci` is masked to
    // its length), 8-byte aligned.
    let [dw0, dw1] = unsafe { burst_read::<2>(entry) };
    (CqeDw0::from(dw0), CqeDw1::from(dw1))
}

/// Read the tag the engine wrote back into the DFL element of command `id`,
/// with one burst.
fn read_tag(id: usize) -> [u8; BCP_TAG_LEN] {
    // SAFETY: see `write_dfl`; DW1-4 lie within the element, and the
    // engine finished writing them before the CQE that got us here.
    let words = unsafe { burst_read::<4>(dfl_ptr(id).add(DFL_CRYPTO_OUT_DW)) };
    let mut tag = [0u8; BCP_TAG_LEN];
    for (bytes, word) in tag.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *bytes = word.to_le_bytes();
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
    write_sqe(sq_idx, [dw0.into(), 0, 0, 0]);
}

/// Write the submission-ring entry at `idx` with one store-multiple: the
/// ring sits in memory the CPU writes uncached, one bus transaction per
/// store, and the doorbell's barrier waits for all of them.
fn write_sqe(idx: usize, dw: [u32; 4]) {
    let e = &GSRAM.bcp_sq[idx];
    #[cfg(target_arch = "arm")]
    {
        let dst: *const _ = e;
        // SAFETY: `dst` is the four word-aligned words of ring entry `idx`,
        // which is the driver's until the doorbell hands it to the engine.
        unsafe {
            core::arch::asm!(
                "stm {dst}, {{r2, r3, r4, r5}}",
                dst = in(reg) dst,
                in("r2") dw[0],
                in("r3") dw[1],
                in("r4") dw[2],
                in("r5") dw[3],
                options(nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(target_arch = "arm"))]
    {
        e.dw0.set(dw[0]);
        e.dw1.set(dw[1]);
        e.dw2.set(dw[2]);
        e.dw3.set(dw[3]);
    }
}

/// Queue command `id`: one SQE per [`BCP_CHUNK_LEN`] chunk of its
/// source, the first NEW and the last LAST, as the FP firmware chunked
/// host commands. Later chunks carry only their byte count in DW1; the
/// engine keeps the rest from the first.
fn submit(s: &mut BcpState, id: usize, cmd: &Cmd<'_>) {
    let len = cmd.len;
    // The interface select of the source / destination descriptors and
    // data, one byte each.
    let dw3 = u32::from(cmd.if_sel) * 0x0101_0101;
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
            SqeDw1::new()
                .with_process_type(cmd.process_type)
                .with_sgl(true)
                .with_xts_data_unit_len(cmd.dul)
        } else {
            SqeDw1::new()
        }
        .with_chunk_byte_cnt(chunk as u16);
        let dw2 = SqeDw2::new()
            .with_key1_idx(key_slot(id, 0) as u16)
            .with_key2_idx(key_slot(id, 1) as u16);

        write_sqe(s.sq_pi as usize, [dw0.into(), dw1.into(), dw2.into(), dw3]);
        s.sq_pi = (s.sq_pi + 1) & MASK;
    }
    // Rung by the next `wake`, at the end of this executor pass, once for
    // every command submitted in it rather than with a barrier each.
    s.bell = true;
}
