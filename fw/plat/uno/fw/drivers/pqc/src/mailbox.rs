// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM-side view of the per-core PQC request mailbox in PSRAM.
//!
//! Mirrors `mailbox.rs` in the FP firmware (`fw/plat/uno/pqc/app/src/`);
//! the two layouts must be kept in step.
//!
//! One mailbox per FP core, depth one.  That is sufficient by
//! construction: [`PqcDriver::acquire_any`](crate::PqcDriver::acquire_any)
//! hands out exclusive use of a core and does not take it back until the
//! operation finishes, so a core can never have two requests outstanding.
//! Hence a mailbox rather than the 16-entry rings the legacy fastpath used
//! — which also matters because PSRAM is scarce.
//!
//! # Placement
//!
//! PSRAM offset `0x0980`, reclaimed from the legacy `hsm_to_fp` IPC rings.
//! Those are dead: the CP firmware build overwrites the legacy HSM image
//! with the tsra ELF, so the legacy HSM firmware that owned them never
//! runs.  The
//! `admin_to_fp` rings below are left alone — Admin's FP channels run in
//! loopback and still write to them.
//!
//! ```text
//! 0xA3E0_0980  mailboxes     3 x 0x100
//! 0xA3E0_0C80  status block  0x70
//! 0xA3E0_0D00  FP0 operand slot 0x1F80   (below the in-use block)
//! 0xA3E0_3AFC  ---- in use: reset_type, cdma, fp_boot_status, admin ----
//! 0xA3E0_4080  FP1 operand slot 0x1F80   (above it)
//! 0xA3E0_6000  FP2 operand slot 0x1F80
//!
//! 0xA3E0_0980 + 0x100*n   per-core mailbox
//!   +0x00 u32  request_seq    HSM -> FP, written last
//!   +0x04 u32  op
//!   +0x08 u32  key_kind
//!   +0x20 ..   xi[32]         HSM -> FP, the ML-DSA seed
//!   +0x10 u32  response_seq   FP -> HSM, written last
//!   +0x14 u32  status
//!   +0x18 u32  pub_key_len
//! ```
//!
//! # Handshake
//!
//! Each side writes its sequence number *last*, so a reader that sees a
//! matching sequence is guaranteed to see the payload belonging to it.
//! The HSM then polls `response_seq` rather than an interrupt pending bit:
//! block 1's pending bits belong to the IPC driver, whose `wake()` clears
//! every bit it processes and would race a reply away.

use core::ptr::read_volatile;
use core::ptr::write_volatile;

use tsra_fw_bulk_copy::copy_slice;

use crate::types::EngineId;

/// Base of the mailbox array in the global SoC map.  An FP core addresses
/// the same memory core-locally at `0x0001_0980`.
const MAILBOX_BASE: usize = 0xA3E0_0980;

/// Bytes per mailbox.
const MAILBOX_STRIDE: usize = 0x100;

/// Length of the ML-DSA private seed.
pub const SEED_LEN: usize = 32;

/// Bytes in each core's operand slot.
///
/// Sized for the largest PQC working set: `MlDsaVerify` needs public key
/// (2592) + message (586) + ctx (255) + signature (4627) = 8060 B. Three
/// slots of this size fit either side of the only part of PSRAM still
/// spoken for (`0x3AFC`-`0x4004`); everything else is legacy fastpath
/// structure that nothing reads, including the 12 KB of FP debug-log rings
/// whose macros the SP defines but never consumes.
pub const SLOT_SIZE: usize = 0x1F80;

/// Global address of each core's operand slot.
const SLOT_ADDRS: [usize; 3] = [0xA3E0_0D00, 0xA3E0_4080, 0xA3E0_6000];

/// Word indices within a mailbox.
mod word {
    pub const REQUEST_SEQ: usize = 0;
    pub const OP: usize = 1;
    pub const KEY_KIND: usize = 2;
    pub const MSG_LEN: usize = 3;
    pub const RESPONSE_SEQ: usize = 4;
    pub const STATUS: usize = 5;
    pub const OUT_LEN: usize = 6;
    pub const CTX_LEN: usize = 7;
    pub const XI: usize = 8;
    pub const RND: usize = 16;
    pub const SIG_LEN: usize = 24;
    pub const PUB_KEY_LEN: usize = 25;
}

/// Operand slot layout, mirroring the FP side.
///
/// One packing serves every operation. Verify forces it to be tight: it is
/// the only command carrying all four operands at once, and at
/// 586 + 255 + 4627 + 2592 = 8060 B it fills the slot exactly.
///
/// ```text
///   offset      max    operand
///        0      586    message
///      588      255    context string
///      844     4627    signature
///     5472     2592    public key
///                      = 8064, the whole slot
/// ```
pub const SLOT_MSG_OFFSET: usize = 0;

/// Offset of the context string within the operand slot.
pub const SLOT_CTX_OFFSET: usize = 588;

/// Offset of the signature within the operand slot.
pub const SLOT_SIG_OFFSET: usize = 844;

/// Offset of the public key within the operand slot.
pub const SLOT_PK_OFFSET: usize = 5472;

/// Offset of the ML-KEM ciphertext; shares the signature region, since no
/// operation produces both and 1568 fits inside 4627.
pub const SLOT_CT_OFFSET: usize = SLOT_SIG_OFFSET;

/// Offset of the ML-KEM shared secret; shares the message region, which
/// ML-KEM does not use.
pub const SLOT_SS_OFFSET: usize = SLOT_MSG_OFFSET;

/// Offset of the private key **written by key generation**, mirroring
/// `SLOT_KEY_OUT_OFFSET` on FP.
///
/// Key generation touches none of the message, context or signature
/// regions, so the expanded key starts at the base of the slot while the
/// public key keeps its usual place.
pub const SLOT_KEY_OUT_OFFSET: usize = SLOT_MSG_OFFSET;

/// Offset of the private key **supplied to signing and decapsulation**,
/// mirroring `SLOT_KEY_IN_OFFSET` on FP.
///
/// Shares the signature region: FP copies the key into dTCM before writing
/// the signature back over it.
pub const SLOT_KEY_IN_OFFSET: usize = SLOT_SIG_OFFSET;

/// Offset of the ML-KEM ciphertext **consumed by decapsulation**,
/// mirroring `SLOT_CT_IN_OFFSET` on FP.
///
/// Borrows the public-key region because the decapsulation key occupies
/// [`SLOT_CT_OFFSET`]; decapsulation takes no public key.
pub const SLOT_CT_IN_OFFSET: usize = SLOT_PK_OFFSET;

/// Length of the ML-KEM shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// Operation selectors are supplied by [`PqcOp`](crate::PqcOp), which is
/// the single definition; these record the correspondence with the FP side.
const _: () = assert!(crate::request::PqcOp::MlDsaGenerateKey as u32 == 1);
const _: () = assert!(crate::request::PqcOp::MlDsaSign as u32 == 2);
const _: () = assert!(crate::request::PqcOp::MlDsaVerify as u32 == 3);
const _: () = assert!(crate::request::PqcOp::MlKemGenerateKey as u32 == 4);
const _: () = assert!(crate::request::PqcOp::MlKemEncapsulate as u32 == 5);
const _: () = assert!(crate::request::PqcOp::MlKemDecapsulate as u32 == 6);

/// A response read back from a core.
#[derive(Debug, Clone, Copy)]
pub struct Response {
    /// Zero on success.
    pub status: u32,

    /// Length of the output written to the operand slot -- public key for
    /// keygen, signature for sign.
    pub out_len: u32,
}

/// Everything a request carries in the mailbox itself.
///
/// Bulk inputs travel in the operand slot; only their lengths appear here.
pub struct RequestParams<'a> {
    /// Operation selector.
    pub op: u32,
    /// `HsmVaultKeyKind` discriminant.
    pub key_kind: u32,
    /// ML-DSA seed, drawn from the device TRNG.
    pub xi: &'a [u8; SEED_LEN],
    /// Per-signature randomness; ignored by operations that do not sign.
    pub rnd: &'a [u8; SEED_LEN],
    /// Length of the message staged in the operand slot.
    pub msg_len: u32,
    /// Length of the context string staged in the operand slot.
    pub ctx_len: u32,
    /// Length of the signature staged in the operand slot (verify only).
    pub sig_len: u32,
    /// Length of the public key staged in the operand slot (verify only).
    pub pub_key_len: u32,
}

/// Stage `data` into `engine`'s operand slot at `offset`.
pub fn write_slot(engine: EngineId, offset: usize, data: &[u8]) -> bool {
    let Some(end) = offset.checked_add(data.len()) else {
        return false;
    };
    if end > SLOT_SIZE {
        return false;
    }
    let base = SLOT_ADDRS[engine.raw() as usize] as *mut u8;

    // SAFETY: the range is checked against SLOT_SIZE above, the slot belongs
    // to this core alone, and it lies outside every region described to the
    // linker. Volatile because an FP core reads these bytes.
    //
    // Copied a word at a time where alignment allows. PSRAM is uncached and
    // off-core, so each access is expensive and a byte-at-a-time loop costs
    // four times what it needs to -- which matters now that whole expanded
    // keys travel through here, not just seeds.
    unsafe {
        let dst = base.add(offset);
        let head = dst.align_offset(align_of::<u32>()).min(data.len());
        for (i, &byte) in data[..head].iter().enumerate() {
            write_volatile(dst.add(i), byte);
        }
        let words = (data.len() - head) / 4;
        let dst_w = dst.add(head) as *mut u32;
        // `copy_slice` needs both sides word aligned. The slot side is, by
        // construction of `head`; `data` is a caller's buffer and need not
        // be, so keep the word loop for that case.
        let src_b = data.as_ptr().add(head);
        if src_b.align_offset(align_of::<u32>()) == 0 {
            copy_slice(
                core::slice::from_raw_parts_mut(dst_w, words),
                core::slice::from_raw_parts(src_b.cast::<u32>(), words),
            );
        } else {
            for i in 0..words {
                let b = &data[head + i * 4..head + i * 4 + 4];
                write_volatile(dst_w.add(i), u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
            }
        }
        let tail = head + words * 4;
        for (i, &byte) in data[tail..].iter().enumerate() {
            write_volatile(dst.add(tail + i), byte);
        }
    }
    true
}

/// Copy `out.len()` bytes out of `engine`'s operand slot at `offset`.
pub fn read_slot_at(engine: EngineId, offset: usize, out: &mut [u8]) -> bool {
    let Some(end) = offset.checked_add(out.len()) else {
        return false;
    };
    if end > SLOT_SIZE {
        return false;
    }
    let base = SLOT_ADDRS[engine.raw() as usize] as *const u8;

    // SAFETY: as `write_slot`, and word-wise for the same reason.
    unsafe {
        let src = base.add(offset);
        let head = src.align_offset(align_of::<u32>()).min(out.len());
        for (i, slot) in out[..head].iter_mut().enumerate() {
            *slot = read_volatile(src.add(i));
        }
        let words = (out.len() - head) / 4;
        let src_w = src.add(head) as *const u32;
        // As `write_slot`: burst only when the caller's buffer is aligned.
        let dst_b = out.as_mut_ptr().add(head);
        if dst_b.align_offset(align_of::<u32>()) == 0 {
            copy_slice(
                core::slice::from_raw_parts_mut(dst_b.cast::<u32>(), words),
                core::slice::from_raw_parts(src_w, words),
            );
        } else {
            for i in 0..words {
                let w = read_volatile(src_w.add(i)).to_ne_bytes();
                out[head + i * 4..head + i * 4 + 4].copy_from_slice(&w);
            }
        }
        let tail = head + words * 4;
        for (i, slot) in out[tail..].iter_mut().enumerate() {
            *slot = read_volatile(src.add(tail + i));
        }
    }
    true
}

/// Base of one core's mailbox.
fn mailbox(engine: EngineId) -> *mut u32 {
    (MAILBOX_BASE + engine.raw() as usize * MAILBOX_STRIDE) as *mut u32
}

/// Data memory barrier.
///
/// Written out rather than pulled from `cortex-m` so this driver keeps its
/// current dependency set. No `nomem`, so the compiler also may not move
/// memory accesses across it.
#[inline(always)]
pub(crate) fn dmb() {
    // SAFETY: a barrier instruction; no operands, no memory of its own.
    unsafe { core::arch::asm!("dmb sy", options(nostack, preserves_flags)) };
}

/// Data synchronisation barrier.
#[inline(always)]
pub(crate) fn dsb() {
    // SAFETY: as `dmb`.
    unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)) };
}

/// Instruction synchronisation barrier.
#[inline(always)]
fn isb() {
    // SAFETY: as `dmb`.
    unsafe { core::arch::asm!("isb sy", options(nostack, preserves_flags)) };
}

/// Base and size of the window covering the mailboxes and all three slots.
const WINDOW_BASE: usize = 0xA3E0_0000;
const WINDOW_SIZE: usize = 32 * 1024;

const _: () = assert!(MAILBOX_BASE >= WINDOW_BASE);
const _: () = assert!(SLOT_ADDRS[2] + SLOT_SIZE <= WINDOW_BASE + WINDOW_SIZE);

/// Map the mailbox/slot window as Normal Non-cacheable rather than leaving it
/// on the default memory map.
///
/// `0xA000_0000..0xBFFF_FFFF` is Device memory by the ARMv7-M default map, and
/// Device reads must complete strictly in order -- so the beats of an `ldm`
/// cannot overlap and a burst read costs the same per word as single loads.
/// Measured from CP1: writes (posted, so they pipeline) run at 13.6 cycles per
/// word while reads sit at 76, and widening the burst moved the write figure
/// only. GSRAM, which is Normal on the default map, bursts 121.6 down to 24.5
/// -- that contrast is what identifies the attribute rather than the RAM as
/// the cause.
///
/// Normal memory drops the implicit ordering Device gave the handshake, so the
/// two places that relied on it take explicit barriers: [`post_request`]
/// before the doorbell, and [`take_response`] after the sequence number.
/// Non-cacheable keeps the window coherent with the fastpath cores with no
/// maintenance, and the region is marked execute-never.
///
/// # Safety
/// Must run before any request is submitted, and region 6 must be free (the
/// stack guard takes 7).
pub unsafe fn map_normal() {
    const MPU_RNR: *mut u32 = 0xE000_ED98 as *mut u32;
    const MPU_RBAR: *mut u32 = 0xE000_ED9C as *mut u32;
    const MPU_RASR: *mut u32 = 0xE000_EDA0 as *mut u32;
    const MPU_CTRL: *mut u32 = 0xE000_ED94 as *mut u32;
    const REGION: u32 = 6;

    // TEX=001, C=0, B=0 -> Normal non-cacheable; S=1 shareable;
    // AP=011 full access; XN=1; SIZE=log2(32K)-1=14; ENABLE.
    const RASR: u32 = (1 << 28) | (0b011 << 24) | (0b001 << 19) | (1 << 18) | (14 << 1) | 1;
    const MPU_CTRL_ENABLE: u32 = 1 << 0;
    const MPU_CTRL_PRIVDEFENA: u32 = 1 << 2;

    dmb();
    write_volatile(MPU_RNR, REGION);
    write_volatile(MPU_RBAR, WINDOW_BASE as u32);
    write_volatile(MPU_RASR, RASR);
    // The stack guard enables the MPU too; setting the bits here as well keeps
    // this independent of which of the two runs first.
    write_volatile(
        MPU_CTRL,
        read_volatile(MPU_CTRL) | MPU_CTRL_ENABLE | MPU_CTRL_PRIVDEFENA,
    );
    dsb();
    isb();
}

/// Post a request, returning the sequence number to match the response
/// against.
pub fn post_request(engine: EngineId, seq: u32, params: &RequestParams<'_>) -> u32 {
    let mb = mailbox(engine);

    // SAFETY: a fixed 256-byte slot in PSRAM reserved for this core, outside
    // every region described to the linker. Volatile because the FP core
    // reads it.
    unsafe {
        write_volatile(mb.add(word::OP), params.op);
        write_volatile(mb.add(word::KEY_KIND), params.key_kind);
        write_volatile(mb.add(word::MSG_LEN), params.msg_len);
        write_volatile(mb.add(word::CTX_LEN), params.ctx_len);
        write_volatile(mb.add(word::SIG_LEN), params.sig_len);
        write_volatile(mb.add(word::PUB_KEY_LEN), params.pub_key_len);
        for i in 0..SEED_LEN / 4 {
            let xi = u32::from_le_bytes([
                params.xi[i * 4],
                params.xi[i * 4 + 1],
                params.xi[i * 4 + 2],
                params.xi[i * 4 + 3],
            ]);
            let rnd = u32::from_le_bytes([
                params.rnd[i * 4],
                params.rnd[i * 4 + 1],
                params.rnd[i * 4 + 2],
                params.rnd[i * 4 + 3],
            ]);
            write_volatile(mb.add(word::XI + i), xi);
            write_volatile(mb.add(word::RND + i), rnd);
        }
        // Commit: the fields above, and anything staged in the operand
        // slot, must be visible before the core is told there is work.
        // On Normal memory that ordering has to be asked for -- Device
        // memory used to give it for free.
        dmb();
        write_volatile(mb.add(word::REQUEST_SEQ), seq);
    }
    seq
}

/// Read a response, if the core has answered request `seq`.
/// The sequence number of the last response engine `engine`'s core
/// posted, which [`take_response`] matches against its request's.
pub(crate) fn response_seq(engine: EngineId) -> u32 {
    // SAFETY: as `take_response`.
    unsafe { read_volatile(mailbox(engine).add(word::RESPONSE_SEQ)) }
}

pub fn take_response(engine: EngineId, seq: u32) -> Option<Response> {
    let mb = mailbox(engine);

    // SAFETY: as above.
    unsafe {
        if read_volatile(mb.add(word::RESPONSE_SEQ)) != seq {
            return None;
        }

        // The window is Normal memory (see `map_normal`), so nothing stops the
        // loads below from being observed before the sequence-number load that
        // guards them. Device ordering used to make that impossible.
        dmb();

        Some(Response {
            status: read_volatile(mb.add(word::STATUS)),
            out_len: read_volatile(mb.add(word::OUT_LEN)),
        })
    }
}

/// First word of the fastpath crash record; see the FP app's `crash`
/// module. Sits above the request and response fields.
const CRASH_WORD: usize = 48;

/// ASCII "FPCR", written last by the faulting core.
const CRASH_MAGIC: u32 = 0x4650_4352;

/// Why a fastpath core stopped, as it managed to report on its way down.
///
/// The fields mirror the hardware crash record and are consumed by the
/// `error!` diagnostics in `engine`, which compile out when no trace
/// backend is selected -- hence the `dead_code` allowance.
#[allow(dead_code)]
pub struct CrashRecord {
    /// 1 = hard fault (MemManage, BusFault and UsageFault all escalate
    /// here), 2 = panic.
    pub kind: u32,
    /// Faulting instruction, or 0 for a panic.
    pub pc: u32,
    /// Link register at the fault, or 0 for a panic.
    pub lr: u32,
    /// Stack pointer at the fault.
    pub sp: u32,
    pub cfsr: u32,
    pub hfsr: u32,
    pub mmfar: u32,
    pub bfar: u32,
    /// Bytes between the stack pointer and the top of `.bss`. Enormous
    /// values mean it wrapped -- the stack had already crossed into `.bss`,
    /// which is the signature of an overflow.
    pub stack_free: u32,
}

/// Read the crash record a core left behind, if it left one.
///
/// Returns `None` when the magic is absent, which is the normal case: a
/// core that is merely slow has not written anything here.
pub fn crash_record(engine: EngineId) -> Option<CrashRecord> {
    let mb = mailbox(engine);

    // SAFETY: words 48..57 of this core's 256-byte mailbox, written only by
    // that core and only on its way down. Volatile because the FP core
    // writes them asynchronously.
    unsafe {
        let p = mb.add(CRASH_WORD);
        if read_volatile(p) != CRASH_MAGIC {
            return None;
        }
        Some(CrashRecord {
            kind: read_volatile(p.add(1)),
            pc: read_volatile(p.add(2)),
            lr: read_volatile(p.add(3)),
            sp: read_volatile(p.add(4)),
            cfsr: read_volatile(p.add(5)),
            hfsr: read_volatile(p.add(6)),
            mmfar: read_volatile(p.add(7)),
            bfar: read_volatile(p.add(8)),
            stack_free: read_volatile(p.add(9)),
        })
    }
}
