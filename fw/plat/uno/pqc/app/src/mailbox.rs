// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-core PQC request mailbox in PSRAM.
//!
//! One fixed-size mailbox per FP core, written by the HSM and answered by
//! the core.  Depth one is sufficient by construction: the HSM-side engine
//! pool hands out exclusive use of a core and does not take it back until
//! the operation finishes, so a core can never have two requests in
//! flight.  That is why this is a mailbox rather than the 16-entry rings
//! the legacy fastpath used.
//!
//! # Placement
//!
//! PSRAM offset `0x0980`, reclaimed from the legacy `hsm_to_fp` IPC rings.
//! Those are dead: the CP firmware build overwrites the legacy HSM image
//! with the tsra ELF, so the legacy HSM firmware that owned them never
//! runs.  The
//! `admin_to_fp` rings below them are *not* dead -- Admin's FP channels run
//! in loopback and still write there -- so they are left alone.
//!
//! An FP core addresses PSRAM core-locally at `0x0001_0000`; the HSM uses
//! the global `0xA3E0_0000`.
//!
//! # Protocol
//!
//! Sequence numbers carry the handshake, so neither side has to trust a
//! doorbell it may have missed or seen twice:
//!
//! 1. HSM writes `op` and `key_kind`, then `request_seq` last.
//! 2. HSM rings the core's doorbell.
//! 3. FP sees the doorbell, reads the request, does the work, writes the
//!    request_seq` last.
//! 4. HSM polls until `response_seq` matches what it sent.
//!
//! Writing the sequence number last on each side means a reader that sees
//! a matching sequence is guaranteed to see the payload that goes with it.
//!
//! # Operand slots
//!
//! Bulk operands do not fit in a mailbox, so each core also owns a
//! full-size operand slot of [`SLOT_SIZE`] bytes — enough for the largest
//! PQC working set, `MlDsaVerify` at 8060 B.
//!
//! The slots are placed either side of the small block of PSRAM that is
//! genuinely spoken for: `reset_type`, the CDMA IO entries, `fp_boot_status`
//! and the Admin index words and queues occupy `0x3AFC`–`0x4004`, and the
//! `admin_to_fp` receive queue is still driven by Admin's loopback.
//! Everything else is legacy fastpath structures that nothing now reads —
//! including the 12 KB of FP debug-log rings, whose macros the SP defines
//! but never consumes (it drains the *CP* rings, which live in GSRAM).
//!
//! ```text
//!   0x0980  mailboxes      3 x 0x100
//!   0x0C80  status block   0x70
//!   0x0D00  FP0 slot       0x1F80        (below the island)
//!   0x3AFC  ---- in use: reset_type, cdma, fp_boot_status, admin ----
//!   0x4080  FP1 slot       0x1F80        (above the island)
//!   0x6000  FP2 slot       0x1F80
//! ```
//!
//! # Seed provenance
//!
//! The ML-DSA seed travels *into* the core, not out of it. An FP core has
//! no entropy source; the HSM owns the device's certified TRNG, so it
//! generates the seed and supplies it in the request. Since the seed is
//! the private key, the HSM already holds it and the response carries only
//! the public key.

use core::ptr::read_volatile;
use core::ptr::write_volatile;

/// Base of PSRAM in this core's local view.
const PSRAM_LOCAL_BASE: usize = 0x0001_0000;

/// Offset of the mailbox array within PSRAM.
const MAILBOX_OFFSET: usize = 0x0980;

/// Bytes per mailbox.  Only the first 0x40 are used; the rest leaves room
/// to grow without moving any core's mailbox.
const MAILBOX_STRIDE: usize = 0x100;

/// Length of the ML-DSA private seed.
pub const SEED_LEN: usize = 32;

/// Bytes in each core's operand slot.
///
/// Sized for the largest PQC working set: `MlDsaVerify` needs public key
/// (2592) + message (586) + ctx (255) + signature (4627) = 8060 B.
pub const SLOT_SIZE: usize = 0x1F80;

/// Offset of each core's operand slot within PSRAM.  FP0 sits below the
/// block of PSRAM still in use, FP1 and FP2 above it.
const SLOT_OFFSETS: [usize; 3] = [0x0D00, 0x4080, 0x6000];

/// Word indices within a mailbox.
mod word {
    /// Incremented by the HSM for every request.
    pub const REQUEST_SEQ: usize = 0;
    /// Operation selector.
    pub const OP: usize = 1;
    /// `HsmVaultKeyKind` discriminant.
    pub const KEY_KIND: usize = 2;
    /// Length of the message in the operand slot (sign only).
    pub const MSG_LEN: usize = 3;
    /// Set equal to `REQUEST_SEQ` once the response is complete.
    pub const RESPONSE_SEQ: usize = 4;
    /// Zero on success.
    pub const STATUS: usize = 5;
    /// Length of the output the core produced -- public key for keygen,
    /// signature for sign.
    pub const OUT_LEN: usize = 6;
    /// Length of the context string in the operand slot (sign only).
    pub const CTX_LEN: usize = 7;
    /// First word of the ML-DSA seed `xi`.
    pub const XI: usize = 8;
    /// First word of the per-signature randomness (sign only).
    pub const RND: usize = 16;
    /// Length of the signature in the operand slot (verify only).
    pub const SIG_LEN: usize = 24;
    /// Length of the public key in the operand slot (verify only).
    pub const PUB_KEY_LEN: usize = 25;
}

/// Operand slot layout.
///
/// One packing serves every operation: each operand has a fixed offset, so
/// a request never has to describe where its parts are, and inputs and
/// outputs of the same operation never overlap.
///
/// Verify is what forces the packing to be tight -- it is the only command
/// carrying all four operands at once, and at 586 + 255 + 4627 + 2592 =
/// 8060 B it fills the slot exactly. Adding an operand, or raising any
/// cap, needs the slot to grow.
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

/// Offset of the ML-KEM ciphertext **produced by encapsulation**.
///
/// Shares the signature region: at 1568 B it fits comfortably inside the
/// 4627 reserved there, and no operation produces both.
pub const SLOT_CT_OFFSET: usize = SLOT_SIG_OFFSET;

/// Offset of the private key **written by key generation**.
///
/// Key generation uses none of the message, context or signature regions,
/// so the expanded key starts at the base of the slot and the public key
/// keeps its usual place at [`SLOT_PK_OFFSET`]:
///
/// ```text
///        0   4896   private key (ML-DSA-87 worst case)
///     5472   2592   public key
/// ```
pub const SLOT_KEY_OUT_OFFSET: usize = SLOT_MSG_OFFSET;

/// Offset of the private key **supplied to signing and decapsulation**.
///
/// Shares the signature region, which is safe because the key is copied
/// into dTCM before the signature is written back over it — the same
/// staging the message and context already rely on:
///
/// ```text
///        0    586   message        (sign only)
///      588    255   context        (sign only)
///      844   4896   private key    -> overwritten by the 4627-byte
///                                     signature once consumed
/// ```
pub const SLOT_KEY_IN_OFFSET: usize = SLOT_SIG_OFFSET;

/// Offset of the ML-KEM ciphertext **consumed by decapsulation**.
///
/// Decapsulation cannot use [`SLOT_CT_OFFSET`] because the private key
/// occupies it, so the ciphertext borrows the public-key region instead —
/// 1568 B inside the 2592 reserved there, and decapsulation takes no
/// public key.
pub const SLOT_CT_IN_OFFSET: usize = SLOT_PK_OFFSET;

/// Offset of the ML-KEM shared secret within the operand slot.
///
/// Shares the message region, which ML-KEM does not use.  Only 32 bytes,
/// but it is an output, so it does not belong in the mailbox alongside the
/// request fields the HSM wrote.
pub const SLOT_SS_OFFSET: usize = SLOT_MSG_OFFSET;

/// Length of the ML-KEM shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// Operation selector, mirroring `PqcOp` on the HSM side.
pub const OP_MLDSA_GENERATE_KEY: u32 = 1;

/// Operation selector: sign a message with a caller-supplied seed.
pub const OP_MLDSA_SIGN: u32 = 2;

/// Operation selector: verify a signature under a supplied public key.
pub const OP_MLDSA_VERIFY: u32 = 3;

/// Operation selector: generate an ML-KEM key pair.
pub const OP_MLKEM_GENERATE_KEY: u32 = 4;

/// Operation selector: encapsulate to an ML-KEM public key.
pub const OP_MLKEM_ENCAPSULATE: u32 = 5;

/// Operation selector: decapsulate an ML-KEM ciphertext.
pub const OP_MLKEM_DECAPSULATE: u32 = 6;

/// Status: request serviced.
pub const STATUS_OK: u32 = 0;

/// Status: the operation is not one this core implements.
pub const STATUS_UNSUPPORTED_OP: u32 = 1;

/// Status: the key kind is not one this core implements.
pub const STATUS_UNSUPPORTED_KIND: u32 = 2;

/// Status: the operand would not fit this core's slot.
pub const STATUS_SLOT_TOO_SMALL: u32 = 3;

/// Status: the crypto itself rejected the request.
///
/// For verify this is the ordinary "bad signature" outcome, not a fault.
pub const STATUS_CRYPTO_FAILED: u32 = 4;

/// A decoded request.
pub struct Request {
    /// Sequence number to echo back.
    pub seq: u32,
    /// Operation selector.
    pub op: u32,
    /// Key kind discriminant.
    pub key_kind: u32,
    /// Caller-supplied ML-DSA seed (`xi`).
    ///
    /// Generated by the HSM, not here: an FP core has no entropy source,
    /// and the HSM owns the device's certified TRNG. The seed *is* the
    /// private key, so the HSM already holds it and the response does not
    /// need to return it.
    pub xi: [u8; SEED_LEN],

    /// Second 32-byte seed field.
    ///
    /// Per-signature randomness for ML-DSA sign, and the `z` half of the
    /// `(d ‖ z)` seed pair for ML-KEM key generation -- the two never
    /// coincide, so one field serves both rather than widening the mailbox.
    /// Drawn from the same TRNG as `xi`, for the same reason.
    pub rnd: [u8; SEED_LEN],

    /// Length of the message staged in the operand slot.
    pub msg_len: usize,

    /// Length of the context string staged in the operand slot.
    pub ctx_len: usize,

    /// Length of the signature staged in the operand slot (verify only).
    pub sig_len: usize,

    /// Length of the public key staged in the operand slot (verify only).
    pub pub_key_len: usize,
}

/// Base of this core's operand slot.
fn slot(core_id: u8) -> *mut u8 {
    (PSRAM_LOCAL_BASE + SLOT_OFFSETS[core_id as usize]) as *mut u8
}

/// A sub-range of this core's operand slot as a mutable byte slice.
///
/// Used to hand the crypto its input and output regions in place; see the
/// `SLOT_*_OFFSET` constants for the sign layout.
pub fn slot_range_mut(core_id: u8, offset: usize, len: usize) -> Option<&'static mut [u8]> {
    if offset.checked_add(len)? > SLOT_SIZE {
        return None;
    }
    // SAFETY: as `slot_mut`, with the range checked against SLOT_SIZE.
    Some(unsafe { core::slice::from_raw_parts_mut(slot(core_id).add(offset), len) })
}

/// Two **disjoint** sub-ranges of this core's operand slot, both mutable.
///
/// Key generation produces a public and a private key at once, into two
/// regions of the same slot. Calling [`slot_range_mut`] twice would hand
/// out two `&'static mut` borrows the compiler cannot prove disjoint;
/// checking the overlap here once makes them sound, and lets the crypto
/// write the private key straight into PSRAM rather than staging it
/// through dTCM and copying it back.
///
/// Returns `None` if either range leaves the slot, or if the two overlap.
pub fn slot_pair_mut(
    core_id: u8,
    a_offset: usize,
    a_len: usize,
    b_offset: usize,
    b_len: usize,
) -> Option<(&'static mut [u8], &'static mut [u8])> {
    let a_end = a_offset.checked_add(a_len)?;
    let b_end = b_offset.checked_add(b_len)?;

    if a_end > SLOT_SIZE || b_end > SLOT_SIZE {
        return None;
    }

    // Disjointness is the whole basis for handing out two mutable borrows.
    if a_offset < b_end && b_offset < a_end {
        return None;
    }

    let base = slot(core_id);

    // SAFETY: as `slot_range_mut`, and both ranges have just been checked
    // to lie inside the slot and not to overlap, so the slices cannot
    // alias each other.
    Some(unsafe {
        (
            core::slice::from_raw_parts_mut(base.add(a_offset), a_len),
            core::slice::from_raw_parts_mut(base.add(b_offset), b_len),
        )
    })
}

/// A sub-range of this core's operand slot as a shared byte slice.///
/// Verify takes four inputs and produces no output, so it can borrow every
/// operand at once without any of them aliasing.
pub fn slot_range(core_id: u8, offset: usize, len: usize) -> Option<&'static [u8]> {
    if offset.checked_add(len)? > SLOT_SIZE {
        return None;
    }
    // SAFETY: as `slot_range_mut`, but shared -- several disjoint shared
    // borrows of the slot are fine, and nothing writes it during a verify.
    unsafe { core::slice::from_raw_parts(slot(core_id), SLOT_SIZE) }.get(offset..offset + len)
}

/// Copy `src` into `dst` eight words per transaction.
///
/// Operand staging reads PSRAM, which is off-core: a word-at-a-time
/// `memcpy` measures 34.6 cycles per word from a fastpath core and nearly
/// all of that is per-transaction overhead, so a burst amortises it the
/// same way the GSRAM spill's does (121.6 down to 24.5 there). Verify
/// stages a signature and a public key on every request, which is enough
/// for this to be worth several percent.
///
/// `r6`/`r7` are left out of the register list because the compiler
/// reserves them. Falls back to `copy_from_slice` when either side is
/// unaligned or there is less than one full burst.
///
/// # Panics
/// Debug-asserts that the two slices are the same length.
pub fn stage(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());

    let bursts = dst.len() / 32;
    let dp = dst.as_mut_ptr();
    let sp = src.as_ptr();
    if bursts == 0 || dp.align_offset(4) != 0 || sp.align_offset(4) != 0 {
        dst.copy_from_slice(src);
        return;
    }

    // SAFETY: both sides are word aligned and valid for `bursts * 8` words,
    // and the slot never overlaps a dTCM staging buffer.
    unsafe {
        core::arch::asm!(
            "2:",
            "ldmia {s}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}",
            "stmia {d}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}",
            "subs  {n}, {n}, #1",
            "bne   2b",
            s = inout(reg) sp => _,
            d = inout(reg) dp => _,
            n = inout(reg) bursts => _,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _,
            out("r4") _, out("r5") _, out("r8") _, out("r9") _,
            options(nostack),
        );
    }

    let done = bursts * 32;
    dst[done..].copy_from_slice(&src[done..]);
}

/// Base of this core's mailbox.
fn mailbox(core_id: u8) -> *mut u32 {
    (PSRAM_LOCAL_BASE + MAILBOX_OFFSET + core_id as usize * MAILBOX_STRIDE) as *mut u32
}

/// Read the pending request, if the HSM has posted a new one.
///
/// Returns `None` when the mailbox has already been answered, so a
/// duplicate or spurious doorbell cannot cause the same request to run
/// twice.
pub fn take_request(core_id: u8) -> Option<Request> {
    let mb = mailbox(core_id);

    // SAFETY: this core's own mailbox, a fixed 256-byte slot in PSRAM that
    // lies outside every region described to the linker. Volatile because
    // the HSM core writes it.
    unsafe {
        let seq = read_volatile(mb.add(word::REQUEST_SEQ));
        if seq == read_volatile(mb.add(word::RESPONSE_SEQ)) {
            return None;
        }
        let mut xi = [0u8; SEED_LEN];
        let mut rnd = [0u8; SEED_LEN];
        for i in 0..SEED_LEN / 4 {
            xi[i * 4..i * 4 + 4]
                .copy_from_slice(&read_volatile(mb.add(word::XI + i)).to_le_bytes());
            rnd[i * 4..i * 4 + 4]
                .copy_from_slice(&read_volatile(mb.add(word::RND + i)).to_le_bytes());
        }

        Some(Request {
            seq,
            op: read_volatile(mb.add(word::OP)),
            key_kind: read_volatile(mb.add(word::KEY_KIND)),
            xi,
            rnd,
            msg_len: read_volatile(mb.add(word::MSG_LEN)) as usize,
            ctx_len: read_volatile(mb.add(word::CTX_LEN)) as usize,
            sig_len: read_volatile(mb.add(word::SIG_LEN)) as usize,
            pub_key_len: read_volatile(mb.add(word::PUB_KEY_LEN)) as usize,
        })
    }
}

/// Publish a response.
///
/// `response_seq` is written last, so the HSM cannot observe a matching
/// sequence number alongside a half-written payload.
///
pub fn respond(core_id: u8, req: &Request, status: u32, out_len: u32) {
    let mb = mailbox(core_id);

    // SAFETY: as above.
    unsafe {
        write_volatile(mb.add(word::STATUS), status);
        write_volatile(mb.add(word::OUT_LEN), out_len);
        // Commit: everything above, and the operand slot, must be visible
        // before the HSM is told the response is ready.
        write_volatile(mb.add(word::RESPONSE_SEQ), req.seq);
    }
}

// ===========================================================================

/// Enable the DWT cycle counter (off out of reset).
pub fn cyc_init() {
    // SAFETY: DEMCR and DWT_CTRL are core peripheral registers.
    unsafe {
        let demcr = 0xE000_EDFC as *mut u32;
        core::ptr::write_volatile(demcr, core::ptr::read_volatile(demcr) | 1 << 24);
        let dwt_ctrl = 0xE000_1000 as *mut u32;
        core::ptr::write_volatile(dwt_ctrl, core::ptr::read_volatile(dwt_ctrl) | 1);
    }
}
