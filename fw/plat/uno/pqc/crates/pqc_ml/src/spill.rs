// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! Off-core storage for the part of the ML-DSA matrix that does not fit in
//! dTCM.
//!
//! Signing expands `A` once per attempt. A core's 32 KB dTCM holds the
//! accumulators plus whatever is left over, which for ML-DSA-44 is the
//! whole 16-element matrix but for ML-DSA-87 is 12 of 56 -- so the other 44
//! are derived again on every retry, at about 43 K cycles each.
//!
//! GSRAM is slower than dTCM but far cheaper than re-deriving: a burst read
//! of one polynomial costs about 9 K cycles against 43 K for the five
//! Keccak permutations `ExpandA` needs. Reads use a four-word `ldm` because
//! that is where the cost is; single-word loads measured 121.6 cycles per
//! word against 35.4 for the burst.
//!
//! Configured by the platform at boot rather than passed through the
//! signing API, so the host build -- and the bit-exactness harness that
//! runs on it -- is unaffected.

use crate::DSA_N;

/// Matrix elements one signature can spill.
///
/// ML-DSA-87 is the worst case: a 56-element matrix with 12 of them held in
/// dTCM. No parameter set spills more.
pub const MATRIX_SLOTS: usize = 44;

/// Key-derived transforms one signature can spill: `s1` (l of them) plus
/// `s2` and `t0` (k each). ML-DSA-87's 7 + 8 + 8 is the worst case.
pub const KEY_SLOTS: usize = 23;

/// Words in a matrix slot. Matrix elements are stored three bytes to a
/// coefficient, so they need a quarter less room than a raw polynomial.
const MATRIX_WORDS: usize = PACKED_WORDS;

/// Words in a key-transform slot. Those are NTT outputs, whose range is not
/// bounded by 2^24, so they are stored unpacked.
const KEY_WORDS: usize = DSA_N;

/// Words one core needs for both regions.
const NEEDED_WORDS: usize = MATRIX_SLOTS * MATRIX_WORDS + KEY_SLOTS * KEY_WORDS;

static mut BASE: *mut i32 = core::ptr::null_mut();

/// Hand the signer a region to spill into.
///
/// A region smaller than [`NEEDED_WORDS`] is refused outright rather than
/// half-used: the signer already falls back to re-deriving whatever it
/// cannot spill, so losing the region costs speed and nothing else.
///
/// # Safety
/// `base` must be valid for `words` `i32` writes, word aligned, and
/// reserved for this core alone for the lifetime of the program.
pub unsafe fn init(base: *mut i32, words: usize) {
    BASE = if words >= NEEDED_WORDS {
        base
    } else {
        core::ptr::null_mut()
    };
}

/// Address of matrix slot `i`, if it exists.
#[inline(always)]
pub(crate) fn matrix_slot(i: usize) -> Option<*mut i32> {
    // SAFETY: written once at boot before any signing request is serviced,
    // and read-only thereafter.
    unsafe {
        if BASE.is_null() || i >= MATRIX_SLOTS {
            None
        } else {
            Some(BASE.add(i * MATRIX_WORDS))
        }
    }
}

/// Address of key-transform slot `j`, if it exists.
///
/// The key region starts above the whole matrix region rather than after
/// however much this parameter set happened to spill, so its base is the
/// same for every variant and the caller does not have to track one.
#[inline(always)]
pub(crate) fn key_slot(j: usize) -> Option<*mut i32> {
    // SAFETY: as `matrix_slot`.
    unsafe {
        if BASE.is_null() || j >= KEY_SLOTS {
            None
        } else {
            Some(BASE.add(MATRIX_SLOTS * MATRIX_WORDS + j * KEY_WORDS))
        }
    }
}

/// Copy a polynomial out to a spill slot.
///
/// # Safety
/// `dst` must come from [`slot`].
pub(crate) unsafe fn store(dst: *mut i32, src: &[i32; DSA_N]) {
    burst(dst, src.as_ptr(), DSA_N);
}

/// Read a polynomial back from a spill slot.
///
/// # Safety
/// `src` must come from [`slot`].
pub(crate) unsafe fn load(dst: &mut [i32; DSA_N], src: *const i32) {
    burst(dst.as_mut_ptr(), src, DSA_N);
}

/// Words a matrix element occupies when packed three bytes to a
/// coefficient.
const PACKED_WORDS: usize = DSA_N * 3 / 4;

/// Where the packed words are staged inside the caller's polynomial while
/// they are expanded in place.
const PACKED_OFF: usize = DSA_N - PACKED_WORDS;

/// Copy a matrix element out to a spill slot, three bytes to a coefficient.
///
/// `ExpandA` samples uniformly from `[0, q)` and `q < 2^23`, so a matrix
/// coefficient always fits in 24 bits and the top byte of the `i32` it is
/// held in is dead weight. GSRAM costs about `87 + 13.6n` cycles for an
/// `n`-word transaction and transactions do not overlap -- two four-word
/// streams measured 1.33x the cost of one eight-word one -- so the only
/// way left to make a spilled element cheaper is to move fewer words.
/// Packing takes the 256 words to 192, which is 32 transactions down to 24.
///
/// Packed a chunk at a time: 32 coefficients make exactly 24 words, which
/// is three whole transactions, so this needs 96 bytes of scratch rather
/// than a second polynomial. These cores already run at 95% of their stack.
///
/// # Safety
/// `dst` must come from [`slot`], and every element of `src` must be in
/// `[0, 2^24)`.
pub(crate) unsafe fn store_packed(dst: *mut i32, src: &[i32; DSA_N]) {
    const COEFFS: usize = 32;
    const WORDS: usize = COEFFS * 3 / 4;
    let mut chunk = [0i32; WORDS];
    for c in 0..DSA_N / COEFFS {
        for g in 0..COEFFS / 4 {
            let i = c * COEFFS + 4 * g;
            let a = src[i] as u32;
            let b = src[i + 1] as u32;
            let e = src[i + 2] as u32;
            let d = src[i + 3] as u32;
            chunk[3 * g] = (a | (b << 24)) as i32;
            chunk[3 * g + 1] = ((b >> 8) | (e << 16)) as i32;
            chunk[3 * g + 2] = ((e >> 16) | (d << 8)) as i32;
        }
        burst(dst.add(c * WORDS), chunk.as_ptr(), WORDS);
    }
}

/// Read a packed matrix element back, expanding it in place.
///
/// The packed words are read into the tail of `dst` and expanded forwards,
/// which needs no second buffer: the write cursor is `4g` while the read
/// cursor is `PACKED_OFF + 3g`, so it only catches up at the last group,
/// where the three words are already in registers before the four are
/// written.
///
/// # Safety
/// `src` must come from [`slot`] and must have been written by
/// [`store_packed`].
pub(crate) unsafe fn load_packed(dst: &mut [i32; DSA_N], src: *const i32) {
    burst(dst.as_mut_ptr().add(PACKED_OFF), src, PACKED_WORDS);
    for g in 0..DSA_N / 4 {
        let w0 = dst[PACKED_OFF + 3 * g] as u32;
        let w1 = dst[PACKED_OFF + 3 * g + 1] as u32;
        let w2 = dst[PACKED_OFF + 3 * g + 2] as u32;
        dst[4 * g] = (w0 & 0x00FF_FFFF) as i32;
        dst[4 * g + 1] = (((w0 >> 24) | (w1 << 8)) & 0x00FF_FFFF) as i32;
        dst[4 * g + 2] = (((w1 >> 16) | (w2 << 16)) & 0x00FF_FFFF) as i32;
        dst[4 * g + 3] = (w2 >> 8) as i32;
    }
}

/// Move `words` words, eight at a time.
///
/// # Safety
/// Both pointers must be valid for `words` words and word aligned, and
/// `words` must be a multiple of eight.
#[inline(always)]
unsafe fn burst(dst: *mut i32, src: *const i32, words: usize) {
    // Eight words per transaction rather than four. GSRAM costs 121.6
    // cycles for a single-word load and 35.4 per word in a four-word
    // burst, so most of it is per-transaction overhead -- which a wider
    // burst amortises further.
    #[cfg(target_arch = "arm")]
    core::arch::asm!(
        "2:",
        "ldmia {s}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}",
        "stmia {d}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}",
        "subs  {n}, {n}, #1",
        "bne   2b",
        s = inout(reg) src => _,
        d = inout(reg) dst => _,
        n = inout(reg) words / 8 => _,
        out("r0") _, out("r1") _, out("r2") _, out("r3") _,
        out("r4") _, out("r5") _, out("r8") _, out("r9") _,
        options(nostack),
    );

    #[cfg(not(target_arch = "arm"))]
    core::ptr::copy_nonoverlapping(src, dst, words);
}
