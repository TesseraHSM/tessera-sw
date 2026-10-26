// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! Off-core storage for the part of the ML-DSA matrix that does not fit in
//! dTCM.
//!
//! Signing expands `A` once per attempt. A core's 32 KB dTCM holds the
//! accumulators plus whatever is left over, packed three bytes to a
//! coefficient: for ML-DSA-44 that is the whole 16-element matrix, but for
//! ML-DSA-87 it is 16 of 56 -- so the other 40 would be derived again on
//! every retry, at about 43 K cycles each.
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
/// ML-DSA-87 is the worst case: a 56-element matrix with 16 of them held in
/// dTCM. No parameter set spills more.
pub const MATRIX_SLOTS: usize = 40;

/// Words in a matrix slot. Matrix elements are stored three bytes to a
/// coefficient, so they need a quarter less room than a raw polynomial.
const MATRIX_WORDS: usize = PACKED_WORDS;

/// Words one core needs.
const NEEDED_WORDS: usize = MATRIX_SLOTS * MATRIX_WORDS;

static mut BASE: *mut i32 = core::ptr::null_mut();

/// Near regions given so far, in order; unused entries are empty.
static mut NEAR: [(*mut i32, usize); NEAR_REGIONS] = [(core::ptr::null_mut(), 0); NEAR_REGIONS];

/// How many separate pieces of near memory a platform can give.
pub const NEAR_REGIONS: usize = 3;

/// Hand the signer memory to keep matrix elements in ahead of the spill:
/// memory the core reads at dTCM speed but that its stack does not cover.
/// Elements there are read in place, like the ones the work buffer holds.
///
/// A platform whose fast memory is in pieces calls this once for each, up
/// to [`NEAR_REGIONS`], the first filled first; any call past those is
/// ignored.
///
/// # Safety
/// `base` must be valid for `words` `i32` reads and writes, word aligned,
/// and reserved for this core alone for the lifetime of the program.
pub unsafe fn init_near(base: *mut i32, words: usize) {
    if let Some(slot) = (*core::ptr::addr_of_mut!(NEAR)).iter_mut().find(|r| r.0.is_null()) {
        *slot = (base, words);
    }
}

/// The regions [`init_near`] gave, in order, empty where none.
///
/// # Safety
/// The caller must be their only user for as long as the slices live.
pub(crate) unsafe fn near() -> [&'static mut [i32]; NEAR_REGIONS] {
    (*core::ptr::addr_of!(NEAR)).map(|(base, words)| {
        if base.is_null() {
            &mut []
        } else {
            core::slice::from_raw_parts_mut(base, words)
        }
    })
}

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

/// Words a matrix element occupies when packed three bytes to a
/// coefficient.
pub(crate) const PACKED_WORDS: usize = DSA_N * 3 / 4;

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
            chunk[3 * g..3 * g + 3].copy_from_slice(&pack4(&src[i..i + 4]));
        }
        burst(dst.add(c * WORDS), chunk.as_ptr(), WORDS);
    }
}

/// Four 24-bit coefficients as three little-endian words: the layout of
/// a spilled matrix element, and of one kept in dTCM.
#[inline(always)]
fn pack4(v: &[i32]) -> [i32; 3] {
    let (a, b, e, d) = (v[0] as u32, v[1] as u32, v[2] as u32, v[3] as u32);
    [
        (a | (b << 24)) as i32,
        ((b >> 8) | (e << 16)) as i32,
        ((e >> 16) | (d << 8)) as i32,
    ]
}

/// Pack a matrix element into dTCM, in the spill's three-bytes-a-
/// coefficient layout, for [`crate::dsa::ntt::poly_pointwise_acc_montgomery_packed`].
///
/// Every element of `src` must be in `[0, 2^24)`.
///
/// # Panics
/// If `dst` holds fewer than [`PACKED_WORDS`] words.
pub(crate) fn pack(dst: &mut [i32], src: &[i32; DSA_N]) {
    for (w, v) in dst[..PACKED_WORDS]
        .as_chunks_mut::<3>()
        .0
        .iter_mut()
        .zip(src.as_chunks::<4>().0)
    {
        *w = pack4(v);
    }
}

/// Read a packed matrix element back without expanding it, for
/// [`crate::dsa::ntt::poly_pointwise_acc_montgomery_packed`].
///
/// # Safety
/// `src` must come from [`slot`] and must have been written by
/// [`store_packed`]; `dst` must hold at least [`PACKED_WORDS`] words.
pub(crate) unsafe fn load_packed_words(dst: &mut [i32], src: *const i32) {
    burst(dst[..PACKED_WORDS].as_mut_ptr(), src, PACKED_WORDS);
}

/// Move `words` words, eight at a time.
///
/// # Safety
/// Both pointers must be valid for `words` words and word aligned, and
/// `words` must be a multiple of eight.
#[inline(always)]
pub unsafe fn burst(dst: *mut i32, src: *const i32, words: usize) {
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
