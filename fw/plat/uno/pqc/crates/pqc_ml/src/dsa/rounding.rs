// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// Rounding operations for ML-DSA (FIPS 204).
use super::params::D;
/// Rounding operations for ML-DSA (FIPS 204).
use super::params::N;
/// Rounding operations for ML-DSA (FIPS 204).
use super::params::Q;
use super::poly::Poly;

/// Power2Round: decompose a into (a1, a0) where a = a1*2^d + a0,
/// with a0 in range [-(2^(d-1)-1), 2^(d-1)].
/// Uses the reference implementation formula.
#[inline]
pub fn power2round(a: i32) -> (i32, i32) {
    // a1 = (a + 2^(d-1) - 1) >> d
    let a1 = (a + (1 << (D - 1)) - 1) >> D;
    // a0 = a - a1 * 2^d
    let a0 = a - (a1 << D);
    (a1, a0)
}

/// Power2Round for a full polynomial.
pub fn poly_power2round(a1: &mut Poly, a0: &mut Poly, a: &Poly) {
    for i in 0..N {
        let (hi, lo) = power2round(a[i]);
        a1[i] = hi;
        a0[i] = lo;
    }
}

/// Decompose: for coefficient a (must be in [0, q)), compute high and low parts
/// w.r.t. gamma2. Returns (a1, a0) such that a = a1*2*gamma2 + a0.
/// Uses the reference implementation's fixed-point arithmetic.
///
/// Forced inline: optimising for size, the compiler left this out of line
/// and every coefficient of every decomposition paid a call, which is more
/// than the arithmetic inside costs.
#[inline(always)]
pub fn decompose(a: i32, gamma2: u32) -> (i32, i32) {
    let mut a1 = (a + 127) >> 7;

    match gamma2 {
        261888 => {
            // (q-1)/32
            a1 = ((a1 * 1025 + (1 << 21)) >> 22) & 15;
        }
        95232 => {
            // (q-1)/88
            a1 = (a1 * 11275 + (1 << 23)) >> 24;
            a1 ^= ((43 - a1) >> 31) & a1;
        }
        _ => {}
    }

    let mut a0 = a - a1 * 2 * gamma2 as i32;
    // If a0 > (q-1)/2, subtract q (handles the wrap-around case)
    a0 -= (((Q as i32 - 1) / 2 - a0) >> 31) & Q as i32;

    (a1, a0)
}

/// HighBits: return high bits of a w.r.t. gamma2.
#[inline]
pub fn highbits(a: i32, gamma2: u32) -> i32 {
    decompose(a, gamma2).0
}

/// LowBits: return low bits of a w.r.t. gamma2.
#[inline]
pub fn lowbits(a: i32, gamma2: u32) -> i32 {
    decompose(a, gamma2).1
}

/// MakeHint: returns 1 if the hint bit should be set.
/// In the reference: make_hint(a0, a1) where a0 and a1 are low/high parts.
/// Returns 1 if |a0| > gamma2 or (a0 == -gamma2 and a1 != 0).
#[inline]
pub fn make_hint(a0: i32, a1: i32, gamma2: u32) -> u8 {
    let g2 = gamma2 as i32;
    if a0 > g2 || a0 < -g2 || (a0 == -g2 && a1 != 0) {
        1
    } else {
        0
    }
}

/// UseHint: adjust the high bits of r according to hint h.
/// Reference implementation.
#[inline]
pub fn use_hint(h: u8, r: i32, gamma2: u32) -> i32 {
    let (r1, r0) = decompose(r, gamma2);
    if h == 0 {
        return r1;
    }
    use_hint_parts(r1, r0, gamma2)
}

/// UseHint for a set hint bit, given r already decomposed into (r1, r0):
/// r1 moved one step towards r0's sign, wrapping.
#[inline]
pub fn use_hint_parts(r1: i32, r0: i32, gamma2: u32) -> i32 {
    match gamma2 {
        261888 => {
            // (q-1)/32, m = 16
            if r0 > 0 {
                (r1 + 1) & 15
            } else {
                (r1 - 1) & 15
            }
        }
        95232 => {
            // (q-1)/88, m = 44
            if r0 > 0 {
                if r1 == 43 {
                    0
                } else {
                    r1 + 1
                }
            } else if r1 == 0 {
                43
            } else {
                r1 - 1
            }
        }
        _ => r1,
    }
}

/// Decompose polynomial: compute w1 (high bits) and w0 (low bits).
pub fn poly_decompose(w1: &mut Poly, w0: &mut Poly, w: &Poly, gamma2: u32) {
    for i in 0..N {
        let (a1, a0) = decompose(w[i], gamma2);
        w1[i] = a1;
        w0[i] = a0;
    }
}

/// Decompose straight off the inverse transform, reducing as it reads, in
/// place -- `w` becomes `(w0 << 6) | w1` -- and pack w1 into `packed` as the
/// commitment hash takes it: 4 bits a coefficient for gamma2 = (q-1)/32,
/// 6 for (q-1)/88, so `packed` is 128 or 192 bytes.
///
/// Folding the reduction into the split costs nothing -- the coefficient
/// is already in a register -- and leaving both parts behind in `w` is
/// what spares signing's r0 check and verification's UseHint a second
/// decomposition: each wants w0 (its sign, for UseHint) and w1 together,
/// and w1 is below 64 for both values of gamma2. Packing w1 as it is made
/// spares writing it out a word a coefficient only to read it back.
///
/// `w` must be an inverse-NTT output (magnitude below q), as both callers'
/// are.
pub fn poly_decompose_pack(packed: &mut [u8], w: &mut Poly, gamma2: u32) {
    // Dispatch once, not once per coefficient: each gamma2 has its own
    // routine, its constants fixed.
    match gamma2 {
        261888 => decompose_pack::<261888>(&mut packed[..N / 2], w),
        95232 => decompose_pack::<95232>(&mut packed[..3 * N / 4], w),
        _ => {}
    }
}

fn decompose_pack<const G: u32>(packed: &mut [u8], w: &mut Poly) {
    // asm/dsa_decompose.S: r1 by a multiply by its divisor's reciprocal
    // rather than the reference's shifts, and the wrap at the top of [0, q)
    // by the identity 16 * 2 * gamma2 = q - 1 (44 * 2 * gamma2 for the
    // other gamma2), the same results bit for bit.
    #[cfg(target_arch = "arm")]
    {
        extern "C" {
            fn pqc_ml_dsa_decompose_pack32(w: *mut i32, packed: *mut u8);
            fn pqc_ml_dsa_decompose_pack88(w: *mut i32, packed: *mut u8);
        }
        // SAFETY: `w` is one word-aligned `[i32; N]`, each pair read before
        // it is written back; `packed` is N / 2 or 3N / 4 bytes, exactly
        // what each routine stores.
        unsafe {
            if G == 261888 {
                pqc_ml_dsa_decompose_pack32(w.as_mut_ptr(), packed.as_mut_ptr());
            } else {
                pqc_ml_dsa_decompose_pack88(w.as_mut_ptr(), packed.as_mut_ptr());
            }
        }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        for (i, w) in w.iter_mut().enumerate() {
            // `w` is the inverse transform's output, which is below q in
            // magnitude, so `caddq` alone lifts it into [0, q) -- `reduce32`
            // first would only map it to the same value.
            let a = super::ntt::caddq(*w);

            let mut a1 = (a + 127) >> 7;
            if G == 261888 {
                a1 = ((a1 * 1025 + (1 << 21)) >> 22) & 15;
            } else {
                a1 = (a1 * 11275 + (1 << 23)) >> 24;
                a1 ^= ((43 - a1) >> 31) & a1;
            }

            let mut a0 = a - a1 * 2 * G as i32;
            a0 -= (((Q as i32 - 1) / 2 - a0) >> 31) & Q as i32;

            *w = (a0 << 6) | a1;
            super::packing::repack_w1(packed, i, a1, G);
        }
    }
}

/// UseHint for polynomial.
pub fn poly_use_hint(wout: &mut Poly, h: &Poly, w: &Poly, gamma2: u32) {
    for i in 0..N {
        wout[i] = use_hint(h[i] as u8, w[i], gamma2);
    }
}
