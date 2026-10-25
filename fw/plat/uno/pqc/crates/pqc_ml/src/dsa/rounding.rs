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

/// Decompose straight off the inverse transform, reducing as it reads.
///
/// Signing used to bring `w` into range with a separate pass and then walk
/// it again to split it. Folding the reduction into the split costs
/// nothing -- the coefficient is already in a register -- and saves reading
/// and writing a whole polynomial per row per attempt. `w` is left as the
/// transform produced it, so the hint pass reduces again on its own way
/// through, which is the same work it was doing before.
///
/// `w` must be an inverse-NTT output (magnitude below q), as both callers'
/// are.
pub fn poly_decompose_reduced(w1: &mut Poly, w0: &mut Poly, w: &Poly, gamma2: u32) {
    // Dispatch once, not once per coefficient. `decompose` selects on
    // gamma2 internally, and inlined into a 256-iteration loop that put the
    // test and a pair of magic constants inside the loop body. Choosing the
    // variant here makes gamma2 a compile-time constant, so the test
    // disappears and the multipliers fold into immediates.
    match gamma2 {
        261888 => decompose_pass::<261888>(w1, w0, w),
        95232 => decompose_pass::<95232>(w1, w0, w),
        _ => {}
    }
}

fn decompose_pass<const G: u32>(w1: &mut Poly, w0: &mut Poly, w: &Poly) {
    // Two coefficients a pass; the per-coefficient arithmetic is the same
    // as the scalar loop below, `a1 * 2 * G` folded into an `mls`.
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: three distinct `[i32; N]`, word aligned, N even; `w1` and
        // `w0` are written, `w` only read.
        unsafe {
            if G == 261888 {
                core::arch::asm!(
                    "2:",
                    "ldrd   {w0}, {w1}, [{wp}], #8",
                    "and    {t}, {q}, {w0}, asr #31",
                    "add    {w0}, {w0}, {t}",
                    "and    {t}, {q}, {w1}, asr #31",
                    "add    {w1}, {w1}, {t}",
                    "add    {h0}, {w0}, #127",
                    "add    {h1}, {w1}, #127",
                    "lsr    {h0}, {h0}, #7",
                    "lsr    {h1}, {h1}, #7",
                    "add    {h0}, {h0}, {h0}, lsl #10",
                    "add    {h1}, {h1}, {h1}, lsl #10",
                    "add    {h0}, {h0}, #0x200000",
                    "add    {h1}, {h1}, #0x200000",
                    "ubfx   {h0}, {h0}, #22, #4",
                    "ubfx   {h1}, {h1}, #22, #4",
                    "mls    {w0}, {h0}, {g2x2}, {w0}",
                    "mls    {w1}, {h1}, {g2x2}, {w1}",
                    "strd   {h0}, {h1}, [{w1p}], #8",
                    "sub    {t}, {half}, {w0}",
                    "and    {t}, {q}, {t}, asr #31",
                    "sub    {w0}, {w0}, {t}",
                    "sub    {t}, {half}, {w1}",
                    "and    {t}, {q}, {t}, asr #31",
                    "sub    {w1}, {w1}, {t}",
                    "strd   {w0}, {w1}, [{w0p}], #8",
                    "subs   {n}, {n}, #1",
                    "bne    2b",
                    wp = inout(reg) w.as_ptr() => _,
                    w1p = inout(reg) w1.as_mut_ptr() => _,
                    w0p = inout(reg) w0.as_mut_ptr() => _,
                    n = inout(reg) N / 2 => _,
                    q = in(reg) Q as i32,
                    half = in(reg) (Q as i32 - 1) / 2,
                    g2x2 = in(reg) 2 * G as i32,
                    w0 = out(reg) _,
                    w1 = out(reg) _,
                    h0 = out(reg) _,
                    h1 = out(reg) _,
                    t = out(reg) _,
                    options(nostack),
                );
            } else {
                core::arch::asm!(
                    "2:",
                    "ldrd   {w0}, {w1}, [{wp}], #8",
                    "and    {t}, {q}, {w0}, asr #31",
                    "add    {w0}, {w0}, {t}",
                    "and    {t}, {q}, {w1}, asr #31",
                    "add    {w1}, {w1}, {t}",
                    "add    {h0}, {w0}, #127",
                    "add    {h1}, {w1}, #127",
                    "lsr    {h0}, {h0}, #7",
                    "lsr    {h1}, {h1}, #7",
                    "mul    {h0}, {h0}, {k}",
                    "mul    {h1}, {h1}, {k}",
                    "add    {h0}, {h0}, #0x800000",
                    "add    {h1}, {h1}, #0x800000",
                    "asr    {h0}, {h0}, #24",
                    "asr    {h1}, {h1}, #24",
                    "rsb    {t}, {h0}, #43",
                    "and    {t}, {h0}, {t}, asr #31",
                    "eor    {h0}, {h0}, {t}",
                    "rsb    {t}, {h1}, #43",
                    "and    {t}, {h1}, {t}, asr #31",
                    "eor    {h1}, {h1}, {t}",
                    "mls    {w0}, {h0}, {g2x2}, {w0}",
                    "mls    {w1}, {h1}, {g2x2}, {w1}",
                    "strd   {h0}, {h1}, [{w1p}], #8",
                    "sub    {t}, {half}, {w0}",
                    "and    {t}, {q}, {t}, asr #31",
                    "sub    {w0}, {w0}, {t}",
                    "sub    {t}, {half}, {w1}",
                    "and    {t}, {q}, {t}, asr #31",
                    "sub    {w1}, {w1}, {t}",
                    "strd   {w0}, {w1}, [{w0p}], #8",
                    "subs   {n}, {n}, #1",
                    "bne    2b",
                    wp = inout(reg) w.as_ptr() => _,
                    w1p = inout(reg) w1.as_mut_ptr() => _,
                    w0p = inout(reg) w0.as_mut_ptr() => _,
                    n = inout(reg) N / 2 => _,
                    q = in(reg) Q as i32,
                    half = in(reg) (Q as i32 - 1) / 2,
                    g2x2 = in(reg) 2 * G as i32,
                    k = in(reg) 11275,
                    w0 = out(reg) _,
                    w1 = out(reg) _,
                    h0 = out(reg) _,
                    h1 = out(reg) _,
                    t = out(reg) _,
                    options(nostack),
                );
            }
        }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        for ((w1, w0), &w) in w1.iter_mut().zip(w0.iter_mut()).zip(w.iter()) {
            // `w` is the inverse transform's output, which is below q in
            // magnitude, so `caddq` alone lifts it into [0, q) -- `reduce32`
            // first would only map it to the same value.
            let a = super::ntt::caddq(w);

            let mut a1 = (a + 127) >> 7;
            if G == 261888 {
                a1 = ((a1 * 1025 + (1 << 21)) >> 22) & 15;
            } else {
                a1 = (a1 * 11275 + (1 << 23)) >> 24;
                a1 ^= ((43 - a1) >> 31) & a1;
            }

            let mut a0 = a - a1 * 2 * G as i32;
            a0 -= (((Q as i32 - 1) / 2 - a0) >> 31) & Q as i32;

            *w1 = a1;
            *w0 = a0;
        }
    }
}

/// UseHint for polynomial.
pub fn poly_use_hint(wout: &mut Poly, h: &Poly, w: &Poly, gamma2: u32) {
    for i in 0..N {
        wout[i] = use_hint(h[i] as u8, w[i], gamma2);
    }
}
