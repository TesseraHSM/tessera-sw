// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::ntt;
/// Polynomial operations for ML-DSA.
use super::params::N;

pub type Poly = [i32; N];

/// Zero-initialize a polynomial.
#[inline]
pub fn poly_zero(p: &mut Poly) {
    for c in p.iter_mut() {
        *c = 0;
    }
}

/// c = a + b
pub fn poly_add(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c[i] = a[i] + b[i];
    }
}

/// c = a - b
pub fn poly_sub(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c[i] = a[i] - b[i];
    }
}

/// In-place a = a + b
pub fn poly_add_inplace(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a[i] += b[i];
    }
}

/// In-place a = a - b
pub fn poly_sub_inplace(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a[i] -= b[i];
    }
}

/// Reduce all coefficients mod q using Barrett reduction.
pub fn poly_reduce(a: &mut Poly) {
    for c in a.iter_mut() {
        *c = ntt::reduce32(*c);
    }
}

/// Reduce every coefficient mod q and lift it into [0, q).
///
/// The two steps are only ever wanted together -- decomposition needs a
/// representative in [0, q) -- so they share one pass over the polynomial
/// rather than two.
pub fn poly_reduce_caddq(a: &mut Poly) {
    for c in a.iter_mut() {
        *c = ntt::caddq(ntt::reduce32(*c));
    }
}

/// Left shift all coefficients by d bits.
pub fn poly_shiftl(a: &mut Poly, d: u32) {
    for i in 0..N {
        a[i] <<= d;
    }
}

/// Check infinity norm: returns true if all |coeffs| < bound.
pub fn poly_chknorm(a: &Poly, bound: u32) -> bool {
    let bound = bound as i32;
    for i in 0..N {
        // Reduce to centered representation
        let mut t = a[i] >> 31;
        t = a[i] - (t & (2 * a[i]));
        if t >= bound {
            return false;
        }
    }
    true
}

/// Convert polynomial to NTT domain (in-place).
pub fn poly_ntt(a: &mut Poly) {
    ntt::ntt(a);
}

/// Convert polynomial from NTT domain (in-place).
pub fn poly_invntt(a: &mut Poly) {
    ntt::invntt(a);
}

/// `a = reduce(a + b)`, reporting whether every coefficient stayed inside
/// `bound`.
///
/// Signing walked the polynomial three times to do this -- add, reduce,
/// then check -- and the last two of those exist only to look at a value
/// the first one already had in a register. One pass does all three.
///
/// The norm check no longer stops at the first violation, since the sum
/// still has to be written out either way, but it saves two passes on
/// every polynomial whether the attempt is accepted or rejected.
pub fn poly_add_reduce_chknorm(a: &mut Poly, b: &Poly, bound: u32) -> bool {
    fused_reduce_chknorm(a, Some((b, false)), bound)
}

/// `a = reduce(a - b)`, reporting whether every coefficient stayed inside
/// `bound`. See [`poly_add_reduce_chknorm`].
pub fn poly_sub_reduce_chknorm(a: &mut Poly, b: &Poly, bound: u32) -> bool {
    fused_reduce_chknorm(a, Some((b, true)), bound)
}

/// `a = reduce(a)`, reporting whether every coefficient stayed inside
/// `bound`.
pub fn poly_reduce_chknorm(a: &mut Poly, bound: u32) -> bool {
    fused_reduce_chknorm(a, None, bound)
}

/// Signing's r0 check on a row [`super::rounding::poly_decompose_reduced`]
/// left as `(w0 << 6) | w1`: `r0 = reduce32(w0 - cs2)` replaces w0, and the
/// result says whether every `|r0|` stayed inside `bound`.
///
/// `cs2` must be below q in magnitude, as an inverse NTT leaves it.
pub fn poly_r0_check(w: &mut Poly, cs2: &Poly, bound: u32) -> bool {
    #[cfg(target_arch = "arm")]
    {
        extern "C" {
            fn pqc_ml_dsa_r0_check(w: *mut i32, cs2: *const i32, bound: i32) -> u32;
        }
        // SAFETY: two distinct `[i32; N]`, word aligned.
        unsafe { pqc_ml_dsa_r0_check(w.as_mut_ptr(), cs2.as_ptr(), bound as i32) == 0 }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let bound = bound as i32;
        let mut ok = true;
        for (v, &c) in w.iter_mut().zip(cs2.iter()) {
            let r0 = ntt::reduce32((*v >> 6) - c);
            ok &= r0.abs() < bound;
            *v = (r0 << 6) | (*v & 63);
        }
        ok
    }
}

fn fused_reduce_chknorm(a: &mut Poly, b: Option<(&Poly, bool)>, bound: u32) -> bool {
    // Two coefficients a pass, `reduce32` as one `mls`, and the bound as a
    // single unsigned compare: |v| < bound exactly when v + bound - 1, taken
    // unsigned, is at most 2 * bound - 2. One loop serves all three forms,
    // as a + s * b with s = 1, -1 or 0 -- the last reading `a` itself as
    // `b` -- for two more multiplies a pair than separate loops took, and
    // two fewer copies of the loop in iTCM.
    #[cfg(target_arch = "arm")]
    {
        let bound = bound as i32;
        let mut bad: u32 = 0;
        let ap = a.as_mut_ptr();
        let (bp, s) = match b {
            Some((b, sub)) => (b.as_ptr(), if sub { -1i32 } else { 1 }),
            None => (ap as *const i32, 0),
        };
        // SAFETY: `a` and `b` are `[i32; N]`, word aligned, N even; only `a`
        // is written, each pair after both are read, so `b` may be `a`.
        unsafe {
            core::arch::asm!(
                "2:",
                "ldrd   {a0}, {a1}, [{ap}]",
                "ldrd   {b0}, {b1}, [{bp}], #8",
                "mla    {a0}, {b0}, {s}, {a0}",
                "mla    {a1}, {b1}, {s}, {a1}",
                "add    {b0}, {a0}, #0x400000",
                "add    {b1}, {a1}, #0x400000",
                "asr    {b0}, {b0}, #23",
                "asr    {b1}, {b1}, #23",
                "mls    {a0}, {b0}, {q}, {a0}",
                "mls    {a1}, {b1}, {q}, {a1}",
                "add    {b0}, {a0}, {bm1}",
                "add    {b1}, {a1}, {bm1}",
                "strd   {a0}, {a1}, [{ap}], #8",
                "cmp    {b0}, {lim}",
                "it     hi",
                "movhi  {bad}, #1",
                "cmp    {b1}, {lim}",
                "it     hi",
                "movhi  {bad}, #1",
                "subs   {n}, {n}, #1",
                "bne    2b",
                ap = inout(reg) ap => _,
                bp = inout(reg) bp => _,
                n = inout(reg) N / 2 => _,
                s = in(reg) s,
                q = in(reg) super::params::Q as i32,
                bm1 = in(reg) bound - 1,
                lim = in(reg) 2 * bound - 2,
                bad = inout(reg) bad,
                a0 = out(reg) _,
                a1 = out(reg) _,
                b0 = out(reg) _,
                b1 = out(reg) _,
                options(nostack),
            );
        }
        bad == 0
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let bound = bound as i32;
        let mut ok = true;
        match b {
            Some((b, sub)) => {
                for (a, &b) in a.iter_mut().zip(b.iter()) {
                    let v = ntt::reduce32(if sub { *a - b } else { *a + b });
                    *a = v;
                    let t = v >> 31;
                    ok &= (v - (t & (2 * v))) < bound;
                }
            }
            None => {
                for a in a.iter_mut() {
                    let v = ntt::reduce32(*a);
                    *a = v;
                    let t = v >> 31;
                    ok &= (v - (t & (2 * v))) < bound;
                }
            }
        }
        ok
    }
}
