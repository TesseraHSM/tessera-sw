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

fn fused_reduce_chknorm(a: &mut Poly, b: Option<(&Poly, bool)>, bound: u32) -> bool {
    // Two coefficients a pass, `reduce32` as one `mls`, and the bound as a
    // single unsigned compare: |v| < bound exactly when v + bound - 1, taken
    // unsigned, is at most 2 * bound - 2. The add/sub choice is made once
    // rather than per coefficient.
    #[cfg(target_arch = "arm")]
    {
        let bound = bound as i32;
        let mut bad: u32 = 0;
        // SAFETY: `a` and `b` are `[i32; N]`, word aligned, N even; `a` is
        // the only one written and is a distinct borrow.
        unsafe {
            match b {
                Some((b, false)) => core::arch::asm!(
                    "2:",
                    "ldrd   {a0}, {a1}, [{ap}]",
                    "ldrd   {b0}, {b1}, [{bp}], #8",
                    "add    {a0}, {a0}, {b0}",
                    "add    {a1}, {a1}, {b1}",
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
                    ap = inout(reg) a.as_mut_ptr() => _,
                    bp = inout(reg) b.as_ptr() => _,
                    n = inout(reg) N / 2 => _,
                    q = in(reg) super::params::Q as i32,
                    bm1 = in(reg) bound - 1,
                    lim = in(reg) 2 * bound - 2,
                    bad = inout(reg) bad,
                    a0 = out(reg) _,
                    a1 = out(reg) _,
                    b0 = out(reg) _,
                    b1 = out(reg) _,
                    options(nostack),
                ),
                Some((b, true)) => core::arch::asm!(
                    "2:",
                    "ldrd   {a0}, {a1}, [{ap}]",
                    "ldrd   {b0}, {b1}, [{bp}], #8",
                    "sub    {a0}, {a0}, {b0}",
                    "sub    {a1}, {a1}, {b1}",
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
                    ap = inout(reg) a.as_mut_ptr() => _,
                    bp = inout(reg) b.as_ptr() => _,
                    n = inout(reg) N / 2 => _,
                    q = in(reg) super::params::Q as i32,
                    bm1 = in(reg) bound - 1,
                    lim = in(reg) 2 * bound - 2,
                    bad = inout(reg) bad,
                    a0 = out(reg) _,
                    a1 = out(reg) _,
                    b0 = out(reg) _,
                    b1 = out(reg) _,
                    options(nostack),
                ),
                None => core::arch::asm!(
                    "2:",
                    "ldrd   {a0}, {a1}, [{ap}]",
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
                    ap = inout(reg) a.as_mut_ptr() => _,
                    n = inout(reg) N / 2 => _,
                    q = in(reg) super::params::Q as i32,
                    bm1 = in(reg) bound - 1,
                    lim = in(reg) 2 * bound - 2,
                    bad = inout(reg) bad,
                    a0 = out(reg) _,
                    a1 = out(reg) _,
                    b0 = out(reg) _,
                    b1 = out(reg) _,
                    options(nostack),
                ),
            }
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
