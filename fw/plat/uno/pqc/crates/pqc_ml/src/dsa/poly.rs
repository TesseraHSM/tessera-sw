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
