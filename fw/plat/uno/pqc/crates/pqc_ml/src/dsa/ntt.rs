// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// Number Theoretic Transform for ML-DSA.
///
/// q = 8380417, n = 256, root of unity ζ = 1753
/// Montgomery domain: R = 2^32
///
/// On ARM targets, the NTT/INTT core loops use inline assembly.
/// On host targets, pure Rust is used.
use super::params::N;
/// Number Theoretic Transform for ML-DSA.
///
/// q = 8380417, n = 256, root of unity ζ = 1753
/// Montgomery domain: R = 2^32
///
/// On ARM targets, the NTT/INTT core loops use inline assembly.
/// On host targets, pure Rust is used.
use super::params::Q;
#[cfg(not(target_arch = "arm"))]
use super::zetas::ZETAS;

/// Montgomery reduction: given a 64-bit value a, compute a * R^{-1} mod q
/// where R = 2^32.
#[inline(always)]
pub fn montgomery_reduce(a: i64) -> i32 {
    // QINV = q^{-1} mod 2^32 = 58728449
    const QINV: i32 = 58728449;
    let t = (a as i32).wrapping_mul(QINV);
    let u = (t as i64).wrapping_mul(Q as i64);
    ((a - u) >> 32) as i32
}

/// reduce32: reduce a mod q to centered representation in roughly (-q/2, q/2).
/// Uses the reference implementation's approach: Q ≈ 2^23, so a/Q ≈ a >> 23.
#[inline(always)]
pub fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q as i32
}

/// Conditional add q: if a is negative, add q.
#[inline(always)]
pub fn caddq(a: i32) -> i32 {
    let mut r = a;
    r += (r >> 31) & (Q as i32);
    r
}

/// Montgomery constants, in the form the pointwise loops want them.
///
/// The reduction is `(a - t*q) >> 32` but `smlal` only accumulates, so one
/// of the two constants has to carry the sign. It must be `q`, not `qinv`.
///
/// Negating `qinv` looks equivalent -- it makes `t` come out negated, so
/// the accumulate subtracts -- but it relies on `-t == -t` in two's
/// complement, which fails for `i32::MIN`, the one value that is its own
/// negative. `t` takes that value for exactly one input in 2^32, and the
/// result is then wrong by exactly `q`. Random testing does not find it:
/// three million random reductions never hit it, and neither did 518
/// device checks. Negating `q` has no such boundary, and costs nothing.
#[cfg(target_arch = "arm")]
const QINV_I: i32 = 58728449;
#[cfg(target_arch = "arm")]
const Q_I: i32 = -(Q as i32);

#[cfg(target_arch = "arm")]
extern "C" {
    /// `asm/dsa_ntt.S`: the forward transform, with the reference's
    /// twiddles, which it carries itself, and an output congruent to the
    /// reference's.
    fn pqc_ml_dsa_ntt(p: *mut i32);
}

/// Forward NTT (in-place). Input coefficients in normal order,
/// output in bit-reversed order. Coefficients are in Montgomery domain.
pub fn ntt(a: &mut [i32; N]) {
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: `a` is 256 word-aligned coefficients.
        unsafe { pqc_ml_dsa_ntt(a.as_mut_ptr()) };
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let mut zetas = ZETAS[1..].iter();
        let mut len: usize = 128;
        while len >= 1 {
            let mut rest: &mut [i32] = a;
            while !rest.is_empty() {
                let (chunk, tail) = rest.split_at_mut(2 * len);
                rest = tail;
                let Some(&zeta) = zetas.next() else { return };
                let zeta = zeta as i64;
                let (lo, hi) = chunk.split_at_mut(len);
                for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
                    let t = montgomery_reduce(zeta * *y as i64);
                    *y = *x - t;
                    *x += t;
                }
            }
            len >>= 1;
        }
    }
}

/// Inverse NTT (in-place). Input in bit-reversed order,
/// output in normal order, multiplied by Montgomery factor.
pub fn invntt(a: &mut [i32; N]) {
    // pqm4's merged-layer inverse as scheduled for the M7 by SLOTHY, final
    // scaling included (asm/dilithium_intt.S).
    #[cfg(target_arch = "arm")]
    {
        extern "C" {
            fn pqc_ml_dsa_invntt(p: *mut i32);
        }
        // SAFETY: `a` is 256 word-aligned `i32`s, which the routine
        // transforms in place; it touches nothing else.
        unsafe { pqc_ml_dsa_invntt(a.as_mut_ptr()) };
    }

    #[cfg(not(target_arch = "arm"))]
    {
        // The inverse consumes the table backwards, one zeta per butterfly
        // window, so a reverse cursor replaces the running index and its
        // bounds check.
        let mut zetas = ZETAS[1..].iter().rev();
        let mut len: usize = 1;
        while len < N {
            let mut rest: &mut [i32] = a;
            while !rest.is_empty() {
                let (chunk, tail) = rest.split_at_mut(2 * len);
                rest = tail;
                let Some(&zeta) = zetas.next() else { break };
                let zeta = -(zeta as i64);
                let (lo, hi) = chunk.split_at_mut(len);
                for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
                    let t = *x;
                    *x = t + *y;
                    *y = montgomery_reduce(zeta * (t - *y) as i64);
                }
            }
            len <<= 1;
        }

        // Final multiply by f = n^{-1} * R^2 mod q = 41978
        // This makes INTT output be in Montgomery domain (multiplied by R),
        // which cancels the R^{-1} from pointwise_montgomery.
        const F: i64 = 41978;
        for x in a.iter_mut() {
            *x = montgomery_reduce(F * *x as i64);
        }
    }
}

/// Pointwise Montgomery multiplication of two NTT-domain polynomials.
///
/// The matrix product assigns on its first column and accumulates on the
/// rest, so this runs k times per attempt and is worth the same treatment
/// as the accumulate.
// Out of line: called from several places per operation, each a whole
// polynomial, so the call costs nothing and the copies do.
#[inline(never)]
pub fn poly_pointwise_montgomery(c: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: three `[i32; N]` with N even, all word aligned; `c` is
        // the only one written and is a distinct borrow.
        unsafe {
            core::arch::asm!(
                "2:",
                "ldrd  {ra}, {rb}, [{ap}], #8",
                "ldrd  {rc}, {rd}, [{bp}], #8",
                "smull {re}, {rf}, {ra}, {rc}",
                "smull {ra}, {rc}, {rb}, {rd}",
                "mul   {rb}, {re}, {qinv}",
                "mul   {rd}, {ra}, {qinv}",
                "smlal {re}, {rf}, {rb}, {q}",
                "smlal {ra}, {rc}, {rd}, {q}",
                "strd  {rf}, {rc}, [{cp}], #8",
                "subs  {n}, {n}, #1",
                "bne   2b",
                ap = inout(reg) a.as_ptr() => _,
                bp = inout(reg) b.as_ptr() => _,
                cp = inout(reg) c.as_mut_ptr() => _,
                n = inout(reg) N / 2 => _,
                qinv = in(reg) QINV_I,
                q = in(reg) Q_I,
                ra = out(reg) _,
                rb = out(reg) _,
                rc = out(reg) _,
                rd = out(reg) _,
                re = out(reg) _,
                rf = out(reg) _,
                options(nostack),
            );
        }
    }

    #[cfg(not(target_arch = "arm"))]
    for ((c, &a), &b) in c.iter_mut().zip(a.iter()).zip(b.iter()) {
        *c = montgomery_reduce(a as i64 * b as i64);
    }
}

/// In-place pointwise Montgomery multiplication: a = a * b.
///
/// Signing multiplies by the challenge and transforms straight back, so a
/// separate destination only costs it a polynomial of scratch.
///
/// Paired for the same reason as the butterflies: the reduction was already
/// optimal, but half the instructions were address arithmetic and loop
/// control.
pub fn poly_pointwise_montgomery_inplace(a: &mut [i32; N], b: &[i32; N]) {
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: both are `[i32; N]` with N even, so N / 2 pairs cover
        // them exactly, and both are word aligned.
        unsafe {
            core::arch::asm!(
                "2:",
                "ldrd  {ra}, {rb}, [{ap}]",
                "ldrd  {rc}, {rd}, [{bp}], #8",
                "smull {re}, {rf}, {ra}, {rc}",
                "smull {ra}, {rc}, {rb}, {rd}",
                "mul   {rb}, {re}, {qinv}",
                "mul   {rd}, {ra}, {qinv}",
                "smlal {re}, {rf}, {rb}, {q}",
                "smlal {ra}, {rc}, {rd}, {q}",
                "strd  {rf}, {rc}, [{ap}], #8",
                "subs  {n}, {n}, #1",
                "bne   2b",
                ap = inout(reg) a.as_mut_ptr() => _,
                bp = inout(reg) b.as_ptr() => _,
                n = inout(reg) N / 2 => _,
                qinv = in(reg) QINV_I,
                q = in(reg) Q_I,
                ra = out(reg) _,
                rb = out(reg) _,
                rc = out(reg) _,
                rd = out(reg) _,
                re = out(reg) _,
                rf = out(reg) _,
                options(nostack),
            );
        }
    }

    #[cfg(not(target_arch = "arm"))]
    for (a, &b) in a.iter_mut().zip(b.iter()) {
        *a = montgomery_reduce(*a as i64 * b as i64);
    }
}

/// Pointwise Montgomery multiply-accumulate with `a` packed three bytes to
/// a coefficient, as [`crate::spill`] packs matrix elements: c += a * b.
///
/// The unpacking rides in the gaps of the multiply chain -- the loop is
/// bound by the single MAC pipe, which the shifts do not use -- so a packed
/// operand costs no more than an unpacked one, and the signer gets to keep
/// a third more of the matrix in dTCM and to skip unpacking spilled
/// elements into a scratch polynomial first.
///
/// # Panics
/// If `a` holds fewer than `N * 3 / 4` words.
pub fn poly_pointwise_acc_montgomery_packed(c: &mut [i32; N], a: &[i32], b: &[i32; N]) {
    let a = &a[..N * 3 / 4];

    #[cfg(target_arch = "arm")]
    {
        // SAFETY: `c` and `b` are `[i32; N]` and `a` holds the 3N/4 packed
        // words of N coefficients; all are word aligned, and `c` is the
        // only one written and a distinct borrow. Four coefficients a pass.
        unsafe {
            core::arch::asm!(
                "2:",
                "ldrd   {w0}, {w1}, [{ap}], #8",
                "ldrd   {x0}, {x1}, [{bp}], #8",
                "ubfx   {t0}, {w0}, #0, #24",
                "lsr    {w0}, {w0}, #24",
                "orr    {w0}, {w0}, {w1}, lsl #8",
                "bic    {w0}, {w0}, #0xFF000000",
                "smull  {t1}, {t2}, {t0}, {x0}",
                "smull  {t0}, {x0}, {w0}, {x1}",
                "mul    {w0}, {t1}, {qinv}",
                "mul    {x1}, {t0}, {qinv}",
                "smlal  {t1}, {t2}, {w0}, {q}",
                "smlal  {t0}, {x0}, {x1}, {q}",
                "ldrd   {t0}, {t1}, [{cp}]",
                "add    {t0}, {t0}, {t2}",
                "add    {t1}, {t1}, {x0}",
                "strd   {t0}, {t1}, [{cp}], #8",
                "ldr    {w0}, [{ap}], #4",
                "ldrd   {x0}, {x1}, [{bp}], #8",
                "lsr    {t0}, {w1}, #16",
                "orr    {t0}, {t0}, {w0}, lsl #16",
                "bic    {t0}, {t0}, #0xFF000000",
                "lsr    {w0}, {w0}, #8",
                "smull  {t1}, {t2}, {t0}, {x0}",
                "smull  {t0}, {x0}, {w0}, {x1}",
                "mul    {w0}, {t1}, {qinv}",
                "mul    {x1}, {t0}, {qinv}",
                "smlal  {t1}, {t2}, {w0}, {q}",
                "smlal  {t0}, {x0}, {x1}, {q}",
                "ldrd   {t0}, {t1}, [{cp}]",
                "add    {t0}, {t0}, {t2}",
                "add    {t1}, {t1}, {x0}",
                "strd   {t0}, {t1}, [{cp}], #8",
                "subs   {n}, {n}, #1",
                "bne    2b",
                cp = inout(reg) c.as_mut_ptr() => _,
                ap = inout(reg) a.as_ptr() => _,
                bp = inout(reg) b.as_ptr() => _,
                n = inout(reg) N / 4 => _,
                qinv = in(reg) QINV_I,
                q = in(reg) Q_I,
                w0 = out(reg) _,
                w1 = out(reg) _,
                x0 = out(reg) _,
                x1 = out(reg) _,
                t0 = out(reg) _,
                t1 = out(reg) _,
                t2 = out(reg) _,
                options(nostack),
            );
        }
    }

    #[cfg(not(target_arch = "arm"))]
    for (g, w) in a.as_chunks::<3>().0.iter().enumerate() {
        let (w0, w1, w2) = (w[0] as u32, w[1] as u32, w[2] as u32);
        let v = [
            w0 & 0x00FF_FFFF,
            ((w0 >> 24) | (w1 << 8)) & 0x00FF_FFFF,
            ((w1 >> 16) | (w2 << 16)) & 0x00FF_FFFF,
            w2 >> 8,
        ];
        for (k, &x) in v.iter().enumerate() {
            c[4 * g + k] += montgomery_reduce(x as i64 * b[4 * g + k] as i64);
        }
    }
}

/// Pointwise Montgomery multiply-accumulate: c += a * b.
// Out of line: called from several places per operation, each a whole
// polynomial, so the call costs nothing and the copies do.
#[inline(never)]
pub fn poly_pointwise_acc_montgomery(c: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: three `[i32; N]` with N even, all word aligned; `c` is
        // the only one written and is a distinct borrow.
        unsafe {
            core::arch::asm!(
                "2:",
                "ldrd  {ra}, {rb}, [{ap}], #8",
                "ldrd  {rc}, {rd}, [{bp}], #8",
                "smull {re}, {rf}, {ra}, {rc}",
                "smull {ra}, {rc}, {rb}, {rd}",
                "mul   {rb}, {re}, {qinv}",
                "mul   {rd}, {ra}, {qinv}",
                "smlal {re}, {rf}, {rb}, {q}",
                "smlal {ra}, {rc}, {rd}, {q}",
                "ldrd  {rb}, {rd}, [{cp}]",
                "add   {rb}, {rb}, {rf}",
                "add   {rd}, {rd}, {rc}",
                "strd  {rb}, {rd}, [{cp}], #8",
                "subs  {n}, {n}, #1",
                "bne   2b",
                ap = inout(reg) a.as_ptr() => _,
                bp = inout(reg) b.as_ptr() => _,
                cp = inout(reg) c.as_mut_ptr() => _,
                n = inout(reg) N / 2 => _,
                qinv = in(reg) QINV_I,
                q = in(reg) Q_I,
                ra = out(reg) _,
                rb = out(reg) _,
                rc = out(reg) _,
                rd = out(reg) _,
                re = out(reg) _,
                rf = out(reg) _,
                options(nostack),
            );
        }
    }

    #[cfg(not(target_arch = "arm"))]
    for ((c, &a), &b) in c.iter_mut().zip(a.iter()).zip(b.iter()) {
        *c += montgomery_reduce(a as i64 * b as i64);
    }
}
