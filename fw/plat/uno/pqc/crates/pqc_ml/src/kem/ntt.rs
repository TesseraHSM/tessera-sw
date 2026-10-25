// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// NTT for ML-KEM: q=3329, 16-bit coefficients, 128-point transform.
use super::params::N;
/// NTT for ML-KEM: q=3329, 16-bit coefficients, 128-point transform.
use super::params::Q;
use super::poly::Poly;
#[cfg(target_arch = "arm")]
use super::zetas::BASEMUL_ZETAS;
#[cfg(target_arch = "arm")]
use super::zetas::PLANT;
use super::zetas::ZETAS;

const QINV: i16 = 62209u16 as i16; // q^{-1} mod 2^16
#[cfg(not(target_arch = "arm"))]
const MONT_SQ: i32 = 1353; // R^2 mod q = 2285^2 mod 3329

#[inline(always)]
pub fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV);
    ((a - t as i32 * Q as i32) >> 16) as i16
}

#[inline(always)]
pub fn barrett_reduce(a: i16) -> i16 {
    // Barrett constant for q=3329: v = floor(2^26 / q + 0.5) = 20159
    const V: i32 = 20159;
    let t = ((V * a as i32 + (1 << 25)) >> 26) as i16;
    a - t * Q as i16
}

/// Montgomery constants for the assembly butterflies.
///
/// The reduction is `(a - t*q) >> 16` but `smlabb` only accumulates, so
/// one constant carries the sign. It must be `q`: negating `qinv` instead
/// relies on `-t == -t`, which fails for `i16::MIN`, and the result is
/// then wrong by exactly `q`. That happens for one input in 2^16 -- often
/// enough that a host model of these instructions caught it in 2 of 300
/// random transforms, and far too rare for a KAT run to see.
#[cfg(target_arch = "arm")]
const QINV_P: i32 = QINV as i32;
#[cfg(target_arch = "arm")]
const Q_NEG: i32 = -(Q as i32);

/// `qinv` in the bottom half, `-q` in the top. `mul` only needs the low
/// half of `qinv` -- the bits of the product it keeps do not depend on the
/// top -- and the `smlabt`/`smulbt` forms read `-q` from the top, so one
/// register serves the whole Montgomery reduction.
#[cfg(target_arch = "arm")]
const QINV_QNEG: i32 = (Q_NEG << 16) | (QINV_P & 0xFFFF);

#[cfg(target_arch = "arm")]
extern "C" {
    /// `asm/kem_ntt.S`: the forward transform, Plantard twiddles `tw`.
    fn pqc_ml_kem_ntt(p: *mut i16, tw: *const i16);
    /// `asm/kem_ntt.S`: the inverse transform with the final scaling,
    /// reading the twiddles down from `tw_end`.
    fn pqc_ml_kem_invntt(p: *mut i16, tw_end: *const i16);
}

/// Forward NTT (in-place). Kyber's 128-point NTT.
/// After NTT, pairs (a[2i], a[2i+1]) represent coefficients in
/// Z_q[x]/(x^2 - zeta^{2*brv(i)+1}).
///
/// On ARM this is `asm/kem_ntt.S`, whose twiddle products are Plantard
/// rather than Montgomery reduced: its outputs equal these mod q but not as
/// integers, and are smaller -- an input bounded by B comes out within
/// B + 7 * 1664 rather than B + 7q. Every caller reduces or multiplies
/// before the representative matters.
pub fn ntt(a: &mut Poly) {
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: `Poly` is word aligned and 256 coefficients long, and
        // PLANT holds the 127 twiddles the transform reads.
        unsafe { pqc_ml_kem_ntt(a.as_mut_ptr(), PLANT.as_ptr()) };
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let mut zetas = ZETAS[1..].iter();
        let mut len: usize = 128;
        while len >= 2 {
            let mut rest: &mut [i16] = &mut a[..];
            while !rest.is_empty() {
                let (chunk, tail) = rest.split_at_mut(2 * len);
                rest = tail;
                let Some(&zeta) = zetas.next() else { return };
                let zeta = zeta as i32;
                let (lo, hi) = chunk.split_at_mut(len);
                for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
                    let t = montgomery_reduce(zeta * *y as i32);
                    *y = *x - t;
                    *x += t;
                }
            }
            len >>= 1;
        }
    }
}

/// Inverse NTT (in-place), including the multiplication by
/// f = mont^2/128 that leaves the result in the Montgomery domain.
///
/// On ARM this is `asm/kem_ntt.S`: Plantard reduced like [`ntt`], equal to
/// this mod q, every output within 1664. It needs an input below 2^14 in
/// magnitude -- the sums are reduced only after the first and fifth layers
/// -- and the accumulations of [`poly_basemul_acc`] that feed it stay under
/// 14200 for k up to 4.
pub fn invntt(a: &mut Poly) {
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: as for `ntt`; the cursor starts one past PLANT's last
        // entry and the transform reads all 127 below it.
        unsafe { pqc_ml_kem_invntt(a.as_mut_ptr(), PLANT.as_ptr().add(PLANT.len())) };
    }

    #[cfg(not(target_arch = "arm"))]
    {
        // Multiply by f = mont^2/128 mod q = 1441 (the reference value).
        const F: i32 = 1441;
        let mut zetas = ZETAS[1..128].iter().rev();
        let mut len: usize = 2;
        while len <= 128 {
            let mut rest: &mut [i16] = &mut a[..];
            while !rest.is_empty() {
                let (chunk, tail) = rest.split_at_mut(2 * len);
                rest = tail;
                let Some(&zeta) = zetas.next() else { return };
                let zeta = zeta as i32;
                let (lo, hi) = chunk.split_at_mut(len);
                for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
                    let t = *x;
                    *x = barrett_reduce(t + *y);
                    *y = montgomery_reduce(-zeta * (t - *y) as i32);
                }
            }
            len <<= 1;
        }
        for x in a.iter_mut() {
            *x = montgomery_reduce(F * *x as i32);
        }
    }
}

/// Basemul: multiply two degree-1 polynomials in Z_q[x]/(x^2 - zeta).
/// r[0] = a[0]*b[0] + a[1]*b[1]*zeta, r[1] = a[0]*b[1] + a[1]*b[0]
#[inline]
fn basemul(r: &mut [i16], a: &[i16], b: &[i16], zeta: i32) {
    r[0] = montgomery_reduce(a[1] as i32 * b[1] as i32);
    r[0] = montgomery_reduce(r[0] as i32 * zeta);
    r[0] += montgomery_reduce(a[0] as i32 * b[0] as i32);
    r[1] = montgomery_reduce(a[0] as i32 * b[1] as i32);
    r[1] += montgomery_reduce(a[1] as i32 * b[0] as i32);
}

/// Pointwise multiply two NTT-domain polynomials.
pub fn poly_basemul(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    for i in 0..N / 4 {
        basemul(
            &mut r[4 * i..],
            &a[4 * i..],
            &b[4 * i..],
            ZETAS[64 + i] as i32,
        );
        basemul(
            &mut r[4 * i + 2..],
            &a[4 * i + 2..],
            &b[4 * i + 2..],
            -(ZETAS[64 + i] as i32),
        );
    }
}

/// One degree-1 product accumulated into `r`, in Z_q[x]/(x^2 - zeta).
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn basemul_acc2(r: &mut [i16], a: &[i16], b: &[i16], zeta: i32) {
    let a0 = a[0] as i32;
    let a1 = a[1] as i32;
    let b0 = b[0] as i32;
    let b1 = b[1] as i32;

    let mut t0 = montgomery_reduce(a1 * b1);
    t0 = montgomery_reduce(t0 as i32 * zeta);
    t0 += montgomery_reduce(a0 * b0);
    let t1 = montgomery_reduce(a0 * b1) + montgomery_reduce(a1 * b0);

    r[0] += t0;
    r[1] += t1;
}

/// Pointwise multiply-accumulate: r += a * b (no intermediate buffer).
///
/// On ARM each degree-1 product takes one word of each operand and three
/// Montgomery reductions where the scalar version took five: `smuadx`
/// forms `a0*b1 + a1*b0` in one instruction and is reduced once, and
/// `a0*b0 + mont(a1*b1)*zeta` is accumulated in 32 bits before its single
/// reduction. The result agrees with the scalar version mod q and is never
/// larger in magnitude, so the 16-bit accumulators keep their headroom.
///
/// Not inlined: the block is a hundred and fifty bytes, and it has four
/// callers in a 32 KB iTCM.
#[inline(never)]
pub fn poly_basemul_acc(r: &mut Poly, a: &Poly, b: &Poly) {
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: three word-aligned polynomials; `r` is the only one
        // written and is a distinct borrow. The zeta cursor reads all of
        // BASEMUL_ZETAS, one per quadruple.
        unsafe {
            core::arch::asm!(
                "2:",
                "ldrsh  {z}, [{zp}], #2",
                "ldr    {x0}, [{ap}], #4",
                "ldr    {x1}, [{bp}], #4",
                "smultt {t}, {x0}, {x1}",
                "smulbb {u}, {x0}, {x1}",
                "mul    {m}, {t}, {k}",
                "smuadx {v}, {x0}, {x1}",
                "smlabt {t}, {m}, {k}, {t}",
                "ldr    {x0}, [{rp}]",
                "smlatb {u}, {t}, {z}, {u}",
                "mul    {m}, {v}, {k}",
                "mul    {t}, {u}, {k}",
                "smlabt {v}, {m}, {k}, {v}",
                "smlabt {u}, {t}, {k}, {u}",
                "pkhtb  {v}, {v}, {u}, asr #16",
                "sadd16 {x0}, {x0}, {v}",
                "str    {x0}, [{rp}], #4",
                "rsb    {z}, {z}, #0",
                "ldr    {x0}, [{ap}], #4",
                "ldr    {x1}, [{bp}], #4",
                "smultt {t}, {x0}, {x1}",
                "smulbb {u}, {x0}, {x1}",
                "mul    {m}, {t}, {k}",
                "smuadx {v}, {x0}, {x1}",
                "smlabt {t}, {m}, {k}, {t}",
                "ldr    {x0}, [{rp}]",
                "smlatb {u}, {t}, {z}, {u}",
                "mul    {m}, {v}, {k}",
                "mul    {t}, {u}, {k}",
                "smlabt {v}, {m}, {k}, {v}",
                "smlabt {u}, {t}, {k}, {u}",
                "pkhtb  {v}, {v}, {u}, asr #16",
                "sadd16 {x0}, {x0}, {v}",
                "str    {x0}, [{rp}], #4",
                "subs   {n}, {n}, #1",
                "bne    2b",
                rp = inout(reg) r.as_mut_ptr() => _,
                ap = inout(reg) a.as_ptr() => _,
                bp = inout(reg) b.as_ptr() => _,
                zp = inout(reg) BASEMUL_ZETAS.as_ptr() => _,
                n = inout(reg) N / 4 => _,
                k = in(reg) QINV_QNEG,
                z = out(reg) _,
                x0 = out(reg) _,
                x1 = out(reg) _,
                t = out(reg) _,
                u = out(reg) _,
                m = out(reg) _,
                v = out(reg) _,
                options(nostack),
            );
        }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let mut zi = 64usize;
        let mut rr: &mut [i16] = &mut r[..];
        let mut aa: &[i16] = &a[..];
        let mut bb: &[i16] = &b[..];
        while !rr.is_empty() {
            let (rc, rt) = rr.split_at_mut(4);
            let (ac, at) = aa.split_at(4);
            let (bc, bt) = bb.split_at(4);
            rr = rt;
            aa = at;
            bb = bt;

            let zeta = ZETAS[zi] as i32;
            zi += 1;
            basemul_acc2(&mut rc[..2], &ac[..2], &bc[..2], zeta);
            basemul_acc2(&mut rc[2..], &ac[2..], &bc[2..], -zeta);
        }
    }
}

/// `t = t * R + e`, reduced: key generation's finish for each row of t_hat,
/// cancelling the R^{-1} that [`poly_basemul_acc`] leaves, adding e_hat
/// and reducing for ByteEncode_12. On ARM it is one pass of
/// `asm/kem_ntt.S`, every result at most q/2 in magnitude; elsewhere the
/// reference's three steps.
pub fn poly_tomont_add(t: &mut Poly, e: &Poly) {
    #[cfg(target_arch = "arm")]
    {
        extern "C" {
            fn pqc_ml_kem_tomont_add(t: *mut i16, e: *const i16);
        }
        // SAFETY: two word-aligned `Poly`s of 256 coefficients; `t` is the
        // only one written and a distinct borrow.
        unsafe { pqc_ml_kem_tomont_add(t.as_mut_ptr(), e.as_ptr()) };
    }

    #[cfg(not(target_arch = "arm"))]
    for i in 0..N {
        let x = montgomery_reduce(t[i] as i32 * MONT_SQ);
        t[i] = barrett_reduce(x + e[i]);
    }
}
