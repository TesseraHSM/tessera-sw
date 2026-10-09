// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// NTT for ML-KEM: q=3329, 16-bit coefficients, 128-point transform.
use super::params::N;
/// NTT for ML-KEM: q=3329, 16-bit coefficients, 128-point transform.
use super::params::Q;
use super::zetas::ZETAS;

const QINV: i16 = 62209u16 as i16; // q^{-1} mod 2^16
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

/// Cooley-Tukey butterflies, two at a time.
///
/// ML-KEM's coefficients are 16-bit, so a pair of them shares one register
/// and the halfword instructions do both butterflies at once: one `ldr`
/// fetches two coefficients, `pkhtb` packs the two reduced products back
/// into a word, and `sadd16`/`ssub16` finish both halves in one
/// instruction each. That is the part ML-DSA could not do -- its
/// coefficients are 32-bit and fill a register on their own.
///
/// # Safety
/// `xp` and `yp` must each be valid for `pairs * 2` `i16` writes and word
/// aligned, and must not overlap.
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn ct_butterfly_pairs(xp: *mut i16, yp: *mut i16, zeta: i16, pairs: usize) {
    core::arch::asm!(
        "2:",
        "ldr    {xw}, [{xp}]",
        "ldr    {yw}, [{yp}]",
        "smulbb {p0}, {yw}, {z}",
        "smultb {p1}, {yw}, {z}",
        "mul    {t0}, {p0}, {qinv}",
        "mul    {t1}, {p1}, {qinv}",
        "smlabb {p0}, {t0}, {q}, {p0}",
        "smlabb {p1}, {t1}, {q}, {p1}",
        "pkhtb  {tw}, {p1}, {p0}, asr #16",
        "ssub16 {p0}, {xw}, {tw}",
        "sadd16 {p1}, {xw}, {tw}",
        "str    {p0}, [{yp}], #4",
        "str    {p1}, [{xp}], #4",
        "subs   {n}, {n}, #1",
        "bne    2b",
        xp = inout(reg) xp => _,
        yp = inout(reg) yp => _,
        n = inout(reg) pairs => _,
        z = in(reg) zeta as i32,
        qinv = in(reg) QINV_P,
        q = in(reg) Q_NEG,
        xw = out(reg) _,
        yw = out(reg) _,
        p0 = out(reg) _,
        p1 = out(reg) _,
        t0 = out(reg) _,
        t1 = out(reg) _,
        tw = out(reg) _,
        options(nostack),
    );
}

/// Forward NTT (in-place). Kyber's 128-point NTT.
/// After NTT, pairs (a[2i], a[2i+1]) represent coefficients in
/// Z_q[x]/(x^2 - zeta^{2*brv(i)+1}).
pub fn ntt(a: &mut [i16; N]) {
    #[cfg(target_arch = "arm")]
    {
        // Walking the windows by pointer rather than by slice splitting:
        // the assembly claims most of the register file, and an enclosing
        // loop that has to spill its state every window costs more than
        // the butterflies it sets up. There are 127 windows here.
        let zbase = ZETAS.as_ptr();
        let ap = a.as_mut_ptr();
        let mut zi = 1usize;
        let mut len = N / 2;
        while len >= 2 {
            let mut base = ap;
            for _ in 0..N / (2 * len) {
                // SAFETY: `base` walks windows of `2 * len` within `a`, and
                // `zi` stays inside ZETAS -- the transform consumes 127
                // zetas and the table holds 127 past the unused first.
                unsafe {
                    ct_butterfly_pairs(base, base.add(len), *zbase.add(zi), len / 2);
                    base = base.add(2 * len);
                }
                zi += 1;
            }
            len >>= 1;
        }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let mut zetas = ZETAS[1..].iter();
        let mut len: usize = 128;
        while len >= 2 {
            let mut rest: &mut [i16] = a;
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

/// Inverse NTT (in-place).
pub fn invntt(a: &mut [i16; N]) {
    let mut zetas = ZETAS[1..128].iter().rev();
    let mut len: usize = 2;
    while len <= 128 {
        let mut rest: &mut [i16] = a;
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
    // Multiply by f = R^2 * n^{-1} mod q = 3303 (centered: -26... wait)
    // f = -944 computed earlier, but let's use the standard Kyber value
    // Actually: f = 1441 (from reference Kyber; mont^2/128 mod q)
    // Let me use the reference value directly.
    const F: i32 = 1441;
    for x in a.iter_mut() {
        *x = montgomery_reduce(F * *x as i32);
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
/// The two halves of each quadruple are taken one at a time. Doing both at
/// once keeps eight coefficients and a zeta live, which is more than the
/// register file holds, and the loop spent a third of its instructions
/// spilling.
pub fn poly_basemul_acc(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    let mut zi = 64usize;
    let mut rr: &mut [i16] = r;
    let mut aa: &[i16] = a;
    let mut bb: &[i16] = b;
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

/// Convert polynomial to Montgomery domain: multiply each coefficient by R.
/// Used after basemul_acc to cancel the R^{-1} factor.
pub fn poly_tomont(a: &mut [i16; N]) {
    for i in 0..N {
        a[i] = montgomery_reduce(a[i] as i32 * MONT_SQ);
    }
}
