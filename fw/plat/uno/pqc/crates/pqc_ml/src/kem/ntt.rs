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

/// `qinv` in the bottom half, `-q` in the top. `mul` only needs the low
/// half of `qinv` -- the bits of the product it keeps do not depend on the
/// top -- and the `smlabt`/`smulbt` forms read `-q` from the top, so one
/// register serves the whole Montgomery reduction.
#[cfg(target_arch = "arm")]
const QINV_QNEG: i32 = (Q_NEG << 16) | (QINV_P & 0xFFFF);

/// The Barrett constant scaled by 2^6: `smmulr` by it computes
/// `(v * a + 2^25) >> 26` -- [`barrett_reduce`]'s quotient, rounding and
/// all -- in one instruction.
#[cfg(target_arch = "arm")]
const BARRETT_V64: i32 = 20159 << 6;

/// One whole inverse layer of Gentleman-Sande butterflies, two at a time.
///
/// The packed counterpart of [`ct_butterfly_pairs`]: `sadd16`/`ssub16`
/// form both sums and both differences at once, the differences take the
/// forward transform's Montgomery multiply, and the sums are Barrett
/// reduced per halfword exactly as [`barrett_reduce`] does, so the result
/// matches the scalar transform bit for bit. The two reductions are
/// independent and are interleaved, so their multiplies keep the single
/// MAC pipe busy.
///
/// One routine serves all seven layers -- the pair count per window is the
/// half-window offset divided by four -- which costs a call per layer but
/// keeps one copy of the loop in the 32 KB iTCM rather than seven.
///
/// # Safety
/// `ap` must be valid for 256 `i16` writes and word aligned; `zp` must be
/// valid for `128 / len` descending `i16` reads; `len` must be a power of
/// two in 2..=128.
#[cfg(target_arch = "arm")]
#[inline(never)]
unsafe fn gs_layer(ap: *mut i16, zp: *const i16, len: usize) {
    core::arch::asm!(
        "2:",
        "ldrsh  {z}, [{zp}], #-2",
        "lsr    {cnt}, {off}, #2",
        "3:",
        "ldr    {x}, [{xp}]",
        "ldr    {y}, [{xp}, {off}]",
        "ssub16 {t1}, {y}, {x}",
        "sadd16 {t0}, {x}, {y}",
        "smulbb {x}, {t1}, {z}",
        "smultb {y}, {t1}, {z}",
        "sxth   {t2}, {t0}",
        "mul    {t1}, {x}, {a}",
        "smmulr {t2}, {t2}, {v}",
        "smlabt {x}, {t1}, {a}, {x}",
        "mul    {t1}, {y}, {a}",
        "smlabt {y}, {t1}, {a}, {y}",
        "asr    {t1}, {t0}, #16",
        "pkhtb  {x}, {y}, {x}, asr #16",
        "smmulr {t1}, {t1}, {v}",
        "str    {x}, [{xp}, {off}]",
        "smulbt {t2}, {t2}, {a}",
        "smulbt {t1}, {t1}, {a}",
        "pkhbt  {t2}, {t2}, {t1}, lsl #16",
        "sadd16 {t0}, {t0}, {t2}",
        "str    {t0}, [{xp}], #4",
        "subs   {cnt}, {cnt}, #1",
        "bne    3b",
        "add    {xp}, {xp}, {off}",
        "subs   {n}, {n}, #1",
        "bne    2b",
        xp = inout(reg) ap => _,
        zp = inout(reg) zp => _,
        n = inout(reg) N / 2 / len => _,
        off = in(reg) len * 2,
        a = in(reg) QINV_QNEG,
        v = in(reg) BARRETT_V64,
        z = out(reg) _,
        cnt = out(reg) _,
        x = out(reg) _,
        y = out(reg) _,
        t0 = out(reg) _,
        t1 = out(reg) _,
        t2 = out(reg) _,
        options(nostack),
    );
}

/// Inverse NTT (in-place).
pub fn invntt(a: &mut [i16; N]) {
    // Multiply by f = mont^2/128 mod q = 1441 (the reference value).
    const F: i32 = 1441;

    #[cfg(target_arch = "arm")]
    {
        let ap = a.as_mut_ptr();
        let mut len = 2;
        while len <= 128 {
            // SAFETY: each layer covers the whole polynomial, and layer
            // `len` consumes the 128 / len zetas that end at 256 / len - 1.
            unsafe { gs_layer(ap, ZETAS.as_ptr().add(256 / len - 1), len) };
            len <<= 1;
        }
        // SAFETY: `[i16; N]` with N even, word aligned as above.
        unsafe {
            core::arch::asm!(
                "2:",
                "ldr    {x}, [{xp}]",
                "smulbb {t0}, {x}, {f}",
                "smultb {t1}, {x}, {f}",
                "mul    {y}, {t0}, {a}",
                "mul    {t2}, {t1}, {a}",
                "smlabt {t0}, {y}, {a}, {t0}",
                "smlabt {t1}, {t2}, {a}, {t1}",
                "pkhtb  {x}, {t1}, {t0}, asr #16",
                "str    {x}, [{xp}], #4",
                "subs   {n}, {n}, #1",
                "bne    2b",
                xp = inout(reg) ap => _,
                n = inout(reg) N / 2 => _,
                f = in(reg) F,
                a = in(reg) QINV_QNEG,
                x = out(reg) _,
                y = out(reg) _,
                t0 = out(reg) _,
                t1 = out(reg) _,
                t2 = out(reg) _,
                options(nostack),
            );
        }
    }

    #[cfg(not(target_arch = "arm"))]
    {
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
pub fn poly_basemul_acc(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: three word-aligned `[i16; N]` (as for the transforms);
        // `r` is the only one written and is a distinct borrow. The zeta
        // cursor reads ZETAS[64..128], one per quadruple.
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
                zp = inout(reg) ZETAS.as_ptr().add(64) => _,
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
}

/// Convert polynomial to Montgomery domain: multiply each coefficient by R.
/// Used after basemul_acc to cancel the R^{-1} factor.
pub fn poly_tomont(a: &mut [i16; N]) {
    for i in 0..N {
        a[i] = montgomery_reduce(a[i] as i32 * MONT_SQ);
    }
}
