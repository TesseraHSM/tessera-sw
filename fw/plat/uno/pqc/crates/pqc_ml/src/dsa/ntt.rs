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

/// Montgomery constants, in the form the butterfly loops want them.
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

/// Cooley-Tukey butterflies, two at a time.
///
/// The generated code was already using the optimal three-instruction
/// Montgomery reduction, so there was nothing to win in the arithmetic --
/// but four of the twelve instructions per butterfly were loop overhead,
/// and `opt-level = "z"` will not unroll to amortise them. Unrolling in
/// Rust instead makes the register allocator spill and fall back to a
/// generic 64-bit reduction, which costs more than the overhead it saves.
///
/// Doing it here sidesteps both: the pair shares one loop increment and
/// one branch, and `ldrd`/`strd` move both coefficients per access. Twelve
/// instructions per butterfly become eight.
///
/// # Safety
/// `xp` and `yp` must each be valid for `pairs * 2` `i32` writes and word
/// aligned, and must not overlap.
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn ct_butterfly_pairs(xp: *mut i32, yp: *mut i32, zeta: i32, pairs: usize) {
    // Six scratch registers, reused across the body. Thumb-2 has about
    // thirteen allocatable registers, and asking for one name per value
    // overruns that: the allocator does not fail, it simply stops
    // terminating.
    core::arch::asm!(
        "2:",
        "ldrd  {a}, {b}, [{yp}]",
        "smull {c}, {d}, {a}, {z}",
        "smull {e}, {f}, {b}, {z}",
        "mul   {a}, {c}, {qinv}",
        "mul   {b}, {e}, {qinv}",
        "smlal {c}, {d}, {a}, {q}",
        "smlal {e}, {f}, {b}, {q}",
        "ldrd  {a}, {b}, [{xp}]",
        "sub   {c}, {a}, {d}",
        "add   {a}, {a}, {d}",
        "sub   {e}, {b}, {f}",
        "add   {b}, {b}, {f}",
        "strd  {c}, {e}, [{yp}], #8",
        "strd  {a}, {b}, [{xp}], #8",
        "subs  {n}, {n}, #1",
        "bne   2b",
        xp = inout(reg) xp => _,
        yp = inout(reg) yp => _,
        n = inout(reg) pairs => _,
        z = in(reg) zeta,
        qinv = in(reg) QINV_I,
        q = in(reg) Q_I,
        a = out(reg) _,
        b = out(reg) _,
        c = out(reg) _,
        d = out(reg) _,
        e = out(reg) _,
        f = out(reg) _,
        options(nostack),
    );
}

/// One whole layer of single-butterfly windows -- the last forward layer,
/// where each window is one adjacent pair with its own zeta.
///
/// Worth its own routine: at `len == 1` there are 128 windows of one
/// butterfly, so the per-window scaffolding costs more than the arithmetic
/// it sets up.
///
/// # Safety
/// `ap` must be valid for `windows * 2` `i32` writes and `zp` for
/// `windows` reads.
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn ct_layer_len1(ap: *mut i32, zp: *const i32, windows: usize) {
    core::arch::asm!(
        "2:",
        "ldr   {z0}, [{zp}], #4",
        "ldr   {z1}, [{zp}], #4",
        "ldrd  {ra}, {rb}, [{ap}]",
        "ldrd  {rc}, {rd}, [{ap}, #8]",
        "smull {re}, {rf}, {rb}, {z0}",
        "smull {rb}, {rd}, {rd}, {z1}",
        "mul   {z0}, {re}, {qinv}",
        "mul   {z1}, {rb}, {qinv}",
        "smlal {re}, {rf}, {z0}, {q}",
        "smlal {rb}, {rd}, {z1}, {q}",
        "sub   {z0}, {ra}, {rf}",
        "add   {ra}, {ra}, {rf}",
        "sub   {z1}, {rc}, {rd}",
        "add   {rc}, {rc}, {rd}",
        "strd  {ra}, {z0}, [{ap}]",
        "strd  {rc}, {z1}, [{ap}, #8]",
        "add   {ap}, {ap}, #16",
        "subs  {n}, {n}, #1",
        "bne   2b",
        ap = inout(reg) ap => _,
        zp = inout(reg) zp => _,
        n = inout(reg) windows => _,
        qinv = in(reg) QINV_I,
        q = in(reg) Q_I,
        z0 = out(reg) _,
        z1 = out(reg) _,
        ra = out(reg) _,
        rb = out(reg) _,
        rc = out(reg) _,
        rd = out(reg) _,
        re = out(reg) _,
        rf = out(reg) _,
        options(nostack),
    );
}

/// A whole layer of butterflies, window loop and all.
///
/// The per-window Rust loop looked cheap but was not: the inner asm block
/// claims twelve registers, which leaves the enclosing loop nothing, so the
/// allocator spilled its state to the stack and reloaded it every window.
/// That cost about twelve instructions per window, six of them stack
/// traffic, and a transform has 255 windows.
///
/// Taking the window loop into the same block fixes it, and making `LEN` a
/// const parameter lets the half-window offset and the pair count become
/// immediates rather than registers -- which is what keeps the whole thing
/// inside the thirteen registers Thumb-2 has to give.
///
/// # Safety
/// `ap` must be valid for `windows * 2 * LEN` `i32` writes, `zp` for
/// `windows` reads. `LEN` must be even.
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn ct_layer<const LEN: usize>(ap: *mut i32, zp: *const i32, windows: usize) {
    core::arch::asm!(
        "2:",
        "ldr   {z}, [{zp}], #4",
        "mov   {cnt}, {pairs}",
        "3:",
        "ldrd  {a}, {b}, [{xp}, {off}]",
        "smull {c}, {d}, {a}, {z}",
        "smull {e}, {f}, {b}, {z}",
        "mul   {a}, {c}, {qinv}",
        "mul   {b}, {e}, {qinv}",
        "smlal {c}, {d}, {a}, {q}",
        "smlal {e}, {f}, {b}, {q}",
        "ldrd  {a}, {b}, [{xp}]",
        "sub   {c}, {a}, {d}",
        "add   {a}, {a}, {d}",
        "sub   {e}, {b}, {f}",
        "add   {b}, {b}, {f}",
        "strd  {c}, {e}, [{xp}, {off}]",
        "strd  {a}, {b}, [{xp}], #8",
        "subs  {cnt}, {cnt}, #1",
        "bne   3b",
        "add   {xp}, {xp}, {off}",
        "subs  {n}, {n}, #1",
        "bne   2b",
        xp = inout(reg) ap => _,
        zp = inout(reg) zp => _,
        n = inout(reg) windows => _,
        qinv = in(reg) QINV_I,
        q = in(reg) Q_I,
        off = const LEN * 4,
        pairs = const LEN / 2,
        z = out(reg) _,
        cnt = out(reg) _,
        a = out(reg) _,
        b = out(reg) _,
        c = out(reg) _,
        d = out(reg) _,
        e = out(reg) _,
        f = out(reg) _,
        options(nostack),
    );
}

/// Forward NTT over raw pointers.
///
/// The wide layers have few windows, so they keep the simple walk; the
/// narrow ones, which are almost all of the 255 windows, hand the whole
/// layer to one assembly block.
#[cfg(target_arch = "arm")]
fn ntt_arm(a: &mut [i32; N]) {
    let zbase = ZETAS.as_ptr();
    let ap = a.as_mut_ptr();
    let mut zi = 1usize;
    let mut len = N / 2;
    while len >= 16 {
        let mut base = ap;
        for _ in 0..N / (2 * len) {
            // SAFETY: `base` walks windows of `2 * len` within `a`, and
            // `zi` stays inside ZETAS -- a transform consumes 255 zetas and
            // the table holds 255 past the unused first entry.
            unsafe {
                ct_butterfly_pairs(base, base.add(len), *zbase.add(zi), len / 2);
                base = base.add(2 * len);
            }
            zi += 1;
        }
        len >>= 1;
    }
    // SAFETY: each call covers exactly the windows of its layer, taking the
    // zetas that follow the ones already consumed.
    unsafe {
        ct_layer::<8>(ap, zbase.add(zi), N / 16);
        zi += N / 16;
        ct_layer::<4>(ap, zbase.add(zi), N / 8);
        zi += N / 8;
        ct_layer::<2>(ap, zbase.add(zi), N / 4);
        zi += N / 4;
        ct_layer_len1(ap, zbase.add(zi), N / 4);
    }
}

/// Forward NTT (in-place). Input coefficients in normal order,
/// output in bit-reversed order. Coefficients are in Montgomery domain.
pub fn ntt(a: &mut [i32; N]) {
    #[cfg(target_arch = "arm")]
    {
        ntt_arm(a);
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

/// Pointwise Montgomery multiply-accumulate: c += a * b.
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
