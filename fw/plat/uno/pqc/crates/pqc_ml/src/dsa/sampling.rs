// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// Sampling routines for ML-DSA (FIPS 204).
use super::params::N;
/// Sampling routines for ML-DSA (FIPS 204).
use super::params::Q;
use super::poly::Poly;
use crate::keccak::shake128_init;
use crate::keccak::shake256_init;
use crate::keccak::ShakeCtx;
use crate::keccak::XofPrefix;
use crate::keccak::SHAKE128_RATE;
use crate::keccak::SHAKE256_RATE;

/// ExpandA: Generate a single element A[i][j] of the public matrix from seed rho.
/// Uses SHAKE128(rho || j || i) with rejection sampling.
///
/// The sponge is squeezed a whole rate block at a time. Extracting three
/// bytes per call instead costs a full lane de-interleave per sample, which
/// dominated the cost of this routine.
pub fn poly_uniform(a: &mut Poly, rho: &XofPrefix, i: u8, j: u8) {
    let mut ctx = shake128_init();
    ctx.absorb_xof(rho, u16::from_le_bytes([j, i]), 2);

    // Three little-endian words hold four 3-byte candidates, so each one
    // is a shift, an OR and a mask rather than three byte loads.
    let mut buf = [0u32; SHAKE128_RATE / 4];
    let mut ctr = 0;
    while ctr < N {
        ctx.squeeze_words(&mut buf);
        let groups = buf.as_chunks::<3>().0;

        // On ARM `asm/rej.S` takes every group that is sure to fit, and
        // the loop below only the few candidates past it.
        #[cfg(target_arch = "arm")]
        let groups = {
            extern "C" {
                fn pqc_ml_dsa_rej(a: *mut i32, ctr: u32, buf: *const u32, groups: u32) -> u32;
            }
            // SAFETY: `a` has room for N coefficients and the routine stores
            // at most N - ctr of them; `buf` holds the groups it reads.
            let r = unsafe {
                pqc_ml_dsa_rej(
                    a.as_mut_ptr(),
                    ctr as u32,
                    buf.as_ptr(),
                    groups.len() as u32,
                )
            };
            ctr = (r & 0xFFFF) as usize;
            &groups[(r >> 16) as usize..]
        };

        for w in groups {
            let (w0, w1, w2) = (u32::from_le(w[0]), u32::from_le(w[1]), u32::from_le(w[2]));
            let mut take = |d: u32| {
                let d = d & 0x7F_FFFF;
                if d < Q && ctr < N {
                    a[ctr] = d as i32;
                    ctr += 1;
                }
            };
            take(w0);
            take((w0 >> 24) | (w1 << 8));
            take((w1 >> 16) | (w2 << 16));
            take(w2 >> 8);
        }
    }
}

/// SampleEta: sample a polynomial with coefficients in [-eta, eta].
/// Uses SHAKE256(seed || nonce).
pub fn poly_sample_eta(a: &mut Poly, seed: &XofPrefix, nonce: u16, eta: u8) {
    let mut ctx = shake256_init();
    ctx.absorb_xof(seed, nonce, 2);

    sample_eta(&mut ctx, a, eta);
}

/// FIPS 204 RejBoundedPoly: each nibble n of the stream, low then high of
/// every byte, gives eta - (n mod (2 eta + 1)) if n < 15 (eta = 2) or n < 9
/// (eta = 4), and is skipped otherwise.
fn sample_eta(ctx: &mut ShakeCtx, a: &mut Poly, eta: u8) {
    // The value each nibble gives, -128 where it is skipped.
    const R: i8 = -128;
    const ETA2: [i8; 16] = [2, 1, 0, -1, -2, 2, 1, 0, -1, -2, 2, 1, 0, -1, -2, R];
    const ETA4: [i8; 16] = [4, 3, 2, 1, 0, -1, -2, -3, -4, R, R, R, R, R, R, R];
    let tab = if eta == 2 { &ETA2 } else { &ETA4 };

    let mut buf = [0u32; SHAKE256_RATE / 4];
    let mut ctr = 0;
    while ctr < N {
        ctx.squeeze_words(&mut buf);

        // On ARM `asm/rej.S` takes the block while eight more still fit,
        // and the loop below only the few past that.
        #[cfg(target_arch = "arm")]
        let used = {
            extern "C" {
                fn pqc_ml_dsa_eta(a: *mut i32, ctr: u32, buf: *const u32, tab: *const i8) -> u32;
            }
            // SAFETY: `a` has room for N coefficients and the routine stops
            // while eight more fit; `buf` is one 34-word block and `tab` 16
            // entries.
            let r = unsafe { pqc_ml_dsa_eta(a.as_mut_ptr(), ctr as u32, buf.as_ptr(), tab.as_ptr()) };
            ctr = (r & 0xFFFF) as usize;
            (r >> 16) as usize
        };
        #[cfg(not(target_arch = "arm"))]
        let used = 0;

        for &w in &buf[used..] {
            for k in 0..8 {
                if ctr == N {
                    return;
                }
                let v = tab[((w >> (4 * k)) & 15) as usize];
                if v != R {
                    a[ctr] = i32::from(v);
                    ctr += 1;
                }
            }
        }
    }
}

/// Largest ExpandMask output for one polynomial: 256 * 20 / 8.
pub const GAMMA1_MAX_BYTES: usize = 640;

/// ExpandMask, first half: squeeze the packed coefficient stream for one
/// polynomial from SHAKE256(seed || nonce).
///
/// Kept separate from the unpacking so signing can hold the bytes and
/// re-derive y in the z pass without running the XOF a second time.
pub fn expand_mask_bytes(out: &mut [u8], seed: &XofPrefix, nonce: u16) {
    let mut ctx = shake256_init();
    ctx.absorb_xof(seed, nonce, 2);
    ctx.squeeze(out);
}

/// ExpandMask, second half: unpack the stream into coefficients in
/// [-(gamma1-1), gamma1].
pub fn unpack_gamma1(a: &mut Poly, buf: &[u8], gamma1: u32) {
    // 18 bits a coefficient for gamma1 = 2^17, 20 for 2^19, each field f
    // standing for gamma1 - f.
    let d = if gamma1 == 1 << 17 { 18 } else { 20 };

    // A word at a time where the stream is word aligned, as every caller's
    // is: one load per five or nine bytes instead of one per byte.
    #[cfg(target_arch = "arm")]
    if (buf.as_ptr() as usize).is_multiple_of(4) {
        extern "C" {
            fn pqc_ml_dsa_unpack_z20(a: *mut i32, buf: *const u8);
            fn pqc_ml_dsa_unpack_z18(a: *mut i32, buf: *const u8);
        }
        // SAFETY: `a` is 256 coefficients; `buf` is word aligned and, as
        // the slicing checks, holds the 576 or 640 bytes read.
        unsafe {
            if d == 18 {
                pqc_ml_dsa_unpack_z18(a.as_mut_ptr(), buf[..576].as_ptr());
            } else {
                pqc_ml_dsa_unpack_z20(a.as_mut_ptr(), buf[..640].as_ptr());
            }
        }
        return;
    }

    super::packing::unpack_centered(a, buf, d, gamma1 as i32);
}

/// SampleInBall: generate the challenge polynomial c with exactly tau nonzero
/// coefficients in {-1, +1} from seed ctilde.
pub fn poly_challenge(c: &mut Poly, ctilde: &[u8], tau: u8) {
    // SampleInBall sets only tau positions, so the rest has to start at
    // zero. Cleared eight words at a time rather than through the loop the
    // compiler turns into a `memset`; this runs once per attempt.
    //
    // SAFETY: `c` is a whole polynomial, word aligned, and every byte of it
    // is written.
    unsafe { crate::fast_zero(c.as_mut_ptr().cast(), core::mem::size_of::<Poly>()) };

    let mut ctx = shake256_init();
    ctx.absorb(ctilde);
    ctx.finalize();

    // One rate block covers the eight sign bytes plus the tau shuffle draws
    // in all but vanishingly rare cases; refill only if it runs out.
    let mut buf = [0u8; SHAKE256_RATE];
    ctx.squeeze(&mut buf);

    // First 8 bytes determine the signs
    let mut signs: u64 = 0;
    for i in 0..8 {
        signs |= (buf[i] as u64) << (8 * i);
    }
    let mut pos = 8;

    // Fisher-Yates shuffle for positions
    for i in (N - tau as usize)..N {
        let j: usize;
        loop {
            if pos == SHAKE256_RATE {
                ctx.squeeze(&mut buf);
                pos = 0;
            }
            let b = buf[pos] as usize;
            pos += 1;
            if b <= i {
                j = b;
                break;
            }
        }
        c[i] = c[j];
        c[j] = 1 - 2 * (signs & 1) as i32;
        signs >>= 1;
    }
}
