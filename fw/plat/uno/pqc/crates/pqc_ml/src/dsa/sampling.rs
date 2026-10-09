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
use crate::keccak::SHAKE128_RATE;
use crate::keccak::SHAKE256_RATE;

/// ExpandA: Generate a single element A[i][j] of the public matrix from seed rho.
/// Uses SHAKE128(rho || j || i) with rejection sampling.
///
/// The sponge is squeezed a whole rate block at a time. Extracting three
/// bytes per call instead costs a full lane de-interleave per sample, which
/// dominated the cost of this routine.
pub fn poly_uniform(a: &mut Poly, rho: &[u8], i: u8, j: u8) {
    let mut ctx = shake128_init();
    ctx.absorb(rho);
    ctx.absorb(&[j, i]);
    ctx.finalize();

    let mut ctr = 0;
    let mut buf = [0u8; SHAKE128_RATE];
    while ctr < N {
        ctx.squeeze(&mut buf);
        let mut pos = 0;
        while pos + 3 <= SHAKE128_RATE && ctr < N {
            // 3-byte rejection sampling
            let d = (buf[pos] as u32)
                | ((buf[pos + 1] as u32) << 8)
                | (((buf[pos + 2] & 0x7F) as u32) << 16);
            pos += 3;
            if d < Q {
                a[ctr] = d as i32;
                ctr += 1;
            }
        }
    }
}

/// SampleEta: sample a polynomial with coefficients in [-eta, eta].
/// Uses SHAKE256(seed || nonce).
pub fn poly_sample_eta(a: &mut Poly, seed: &[u8], nonce: u16, eta: u8) {
    let mut ctx = shake256_init();
    ctx.absorb(seed);
    ctx.absorb(&nonce.to_le_bytes());
    ctx.finalize();

    match eta {
        2 => sample_eta2(&mut ctx, a),
        4 => sample_eta4(&mut ctx, a),
        _ => {}
    }
}

fn sample_eta2(ctx: &mut ShakeCtx, a: &mut Poly) {
    // eta=2: sample from {0,1,2,3,4}, map to {-2,-1,0,1,2}
    // Each byte gives 2 samples: low nibble and high nibble
    // t0 mod 5 - 2 where t0 is a 3-bit value... no, for eta=2:
    // Use rejection: sample 4-bit values, accept if < 5 (but simpler below)
    // Actually FIPS 204 uses: each byte → 2 samples via t0 = byte & 0xF, t1 = byte >> 4
    // Then: s = t0 mod 5 ... no.
    //
    // FIPS 204 eta=2 sampling (Algorithm 14 "CoeffFromHalfByte"):
    // if eta=2 and b < 15: return b mod 5 - eta
    // But simpler approach used by reference implementation:
    // Extract nibbles, reject if >= 15
    let mut ctr = 0;
    let mut buf = [0u8; SHAKE256_RATE];
    let mut pos = SHAKE256_RATE;
    while ctr < N {
        if pos == SHAKE256_RATE {
            ctx.squeeze(&mut buf);
            pos = 0;
        }
        let byte = buf[pos];
        pos += 1;
        let t0 = byte & 0x0F;
        let t1 = byte >> 4;
        if t0 < 15 {
            a[ctr] = 2 - (t0 as i32 % 5);
            // Actually the formula is: (t0 % 5) gives 0..4, then eta - result
            // which is 2 - (t0 % 5), range: -2..2 ✓
            // Correction: the FIPS says return (b mod 5) and then sign is embedded
            // Actually for eta=2: return 2 - (b mod 5), range [−2, 2]
            // Wait, let me re-check: b mod 5 ∈ {0,1,2,3,4}, so eta - (b mod 5) = 2 - {0,1,2,3,4} = {2,1,0,-1,-2}
            ctr += 1;
        }
        if ctr < N && t1 < 15 {
            a[ctr] = 2 - (t1 as i32 % 5);
            ctr += 1;
        }
    }
}

fn sample_eta4(ctx: &mut ShakeCtx, a: &mut Poly) {
    // eta=4: each nibble directly gives value in {0..8}, map to 4 - nibble = {-4..4}
    // No rejection needed since all 4-bit values 0..8 are valid... wait:
    // Actually for eta=4, b < 9: return 4 - b. 4-bit nibble is 0..15.
    // Reject if nibble >= 9.
    let mut ctr = 0;
    let mut buf = [0u8; SHAKE256_RATE];
    let mut pos = SHAKE256_RATE;
    while ctr < N {
        if pos == SHAKE256_RATE {
            ctx.squeeze(&mut buf);
            pos = 0;
        }
        let byte = buf[pos];
        pos += 1;
        let t0 = byte & 0x0F;
        let t1 = byte >> 4;
        if t0 < 9 {
            a[ctr] = 4 - t0 as i32;
            ctr += 1;
        }
        if ctr < N && t1 < 9 {
            a[ctr] = 4 - t1 as i32;
            ctr += 1;
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
pub fn expand_mask_bytes(out: &mut [u8], seed: &[u8], nonce: u16) {
    let mut ctx = shake256_init();
    ctx.absorb(seed);
    ctx.absorb(&nonce.to_le_bytes());
    ctx.finalize();
    ctx.squeeze(out);
}

/// ExpandMask, second half: unpack the stream into coefficients in
/// [-(gamma1-1), gamma1].
pub fn unpack_gamma1(a: &mut Poly, buf: &[u8], gamma1: u32) {
    match gamma1 {
        131072 => unpack_gamma1_17(buf, a),
        524288 => unpack_gamma1_19(buf, a),
        _ => {}
    }
}

fn unpack_gamma1_17(buf: &[u8], a: &mut Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &buf[..576];
    // 18 bits per coefficient, packed little-endian
    // gamma1 = 2^17, coefficients in [-(2^17-1), 2^17]
    // Stored as gamma1 - coeff, so value in [0, 2*gamma1]
    for i in 0..N / 4 {
        // 4 coefficients from 9 bytes
        let off = 9 * i;
        a[4 * i] = (buf[off] as i32)
            | ((buf[off + 1] as i32) << 8)
            | (((buf[off + 2] & 0x03) as i32) << 16);
        a[4 * i] = (1 << 17) - a[4 * i];

        a[4 * i + 1] = ((buf[off + 2] as i32) >> 2)
            | ((buf[off + 3] as i32) << 6)
            | (((buf[off + 4] & 0x0F) as i32) << 14);
        a[4 * i + 1] = (1 << 17) - a[4 * i + 1];

        a[4 * i + 2] = ((buf[off + 4] as i32) >> 4)
            | ((buf[off + 5] as i32) << 4)
            | (((buf[off + 6] & 0x3F) as i32) << 12);
        a[4 * i + 2] = (1 << 17) - a[4 * i + 2];

        a[4 * i + 3] = ((buf[off + 6] as i32) >> 6)
            | ((buf[off + 7] as i32) << 2)
            | ((buf[off + 8] as i32) << 10);
        a[4 * i + 3] = (1 << 17) - a[4 * i + 3];
    }
}

fn unpack_gamma1_19(buf: &[u8], a: &mut Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &buf[..640];
    // 20 bits per coefficient
    // gamma1 = 2^19, stored as gamma1 - coeff
    for i in 0..N / 2 {
        let off = 5 * i;
        a[2 * i] = (buf[off] as i32)
            | ((buf[off + 1] as i32) << 8)
            | (((buf[off + 2] & 0x0F) as i32) << 16);
        a[2 * i] = (1 << 19) - a[2 * i];

        a[2 * i + 1] = ((buf[off + 2] as i32) >> 4)
            | ((buf[off + 3] as i32) << 4)
            | ((buf[off + 4] as i32) << 12);
        a[2 * i + 1] = (1 << 19) - a[2 * i + 1];
    }
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
