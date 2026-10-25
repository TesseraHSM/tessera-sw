// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// ML-KEM sampling: ExpandA (SHAKE128) and CBD (centered binomial).
use super::params::N;
/// ML-KEM sampling: ExpandA (SHAKE128) and CBD (centered binomial).
use super::params::Q;
use super::poly::Poly;
use crate::keccak::shake128_init;
use crate::keccak::shake256_init;
use crate::keccak::XofPrefix;
use crate::keccak::SHAKE128_RATE;

/// ExpandA: generate one matrix element from SHAKE128(rho || j || i).
/// Rejection sampling mod q=3329, exactly like ML-DSA but with 12-bit extraction.
///
/// Squeezed a whole rate block at a time: see `dsa::sampling::poly_uniform`.
pub fn poly_uniform(a: &mut Poly, rho: &XofPrefix, i: u8, j: u8) {
    // FIPS 203 / Kyber: XOF(ρ, i, j) = SHAKE128(ρ ‖ j ‖ i)  — column, row order
    let mut ctx = shake128_init();
    ctx.absorb_xof(rho, u16::from_le_bytes([j, i]), 2);

    // Three little-endian words hold eight 12-bit candidates, so each one
    // is a shift (and at most one OR) and a mask rather than byte loads.
    let mut buf = [0u32; SHAKE128_RATE / 4];
    let mut ctr = 0;
    while ctr < N {
        ctx.squeeze_words(&mut buf);
        let groups = buf.as_chunks::<3>().0;

        // As in `dsa::sampling::poly_uniform`: `asm/rej.S` takes every
        // group sure to fit, the loop below the rest.
        #[cfg(target_arch = "arm")]
        let groups = {
            extern "C" {
                fn pqc_ml_kem_rej(a: *mut i16, ctr: u32, buf: *const u32, groups: u32) -> u32;
            }
            // SAFETY: `a` has room for N coefficients and the routine stores
            // at most N - ctr of them; `buf` holds the groups it reads.
            let r = unsafe {
                pqc_ml_kem_rej(
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
                let d = (d & 0xFFF) as u16;
                if d < Q && ctr < N {
                    a[ctr] = d as i16;
                    ctr += 1;
                }
            };
            take(w0);
            take(w0 >> 12);
            take((w0 >> 24) | (w1 << 8));
            take(w1 >> 4);
            take(w1 >> 16);
            take((w1 >> 28) | (w2 << 4));
            take(w2 >> 8);
            take(w2 >> 20);
        }
    }
}

/// CBD(eta): Centered Binomial Distribution sampling from PRF output.
/// Uses SHAKE256(seed || nonce) to generate eta*N/4 bytes, then
/// each coefficient = (sum of eta bits) - (sum of eta bits).
pub fn poly_cbd(r: &mut Poly, seed: &XofPrefix, nonce: u8, eta: u8) {
    let mut ctx = shake256_init();
    ctx.absorb_xof(seed, nonce as u16, 1);

    // 2 * eta bits a coefficient, as words for `asm/kem_cbd.S` -- and room
    // for one more than eta = 3's 48, since its `cbd3` reads every 3-byte
    // group as a word.
    let mut buf = [0u32; CBD_WORDS];
    ctx.squeeze_words(&mut buf[..eta as usize * N / 16]);

    match eta {
        2 => cbd2(r, &buf),
        3 => cbd3(r, &buf),
        _ => {}
    }
}

const CBD_WORDS: usize = 3 * N / 16 + 1;

#[cfg(target_arch = "arm")]
extern "C" {
    fn pqc_ml_kem_cbd2(r: *mut i16, buf: *const u32);
    fn pqc_ml_kem_cbd3(r: *mut i16, buf: *const u32);
}

fn cbd2(r: &mut Poly, buf: &[u32; CBD_WORDS]) {
    // SAFETY: `r` has room for the N coefficients stored and `buf` holds
    // the N / 8 words read.
    #[cfg(target_arch = "arm")]
    unsafe {
        pqc_ml_kem_cbd2(r.as_mut_ptr(), buf.as_ptr())
    };

    // eta=2: 4 bits per coefficient (2 + 2)
    #[cfg(not(target_arch = "arm"))]
    for i in 0..N / 8 {
        let t = u32::from_le(buf[i]);
        let d = (t & 0x55555555) + ((t >> 1) & 0x55555555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            r[8 * i + j] = a - b;
        }
    }
}

fn cbd3(r: &mut Poly, buf: &[u32; CBD_WORDS]) {
    // SAFETY: `r` has room for the N coefficients stored, and `buf` the
    // 3 * N / 4 + 1 bytes read -- the last group's word runs one past.
    #[cfg(target_arch = "arm")]
    unsafe {
        pqc_ml_kem_cbd3(r.as_mut_ptr(), buf.as_ptr())
    };

    // eta=3: 6 bits per coefficient (3 + 3), 3 bytes → 4 coefficients
    #[cfg(not(target_arch = "arm"))]
    for i in 0..N / 4 {
        let byte = |k: usize| (u32::from_le(buf[k / 4]) >> (8 * (k % 4))) & 0xFF;
        let t = byte(3 * i) | (byte(3 * i + 1) << 8) | (byte(3 * i + 2) << 16);
        let d = (t & 0x249249) + ((t >> 1) & 0x249249) + ((t >> 2) & 0x249249);
        for j in 0..4 {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            r[4 * i + j] = a - b;
        }
    }
}
