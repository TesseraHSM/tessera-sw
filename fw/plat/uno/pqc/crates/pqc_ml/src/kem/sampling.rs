// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// ML-KEM sampling: ExpandA (SHAKE128) and CBD (centered binomial).
use super::params::N;
/// ML-KEM sampling: ExpandA (SHAKE128) and CBD (centered binomial).
use super::params::Q;
use super::poly::Poly;
use crate::keccak::shake128_init;
use crate::keccak::shake256_init;
use crate::keccak::SHAKE128_RATE;

/// ExpandA: generate one matrix element from SHAKE128(rho || j || i).
/// Rejection sampling mod q=3329, exactly like ML-DSA but with 12-bit extraction.
///
/// Squeezed a whole rate block at a time: see `dsa::sampling::poly_uniform`.
pub fn poly_uniform(a: &mut Poly, rho: &[u8], i: u8, j: u8) {
    let mut ctx = shake128_init();
    ctx.absorb(rho);
    // FIPS 203 / Kyber: XOF(ρ, i, j) = SHAKE128(ρ ‖ j ‖ i)  — column, row order
    ctx.absorb(&[j, i]);
    ctx.finalize();

    // Three little-endian words hold eight 12-bit candidates, so each one
    // is a shift (and at most one OR) and a mask rather than byte loads.
    let mut buf = [0u32; SHAKE128_RATE / 4];
    let mut ctr = 0;
    while ctr < N {
        ctx.squeeze_words(&mut buf);
        for w in buf.as_chunks::<3>().0 {
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
pub fn poly_cbd(r: &mut Poly, seed: &[u8], nonce: u8, eta: u8) {
    let mut ctx = shake256_init();
    ctx.absorb(seed);
    ctx.absorb(&[nonce]);
    ctx.finalize();

    let nbytes = eta as usize * N / 4;
    // Max: eta=3, 192 bytes
    let mut buf = [0u8; 192];
    ctx.squeeze(&mut buf[..nbytes]);

    match eta {
        2 => cbd2(r, &buf),
        3 => cbd3(r, &buf),
        _ => {}
    }
}

fn cbd2(r: &mut Poly, buf: &[u8]) {
    // eta=2: 4 bits per coefficient (2 + 2)
    for i in 0..N / 8 {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let d = (t & 0x55555555) + ((t >> 1) & 0x55555555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            r[8 * i + j] = a - b;
        }
    }
}

fn cbd3(r: &mut Poly, buf: &[u8]) {
    // eta=3: 6 bits per coefficient (3 + 3), 3 bytes → 4 coefficients
    for i in 0..N / 4 {
        let t =
            buf[3 * i] as u32 | ((buf[3 * i + 1] as u32) << 8) | ((buf[3 * i + 2] as u32) << 16);
        let d = (t & 0x249249) + ((t >> 1) & 0x249249) + ((t >> 2) & 0x249249);
        for j in 0..4 {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            r[4 * i + j] = a - b;
        }
    }
}
