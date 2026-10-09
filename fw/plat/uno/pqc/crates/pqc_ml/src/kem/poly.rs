// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::ntt;
/// ML-KEM polynomial operations (i16 coefficients, q=3329).
use super::params::N;
/// ML-KEM polynomial operations (i16 coefficients, q=3329).
use super::params::Q;

pub type Poly = [i16; N];

pub fn poly_zero(p: &mut Poly) {
    for c in p.iter_mut() {
        *c = 0;
    }
}

pub fn poly_add(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r[i] = a[i] + b[i];
    }
}

pub fn poly_sub(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r[i] = a[i] - b[i];
    }
}

pub fn poly_add_inplace(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a[i] += b[i];
    }
}

pub fn poly_reduce(a: &mut Poly) {
    for i in 0..N {
        a[i] = ntt::barrett_reduce(a[i]);
    }
}

/// Convert to unsigned [0, q) for packing.
pub fn poly_to_unsigned(a: &mut Poly) {
    for i in 0..N {
        a[i] = a[i] + ((a[i] >> 15) & Q as i16);
    }
}

/// Reciprocal of q for the division in `compress`: `n / q` is
/// `(n * Q_RECIP) >> Q_RECIP_SHIFT` for every n a compression can produce.
/// The Cortex-M7's divider is not pipelined, and this is on the path of
/// every ciphertext coefficient.
const Q_RECIP: u64 = 10_321_340;
const Q_RECIP_SHIFT: u32 = 35;

/// Compress: round((2^d / q) * x) mod 2^d
pub fn compress(x: u16, d: u8) -> u16 {
    let shifted = (x as u32) << d;
    let n = (shifted + Q as u32 / 2) as u64;
    ((n * Q_RECIP) >> Q_RECIP_SHIFT) as u16 & ((1u16 << d) - 1)
}

/// Decompress: round((q / 2^d) * y)
pub fn decompress(y: u16, d: u8) -> u16 {
    ((y as u32 * Q as u32 + (1 << (d - 1))) >> d) as u16
}

/// Lift a centered coefficient into [0, q).
#[inline(always)]
fn unsigned(x: i16) -> u16 {
    let t = x as i32;
    (t + ((t >> 31) & Q as i32)) as u16
}

pub fn poly_compress(r: &mut [u8], a: &Poly, d: u8) {
    match d {
        4 => {
            // Exact output length, so the byte writes need no check.
            let r = &mut r[..128];
            for i in 0..N / 2 {
                let t0 = compress(unsigned(a[2 * i]), 4);
                let t1 = compress(unsigned(a[2 * i + 1]), 4);
                r[i] = (t0 | (t1 << 4)) as u8;
            }
        }
        5 => {
            // Exact output length, so the byte writes need no check.
            let r = &mut r[..160];
            for i in 0..N / 8 {
                let mut t = [0u16; 8];
                for j in 0..8 {
                    t[j] = compress(unsigned(a[8 * i + j]), 5);
                }
                r[5 * i] = (t[0] | (t[1] << 5)) as u8;
                r[5 * i + 1] = ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7)) as u8;
                r[5 * i + 2] = ((t[3] >> 1) | (t[4] << 4)) as u8;
                r[5 * i + 3] = ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6)) as u8;
                r[5 * i + 4] = ((t[6] >> 2) | (t[7] << 3)) as u8;
            }
        }
        10 => {
            // Exact output length, so the byte writes need no check.
            let r = &mut r[..320];
            for i in 0..N / 4 {
                let mut t = [0u16; 4];
                for j in 0..4 {
                    t[j] = compress(unsigned(a[4 * i + j]), 10);
                }
                r[5 * i] = t[0] as u8;
                r[5 * i + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                r[5 * i + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                r[5 * i + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                r[5 * i + 4] = (t[3] >> 2) as u8;
            }
        }
        11 => {
            // Exact output length, so the byte writes need no check.
            let r = &mut r[..352];
            for i in 0..N / 8 {
                let mut t = [0u16; 8];
                for j in 0..8 {
                    t[j] = compress(unsigned(a[8 * i + j]), 11);
                }
                r[11 * i] = t[0] as u8;
                r[11 * i + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                r[11 * i + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                r[11 * i + 3] = (t[2] >> 2) as u8;
                r[11 * i + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                r[11 * i + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                r[11 * i + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                r[11 * i + 7] = (t[5] >> 1) as u8;
                r[11 * i + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                r[11 * i + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                r[11 * i + 10] = (t[7] >> 3) as u8;
            }
        }
        _ => {}
    }
}

pub fn poly_decompress(r: &mut Poly, buf: &[u8], d: u8) {
    match d {
        4 => {
            // Exact input length, so the byte reads need no check.
            let buf = &buf[..128];
            for i in 0..N / 2 {
                r[2 * i] = decompress(buf[i] as u16 & 0xF, 4) as i16;
                r[2 * i + 1] = decompress(buf[i] as u16 >> 4, 4) as i16;
            }
        }
        5 => {
            // Exact input length, so the byte reads need no check.
            let buf = &buf[..160];
            for i in 0..N / 8 {
                let o = 5 * i;
                r[8 * i] = decompress((buf[o] as u16) & 0x1F, 5) as i16;
                r[8 * i + 1] =
                    decompress(((buf[o] as u16) >> 5 | (buf[o + 1] as u16) << 3) & 0x1F, 5) as i16;
                r[8 * i + 2] = decompress(((buf[o + 1] as u16) >> 2) & 0x1F, 5) as i16;
                r[8 * i + 3] = decompress(
                    ((buf[o + 1] as u16) >> 7 | (buf[o + 2] as u16) << 1) & 0x1F,
                    5,
                ) as i16;
                r[8 * i + 4] = decompress(
                    ((buf[o + 2] as u16) >> 4 | (buf[o + 3] as u16) << 4) & 0x1F,
                    5,
                ) as i16;
                r[8 * i + 5] = decompress(((buf[o + 3] as u16) >> 1) & 0x1F, 5) as i16;
                r[8 * i + 6] = decompress(
                    ((buf[o + 3] as u16) >> 6 | (buf[o + 4] as u16) << 2) & 0x1F,
                    5,
                ) as i16;
                r[8 * i + 7] = decompress(((buf[o + 4] as u16) >> 3) & 0x1F, 5) as i16;
            }
        }
        10 => {
            // Exact input length, so the byte reads need no check.
            let buf = &buf[..320];
            for i in 0..N / 4 {
                let o = 5 * i;
                r[4 * i] =
                    decompress((buf[o] as u16 | ((buf[o + 1] as u16) << 8)) & 0x3FF, 10) as i16;
                r[4 * i + 1] = decompress(
                    (((buf[o + 1] as u16) >> 2) | ((buf[o + 2] as u16) << 6)) & 0x3FF,
                    10,
                ) as i16;
                r[4 * i + 2] = decompress(
                    (((buf[o + 2] as u16) >> 4) | ((buf[o + 3] as u16) << 4)) & 0x3FF,
                    10,
                ) as i16;
                r[4 * i + 3] = decompress(
                    (((buf[o + 3] as u16) >> 6) | ((buf[o + 4] as u16) << 2)) & 0x3FF,
                    10,
                ) as i16;
            }
        }
        11 => {
            // Exact input length, so the byte reads need no check.
            let buf = &buf[..352];
            for i in 0..N / 8 {
                let o = 11 * i;
                r[8 * i] =
                    decompress((buf[o] as u16 | ((buf[o + 1] as u16) << 8)) & 0x7FF, 11) as i16;
                r[8 * i + 1] = decompress(
                    (((buf[o + 1] as u16) >> 3) | ((buf[o + 2] as u16) << 5)) & 0x7FF,
                    11,
                ) as i16;
                r[8 * i + 2] = decompress(
                    (((buf[o + 2] as u16) >> 6)
                        | ((buf[o + 3] as u16) << 2)
                        | ((buf[o + 4] as u16) << 10))
                        & 0x7FF,
                    11,
                ) as i16;
                r[8 * i + 3] = decompress(
                    (((buf[o + 4] as u16) >> 1) | ((buf[o + 5] as u16) << 7)) & 0x7FF,
                    11,
                ) as i16;
                r[8 * i + 4] = decompress(
                    (((buf[o + 5] as u16) >> 4) | ((buf[o + 6] as u16) << 4)) & 0x7FF,
                    11,
                ) as i16;
                r[8 * i + 5] = decompress(
                    (((buf[o + 6] as u16) >> 7)
                        | ((buf[o + 7] as u16) << 1)
                        | ((buf[o + 8] as u16) << 9))
                        & 0x7FF,
                    11,
                ) as i16;
                r[8 * i + 6] = decompress(
                    (((buf[o + 8] as u16) >> 2) | ((buf[o + 9] as u16) << 6)) & 0x7FF,
                    11,
                ) as i16;
                r[8 * i + 7] = decompress(
                    (((buf[o + 9] as u16) >> 5) | ((buf[o + 10] as u16) << 3)) & 0x7FF,
                    11,
                ) as i16;
            }
        }
        _ => {}
    }
}
