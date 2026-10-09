// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// ML-KEM byte encoding/decoding (12-bit polynomial packing).
use super::params::N;
use super::poly::Poly;

/// Encode polynomial with 12-bit coefficients (384 bytes).
/// Converts from centered [-q/2, q/2] to unsigned [0, q) before encoding.
pub fn byte_encode_12(r: &mut [u8], a: &Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let r = &mut r[..384];
    for i in 0..N / 2 {
        let mut t0 = a[2 * i] as i32;
        t0 += (t0 >> 31) & super::params::Q as i32;
        let mut t1 = a[2 * i + 1] as i32;
        t1 += (t1 >> 31) & super::params::Q as i32;
        let t0 = t0 as u16;
        let t1 = t1 as u16;
        r[3 * i] = t0 as u8;
        r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        r[3 * i + 2] = (t1 >> 4) as u8;
    }
}

/// Decode polynomial from 12-bit encoding (384 bytes).
pub fn byte_decode_12(a: &mut Poly, buf: &[u8]) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &buf[..384];
    for i in 0..N / 2 {
        a[2 * i] = ((buf[3 * i] as u16) | (((buf[3 * i + 1] & 0x0F) as u16) << 8)) as i16;
        a[2 * i + 1] = (((buf[3 * i + 1] >> 4) as u16) | ((buf[3 * i + 2] as u16) << 4)) as i16;
    }
}

/// Encode polynomial with 1-bit coefficients (32 bytes) — for message encoding.
pub fn byte_encode_1(r: &mut [u8], a: &Poly) {
    for i in 0..N / 8 {
        r[i] = 0;
        for j in 0..8 {
            r[i] |= ((a[8 * i + j] & 1) as u8) << j;
        }
    }
}

/// Decode polynomial from 1-bit encoding (32 bytes).
pub fn byte_decode_1(a: &mut Poly, buf: &[u8]) {
    for i in 0..N / 8 {
        for j in 0..8 {
            a[8 * i + j] = ((buf[i] >> j) & 1) as i16;
        }
    }
}
