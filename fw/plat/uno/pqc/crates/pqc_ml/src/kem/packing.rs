// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// ML-KEM byte encoding/decoding (12-bit polynomial packing).
use super::params::N;
use super::poly::Poly;

/// Encode polynomial with 12-bit coefficients (384 bytes).
/// Converts from centered [-q/2, q/2] to unsigned [0, q) before encoding.
///
/// Eight coefficients fill exactly three little-endian words, so each
/// group is a few shifts and three word stores rather than a byte store
/// for every one and a half coefficients.
pub fn byte_encode_12(r: &mut [u8], a: &Poly) {
    // Whole words, stored as `[u8; 4]` arrays: a `copy_from_slice` of a
    // four-byte subslice is two out-of-line calls at this opt-level, six per
    // eight coefficients, which cost more than the byte stores they replace.
    let out = r[..384].as_chunks_mut::<4>().0.as_chunks_mut::<3>().0;
    for (out, c) in out.iter_mut().zip(a.as_chunks::<8>().0) {
        let t = |i: usize| {
            let x = c[i] as i32;
            (x + ((x >> 31) & super::params::Q as i32)) as u32
        };
        out[0] = (t(0) | (t(1) << 12) | (t(2) << 24)).to_le_bytes();
        out[1] = ((t(2) >> 8) | (t(3) << 4) | (t(4) << 16) | (t(5) << 28)).to_le_bytes();
        out[2] = ((t(5) >> 4) | (t(6) << 8) | (t(7) << 20)).to_le_bytes();
    }
}

/// Decode polynomial from 12-bit encoding (384 bytes), three words per
/// eight coefficients as [`byte_encode_12`] packs them.
pub fn byte_decode_12(a: &mut Poly, buf: &[u8]) {
    for (c, inp) in a
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(buf[..384].as_chunks::<12>().0)
    {
        let w = |k: usize| {
            u32::from_le_bytes([inp[4 * k], inp[4 * k + 1], inp[4 * k + 2], inp[4 * k + 3]])
        };
        let (w0, w1, w2) = (w(0), w(1), w(2));
        c[0] = (w0 & 0xFFF) as i16;
        c[1] = ((w0 >> 12) & 0xFFF) as i16;
        c[2] = (((w0 >> 24) | (w1 << 8)) & 0xFFF) as i16;
        c[3] = ((w1 >> 4) & 0xFFF) as i16;
        c[4] = ((w1 >> 16) & 0xFFF) as i16;
        c[5] = (((w1 >> 28) | (w2 << 4)) & 0xFFF) as i16;
        c[6] = ((w2 >> 8) & 0xFFF) as i16;
        c[7] = (w2 >> 20) as i16;
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
