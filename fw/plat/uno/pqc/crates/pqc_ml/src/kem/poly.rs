// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::ntt;
/// ML-KEM polynomial operations (i16 coefficients, q=3329).
use super::params::N;
/// ML-KEM polynomial operations (i16 coefficients, q=3329).
use super::params::Q;

/// A polynomial's 256 coefficients, word aligned: the assembly moves two
/// coefficients a word and the transforms two words at a time with
/// `ldrd`/`strd`, which fault on an address that is only halfword aligned.
#[derive(Clone, Copy)]
#[repr(C, align(4))]
pub struct Poly(pub [i16; N]);

impl Poly {
    pub const ZERO: Poly = Poly([0; N]);
}

impl core::ops::Deref for Poly {
    type Target = [i16; N];
    fn deref(&self) -> &[i16; N] {
        &self.0
    }
}

impl core::ops::DerefMut for Poly {
    fn deref_mut(&mut self) -> &mut [i16; N] {
        &mut self.0
    }
}

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

/// Compress every coefficient to `d` bits and pack them little-endian
/// (ByteEncode_d of FIPS 203), `d` in 1..=11.
///
/// One loop serves every `d`, a word at a time. Specialised byte shuffles
/// for each `d` were a little quicker per coefficient but took 0.9 KB of a
/// 32 KB iTCM for what is a few percent of a ciphertext operation.
pub fn poly_compress(r: &mut [u8], a: &Poly, d: u8) {
    let out = &mut r[..32 * d as usize];
    let d = d as u32;
    let mut words = out.as_chunks_mut::<4>().0.iter_mut();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in a.iter() {
        let t = compress(unsigned(c), d as u8) as u32;
        acc |= t << bits;
        bits += d;
        if bits >= 32 {
            if let Some(w) = words.next() {
                *w = acc.to_le_bytes();
            }
            // `bits - d` of `t` went into the word just written; the rest
            // starts the next one. 32 - (bits - d) is at most 11.
            acc = t >> (32 - (bits - d));
            bits -= 32;
        }
    }
}

/// Unpack `d`-bit little-endian values (ByteDecode_d) and decompress them,
/// `d` in 1..=11; the inverse of [`poly_compress`].
pub fn poly_decompress(r: &mut Poly, buf: &[u8], d: u8) {
    let src = &buf[..32 * d as usize];
    let d = d as u32;
    let mask = (1u32 << d) - 1;
    let mut words = src.as_chunks::<4>().0.iter();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in r.iter_mut() {
        let t = if bits >= d {
            let t = acc & mask;
            acc >>= d;
            bits -= d;
            t
        } else {
            let w = words.next().map_or(0, |w| u32::from_le_bytes(*w));
            let t = (acc | (w << bits)) & mask;
            acc = w >> (d - bits);
            bits += 32 - d;
            t
        };
        *c = decompress(t as u16, d as u8) as i16;
    }
}
