// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// Bit-packing and unpacking routines for ML-DSA keys and signatures.
use super::params::D;
/// Bit-packing and unpacking routines for ML-DSA keys and signatures.
use super::params::N;
use super::poly::Poly;

// ---- t1 packing: 10 bits per coefficient, 320 bytes per poly ----

pub fn pack_t1(buf: &mut [u8], a: &Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &mut buf[..320];
    for i in 0..N / 4 {
        let off = 5 * i;
        buf[off] = (a[4 * i] & 0xFF) as u8;
        buf[off + 1] = ((a[4 * i] >> 8) | (a[4 * i + 1] << 2)) as u8;
        buf[off + 2] = ((a[4 * i + 1] >> 6) | (a[4 * i + 2] << 4)) as u8;
        buf[off + 3] = ((a[4 * i + 2] >> 4) | (a[4 * i + 3] << 6)) as u8;
        buf[off + 4] = (a[4 * i + 3] >> 2) as u8;
    }
}

pub fn unpack_t1(a: &mut Poly, buf: &[u8]) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &buf[..320];
    for i in 0..N / 4 {
        let off = 5 * i;
        a[4 * i] = ((buf[off] as i32) | ((buf[off + 1] as i32) << 8)) & 0x3FF;
        a[4 * i + 1] = (((buf[off + 1] as i32) >> 2) | ((buf[off + 2] as i32) << 6)) & 0x3FF;
        a[4 * i + 2] = (((buf[off + 2] as i32) >> 4) | ((buf[off + 3] as i32) << 4)) & 0x3FF;
        a[4 * i + 3] = (((buf[off + 3] as i32) >> 6) | ((buf[off + 4] as i32) << 2)) & 0x3FF;
    }
}

// ---- t0 packing: 13 bits per coefficient (centered), 416 bytes per poly ----

pub fn pack_t0(buf: &mut [u8], a: &Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &mut buf[..416];
    // Coefficients are in [-(2^(d-1)-1), 2^(d-1)] = [-4095, 4096]
    // Store as (1 << (d-1)) - a, so range [0, 2^d)
    for i in 0..N / 8 {
        let off = 13 * i;
        let mut t = [0u32; 8];
        for j in 0..8 {
            t[j] = ((1i32 << (D - 1)) - a[8 * i + j]) as u32;
        }
        buf[off] = t[0] as u8;
        buf[off + 1] = (t[0] >> 8) as u8 | (t[1] << 5) as u8;
        buf[off + 2] = (t[1] >> 3) as u8;
        buf[off + 3] = (t[1] >> 11) as u8 | (t[2] << 2) as u8;
        buf[off + 4] = (t[2] >> 6) as u8 | (t[3] << 7) as u8;
        buf[off + 5] = (t[3] >> 1) as u8;
        buf[off + 6] = (t[3] >> 9) as u8 | (t[4] << 4) as u8;
        buf[off + 7] = (t[4] >> 4) as u8;
        buf[off + 8] = (t[4] >> 12) as u8 | (t[5] << 1) as u8;
        buf[off + 9] = (t[5] >> 7) as u8 | (t[6] << 6) as u8;
        buf[off + 10] = (t[6] >> 2) as u8;
        buf[off + 11] = (t[6] >> 10) as u8 | (t[7] << 3) as u8;
        buf[off + 12] = (t[7] >> 5) as u8;
    }
}

/// Unpack 256 `d`-bit fields, little-endian as FIPS 204's BitPack writes
/// them, as `bias - field`: the form of `t0` (13 bits, bias 2^12), and of
/// `s1`/`s2` for both values of eta (3 or 4 bits, bias eta).
///
/// Signing reads these straight out of the secret key where it lies, in
/// PSRAM, which charges about 35 cycles an access whether the access is a
/// byte or a word. Taking the stream a word at a time is a quarter of the
/// accesses the byte-wise unpackers made, and one routine for all three
/// shapes is smaller than any one of them was.
#[inline(never)]
pub(crate) fn unpack_centered(a: &mut Poly, buf: &[u8], d: u32, bias: i32) {
    // The stream is 8d words. It is first copied into the top of `a` --
    // from PSRAM a burst of eight words at a time, where a lone word load
    // costs 35 cycles -- and unpacked from there downwards into `a`, which
    // overtakes no word before reading it: coefficient i is written only
    // after the ceil(d*(i+1)/32) words holding it have been read, and the
    // stream starts 8d words from the end.
    let words = 8 * d as usize;
    let top = N - words;
    let src = &buf[..4 * words];
    #[cfg(target_arch = "arm")]
    let staged = (src.as_ptr() as usize).is_multiple_of(4) && {
        // SAFETY: `a[top..]` holds `words` words, a multiple of eight, and
        // `src` is word aligned and as long.
        unsafe { crate::spill::burst(a.as_mut_ptr().add(top), src.as_ptr().cast(), words) };
        true
    };
    #[cfg(not(target_arch = "arm"))]
    let staged = false;
    if !staged {
        for (k, w) in src.as_chunks::<4>().0.iter().enumerate() {
            a[top + k] = i32::from_le_bytes(*w);
        }
    }

    let mask = (1u32 << d) - 1;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut next = top;
    for i in 0..N {
        let t = if bits >= d {
            let t = acc & mask;
            acc >>= d;
            bits -= d;
            t
        } else {
            let w = a[next] as u32;
            next += 1;
            let t = (acc | (w << bits)) & mask;
            acc = w >> (d - bits);
            bits += 32 - d;
            t
        };
        a[i] = bias - t as i32;
    }
}

// ---- eta packing: parameterized by eta ----

pub fn pack_eta(buf: &mut [u8], a: &Poly, eta: u8) {
    match eta {
        2 => pack_eta2(buf, a),
        4 => pack_eta4(buf, a),
        _ => {}
    }
}

// eta=2: 3 bits per coefficient, pack 8 coefficients into 3 bytes
fn pack_eta2(buf: &mut [u8], a: &Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &mut buf[..96];
    for i in 0..N / 8 {
        let mut t = [0u8; 8];
        for j in 0..8 {
            t[j] = (2 - a[8 * i + j]) as u8; // map [-2,2] -> [0,4]
        }
        buf[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
        buf[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        buf[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
}

// eta=4: 4 bits per coefficient, pack 2 coefficients per byte
fn pack_eta4(buf: &mut [u8], a: &Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &mut buf[..128];
    for i in 0..N / 2 {
        let t0 = (4 - a[2 * i]) as u8;
        let t1 = (4 - a[2 * i + 1]) as u8;
        buf[i] = t0 | (t1 << 4);
    }
}

// ---- z packing (gamma1-bounded) ----

pub fn pack_z(buf: &mut [u8], a: &Poly, gamma1: u32) {
    match gamma1 {
        131072 => pack_z17(buf, a),
        524288 => pack_z19(buf, a),
        _ => {}
    }
}

/// BitUnpack of z, gamma1 - field: the same encoding as the signer's y, so
/// the same unpacker.
pub fn unpack_z(a: &mut Poly, buf: &[u8], gamma1: u32) {
    super::sampling::unpack_gamma1(a, buf, gamma1);
}

// gamma1 = 2^17: 18 bits per coefficient, stored as gamma1 - coeff
fn pack_z17(buf: &mut [u8], a: &Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &mut buf[..576];
    for i in 0..N / 4 {
        let mut t = [0u32; 4];
        for j in 0..4 {
            t[j] = ((1i32 << 17) - a[4 * i + j]) as u32;
        }
        let off = 9 * i;
        buf[off] = t[0] as u8;
        buf[off + 1] = (t[0] >> 8) as u8;
        buf[off + 2] = ((t[0] >> 16) | (t[1] << 2)) as u8;
        buf[off + 3] = (t[1] >> 6) as u8;
        buf[off + 4] = ((t[1] >> 14) | (t[2] << 4)) as u8;
        buf[off + 5] = (t[2] >> 4) as u8;
        buf[off + 6] = ((t[2] >> 12) | (t[3] << 6)) as u8;
        buf[off + 7] = (t[3] >> 2) as u8;
        buf[off + 8] = (t[3] >> 10) as u8;
    }
}

// gamma1 = 2^19: 20 bits per coefficient
fn pack_z19(buf: &mut [u8], a: &Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &mut buf[..640];
    for i in 0..N / 2 {
        let t0 = ((1i32 << 19) - a[2 * i]) as u32;
        let t1 = ((1i32 << 19) - a[2 * i + 1]) as u32;
        let off = 5 * i;
        buf[off] = t0 as u8;
        buf[off + 1] = (t0 >> 8) as u8;
        buf[off + 2] = ((t0 >> 16) | (t1 << 4)) as u8;
        buf[off + 3] = (t1 >> 4) as u8;
        buf[off + 4] = (t1 >> 12) as u8;
    }
}

// ---- w1 packing ----

pub fn pack_w1(buf: &mut [u8], a: &Poly, gamma2: u32) {
    match gamma2 {
        95232 => pack_w1_6bit(buf, a),  // 6 bits
        261888 => pack_w1_4bit(buf, a), // 4 bits
        _ => {}
    }
}

// gamma2 = (q-1)/88: w1 in [0, 43], 6 bits per coefficient
fn pack_w1_6bit(buf: &mut [u8], a: &Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &mut buf[..192];
    for i in 0..N / 4 {
        let off = 3 * i;
        buf[off] = (a[4 * i] | (a[4 * i + 1] << 6)) as u8;
        buf[off + 1] = ((a[4 * i + 1] >> 2) | (a[4 * i + 2] << 4)) as u8;
        buf[off + 2] = ((a[4 * i + 2] >> 4) | (a[4 * i + 3] << 2)) as u8;
    }
}

// gamma2 = (q-1)/32: w1 in [0, 15], 4 bits per coefficient
fn pack_w1_4bit(buf: &mut [u8], a: &Poly) {
    // Narrow to the exact encoded length once, so the byte accesses
    // below are provably in range and carry no bounds check each.
    let buf = &mut buf[..128];
    for i in 0..N / 2 {
        buf[i] = (a[2 * i] | (a[2 * i + 1] << 4)) as u8;
    }
}

// ---- Hint packing ----

/// Pack hint vector h (k polynomials) into signature format.
/// Returns the number of nonzero hints, or -1 if > omega.
pub fn pack_hints(buf: &mut [u8], h: &[Poly], k: usize, omega: u8) -> i32 {
    let mut cnt = 0u32;
    let mut idx = 0usize;

    for i in 0..k {
        for j in 0..N {
            if h[i][j] != 0 {
                if cnt >= omega as u32 {
                    return -1;
                }
                buf[idx] = j as u8;
                idx += 1;
                cnt += 1;
            }
        }
        buf[omega as usize + i] = cnt as u8;
    }

    // Zero-fill remaining positions
    while idx < omega as usize {
        buf[idx] = 0;
        idx += 1;
    }

    cnt as i32
}

/// Unpack hints from signature. Returns true if valid.
pub fn unpack_hints(h: &mut [Poly], buf: &[u8], k: usize, omega: u8) -> bool {
    for i in 0..k {
        for j in 0..N {
            h[i][j] = 0;
        }
    }

    let mut prev = 0u8;
    for i in 0..k {
        let limit = buf[omega as usize + i];
        if limit < prev || limit > omega {
            return false;
        }
        for j in prev..limit {
            let idx = buf[j as usize] as usize;
            if idx >= N {
                return false;
            }
            // Check strictly increasing within each polynomial
            if j > prev && buf[j as usize] <= buf[(j - 1) as usize] {
                return false;
            }
            h[i][idx] = 1;
        }
        prev = limit;
    }

    // Check remaining bytes are zero
    for i in prev as usize..omega as usize {
        if buf[i] != 0 {
            return false;
        }
    }

    true
}
