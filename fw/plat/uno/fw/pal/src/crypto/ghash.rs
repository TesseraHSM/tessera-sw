// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GHASH (NIST SP 800-38D) for the Uno PAL's AES-GCM.
//!
//! GHASH processes input in 16-byte blocks over `GF(2^128)`.  The
//! accumulator is updated as:
//!
//! `Y_i = (Y_{i-1} ⊕ X_i) · H`
//!
//! The multiplication is table-driven (Shoup's 4-bit method): [`Ghash`]
//! precomputes `H`'s sixteen small multiples once per key and then
//! consumes the state four bits at a time, 32 rounds per block instead
//! of 128. See [`Ghash::mul_by_h`] for why the table lookups are
//! constant-time on the HSM and what would break that.

/// GHASH accumulator over `GF(2^128)`.
///
/// Processes arbitrary-length input in 16-byte blocks, zero-padding
/// any partial tail block, and produces a 16-byte authentication hash.
///
/// Carries a 256-byte table of `H`'s small multiples, built once in
/// [`Ghash::new`] and reused for every block, so the per-block cost is
/// 32 table-driven rounds rather than 128 bit-serial ones. Deliberately
/// neither `Copy` nor `Clone`: the table makes a copy expensive, and
/// nothing needs one.
#[derive(Debug)]
pub(super) struct Ghash {
    /// `H`'s multiples, high and low halves: entry `i` is `i · H`.
    hh: [u64; 16],
    hl: [u64; 16],

    /// Running authentication state.
    y: [u8; 16],
}

impl Ghash {
    /// Create a new GHASH accumulator from a 16-byte hash subkey `H`.
    ///
    /// Returns `None` when `h.len() != 16`.
    pub(super) fn new(h: &[u8]) -> Option<Self> {
        let h: &[u8; 16] = h.try_into().ok()?;

        let mut hh = [0u64; 16];
        let mut hl = [0u64; 16];

        let mut vh = u64::from_be_bytes(h[..8].try_into().ok()?);
        let mut vl = u64::from_be_bytes(h[8..].try_into().ok()?);

        // Entry 8 is H itself: index bits are read most-significant
        // first, so 0b1000 selects one times H.
        hh[8] = vh;
        hl[8] = vl;

        // Entries 4, 2, 1 are successive halvings of H -- the same
        // shift-and-reduce step the bit-serial form ran 128 times, here
        // run three times and then reused.
        let mut i = 4;
        while i > 0 {
            let carry = (vl & 1) * 0xe100_0000;
            vl = (vh << 63) | (vl >> 1);
            vh = (vh >> 1) ^ (carry << 32);
            hh[i] = vh;
            hl[i] = vl;
            i >>= 1;
        }

        // The rest are sums of those, since multiplication by a nibble
        // is linear: 0b1010 · H = 0b1000 · H ⊕ 0b0010 · H.
        let mut i = 2;
        while i <= 8 {
            let (base_h, base_l) = (hh[i], hl[i]);
            for j in 1..i {
                hh[i + j] = base_h ^ hh[j];
                hl[i + j] = base_l ^ hl[j];
            }
            i *= 2;
        }

        Some(Self {
            hh,
            hl,
            y: [0u8; 16],
        })
    }

    /// Absorb `data`, zero-padding the final block to 16 bytes.
    ///
    /// Follows the GHASH update rule: each block is XORed into the
    /// running state before a finite-field multiplication by `H`.
    pub(super) fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            xor_block_arr(&mut self.y, &block);
            self.mul_by_h();
        }
    }

    /// Multiply the running state by `H`, four bits at a time.
    ///
    /// Walks `y` from its least-significant byte, folding in one table
    /// entry per nibble and shifting the accumulator down by four bits
    /// between entries. [`LAST4`] supplies the reduction residue for the
    /// four bits each shift discards, which is what keeps the result in
    /// the field without a second pass.
    ///
    /// ## Constant-time only because the HSM has no data cache
    ///
    /// The nibbles indexing `hh`/`hl`/[`LAST4`] are derived from the
    /// running state, which depends on the key. On a core with a data
    /// cache these lookups would leak it through timing -- the classic
    /// attack on table-driven `GF(2^128)`. They are safe here because
    /// the HSM runs with the D-cache **off**: `SCB_EnableDCache` is defined
    /// by CMSIS but never called anywhere in the tree, and Cortex-M7
    /// comes out of reset with it disabled, so every access lands in
    /// SRAM at a fixed cost.
    ///
    /// **If the D-cache is ever enabled, this must go back to the
    /// bit-serial form** (or preload the table per block), and the
    /// tables must be treated as key material for the purpose.
    fn mul_by_h(&mut self) {
        let x = self.y;

        let nibble = (x[15] & 0x0f) as usize;
        let mut zh = self.hh[nibble];
        let mut zl = self.hl[nibble];

        for i in (0..16).rev() {
            let lo = (x[i] & 0x0f) as usize;
            let hi = (x[i] >> 4) as usize;

            // The first low nibble is already folded in above, so the
            // top of the loop skips it exactly once.
            if i != 15 {
                let rem = (zl & 0x0f) as usize;
                zl = (zh << 60) | (zl >> 4);
                zh = (zh >> 4) ^ (LAST4[rem] << 48);
                zh ^= self.hh[lo];
                zl ^= self.hl[lo];
            }

            let rem = (zl & 0x0f) as usize;
            zl = (zh << 60) | (zl >> 4);
            zh = (zh >> 4) ^ (LAST4[rem] << 48);
            zh ^= self.hh[hi];
            zl ^= self.hl[hi];
        }

        self.y[..8].copy_from_slice(&zh.to_be_bytes());
        self.y[8..].copy_from_slice(&zl.to_be_bytes());
    }

    /// Return the final GHASH value as a byte array.
    pub(super) fn finish(self) -> [u8; 16] {
        self.y
    }
}

/// Reduction residues for the four bits each shift-by-four discards.
///
/// Entry `i` is the value the polynomial `x^128 + x^7 + x^2 + x + 1`
/// folds back when nibble `i` falls off the bottom of the accumulator.
const LAST4: [u64; 16] = [
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940, 0xc560,
    0x9180, 0x8da0, 0xa9c0, 0xb5e0,
];

/// XOR 16 bytes of `src` into `dst` (fixed-size array variant).
fn xor_block_arr(dst: &mut [u8; 16], src: &[u8; 16]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::Ghash;

    #[test]
    fn ghash_matches_nist_gcm_test_case() {
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let ciphertext = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        let lengths = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128];

        let mut ghash = Ghash::new(&h).expect("valid H");
        ghash.update(&ciphertext);
        ghash.update(&lengths);

        assert_eq!(
            ghash.finish(),
            [
                0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc, 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0,
                0xf8, 0x85,
            ]
        );
    }
}
