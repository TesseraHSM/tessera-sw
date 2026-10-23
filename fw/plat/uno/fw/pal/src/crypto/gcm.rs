// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pure-software AES-GCM for the Uno PAL.
//!
//! AES-GCM combines AES-CTR encryption with GHASH authentication.
//! The caller supplies buffers laid out as `[padded_AAD | text]` where
//! the AAD region is zero-padded to a multiple of [`GCM_AAD_PAD`] bytes
//! per the scheme in `tsra_fw_core_crypto_gcm_buf`.
//!
//! ## GCM operations
//!
//! | Entry point                      | AAD + text layout | Description                        |
//! |----------------------------------|-------------------|------------------------------------|
//! | [`gcm_encrypt_impl`]             | separate src/dst  | Encrypt, separate plaintext/ct     |
//! | [`gcm_encrypt_in_place_impl`]    | single buffer     | Encrypt text in-place, compute tag |
//! | [`gcm_decrypt_impl`]             | separate src/dst  | Verify tag, decrypt to separate    |
//! | [`gcm_decrypt_in_place_impl`]    | single buffer     | Verify tag, decrypt text in-place  |
//!
//! ## AES-GCM algorithm outline (encrypt)
//!
//! 1. Build J₀ from the 96-bit IV: `J₀ = IV ‖ 0³¹ ‖ 1`.
//! 2. Encrypt the text portion using AES-CTR starting at J₀ + 1.
//! 3. Compute GHASH of `(AAD, ciphertext, len(AAD)‖len(C))` using
//!    hash subkey `H = AES_K(0¹²⁸)`.
//! 4. Produce tag: `T = GHASH_result ⊕ AES_K(J₀)`.
//!
//! Decryption reverses the process: verify the tag first, then decrypt.
//!
//! ## GHASH
//!
//! The GHASH authenticator (NIST SP 800-38D) processes input in 16-byte
//! blocks over `GF(2^128)`.  The accumulator is updated as:
//!
//! `Y_i = (Y_{i-1} ⊕ X_i) · H`
//!
//! The multiplication is table-driven (Shoup's 4-bit method): [`Ghash`]
//! precomputes `H`'s sixteen small multiples once per key and then
//! consumes the state four bits at a time, 32 rounds per block instead
//! of 128. See [`Ghash::mul_by_h`] for why the table lookups are
//! constant-time on CP1 and what would break that.
//!
//! GHASH itself is pure software — no DMA, no async — but accepts
//! `DmaBuf` slices for consistency with the PAL calling convention.

use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_uno_drivers_aes::AesMode;
use tsra_fw_uno_drivers_aes::AesOp;

use super::aes::AES_BLOCK_SIZE;
use crate::UnoHsmPal;

// =============================================================================
// Constants
// =============================================================================

/// GCM IV length in bytes (96 bits).
pub const GCM_IV_LEN: usize = 12;

/// GCM authentication tag length in bytes (128 bits).
pub const GCM_TAG_LEN: usize = 16;

/// AAD-padding granularity.  The padded AAD region is always a multiple
/// of this many bytes, matching the convention in `gcm_buf`.
const GCM_AAD_PAD: usize = 32;

/// Byte offset of the 32-bit big-endian counter within a 16-byte CTR
/// block.  GCM places the counter in the last 4 bytes.
const CTR_LOW_OFFSET: usize = 12;

// =============================================================================
// GHASH accumulator
// =============================================================================

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
    /// ## Constant-time only because CP1 has no data cache
    ///
    /// The nibbles indexing `hh`/`hl`/[`LAST4`] are derived from the
    /// running state, which depends on the key. On a core with a data
    /// cache these lookups would leak it through timing -- the classic
    /// attack on table-driven `GF(2^128)`. They are safe here because
    /// CP1 runs with the D-cache **off**: `SCB_EnableDCache` is defined
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

    /// Write the final GHASH value to a 16-byte output buffer.
    fn finish_into(self, out: &mut DmaBuf) -> HsmResult<()> {
        if out.len() != 16 {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        out.copy_from_slice(&self.y);
        Ok(())
    }

    /// Return the final GHASH value as a byte array.
    #[cfg(any(test, feature = "bcp"))]
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
// Buffer layout
// =============================================================================

/// Describes the `[padded_AAD | text]` split inside a GCM buffer.
///
/// Given a buffer of `src_len` bytes and an unpadded `aad_len`, the
/// first `pad_len` bytes hold the zero-padded AAD and the remaining
/// `text_len` bytes hold the plaintext (or ciphertext).
#[derive(Debug, Clone, Copy)]
struct GcmLayout {
    /// Length of the padded AAD region (a multiple of [`GCM_AAD_PAD`]).
    pad_len: usize,

    /// Length of the text (plaintext or ciphertext) that follows the
    /// padded AAD region.
    text_len: usize,
}

impl GcmLayout {
    /// Compute the layout from a total buffer size and an unpadded AAD
    /// length.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::AesGcmInvalidBufferSize`] if the padded AAD
    /// length exceeds the buffer.
    fn new(src_len: usize, aad_len: usize) -> HsmResult<Self> {
        let pad_len = padded_aad_len(aad_len);
        if pad_len > src_len {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        Ok(Self {
            pad_len,
            text_len: src_len - pad_len,
        })
    }

    /// The byte range that covers the text portion of the buffer.
    fn text_range(&self) -> core::ops::Range<usize> {
        self.pad_len..self.pad_len + self.text_len
    }
}

/// Compute the padded AAD length (a multiple of [`GCM_AAD_PAD`]).
///
/// Returns 0 when `aad_len` is 0 (no AAD region at all).
pub(super) fn padded_aad_len(aad_len: usize) -> usize {
    if aad_len == 0 {
        0
    } else {
        (aad_len + GCM_AAD_PAD - 1) & !(GCM_AAD_PAD - 1)
    }
}

/// Byte offset of the unpadded AAD content within the padded region.
///
/// When `aad_len % GCM_AAD_PAD` is in `[1, AES_BLOCK_SIZE]`, the
/// `gcm_buf` convention prepends 16 zero bytes before the AAD content,
/// pushing the real AAD to offset 16.  Otherwise the AAD starts at
/// offset 0.
fn aad_content_offset(aad_len: usize) -> usize {
    let rem = aad_len % GCM_AAD_PAD;
    if rem != 0 && rem <= AES_BLOCK_SIZE {
        AES_BLOCK_SIZE
    } else {
        0
    }
}

/// Extract the unpadded AAD slice from a `[padded_AAD | text]` buffer.
///
/// # Errors
///
/// Returns [`HsmError::AesGcmInvalidBufferSize`] if the AAD content
/// does not fit within the padded region.
fn extract_aad(data: &DmaBuf, aad_len: usize) -> HsmResult<&DmaBuf> {
    let layout = GcmLayout::new(data.len(), aad_len)?;
    let start = aad_content_offset(aad_len);
    if start + aad_len > layout.pad_len {
        return Err(HsmError::AesGcmInvalidBufferSize);
    }
    Ok(&data[start..start + aad_len])
}

// =============================================================================
// J₀ (initial counter block) helpers
// =============================================================================

/// Build the GCM initial counter block J₀ from a 96-bit IV.
///
/// `J₀ = IV ‖ 0x00000001` (12 bytes IV + 4-byte big-endian counter = 1).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArg`] if `iv` is not [`GCM_IV_LEN`] bytes.
fn write_j0(dst: &mut DmaBuf, iv: &DmaBuf) -> HsmResult<()> {
    if iv.len() != GCM_IV_LEN {
        return Err(HsmError::InvalidArg);
    }
    dst[..AES_BLOCK_SIZE].fill(0);
    dst[..GCM_IV_LEN].copy_from_slice(iv);
    dst[15] = 1; // counter = 1 in big-endian
    Ok(())
}

/// Increment the 32-bit big-endian counter in the last 4 bytes of a
/// 16-byte block, wrapping at 2³².  This advances J₀ → J₀ + 1, which
/// is the first counter value used by AES-CTR.
fn increment_counter(block: &mut DmaBuf) {
    let ctr = u32::from_be_bytes([
        block[CTR_LOW_OFFSET],
        block[CTR_LOW_OFFSET + 1],
        block[CTR_LOW_OFFSET + 2],
        block[CTR_LOW_OFFSET + 3],
    ]);
    block[CTR_LOW_OFFSET..CTR_LOW_OFFSET + 4].copy_from_slice(&ctr.wrapping_add(1).to_be_bytes());
}

// =============================================================================
// Tag helpers
// =============================================================================

/// Constant-time comparison of two byte slices.
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// XOR 16 bytes of `src` into `dst` (`DmaBuf` variant).
///
/// # Errors
///
/// Returns [`HsmError::AesGcmInvalidBufferSize`] if either buffer is
/// not exactly [`AES_BLOCK_SIZE`] bytes.
fn xor_block(dst: &mut DmaBuf, src: &DmaBuf) -> HsmResult<()> {
    if dst.len() != AES_BLOCK_SIZE || src.len() != AES_BLOCK_SIZE {
        return Err(HsmError::AesGcmInvalidBufferSize);
    }
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
    Ok(())
}

/// Write the bit-length of `byte_len` as a big-endian 64-bit integer
/// at `dst[offset..offset + 8]`.
///
/// # Errors
///
/// Returns [`HsmError::AesGcmInvalidBufferSize`] if `byte_len` would
/// overflow when multiplied by 8.
fn write_bit_length(dst: &mut DmaBuf, offset: usize, byte_len: usize) -> HsmResult<()> {
    let bits = u64::try_from(byte_len)
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(HsmError::AesGcmInvalidBufferSize)?;
    dst[offset..offset + 8].copy_from_slice(&bits.to_be_bytes());
    Ok(())
}

/// Compute `GHASH(H, AAD, ciphertext)` and write the result to `tag`.
///
/// Follows NIST SP 800-38D § 6.4:
///   `GHASH_H(A ‖ C ‖ len(A)₆₄ ‖ len(C)₆₄)`
///
/// `lengths` is a caller-supplied 16-byte scratch buffer used to hold
/// the `len(A) ‖ len(C)` block.
fn compute_ghash(
    h: &DmaBuf,
    aad: &DmaBuf,
    ciphertext: &DmaBuf,
    lengths: &mut DmaBuf,
    tag: &mut DmaBuf,
) -> HsmResult<()> {
    if h.len() != AES_BLOCK_SIZE || lengths.len() != AES_BLOCK_SIZE || tag.len() != GCM_TAG_LEN {
        return Err(HsmError::AesGcmInvalidBufferSize);
    }

    write_bit_length(lengths, 0, aad.len())?;
    write_bit_length(lengths, 8, ciphertext.len())?;

    let mut ghash = Ghash::new(h).ok_or(HsmError::AesGcmInvalidBufferSize)?;
    ghash.update(aad);
    ghash.update(ciphertext);
    ghash.update(lengths);
    ghash.finish_into(tag)
}

// =============================================================================
// AES-GCM implementation on UnoHsmPal
// =============================================================================

impl UnoHsmPal {
    // ── AES primitives used by GCM ──────────────────────────────────

    /// Single-block AES-ECB encrypt: `output = AES_K(block)`.
    ///
    /// Both `block` and `output` must be exactly [`AES_BLOCK_SIZE`].
    pub(super) async fn ecb_encrypt_block(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        block: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        if block.len() != AES_BLOCK_SIZE || output.len() != AES_BLOCK_SIZE {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        self.alloc_scoped_async(io, async |scope| {
            let input = scope.dma_alloc(AES_BLOCK_SIZE)?;
            input.copy_from_slice(block);
            self.aes_run(AesMode::Ecb, AesOp::Encrypt, key, None, input, output)
                .await
        })
        .await
    }

    /// AES-CTR encrypt/decrypt from `input` into `output`.
    ///
    /// Constructs the initial counter J₀ + 1 from `iv`, then submits a
    /// single AES-CTR command covering the full input.  Empty input is
    /// a no-op.
    async fn ctr_crypt(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        if input.is_empty() {
            return Ok(());
        }
        if output.len() < input.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        self.alloc_scoped_async(io, async |scope| {
            let ctr = scope.dma_alloc(AES_BLOCK_SIZE)?;
            write_j0(ctr, iv)?;
            increment_counter(ctr);
            self.aes_run(
                AesMode::Ctr,
                AesOp::Encrypt,
                key,
                Some(ctr),
                input,
                &mut output[..input.len()],
            )
            .await
        })
        .await
    }

    /// In-place AES-CTR over `data`.
    ///
    /// Copies `data` into a freshly allocated, disjoint scratch buffer and
    /// runs the transform from scratch back into `data`.
    ///
    /// This avoids forming an `&` alias over `data` that would coexist with
    /// the `&mut data` borrow — such overlapping `&`/`&mut` references are
    /// undefined behavior in Rust, even though the AES engine reads each
    /// input block before writing the corresponding output block.
    async fn ctr_crypt_in_place(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        data: &mut DmaBuf,
    ) -> HsmResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.alloc_scoped_async(io, async |scope| {
            let scratch = scope.dma_alloc(data.len())?;
            scratch.copy_from_slice(data);
            self.ctr_crypt(io, key, iv, scratch, data).await
        })
        .await
    }

    // ── GCM tag computation ─────────────────────────────────────────

    /// Compute the GCM authentication tag.
    ///
    /// `T = GHASH(H, AAD, ciphertext) ⊕ AES_K(J₀)`
    ///
    /// where `H = AES_K(0¹²⁸)` and `J₀ = IV ‖ 0x00000001`.
    async fn compute_tag(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad: &DmaBuf,
        ciphertext: &DmaBuf,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        if tag.len() != GCM_TAG_LEN {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        self.alloc_scoped_async(io, async |scope| {
            // H = AES_K(0^128)
            let zero = scope.dma_alloc_zeroed(AES_BLOCK_SIZE)?;
            let h = scope.dma_alloc(AES_BLOCK_SIZE)?;
            self.ecb_encrypt_block(io, key, zero, h).await?;

            // E(K, J₀)
            let j0 = scope.dma_alloc(AES_BLOCK_SIZE)?;
            write_j0(j0, iv)?;
            let ek_j0 = scope.dma_alloc(AES_BLOCK_SIZE)?;
            self.aes_run(AesMode::Ecb, AesOp::Encrypt, key, None, j0, ek_j0)
                .await?;

            // T = GHASH(H, AAD, C) ⊕ E(K, J₀)
            let lengths = scope.dma_alloc(AES_BLOCK_SIZE)?;
            compute_ghash(h, aad, ciphertext, lengths, tag)?;
            xor_block(tag, ek_j0)
        })
        .await
    }

    /// Compute the expected tag and verify it against `expected` in
    /// constant time.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::AesGcmDecryptTagDoesNotMatch`] on mismatch.
    async fn verify_tag(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad: &DmaBuf,
        ciphertext: &DmaBuf,
        expected: &DmaBuf,
    ) -> HsmResult<()> {
        let matches = self
            .alloc_scoped_async(io, async |scope| {
                let computed = scope.dma_alloc(GCM_TAG_LEN)?;
                self.compute_tag(io, key, iv, aad, ciphertext, computed)
                    .await?;
                Ok::<_, HsmError>(constant_time_eq(computed, expected))
            })
            .await?;
        if !matches {
            return Err(HsmError::AesGcmDecryptTagDoesNotMatch);
        }
        Ok(())
    }

    // ── Public GCM entry points ─────────────────────────────────────

    /// AES-GCM encrypt with separate `[padded_AAD | text]` source and
    /// destination buffers.
    ///
    /// The padded-AAD region is copied verbatim; only the text portion
    /// is encrypted via AES-CTR.  The authentication tag covers the
    /// original AAD and the resulting ciphertext.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn gcm_encrypt_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        plaintext: &DmaBuf,
        ciphertext: &mut DmaBuf,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        if tag.len() != GCM_TAG_LEN || ciphertext.len() < plaintext.len() {
            return Err(HsmError::InvalidArg);
        }
        let layout = GcmLayout::new(plaintext.len(), aad_len)?;
        let aad = extract_aad(plaintext, aad_len)?;

        // Copy the padded-AAD region verbatim.
        ciphertext[..layout.pad_len].copy_from_slice(&plaintext[..layout.pad_len]);

        // Encrypt the text portion.
        self.ctr_crypt(
            io,
            key,
            iv,
            &plaintext[layout.text_range()],
            &mut ciphertext[layout.text_range()],
        )
        .await?;

        // Tag covers AAD + encrypted text.
        self.compute_tag(io, key, iv, aad, &ciphertext[layout.text_range()], tag)
            .await
    }

    /// AES-GCM encrypt in-place over `[padded_AAD | text]`.
    ///
    /// The text portion is encrypted via AES-CTR and the tag is
    /// computed over the AAD + resulting ciphertext.
    pub(super) async fn gcm_encrypt_in_place_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        data: &mut DmaBuf,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        if tag.len() != GCM_TAG_LEN {
            return Err(HsmError::InvalidArg);
        }
        let layout = GcmLayout::new(data.len(), aad_len)?;

        self.ctr_crypt_in_place(io, key, iv, &mut data[layout.text_range()])
            .await?;

        let aad = extract_aad(data, aad_len)?;
        self.compute_tag(io, key, iv, aad, &data[layout.text_range()], tag)
            .await
    }

    /// AES-GCM decrypt with separate `[padded_AAD | text]` source and
    /// destination buffers.
    ///
    /// Verifies the tag first (authenticate-then-decrypt).  On tag
    /// mismatch the plaintext buffer is not written.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn gcm_decrypt_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        tag: &DmaBuf,
        ciphertext: &DmaBuf,
        plaintext: &mut DmaBuf,
    ) -> HsmResult<()> {
        if tag.len() != GCM_TAG_LEN || plaintext.len() < ciphertext.len() {
            return Err(HsmError::InvalidArg);
        }
        let layout = GcmLayout::new(ciphertext.len(), aad_len)?;
        let aad = extract_aad(ciphertext, aad_len)?;

        // Authenticate before decrypting.
        self.verify_tag(io, key, iv, aad, &ciphertext[layout.text_range()], tag)
            .await?;

        // Copy padded-AAD and decrypt the text portion.
        plaintext[..layout.pad_len].copy_from_slice(&ciphertext[..layout.pad_len]);
        self.ctr_crypt(
            io,
            key,
            iv,
            &ciphertext[layout.text_range()],
            &mut plaintext[layout.text_range()],
        )
        .await
    }

    /// AES-GCM decrypt in-place over `[padded_AAD | text]`.
    ///
    /// Verifies the tag first (authenticate-then-decrypt).  On tag
    /// mismatch the data buffer is not modified.
    pub(super) async fn gcm_decrypt_in_place_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        tag: &DmaBuf,
        data: &mut DmaBuf,
    ) -> HsmResult<()> {
        if tag.len() != GCM_TAG_LEN {
            return Err(HsmError::InvalidArg);
        }
        let layout = GcmLayout::new(data.len(), aad_len)?;
        let aad = extract_aad(data, aad_len)?;

        // Authenticate before decrypting.
        self.verify_tag(io, key, iv, aad, &data[layout.text_range()], tag)
            .await?;

        self.ctr_crypt_in_place(io, key, iv, &mut data[layout.text_range()])
            .await
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use tsra_fw_hsm_pal_traits::DmaBuf;

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
        let ciphertext = unsafe { DmaBuf::from_raw(&ciphertext) };
        let lengths = unsafe { DmaBuf::from_raw(&lengths) };
        ghash.update(ciphertext);
        ghash.update(lengths);

        assert_eq!(
            ghash.finish(),
            [
                0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc, 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0,
                0xf8, 0x85,
            ]
        );
    }
}
