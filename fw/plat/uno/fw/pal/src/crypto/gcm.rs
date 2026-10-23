// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-GCM for the Uno PAL on the BCP (CDMA) bulk crypto engine.
//!
//! The caller supplies `[padded_AAD | text]` buffers, the AAD zero-padded
//! to a multiple of [`GCM_AAD_PAD`] bytes per the scheme in
//! `tsra_fw_core_crypto_gcm_buf`, which makes the region's GHASH blocks
//! those of the standard AAD up to a leading all-zero block (which GHASH
//! ignores).
//!
//! ## Tag correction
//!
//! The engine only processes whole blocks and its length block counts the
//! padded AAD, so the PAL hands it the text rounded up to whole blocks,
//! zero-padded, and corrects the tag in software. With `L` the standard
//! length block, `L'` the engine's (padded AAD and rounded text lengths)
//! and `H = E_K(0¹²⁸)`:
//!
//! * **Decrypt**: the zero-padded final block is exactly the block GHASH
//!   takes, so only the length block differs. The engine is given the tag
//!   it should compute, `T' = T ⊕ (L ⊕ L')·H`, and authenticates the
//!   message itself.
//! * **Encrypt**: the engine also encrypts the padding, leaving keystream
//!   `D` (zero within the text) in the final ciphertext block, so
//!   `T = T' ⊕ D·H² ⊕ (L ⊕ L')·H`.
//!
//! When `L = L'` (AAD a multiple of 32 bytes, text of whole blocks) the
//! engine's tag is the tag and nothing else runs; otherwise `H` takes one
//! block on the CP1 AES engine. With no text at all there is nothing for
//! the engine, so the tag is computed in software (GMAC).
//!
//! The engine runs in place on the caller's buffer when it can: whole
//! blocks, or a partial final block when the caller lends scratch past the
//! message to zero-pad it in place (`gcm_open_in_place` lends the tag's
//! bytes). Otherwise, or for a misaligned buffer, the message goes through
//! a scratch buffer instead.
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

use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_uno_drivers_aes::AesMode;
use tsra_fw_uno_drivers_aes::AesOp;
use tsra_fw_uno_drivers_bcp::BCP_ADDR_ALIGN;
use tsra_fw_uno_drivers_bcp::BCP_KEY_LEN;
use tsra_fw_uno_drivers_bcp::BCP_MAX_SRC_LEN;
use tsra_fw_uno_drivers_bcp::BcpError;
use tsra_fw_uno_drivers_bcp::GcmCompletion;
use tsra_fw_uno_drivers_bcp::GcmData;
use tsra_fw_uno_drivers_bcp::GcmOp;
use tsra_fw_uno_drivers_bcp::GcmRequest;

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

type Block = [u8; AES_BLOCK_SIZE];

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
// Helpers
// =============================================================================

/// Compute the padded AAD length (a multiple of [`GCM_AAD_PAD`]).
///
/// Returns 0 when `aad_len` is 0 (no AAD region at all).
fn padded_aad_len(aad_len: usize) -> usize {
    aad_len.next_multiple_of(GCM_AAD_PAD)
}

/// GCM length block `[8·aad_len]₆₄ ‖ [8·text_len]₆₄`.
fn len_block(aad_len: usize, text_len: usize) -> Block {
    let mut b = [0u8; AES_BLOCK_SIZE];
    b[..8].copy_from_slice(&(aad_len as u64 * 8).to_be_bytes());
    b[8..].copy_from_slice(&(text_len as u64 * 8).to_be_bytes());
    b
}

fn xor(a: &Block, b: &Block) -> Block {
    core::array::from_fn(|i| a[i] ^ b[i])
}

/// Constant-time comparison of two blocks.
fn constant_time_eq(a: &Block, b: &Block) -> bool {
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn ghash(h: &Block) -> HsmResult<Ghash> {
    Ghash::new(h).ok_or(HsmError::AesGcmInvalidBufferSize)
}

/// A `len`-byte buffer aligned for the engine, from the scope's DMA heap.
fn engine_buf<S: HsmScopedAlloc>(scope: &S, len: usize) -> HsmResult<&mut DmaBuf> {
    let raw = scope.dma_alloc(len + BCP_ADDR_ALIGN - 1)?;
    let off = raw.as_ptr().align_offset(BCP_ADDR_ALIGN);
    Ok(&mut raw[off..off + len])
}

fn is_aligned(buf: &DmaBuf) -> bool {
    buf.as_ptr().align_offset(BCP_ADDR_ALIGN) == 0
}

/// GCM direction; a decrypt carries the tag to check.
#[derive(Clone, Copy)]
enum Dir<'a> {
    Encrypt,
    Decrypt(&'a Block),
}

/// The caller's `[padded_AAD | text]` input and output.
enum Bufs<'a> {
    /// Read `src`, write `dst` (the same length).
    Copy {
        src: &'a DmaBuf,
        dst: &'a mut DmaBuf,
    },
    /// Transform in place.
    InPlace(&'a mut DmaBuf),
    /// Transform `buf[..len]` in place; `buf[len..]` is scratch, room to
    /// zero-pad a partial final block for the engine in place.
    Slack { buf: &'a mut DmaBuf, len: usize },
}

impl Bufs<'_> {
    fn src(&self) -> &DmaBuf {
        match self {
            Self::Copy { src, .. } => src,
            Self::InPlace(buf) => buf,
            Self::Slack { buf, len } => &buf[..*len],
        }
    }

    fn dst(&mut self) -> &mut DmaBuf {
        match self {
            Self::Copy { dst, .. } => dst,
            Self::InPlace(buf) => buf,
            Self::Slack { buf, len } => &mut buf[..*len],
        }
    }

    fn aligned(&self) -> bool {
        match self {
            Self::Copy { src, dst } => is_aligned(src) && is_aligned(dst),
            Self::InPlace(buf) | Self::Slack { buf, .. } => is_aligned(buf),
        }
    }

    /// Bytes the engine may run over in place: the message plus any slack.
    fn room(&self) -> usize {
        match self {
            Self::Slack { buf, .. } => buf.len(),
            _ => self.src().len(),
        }
    }

    /// Hand the first `n` bytes (at most [`room`](Self::room)) to the
    /// engine as they are.
    fn engine_data(&mut self, n: usize) -> GcmData<'_> {
        match self {
            Self::Copy { src, dst } => GcmData::Copy {
                src: &src[..n],
                dst: &mut dst[..n],
            },
            Self::InPlace(buf) | Self::Slack { buf, .. } => GcmData::InPlace(&mut buf[..n]),
        }
    }
}

// =============================================================================
// AES-GCM implementation on UnoHsmPal
// =============================================================================

impl UnoHsmPal {
    /// `H = E_K(0¹²⁸)` on the CP1 AES engine.
    async fn hash_subkey<S: HsmScopedAlloc>(&self, key: &DmaBuf, scope: &S) -> HsmResult<Block> {
        let zero = scope.dma_alloc_zeroed(AES_BLOCK_SIZE)?;
        let out = scope.dma_alloc(AES_BLOCK_SIZE)?;
        self.aes_run(AesMode::Ecb, AesOp::Encrypt, key, None, zero, out)
            .await?;
        let mut h = [0u8; AES_BLOCK_SIZE];
        h.copy_from_slice(out);
        out.zeroize();
        Ok(h)
    }

    /// AES-256-GCM over `bufs`; returns the tag of an encrypt. A decrypt
    /// that fails authentication wipes its output text and returns
    /// [`HsmError::AesGcmDecryptTagDoesNotMatch`].
    async fn gcm_run(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        dir: Dir<'_>,
        mut bufs: Bufs<'_>,
    ) -> HsmResult<Block> {
        if key.len() != BCP_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        let iv: &[u8] = iv;
        let iv: &[u8; GCM_IV_LEN] = iv.try_into().map_err(|_| HsmError::InvalidArg)?;
        let len = bufs.src().len();
        let pad = padded_aad_len(aad_len);
        let text_len = len
            .checked_sub(pad)
            .ok_or(HsmError::AesGcmInvalidBufferSize)?;
        if text_len == 0 {
            return self.gmac(io, key, iv, aad_len, dir, bufs).await;
        }
        let rounded = text_len.next_multiple_of(AES_BLOCK_SIZE);
        let tail = text_len % AES_BLOCK_SIZE;
        if pad + rounded > BCP_MAX_SRC_LEN {
            return Err(HsmError::InvalidArg);
        }
        let len_fix = xor(&len_block(aad_len, text_len), &len_block(pad, rounded));
        let fix = len_fix != [0; AES_BLOCK_SIZE];

        self.alloc_scoped_async(io, async |scope| {
            let h = if fix {
                Some(self.hash_subkey(key, scope).await?)
            } else {
                None
            };

            // The tag the engine checks a decrypt against.
            let engine_tag = match (dir, &h) {
                (Dir::Decrypt(t), Some(h)) => {
                    let mut g = ghash(h)?;
                    g.update(&len_fix);
                    xor(t, &g.finish())
                }
                (Dir::Decrypt(t), None) => *t,
                (Dir::Encrypt, _) => [0; AES_BLOCK_SIZE],
            };
            let req = |data| GcmRequest {
                op: match dir {
                    Dir::Encrypt => GcmOp::Encrypt,
                    Dir::Decrypt(_) => GcmOp::Decrypt,
                },
                key,
                iv,
                aad_len: pad,
                unpadded_aad_len: aad_len,
                tag: &engine_tag,
                data,
            };

            // `pad_ks`: the keystream the engine leaves in the final block
            // past the text (encrypt only).
            let mut pad_ks = [0u8; AES_BLOCK_SIZE];
            let result = if bufs.aligned() && bufs.room() >= pad + rounded {
                // Whole blocks, or slack to zero-pad the final one in place.
                if let Bufs::Slack { buf, len } = &mut bufs {
                    buf[*len..pad + rounded].fill(0);
                }
                let done = self.bcp.gcm(req(bufs.engine_data(pad + rounded))).await;
                let result = verdict(dir, &engine_tag, done);
                if result.is_err() {
                    bufs.dst()[pad..len].zeroize();
                } else if let (Dir::Encrypt, Bufs::Slack { buf, len }) = (dir, &bufs)
                    && tail != 0
                {
                    pad_ks[tail..].copy_from_slice(&buf[*len..pad + rounded]);
                }
                result
            } else {
                let work = engine_buf(scope, pad + rounded)?;
                work[..len].copy_from_slice(bufs.src());
                work[len..].fill(0);
                let done = self.bcp.gcm(req(GcmData::InPlace(work))).await;
                let result = verdict(dir, &engine_tag, done);
                if result.is_ok() {
                    if tail != 0 {
                        pad_ks[tail..].copy_from_slice(&work[len..]);
                    }
                    bufs.dst()[..len].copy_from_slice(&work[..len]);
                }
                work.zeroize();
                result
            };
            let engine_tag = result?;

            match (dir, h) {
                (Dir::Encrypt, Some(h)) => {
                    // T = T' ⊕ D·H² ⊕ (L ⊕ L')·H.
                    let mut g = ghash(&h)?;
                    if tail != 0 {
                        g.update(&pad_ks);
                    }
                    g.update(&len_fix);
                    Ok(xor(&engine_tag, &g.finish()))
                }
                _ => Ok(engine_tag),
            }
        })
        .await
    }

    /// GCM with no text: the tag is `GHASH(AAD, L) ⊕ E_K(J₀)`, computed in
    /// software with `H` and `E_K(J₀)` from one CP1 AES command.
    async fn gmac(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &[u8; GCM_IV_LEN],
        aad_len: usize,
        dir: Dir<'_>,
        mut bufs: Bufs<'_>,
    ) -> HsmResult<Block> {
        self.alloc_scoped_async(io, async |scope| {
            // [0¹²⁸ | J₀] → [H | E_K(J₀)].
            let blocks = scope.dma_alloc_zeroed(2 * AES_BLOCK_SIZE)?;
            blocks[AES_BLOCK_SIZE..AES_BLOCK_SIZE + GCM_IV_LEN].copy_from_slice(iv);
            blocks[2 * AES_BLOCK_SIZE - 1] = 1;
            let out = scope.dma_alloc(2 * AES_BLOCK_SIZE)?;
            self.aes_run(AesMode::Ecb, AesOp::Encrypt, key, None, blocks, out)
                .await?;
            let (h, ek_j0) = out.split_at(AES_BLOCK_SIZE);
            let mut g = Ghash::new(h).ok_or(HsmError::AesGcmInvalidBufferSize)?;
            // The padded region's blocks are the AAD's, after a possible
            // leading zero block that leaves GHASH unchanged.
            g.update(bufs.src());
            g.update(&len_block(aad_len, 0));
            let mut ek = [0u8; AES_BLOCK_SIZE];
            ek.copy_from_slice(ek_j0);
            let tag = xor(&g.finish(), &ek);
            out.zeroize();
            ek.fill(0);

            if let Dir::Decrypt(expected) = dir
                && !constant_time_eq(&tag, expected)
            {
                return Err(HsmError::AesGcmDecryptTagDoesNotMatch);
            }
            if let Bufs::Copy { src, dst } = &mut bufs {
                dst.copy_from_slice(src);
            }
            Ok(tag)
        })
        .await
    }

    // ── Public GCM entry points ─────────────────────────────────────

    /// AES-256-GCM encrypt from `plaintext` into `ciphertext`, both
    /// `[padded_AAD | text]`; the padded AAD is copied through.
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
        let dst = &mut ciphertext[..plaintext.len()];
        let bufs = Bufs::Copy {
            src: plaintext,
            dst,
        };
        let t = self
            .gcm_run(io, key, iv, aad_len, Dir::Encrypt, bufs)
            .await?;
        tag.copy_from_slice(&t);
        Ok(())
    }

    /// AES-256-GCM encrypt in place over `[padded_AAD | text]`.
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
        let t = self
            .gcm_run(io, key, iv, aad_len, Dir::Encrypt, Bufs::InPlace(data))
            .await?;
        tag.copy_from_slice(&t);
        Ok(())
    }

    /// AES-256-GCM decrypt from `ciphertext` into `plaintext`, both
    /// `[padded_AAD | text]`. On a tag mismatch the plaintext text is
    /// wiped.
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
        let tag: &[u8] = tag;
        let tag: &Block = tag.try_into().map_err(|_| HsmError::InvalidArg)?;
        if plaintext.len() < ciphertext.len() {
            return Err(HsmError::InvalidArg);
        }
        let dst = &mut plaintext[..ciphertext.len()];
        let bufs = Bufs::Copy {
            src: ciphertext,
            dst,
        };
        self.gcm_run(io, key, iv, aad_len, Dir::Decrypt(tag), bufs)
            .await
            .map(|_| ())
    }

    /// AES-256-GCM decrypt in place over `[padded_AAD | text]`. On a tag
    /// mismatch the text is wiped.
    pub(super) async fn gcm_decrypt_in_place_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        tag: &DmaBuf,
        data: &mut DmaBuf,
    ) -> HsmResult<()> {
        let tag: &[u8] = tag;
        let tag: &Block = tag.try_into().map_err(|_| HsmError::InvalidArg)?;
        self.gcm_run(io, key, iv, aad_len, Dir::Decrypt(tag), Bufs::InPlace(data))
            .await
            .map(|_| ())
    }

    /// AES-256-GCM decrypt in place over `[padded_AAD | text | tag]`,
    /// borrowing the tag's bytes to zero-pad a partial final block in place
    /// and restoring them. On a tag mismatch the text is wiped.
    pub(super) async fn gcm_open_in_place_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        data: &mut DmaBuf,
    ) -> HsmResult<()> {
        let len = data
            .len()
            .checked_sub(GCM_TAG_LEN)
            .ok_or(HsmError::InvalidArg)?;
        let mut tag = [0u8; GCM_TAG_LEN];
        tag.copy_from_slice(&data[len..]);
        let result = self
            .gcm_run(
                io,
                key,
                iv,
                aad_len,
                Dir::Decrypt(&tag),
                Bufs::Slack {
                    buf: &mut *data,
                    len,
                },
            )
            .await
            .map(|_| ());
        data[len..].copy_from_slice(&tag);
        result
    }
}

/// Interpret an engine completion: the engine's tag for an encrypt, or the
/// verdict on a decrypt.
fn verdict(dir: Dir<'_>, engine_tag: &Block, done: HsmResult<GcmCompletion>) -> HsmResult<Block> {
    let done = done?;
    match dir {
        Dir::Encrypt if done.ok() => Ok(done.tag),
        Dir::Decrypt(_) if done.ok() && constant_time_eq(&done.tag, engine_tag) => Ok(done.tag),
        Dir::Decrypt(_) if done.ok() || done.tag_mismatch_only() => {
            Err(HsmError::AesGcmDecryptTagDoesNotMatch)
        }
        _ => Err(BcpError::CMD_ERROR),
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
