// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-GCM for the Uno PAL on the BCP (CDMA) bulk crypto engine, used
//! by the default build. With `bulk_crypto` the FP firmware owns the
//! engine, and the PAL's AES-GCM is the software `gcm` module instead.
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
//! block on the HSM AES engine. With no text at all there is nothing for
//! the engine, so the tag is computed in software (GMAC).
//!
//! The engine runs on the caller's buffers when they hold whole blocks and
//! are aligned for it. Otherwise the message goes through an aligned,
//! zero-padded scratch buffer instead.
//!
//! The tag corrections and GMAC use the software [`Ghash`].

use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmError;
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
use super::ghash::Ghash;
use crate::UnoHsmIo;
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
}

impl Bufs<'_> {
    fn src(&self) -> &DmaBuf {
        match self {
            Self::Copy { src, .. } => src,
            Self::InPlace(buf) => buf,
        }
    }

    fn dst(&mut self) -> &mut DmaBuf {
        match self {
            Self::Copy { dst, .. } => dst,
            Self::InPlace(buf) => buf,
        }
    }

    fn aligned(&self) -> bool {
        match self {
            Self::Copy { src, dst } => is_aligned(src) && is_aligned(dst),
            Self::InPlace(buf) => is_aligned(buf),
        }
    }

    /// Hand the first `n` bytes to the engine as they are.
    fn engine_data(&mut self, n: usize) -> GcmData<'_> {
        match self {
            Self::Copy { src, dst } => GcmData::Copy {
                src: &src[..n],
                dst: &mut dst[..n],
            },
            Self::InPlace(buf) => GcmData::InPlace(&mut buf[..n]),
        }
    }
}

// =============================================================================
// AES-GCM implementation on UnoHsmPal
// =============================================================================

impl UnoHsmPal {
    /// `H = E_K(0¹²⁸)` on the HSM AES engine.
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
        io: &UnoHsmIo,
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
        // The engine's length block counts the padded AAD and the rounded
        // text; GCM's counts what was given. The tag needs correcting by
        // their difference when they differ.
        let fix = pad != aad_len || rounded != text_len;

        // Whole blocks, no length-block fix and buffers the engine can use as
        // they are (most masked keys): one engine command, with no scratch,
        // no hash subkey and no tag correction.
        if !fix && bufs.aligned() {
            let engine_tag = match dir {
                Dir::Decrypt(t) => *t,
                Dir::Encrypt => [0; AES_BLOCK_SIZE],
            };
            let done = self
                .bcp
                .gcm(GcmRequest {
                    op: match dir {
                        Dir::Encrypt => GcmOp::Encrypt,
                        Dir::Decrypt(_) => GcmOp::Decrypt,
                    },
                    key,
                    iv,
                    aad_len: pad,
                    unpadded_aad_len: aad_len,
                    tag: &engine_tag,
                    data: bufs.engine_data(len),
                })
                .await;
            let result = verdict(dir, &engine_tag, done);
            if result.is_err() {
                bufs.dst()[pad..len].zeroize();
            }
            return result;
        }

        let len_fix = xor(&len_block(aad_len, text_len), &len_block(pad, rounded));
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
            let result = if tail == 0 && bufs.aligned() {
                // Whole blocks: the engine runs on the caller's buffers.
                let done = self.bcp.gcm(req(bufs.engine_data(len))).await;
                let result = verdict(dir, &engine_tag, done);
                if result.is_err() {
                    bufs.dst()[pad..len].zeroize();
                }
                result
            } else {
                // A partial final block, zero-padded to a whole one, or a
                // misaligned buffer: run on an aligned scratch copy.
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
    /// software with `H` and `E_K(J₀)` from one HSM AES command.
    async fn gmac(
        &self,
        io: &UnoHsmIo,
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
        io: &UnoHsmIo,
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
        io: &UnoHsmIo,
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
        io: &UnoHsmIo,
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
        io: &UnoHsmIo,
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
