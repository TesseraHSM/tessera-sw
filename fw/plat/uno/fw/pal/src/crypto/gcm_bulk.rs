// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-GCM on the BCP (CDMA) bulk crypto engine — the Uno
//! implementation of [`HsmAes::gcm_bulk_encrypt`] /
//! [`HsmAes::gcm_bulk_decrypt`].
//!
//! The engine only processes whole blocks: AAD padded to 32 bytes and
//! text in 16-byte multiples. Its tag therefore covers the padded AAD
//! length and only the aligned text. The PAL submits the aligned text and
//! corrects the tag in software, the same correction the CP firmware
//! applied for the FP fast path:
//!
//! * `H = E_K(0)` and `E_K(J0)` come from the CP1 AES engine (ECB), as
//!   does the keystream `E_K(J0 + 1 + n)` for a final partial block.
//! * With `S = T ⊕ E_K(J0)` the GHASH value, `L'` the engine's length
//!   block (padded AAD, aligned text), `L` the correct one, and `C` the
//!   zero-padded final partial ciphertext block:
//!   * no partial block: `S = S' ⊕ (L' ⊕ L)·H`
//!   * partial block: `S = (S' ⊕ (L' ⊕ C)·H ⊕ L)·H`
//!
//! The padded AAD layout (`gcm_buf`) makes the engine's AAD blocks equal
//! the standard ones up to a leading all-zero block, which GHASH ignores,
//! so only the length block differs. Sources with no whole text block skip
//! the engine and run GHASH in software.
//!
//! A decrypt with no partial block hands the engine the tag it should
//! compute, `T' = T ⊕ (L' ⊕ L)·H`, so an authentic message completes
//! without error. Otherwise the engine reports a tag mismatch, which is
//! expected; the corrected tag is always compared here.
//!
//! [`HsmAes::gcm_bulk_encrypt`]: tsra_fw_hsm_pal_traits::HsmAes::gcm_bulk_encrypt
//! [`HsmAes::gcm_bulk_decrypt`]: tsra_fw_hsm_pal_traits::HsmAes::gcm_bulk_decrypt

use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_uno_drivers_bcp::BCP_KEY_LEN;
use tsra_fw_uno_drivers_bcp::BCP_MAX_SRC_LEN;
use tsra_fw_uno_drivers_bcp::BCP_TEXT_ALIGN;
use tsra_fw_uno_drivers_bcp::BcpError;
use tsra_fw_uno_drivers_bcp::GcmOp;
use tsra_fw_uno_drivers_bcp::GcmRequest;

use super::aes::AES_BLOCK_SIZE;
use super::gcm::GCM_IV_LEN;
use super::gcm::GCM_TAG_LEN;
use super::gcm::Ghash;
use super::gcm::constant_time_eq;
use super::gcm::padded_aad_len;
use crate::UnoHsmPal;

type Block = [u8; AES_BLOCK_SIZE];

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

/// A `len`-byte, 16-byte-aligned buffer from the scope's DMA heap.
fn aligned<S: HsmScopedAlloc>(scope: &S, len: usize) -> HsmResult<&mut DmaBuf> {
    let raw = scope.dma_alloc(len + BCP_TEXT_ALIGN - 1)?;
    let off = raw.as_ptr().align_offset(BCP_TEXT_ALIGN);
    Ok(&mut raw[off..off + len])
}

impl UnoHsmPal {
    /// AES-256-GCM encrypt on the BCP. See [`gcm_bulk_run`](Self::gcm_bulk_run).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn gcm_bulk_encrypt_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        src: &DmaBuf,
        dst: &mut DmaBuf,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        if tag.len() != GCM_TAG_LEN {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        let t = self
            .gcm_bulk_run(io, None, key, iv, aad_len, src, dst)
            .await?;
        tag.copy_from_slice(&t);
        Ok(())
    }

    /// AES-256-GCM decrypt on the BCP; wipes the plaintext on a tag
    /// mismatch.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn gcm_bulk_decrypt_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        tag: &DmaBuf,
        src: &DmaBuf,
        dst: &mut DmaBuf,
    ) -> HsmResult<()> {
        let tag: &[u8] = tag;
        let tag: &Block = tag
            .try_into()
            .map_err(|_| HsmError::AesGcmInvalidBufferSize)?;
        let t = self
            .gcm_bulk_run(io, Some(tag), key, iv, aad_len, src, dst)
            .await?;
        if !constant_time_eq(&t, tag) {
            let text_len = src.len() - padded_aad_len(aad_len);
            dst[..text_len].zeroize();
            return Err(HsmError::AesGcmDecryptTagDoesNotMatch);
        }
        Ok(())
    }

    /// Transform `[padded_AAD | text]` from `src` into `dst` and return the
    /// tag. `expected` is the decrypt tag (`None` encrypts); the tag
    /// returned for a decrypt is the computed one, for the caller to
    /// compare.
    #[allow(clippy::too_many_arguments)]
    async fn gcm_bulk_run(
        &self,
        io: &impl HsmIo,
        expected: Option<&Block>,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        src: &DmaBuf,
        dst: &mut DmaBuf,
    ) -> HsmResult<Block> {
        if key.len() != BCP_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        let iv: &[u8] = iv;
        let iv: &[u8; GCM_IV_LEN] = iv.try_into().map_err(|_| HsmError::InvalidArg)?;
        let pad = padded_aad_len(aad_len);
        let text_len = src
            .len()
            .checked_sub(pad)
            .ok_or(HsmError::AesGcmInvalidBufferSize)?;
        if dst.len() < text_len {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        let encrypt = expected.is_none();
        let aligned_len = text_len - text_len % AES_BLOCK_SIZE;
        let tail_len = text_len - aligned_len;
        if pad + aligned_len > BCP_MAX_SRC_LEN {
            return Err(HsmError::InvalidArg);
        }

        self.alloc_scoped_async(io, async |scope| {
            let blk = scope.dma_alloc(AES_BLOCK_SIZE)?;
            let out = scope.dma_alloc(AES_BLOCK_SIZE)?;

            // H = E_K(0¹²⁸).
            blk.fill(0);
            self.ecb_encrypt_block(io, key, blk, out).await?;
            let mut h = [0u8; AES_BLOCK_SIZE];
            h.copy_from_slice(out);

            // E_K(J0), J0 = IV ‖ 1.
            blk[..GCM_IV_LEN].copy_from_slice(iv);
            blk[GCM_IV_LEN..].copy_from_slice(&1u32.to_be_bytes());
            self.ecb_encrypt_block(io, key, blk, out).await?;
            let mut ek_j0 = [0u8; AES_BLOCK_SIZE];
            ek_j0.copy_from_slice(out);

            // Final partial block: CTR with E_K(J0 + 1 + aligned blocks).
            let tail_ct = if tail_len > 0 {
                let ctr = 2 + (aligned_len / AES_BLOCK_SIZE) as u32;
                blk[GCM_IV_LEN..].copy_from_slice(&ctr.to_be_bytes());
                self.ecb_encrypt_block(io, key, blk, out).await?;
                let tail_in = &src[pad + aligned_len..pad + text_len];
                let mut ct = [0u8; AES_BLOCK_SIZE];
                for i in 0..tail_len {
                    let o = tail_in[i] ^ out[i];
                    dst[aligned_len + i] = o;
                    ct[i] = if encrypt { o } else { tail_in[i] };
                }
                out.zeroize();
                Some(ct)
            } else {
                None
            };

            let mut ghash = Ghash::new(&h).ok_or(HsmError::AesGcmInvalidBufferSize)?;
            let len = len_block(aad_len, text_len);

            let s = if aligned_len > 0 {
                let len_hw = len_block(pad, aligned_len);

                // The tag the engine should compute: T' = T ⊕ (L' ⊕ L)·H when
                // there is no partial block; otherwise it cannot match.
                let hw_tag = match expected {
                    Some(t) if tail_ct.is_none() => {
                        let mut g = Ghash::new(&h).ok_or(HsmError::AesGcmInvalidBufferSize)?;
                        g.update(&xor(&len_hw, &len));
                        xor(t, &g.finish())
                    }
                    _ => [0u8; AES_BLOCK_SIZE],
                };

                let t_hw = self
                    .bcp_gcm(
                        encrypt,
                        key,
                        iv,
                        &hw_tag,
                        aad_len,
                        pad,
                        aligned_len,
                        src,
                        dst,
                        scope,
                    )
                    .await?;
                let s_hw = xor(&t_hw, &ek_j0);
                match tail_ct {
                    None => {
                        ghash.update(&xor(&len_hw, &len));
                        xor(&s_hw, &ghash.finish())
                    }
                    Some(ct) => {
                        ghash.update(&xor(&len_hw, &ct));
                        ghash.update(&xor(&s_hw, &len));
                        ghash.finish()
                    }
                }
            } else {
                // No whole text block for the engine.
                ghash.update(&src[..pad]);
                if let Some(ct) = tail_ct {
                    ghash.update(&ct);
                }
                ghash.update(&len);
                ghash.finish()
            };

            Ok(xor(&s, &ek_j0))
        })
        .await
    }

    /// Run `[padded_AAD | aligned text]` on the engine through
    /// 16-byte-aligned bounce buffers, write the aligned text to `dst`,
    /// and return the engine's tag `T'` (over the padded AAD length).
    #[allow(clippy::too_many_arguments)]
    async fn bcp_gcm<S: HsmScopedAlloc>(
        &self,
        encrypt: bool,
        key: &DmaBuf,
        iv: &[u8; GCM_IV_LEN],
        tag: &Block,
        aad_len: usize,
        pad: usize,
        aligned_len: usize,
        src: &DmaBuf,
        dst: &mut DmaBuf,
        scope: &S,
    ) -> HsmResult<Block> {
        // The engine writes the padded AAD through ahead of the text, so
        // its destination is as long as its source.
        let hw_src = aligned(scope, pad + aligned_len)?;
        let hw_dst = aligned(scope, pad + aligned_len)?;
        hw_src.copy_from_slice(&src[..pad + aligned_len]);
        let key: &[u8] = key;

        let done = self
            .bcp
            .gcm(GcmRequest {
                op: if encrypt {
                    GcmOp::Encrypt
                } else {
                    GcmOp::Decrypt
                },
                key,
                iv,
                aad_len: pad,
                unpadded_aad_len: aad_len,
                tag,
                src: &*hw_src,
                dst: &mut *hw_dst,
            })
            .await;
        hw_src.zeroize();

        // A decrypt may fail only on the tag, which is checked by the caller
        // after correction.
        let ok = match &done {
            Ok(c) => c.ok() || (!encrypt && c.tag_mismatch_only()),
            Err(_) => false,
        };
        if ok {
            dst[..aligned_len].copy_from_slice(&hw_dst[pad..pad + aligned_len]);
        }
        hw_dst.zeroize();

        let done = done?;
        if !ok {
            return Err(BcpError::CMD_ERROR);
        }
        Ok(done.tag)
    }
}
