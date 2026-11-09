// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-GCM host-to-host over raw SGLs for the Uno PAL.
//!
//! Runs on the CP AES core (ECB for `H`/`E_K(J₀)`, CTR for the text) with
//! software GHASH, in both build configurations. The host stream has the
//! same `[padded AAD | text]` layout as the in-place GCM commands; the
//! padded AAD region is copied to `dst` unchanged.
//!
//! Data is streamed through the per-IO DMA slot in [`SGL_CHUNK`]-byte
//! pieces, so the input cannot be snapshotted and the host can change
//! `src` between reads. Decrypt therefore makes a verify pass that checks
//! the tag and records the GHASH state after every chunk, then a decrypt
//! pass that re-reads each chunk and compares its GHASH state against the
//! recorded checkpoint *before* writing that chunk to `dst`. GHASH is
//! keyed by the secret `H`, so a host that changes already-verified input
//! cannot reproduce a checkpoint except with the GCM forgery probability:
//! every byte written to `dst` was covered by the verified tag. On any
//! decrypt-pass failure the output is scrubbed (best effort) and the error
//! returned.

use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_uno_drivers_aes::AesMode;
use tsra_fw_uno_drivers_aes::AesOp;

use super::aes::AES_BLOCK_SIZE;
use super::gcm::GCM_IV_LEN;
use super::gcm::GCM_TAG_LEN;
use super::ghash::Ghash;
use crate::UnoHsmIo;
use crate::UnoHsmPal;
use crate::gdma::HostSgl;

/// Bytes moved per GDMA/AES round trip. Must be a multiple of
/// [`AES_BLOCK_SIZE`] so every GHASH update except the last is whole blocks.
const SGL_CHUNK: usize = 2048;

/// Alignment of the padded AAD region in the host stream.
const SGL_AAD_PAD: usize = 32;

/// Maximum chunks per pass that decrypt can checkpoint. The TBOR caller
/// caps `len` at 16 KiB including the padded AAD, i.e. at most
/// `16384 / SGL_CHUNK + 1` chunks; larger streams fail before any output.
const SGL_MAX_CHUNKS: usize = 16;

/// Per-chunk GHASH states recorded by the verify pass.
type Checkpoints = [[u8; GCM_TAG_LEN]; SGL_MAX_CHUNKS];

/// What one pass over the host stream does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// Encrypt text, write `[AAD | ciphertext]`, GHASH the ciphertext.
    Encrypt,
    /// GHASH AAD and ciphertext only; nothing is written.
    Verify,
    /// Decrypt text, write `[AAD | plaintext]`, GHASH the ciphertext.
    Decrypt,
}

/// Padded AAD region length and AAD content offset within it.
fn sgl_aad_layout(aad_len: usize, len: usize) -> HsmResult<(usize, usize)> {
    if aad_len == 0 {
        return Ok((0, 0));
    }
    let padded = aad_len
        .checked_next_multiple_of(SGL_AAD_PAD)
        .ok_or(HsmError::AesGcmInvalidBufferSize)?;
    if padded > len {
        return Err(HsmError::AesGcmInvalidBufferSize);
    }
    let rem = aad_len % SGL_AAD_PAD;
    let off = if rem != 0 && rem <= AES_BLOCK_SIZE {
        AES_BLOCK_SIZE
    } else {
        0
    };
    Ok((padded, off))
}

/// Constant-time byte comparison.
fn sgl_ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Record (verify pass) or check (decrypt pass) GHASH `state` against
/// checkpoint `*k`, then advance `*k`. Encrypt passes are not checkpointed.
///
/// # Errors
/// * [`HsmError::AesGcmInvalidBufferSize`] if more than [`SGL_MAX_CHUNKS`]
///   chunks are checkpointed.
/// * [`HsmError::AesGcmDecryptTagDoesNotMatch`] if the decrypt-pass state
///   differs from the verified one.
fn sgl_checkpoint(
    pass: Pass,
    cps: &mut Checkpoints,
    k: &mut usize,
    state: &[u8; GCM_TAG_LEN],
) -> HsmResult<()> {
    if pass == Pass::Encrypt {
        return Ok(());
    }
    let cp = cps.get_mut(*k).ok_or(HsmError::AesGcmInvalidBufferSize)?;
    *k += 1;
    if pass == Pass::Verify {
        *cp = *state;
    } else if !sgl_ct_eq(cp, state) {
        return Err(HsmError::AesGcmDecryptTagDoesNotMatch);
    }
    Ok(())
}

/// `bits(n)` as big-endian u64.
fn sgl_bits(n: usize) -> HsmResult<[u8; 8]> {
    u64::try_from(n)
        .ok()
        .and_then(|b| b.checked_mul(8))
        .map(u64::to_be_bytes)
        .ok_or(HsmError::AesGcmInvalidBufferSize)
}

impl UnoHsmPal {
    /// AES-GCM encrypt `len` bytes from host SGL `src` to host SGL `dst`
    /// and return the tag in `tag`.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] for a bad IV/tag length or malformed SGL.
    /// * [`HsmError::AesGcmInvalidBufferSize`] if the padded AAD exceeds `len`.
    /// * Any GDMA or AES driver error.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn gcm_encrypt_sgl_impl(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        len: usize,
        src: &[u8; 16],
        dst: &[u8; 16],
        tag: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        if tag.len() != GCM_TAG_LEN {
            return Err(HsmError::InvalidArg);
        }
        let mut unused = [[0u8; GCM_TAG_LEN]; SGL_MAX_CHUNKS];
        let t = self
            .gcm_sgl_pass(
                io,
                key,
                iv,
                aad_len,
                len,
                src,
                Some(dst),
                Pass::Encrypt,
                &mut unused,
            )
            .await?;
        tag.copy_from_slice(&t);
        Ok(())
    }

    /// AES-GCM decrypt `len` bytes from host SGL `src` to host SGL `dst`
    /// after verifying `tag`.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] for a bad IV/tag length or malformed SGL.
    /// * [`HsmError::AesGcmInvalidBufferSize`] if the padded AAD exceeds `len`.
    /// * [`HsmError::AesGcmDecryptTagDoesNotMatch`] on authentication failure.
    /// * Any GDMA or AES driver error.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn gcm_decrypt_sgl_impl(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        len: usize,
        tag: &HsmDmaBuf,
        src: &[u8; 16],
        dst: &[u8; 16],
    ) -> HsmResult<()> {
        if tag.len() != GCM_TAG_LEN {
            return Err(HsmError::InvalidArg);
        }
        let check = |t: [u8; GCM_TAG_LEN]| {
            if sgl_ct_eq(&t, tag) {
                Ok(())
            } else {
                Err(HsmError::AesGcmDecryptTagDoesNotMatch)
            }
        };
        let mut cps = [[0u8; GCM_TAG_LEN]; SGL_MAX_CHUNKS];
        let result = match self
            .gcm_sgl_pass(io, key, iv, aad_len, len, src, None, Pass::Verify, &mut cps)
            .await
            .and_then(check)
        {
            Ok(()) => {
                let r = self
                    .gcm_sgl_pass(
                        io,
                        key,
                        iv,
                        aad_len,
                        len,
                        src,
                        Some(dst),
                        Pass::Decrypt,
                        &mut cps,
                    )
                    .await
                    .and_then(check);
                if r.is_err() {
                    // Retract any output; keep the original error.
                    let _ = self.gcm_sgl_scrub(io, len, dst).await;
                }
                r
            }
            Err(e) => Err(e),
        };
        cps.fill([0; GCM_TAG_LEN]);
        result
    }

    /// One streaming pass over `[padded AAD | text]`; returns the computed tag.
    #[allow(clippy::too_many_arguments)]
    async fn gcm_sgl_pass(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        len: usize,
        src: &[u8; 16],
        dst: Option<&[u8; 16]>,
        pass: Pass,
        cps: &mut Checkpoints,
    ) -> HsmResult<[u8; GCM_TAG_LEN]> {
        if iv.len() != GCM_IV_LEN {
            return Err(HsmError::InvalidArg);
        }
        let (padded, off) = sgl_aad_layout(aad_len, len)?;
        let text_len = len - padded;
        let aad_bits = sgl_bits(aad_len)?;
        let text_bits = sgl_bits(text_len)?;

        let mut rd = HostSgl::new(src, len)?;
        let mut wr = match dst {
            Some(d) => Some(HostSgl::new(d, len)?),
            None => None,
        };

        self.alloc_scoped_async(io, async |scope| {
            let h = scope.dma_alloc_zeroed(AES_BLOCK_SIZE)?;
            let j0 = scope.dma_alloc_zeroed(AES_BLOCK_SIZE)?;
            let ej0 = scope.dma_alloc_zeroed(AES_BLOCK_SIZE)?;
            let ctr = scope.dma_alloc_zeroed(AES_BLOCK_SIZE)?;
            let desc = scope.dma_alloc(AES_BLOCK_SIZE)?;
            let buf = scope.dma_alloc_zeroed(SGL_CHUNK)?;
            let out = scope.dma_alloc_zeroed(SGL_CHUNK)?;

            let result = async {
                // H = E_K(0^128); `ctr` is still all-zero here.
                self.aes_run(AesMode::Ecb, AesOp::Encrypt, key, None, ctr, h)
                    .await?;
                j0[..GCM_IV_LEN].copy_from_slice(iv);
                j0[AES_BLOCK_SIZE - 1] = 1;
                self.aes_run(AesMode::Ecb, AesOp::Encrypt, key, None, j0, ej0)
                    .await?;
                let mut ghash = Ghash::new(h).ok_or(HsmError::AesGcmInvalidBufferSize)?;
                let mut k = 0;

                // Padded AAD region: copy through, GHASH the content. Chunk
                // boundaries are block-aligned and `off` is 0 or 16, so
                // every non-final GHASH update is whole blocks.
                let aad_end = off + aad_len;
                let mut p = 0;
                while p < padded {
                    let n = core::cmp::min(SGL_CHUNK, padded - p);
                    rd.read_into(self, io, desc, &mut buf[..n]).await?;
                    let s = core::cmp::max(p, off);
                    let e = core::cmp::min(p + n, aad_end);
                    if s < e {
                        ghash.update(&buf[s - p..e - p]);
                    }
                    sgl_checkpoint(pass, cps, &mut k, &ghash.state())?;
                    if let Some(w) = wr.as_mut() {
                        w.write_from(self, io, desc, &buf[..n]).await?;
                    }
                    p += n;
                }

                // Text: CTR from inc32(J₀), counter recomputed per chunk.
                let ctr0 = u32::from_be_bytes([j0[12], j0[13], j0[14], j0[15]]);
                let op = if pass == Pass::Encrypt {
                    AesOp::Encrypt
                } else {
                    AesOp::Decrypt
                };
                let mut done = 0;
                while done < text_len {
                    let n = core::cmp::min(SGL_CHUNK, text_len - done);
                    rd.read_into(self, io, desc, &mut buf[..n]).await?;
                    if pass != Pass::Encrypt {
                        ghash.update(&buf[..n]);
                        sgl_checkpoint(pass, cps, &mut k, &ghash.state())?;
                    }
                    if pass != Pass::Verify {
                        let nb = n.next_multiple_of(AES_BLOCK_SIZE);
                        buf[n..nb].fill(0);
                        let blocks = u32::try_from(done / AES_BLOCK_SIZE)
                            .map_err(|_| HsmError::AesGcmInvalidBufferSize)?;
                        ctr.copy_from_slice(j0);
                        ctr[12..16].copy_from_slice(
                            &ctr0.wrapping_add(1).wrapping_add(blocks).to_be_bytes(),
                        );
                        self.aes_run(AesMode::Ctr, op, key, Some(ctr), &buf[..nb], &mut out[..nb])
                            .await?;
                        if pass == Pass::Encrypt {
                            ghash.update(&out[..n]);
                        }
                        if let Some(w) = wr.as_mut() {
                            w.write_from(self, io, desc, &out[..n]).await?;
                        }
                    }
                    done += n;
                }

                let mut lengths = [0u8; AES_BLOCK_SIZE];
                lengths[..8].copy_from_slice(&aad_bits);
                lengths[8..].copy_from_slice(&text_bits);
                ghash.update(&lengths);
                let mut t = ghash.finish();
                for (x, y) in t.iter_mut().zip(ej0.iter()) {
                    *x ^= y;
                }
                Ok(t)
            }
            .await;

            h.fill(0);
            ej0.fill(0);
            buf.fill(0);
            out.fill(0);
            result
        })
        .await
    }

    /// Overwrite `len` bytes of host SGL `dst` with zeros.
    async fn gcm_sgl_scrub(&self, io: &UnoHsmIo, len: usize, dst: &[u8; 16]) -> HsmResult<()> {
        let mut wr = HostSgl::new(dst, len)?;
        self.alloc_scoped_async(io, async |scope| {
            let desc = scope.dma_alloc(AES_BLOCK_SIZE)?;
            let zeros = scope.dma_alloc_zeroed(SGL_CHUNK)?;
            let mut done = 0;
            while done < len {
                let n = core::cmp::min(SGL_CHUNK, len - done);
                wr.write_from(self, io, desc, &zeros[..n]).await?;
                done += n;
            }
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_layout_offsets_and_bounds() {
        assert_eq!(sgl_aad_layout(0, 0), Ok((0, 0)));
        assert_eq!(sgl_aad_layout(1, 32), Ok((32, 16)));
        assert_eq!(sgl_aad_layout(16, 32), Ok((32, 16)));
        assert_eq!(sgl_aad_layout(17, 32), Ok((32, 0)));
        assert_eq!(sgl_aad_layout(32, 32), Ok((32, 0)));
        assert_eq!(sgl_aad_layout(33, 64), Ok((64, 16)));
        assert_eq!(
            sgl_aad_layout(1, 31),
            Err(HsmError::AesGcmInvalidBufferSize)
        );
        assert_eq!(
            sgl_aad_layout(usize::MAX, usize::MAX),
            Err(HsmError::AesGcmInvalidBufferSize)
        );
    }

    #[test]
    fn ct_eq_and_bits() {
        assert!(sgl_ct_eq(b"abc", b"abc"));
        assert!(!sgl_ct_eq(b"abc", b"abd"));
        assert!(!sgl_ct_eq(b"abc", b"ab"));
        assert_eq!(sgl_bits(2049), Ok((2049u64 * 8).to_be_bytes()));
        assert_eq!(sgl_bits(usize::MAX), Err(HsmError::AesGcmInvalidBufferSize));
    }

    #[test]
    fn checkpoint_detects_changed_chunk_before_release() {
        let mut cps = [[0u8; GCM_TAG_LEN]; SGL_MAX_CHUNKS];
        let states = [[1u8; GCM_TAG_LEN], [2u8; GCM_TAG_LEN], [3u8; GCM_TAG_LEN]];
        let mut k = 0;
        for st in &states {
            sgl_checkpoint(Pass::Verify, &mut cps, &mut k, st).unwrap();
        }
        let mut k = 0;
        sgl_checkpoint(Pass::Decrypt, &mut cps, &mut k, &states[0]).unwrap();
        assert_eq!(
            sgl_checkpoint(Pass::Decrypt, &mut cps, &mut k, &[9u8; GCM_TAG_LEN]),
            Err(HsmError::AesGcmDecryptTagDoesNotMatch)
        );
    }

    #[test]
    fn checkpoint_bounds_chunk_count() {
        let mut cps = [[0u8; GCM_TAG_LEN]; SGL_MAX_CHUNKS];
        let mut k = SGL_MAX_CHUNKS;
        let st = [0u8; GCM_TAG_LEN];
        assert_eq!(
            sgl_checkpoint(Pass::Verify, &mut cps, &mut k, &st),
            Err(HsmError::AesGcmInvalidBufferSize)
        );
        // Encrypt is never checkpointed or bounded.
        assert_eq!(sgl_checkpoint(Pass::Encrypt, &mut cps, &mut k, &st), Ok(()));
    }
}
