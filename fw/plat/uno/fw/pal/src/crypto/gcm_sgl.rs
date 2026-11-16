// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-GCM host-to-host over raw SGLs for the Uno PAL.
//!
//! The streaming algorithm (two-pass decrypt with per-chunk GHASH
//! checkpoints) lives in the host-tested [`tsra_fw_uno_aes_sgl::gcm`]
//! crate; this module binds it to the CP AES core (ECB for `H`/`E_K(J₀)`,
//! CTR for the text) and to host SGLs streamed through the per-IO DMA
//! slot.

use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_uno_aes_sgl::gcm::GcmSglIo;
use tsra_fw_uno_aes_sgl::gcm::SGL_CHUNK;
use tsra_fw_uno_aes_sgl::gcm::SglBuf;
use tsra_fw_uno_aes_sgl::gcm::gcm_decrypt_sgl;
use tsra_fw_uno_aes_sgl::gcm::gcm_encrypt_sgl;
use tsra_fw_uno_drivers_aes::AesMode;
use tsra_fw_uno_drivers_aes::AesOp;

use super::aes::AES_BLOCK_SIZE;
use super::gcm::GCM_TAG_LEN;
use crate::UnoHsmIo;
use crate::UnoHsmPal;
use crate::gdma::HostSgl;

/// [`GcmSglIo`] over host SGLs `src`/`dst` and the CP AES core.
struct PalGcmSglIo<'a> {
    pal: &'a UnoHsmPal,
    io: &'a UnoHsmIo,
    key: &'a HsmDmaBuf,
    src: &'a [u8; 16],
    dst: &'a [u8; 16],
    len: usize,
    rd: Option<HostSgl>,
    wr: Option<HostSgl>,
    desc: &'a mut HsmDmaBuf,
    buf: &'a mut HsmDmaBuf,
    out: &'a mut HsmDmaBuf,
    blk_in: &'a mut HsmDmaBuf,
    blk_out: &'a mut HsmDmaBuf,
    ctr: &'a mut HsmDmaBuf,
}

impl<'a> PalGcmSglIo<'a> {
    /// Allocate the DMA buffers from `scope`. The SGLs are opened by the
    /// first [`GcmSglIo::rewind`].
    fn new<A: HsmScopedAlloc>(
        pal: &'a UnoHsmPal,
        io: &'a UnoHsmIo,
        key: &'a HsmDmaBuf,
        len: usize,
        src: &'a [u8; 16],
        dst: &'a [u8; 16],
        scope: &'a A,
    ) -> HsmResult<Self> {
        Ok(Self {
            pal,
            io,
            key,
            src,
            dst,
            len,
            rd: None,
            wr: None,
            desc: scope.dma_alloc(AES_BLOCK_SIZE)?,
            buf: scope.dma_alloc_zeroed(SGL_CHUNK)?,
            out: scope.dma_alloc_zeroed(SGL_CHUNK)?,
            blk_in: scope.dma_alloc_zeroed(AES_BLOCK_SIZE)?,
            blk_out: scope.dma_alloc_zeroed(AES_BLOCK_SIZE)?,
            ctr: scope.dma_alloc_zeroed(AES_BLOCK_SIZE)?,
        })
    }
}

impl GcmSglIo for PalGcmSglIo<'_> {
    fn buf(&mut self) -> &mut [u8] {
        self.buf
    }

    fn out(&mut self) -> &mut [u8] {
        self.out
    }

    fn rewind(&mut self, write: bool) -> HsmResult<()> {
        self.rd = Some(HostSgl::new(self.src, self.len)?);
        self.wr = if write {
            Some(HostSgl::new(self.dst, self.len)?)
        } else {
            None
        };
        Ok(())
    }

    async fn read(&mut self, n: usize) -> HsmResult<()> {
        if n > self.buf.len() {
            return Err(HsmError::InvalidArg);
        }
        let rd = self.rd.as_mut().ok_or(HsmError::InvalidArg)?;
        rd.read_into(self.pal, self.io, self.desc, &mut self.buf[..n])
            .await
    }

    async fn write(&mut self, from: SglBuf, n: usize) -> HsmResult<()> {
        let wr = self.wr.as_mut().ok_or(HsmError::InvalidArg)?;
        let src: &HsmDmaBuf = match from {
            SglBuf::In => self.buf,
            SglBuf::Out => self.out,
        };
        if n > src.len() {
            return Err(HsmError::InvalidArg);
        }
        wr.write_from(self.pal, self.io, self.desc, &src[..n]).await
    }

    async fn ecb_encrypt(
        &mut self,
        block: &[u8; AES_BLOCK_SIZE],
    ) -> HsmResult<[u8; AES_BLOCK_SIZE]> {
        self.blk_in.copy_from_slice(block);
        let r = self
            .pal
            .aes_run(
                AesMode::Ecb,
                AesOp::Encrypt,
                self.key,
                None,
                self.blk_in,
                self.blk_out,
            )
            .await;
        let mut e = [0u8; AES_BLOCK_SIZE];
        e.copy_from_slice(self.blk_out);
        self.blk_in.fill(0);
        self.blk_out.fill(0);
        r.map(|()| e)
    }

    async fn ctr(
        &mut self,
        encrypt: bool,
        counter: &[u8; AES_BLOCK_SIZE],
        nb: usize,
    ) -> HsmResult<()> {
        if nb > self.buf.len() || nb > self.out.len() {
            return Err(HsmError::InvalidArg);
        }
        self.ctr.copy_from_slice(counter);
        let op = if encrypt {
            AesOp::Encrypt
        } else {
            AesOp::Decrypt
        };
        self.pal
            .aes_run(
                AesMode::Ctr,
                op,
                self.key,
                Some(&mut *self.ctr),
                &self.buf[..nb],
                &mut self.out[..nb],
            )
            .await
    }
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
        let t = self
            .alloc_scoped_async(io, async |scope| {
                let mut s = PalGcmSglIo::new(self, io, key, len, src, dst, scope)?;
                gcm_encrypt_sgl(&mut s, iv, aad_len, len).await
            })
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
        self.alloc_scoped_async(io, async |scope| {
            let mut s = PalGcmSglIo::new(self, io, key, len, src, dst, scope)?;
            gcm_decrypt_sgl(&mut s, iv, aad_len, len, tag).await
        })
        .await
    }
}
