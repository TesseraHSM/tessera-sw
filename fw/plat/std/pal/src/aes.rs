// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmAes`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdAes`](crate::drivers::aes::StdAes)
//! driver. All implemented crypto work is offloaded to the worker pool by
//! the driver. Newly added AES-KW/AES-XTS trait entry points are stubbed
//! with `todo!()` for now.

use core::convert::TryInto;

use tsra_fw_core_crypto_gcm_buf::aad_offset;
use tsra_fw_core_crypto_gcm_buf::padded_aad_len;

use super::*;

fn aes_op_is_encrypt(op: AesOp) -> bool {
    matches!(op, AesOp::Encrypt)
}

fn gcm_iv(iv: &DmaBuf) -> HsmResult<&[u8; 12]> {
    let iv: &[u8] = iv;
    iv.try_into().map_err(|_| HsmError::AesGcmInvalidBufferSize)
}

fn gcm_tag(tag: &DmaBuf) -> HsmResult<&[u8; 16]> {
    let tag: &[u8] = tag;
    tag.try_into()
        .map_err(|_| HsmError::AesGcmInvalidBufferSize)
}

fn gcm_tag_mut(tag: &mut DmaBuf) -> HsmResult<&mut [u8; 16]> {
    let tag: &mut [u8] = tag;
    tag.try_into()
        .map_err(|_| HsmError::AesGcmInvalidBufferSize)
}

/// Split a `[padded_AAD | text]` GCM buffer (the [`HsmAes`] layout, per
/// `tsra_fw_core_crypto_gcm_buf`) into the AAD content and the length of
/// the padded AAD region that precedes the text.
fn gcm_layout(buf: &[u8], aad_len: usize) -> HsmResult<(Option<&[u8]>, usize)> {
    let pad = padded_aad_len(aad_len);
    if pad > buf.len() {
        return Err(HsmError::AesGcmInvalidBufferSize);
    }
    if aad_len == 0 {
        return Ok((None, 0));
    }
    let off = aad_offset(aad_len);
    Ok((Some(&buf[off..off + aad_len]), pad))
}

impl HsmAes for StdHsmPal {
    async fn aes_gen_key(&self, _io: &impl HsmIo, key: &mut [u8]) -> HsmResult<()> {
        self.aes.gen_key(key).await
    }

    async fn aes_cbc_enc_dec(
        &self,
        _io: &impl HsmIo,
        op: AesOp,
        key: &DmaBuf,
        input: &DmaBuf,
        iv_in: &DmaBuf,
        output: &mut DmaBuf,
        iv_out: Option<&mut DmaBuf>,
    ) -> HsmResult<()> {
        let mut iv = iv_in.to_vec();
        self.aes
            .cbc_enc_dec(key, aes_op_is_encrypt(op), &mut iv, input, output)
            .await?;
        if let Some(iv_out) = iv_out {
            iv_out[..iv.len()].copy_from_slice(&iv);
        }
        Ok(())
    }

    async fn aes_cbc_enc_dec_in_place(
        &self,
        _io: &impl HsmIo,
        op: AesOp,
        key: &DmaBuf,
        data: &mut DmaBuf,
        iv_in: &DmaBuf,
        iv_out: Option<&mut DmaBuf>,
    ) -> HsmResult<()> {
        let mut iv = iv_in.to_vec();
        let input = data.to_vec();
        self.aes
            .cbc_enc_dec(key, aes_op_is_encrypt(op), &mut iv, &input, data)
            .await?;
        if let Some(iv_out) = iv_out {
            iv_out[..iv.len()].copy_from_slice(&iv);
        }
        Ok(())
    }

    async fn aes_ecb_enc_dec(
        &self,
        _io: &impl HsmIo,
        op: AesOp,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.aes
            .ecb_enc_dec(key, aes_op_is_encrypt(op), input, output)
            .await
    }

    async fn aes_ecb_enc_dec_in_place(
        &self,
        _io: &impl HsmIo,
        op: AesOp,
        key: &DmaBuf,
        data: &mut DmaBuf,
    ) -> HsmResult<()> {
        let input = data.to_vec();
        self.aes
            .ecb_enc_dec(key, aes_op_is_encrypt(op), &input, data)
            .await
    }

    async fn gcm_encrypt(
        &self,
        _io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        plaintext: &DmaBuf,
        ciphertext: &mut DmaBuf,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        let iv = gcm_iv(iv)?;
        let tag = gcm_tag_mut(tag)?;
        let (aad, pad) = gcm_layout(plaintext, aad_len)?;
        if ciphertext.len() < plaintext.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        ciphertext[..pad].copy_from_slice(&plaintext[..pad]);
        self.aes
            .gcm_encrypt(key, iv, aad, &plaintext[pad..], &mut ciphertext[pad..], tag)
            .await
    }

    async fn gcm_encrypt_in_place(
        &self,
        _io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        data: &mut DmaBuf,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        let iv = gcm_iv(iv)?;
        let tag = gcm_tag_mut(tag)?;
        let input = data.to_vec();
        let (aad, pad) = gcm_layout(&input, aad_len)?;
        self.aes
            .gcm_encrypt(key, iv, aad, &input[pad..], &mut data[pad..], tag)
            .await
    }

    async fn gcm_decrypt(
        &self,
        _io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        tag: &DmaBuf,
        ciphertext: &DmaBuf,
        plaintext: &mut DmaBuf,
    ) -> HsmResult<()> {
        let iv = gcm_iv(iv)?;
        let tag = gcm_tag(tag)?;
        let (aad, pad) = gcm_layout(ciphertext, aad_len)?;
        if plaintext.len() < ciphertext.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        plaintext[..pad].copy_from_slice(&ciphertext[..pad]);
        self.aes
            .gcm_decrypt(key, iv, aad, tag, &ciphertext[pad..], &mut plaintext[pad..])
            .await
    }

    async fn gcm_decrypt_in_place(
        &self,
        _io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        tag: &DmaBuf,
        data: &mut DmaBuf,
    ) -> HsmResult<()> {
        let iv = gcm_iv(iv)?;
        let tag = gcm_tag(tag)?;
        let input = data.to_vec();
        let (aad, pad) = gcm_layout(&input, aad_len)?;
        self.aes
            .gcm_decrypt(key, iv, aad, tag, &input[pad..], &mut data[pad..])
            .await
    }

    async fn aes_kw_wrap(
        &self,
        _io: &impl HsmIo,
        _key: &DmaBuf,
        _input: &DmaBuf,
        _output: &mut DmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn aes_kw_unwrap(
        &self,
        _io: &impl HsmIo,
        _key: &DmaBuf,
        _input: &DmaBuf,
        _output: &mut DmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn aes_kwp_wrap(
        &self,
        _io: &impl HsmIo,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.aes.kwp_wrap(key, input, output).await
    }

    async fn aes_kwp_unwrap(
        &self,
        _io: &impl HsmIo,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<usize> {
        self.aes.kwp_unwrap(key, input, output).await
    }

    // AES-XTS support is currently disabled; the stub entry points are
    // retained here, commented out, for future re-enablement.
    //
    // async fn aes_xts_gen_key(&self, _io: &impl HsmIo, _key: &mut [u8]) -> HsmResult<()> {
    //     todo!()
    // }
    //
    // async fn aes_xts_encrypt(
    //     &self,
    //     _io: &impl HsmIo,
    //     _key: &DmaBuf,
    //     _tweak: &DmaBuf,
    //     _dul: XtsDataUnitLen,
    //     _input: &DmaBuf,
    //     _output: &mut DmaBuf,
    // ) -> HsmResult<()> {
    //     todo!()
    // }
    //
    // async fn aes_xts_decrypt(
    //     &self,
    //     _io: &impl HsmIo,
    //     _key: &DmaBuf,
    //     _tweak: &DmaBuf,
    //     _dul: XtsDataUnitLen,
    //     _input: &DmaBuf,
    //     _output: &mut DmaBuf,
    // ) -> HsmResult<()> {
    //     todo!()
    // }
    //
    // async fn aes_xts_encrypt_in_place(
    //     &self,
    //     _io: &impl HsmIo,
    //     _key: &DmaBuf,
    //     _tweak: &DmaBuf,
    //     _dul: XtsDataUnitLen,
    //     _data: &mut DmaBuf,
    // ) -> HsmResult<()> {
    //     todo!()
    // }
    //
    // async fn aes_xts_decrypt_in_place(
    //     &self,
    //     _io: &impl HsmIo,
    //     _key: &DmaBuf,
    //     _tweak: &DmaBuf,
    //     _dul: XtsDataUnitLen,
    //     _data: &mut DmaBuf,
    // ) -> HsmResult<()> {
    //     todo!()
    // }
}
