// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmAes`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdAes`](crate::drivers::aes::StdAes)
//! driver. All implemented crypto work is offloaded to the worker pool by
//! the driver. Newly added AES-KW/AES-XTS trait entry points are stubbed
//! with `todo!()` for now.

use core::convert::TryInto;

use super::*;

fn aes_op_is_encrypt(op: AesOp) -> bool {
    matches!(op, AesOp::Encrypt)
}

fn gcm_iv(iv: &HsmDmaBuf) -> HsmResult<&[u8; 12]> {
    let iv: &[u8] = iv;
    iv.try_into().map_err(|_| HsmError::AesGcmInvalidBufferSize)
}

fn gcm_tag(tag: &HsmDmaBuf) -> HsmResult<&[u8; 16]> {
    let tag: &[u8] = tag;
    tag.try_into()
        .map_err(|_| HsmError::AesGcmInvalidBufferSize)
}

fn gcm_tag_mut(tag: &mut HsmDmaBuf) -> HsmResult<&mut [u8; 16]> {
    let tag: &mut [u8] = tag;
    tag.try_into()
        .map_err(|_| HsmError::AesGcmInvalidBufferSize)
}

impl HsmAes for StdHsmPal {
    async fn aes_gen_key(&self, _io: &StdHsmIo, key: &mut [u8]) -> HsmResult<()> {
        self.aes.gen_key(key).await
    }

    async fn aes_cbc_enc_dec(
        &self,
        _io: &StdHsmIo,
        op: AesOp,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        iv_in: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
        iv_out: Option<&mut HsmDmaBuf>,
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
        _io: &StdHsmIo,
        op: AesOp,
        key: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
        iv_in: &HsmDmaBuf,
        iv_out: Option<&mut HsmDmaBuf>,
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

    async fn aes_cbc_enc_dec_in_place_iv(
        &self,
        _io: &StdHsmIo,
        op: AesOp,
        key: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
        iv: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        if iv.len() != 16 || data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(HsmError::InvalidArg);
        }

        let input = data.to_vec();
        self.aes
            .cbc_enc_dec(key, aes_op_is_encrypt(op), iv, &input, data)
            .await
    }

    async fn aes_ecb_enc_dec(
        &self,
        _io: &StdHsmIo,
        op: AesOp,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.aes
            .ecb_enc_dec(key, aes_op_is_encrypt(op), input, output)
            .await
    }

    async fn aes_ecb_enc_dec_in_place(
        &self,
        _io: &StdHsmIo,
        op: AesOp,
        key: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let input = data.to_vec();
        self.aes
            .ecb_enc_dec(key, aes_op_is_encrypt(op), &input, data)
            .await
    }

    async fn gcm_encrypt(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        plaintext: &HsmDmaBuf,
        ciphertext: &mut HsmDmaBuf,
        tag: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let iv = gcm_iv(iv)?;
        let tag = gcm_tag_mut(tag)?;
        if aad_len > plaintext.len() || aad_len > ciphertext.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        let aad: Option<&[u8]> = if aad_len > 0 {
            Some(&plaintext[..aad_len])
        } else {
            None
        };
        let data: &[u8] = &plaintext[aad_len..];
        if let Some(aad) = aad {
            ciphertext[..aad_len].copy_from_slice(aad);
        }
        self.aes
            .gcm_encrypt(key, iv, aad, data, &mut ciphertext[aad_len..], tag)
            .await
    }

    async fn gcm_encrypt_in_place(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        data: &mut HsmDmaBuf,
        tag: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let iv = gcm_iv(iv)?;
        let tag = gcm_tag_mut(tag)?;
        if aad_len > data.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        let input = data.to_vec();
        let aad = if aad_len > 0 {
            Some(&input[..aad_len])
        } else {
            None
        };
        let plaintext = &input[aad_len..];
        self.aes
            .gcm_encrypt(key, iv, aad, plaintext, &mut data[aad_len..], tag)
            .await
    }

    async fn gcm_decrypt(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        tag: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        plaintext: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let iv = gcm_iv(iv)?;
        let tag = gcm_tag(tag)?;
        if aad_len > ciphertext.len() || aad_len > plaintext.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        let aad: Option<&[u8]> = if aad_len > 0 {
            plaintext[..aad_len].copy_from_slice(&ciphertext[..aad_len]);
            Some(&ciphertext[..aad_len])
        } else {
            None
        };
        let data: &[u8] = &ciphertext[aad_len..];
        self.aes
            .gcm_decrypt(key, iv, aad, tag, data, &mut plaintext[aad_len..])
            .await
    }

    async fn gcm_decrypt_in_place(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        tag: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let iv = gcm_iv(iv)?;
        let tag = gcm_tag(tag)?;
        if aad_len > data.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        let input = data.to_vec();
        let aad = if aad_len > 0 {
            Some(&input[..aad_len])
        } else {
            None
        };
        let ciphertext = &input[aad_len..];
        self.aes
            .gcm_decrypt(key, iv, aad, tag, ciphertext, &mut data[aad_len..])
            .await
    }

    async fn aes_kw_wrap(
        &self,
        _io: &StdHsmIo,
        _key: &HsmDmaBuf,
        _input: &HsmDmaBuf,
        _output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn aes_kw_unwrap(
        &self,
        _io: &StdHsmIo,
        _key: &HsmDmaBuf,
        _input: &HsmDmaBuf,
        _output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn aes_kwp_wrap(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.aes.kwp_wrap(key, input, output).await
    }

    async fn aes_kwp_unwrap(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<usize> {
        self.aes.kwp_unwrap(key, input, output).await
    }

    // AES-XTS support is currently disabled; the stub entry points are
    // retained here, commented out, for future re-enablement.
    //
    // async fn aes_xts_gen_key(&self, _io: &StdHsmIo, _key: &mut [u8]) -> HsmResult<()> {
    //     todo!()
    // }
    //
    // async fn aes_xts_encrypt(
    //     &self,
    //     _io: &StdHsmIo,
    //     _key: &HsmDmaBuf,
    //     _tweak: &HsmDmaBuf,
    //     _dul: XtsDataUnitLen,
    //     _input: &HsmDmaBuf,
    //     _output: &mut HsmDmaBuf,
    // ) -> HsmResult<()> {
    //     todo!()
    // }
    //
    // async fn aes_xts_decrypt(
    //     &self,
    //     _io: &StdHsmIo,
    //     _key: &HsmDmaBuf,
    //     _tweak: &HsmDmaBuf,
    //     _dul: XtsDataUnitLen,
    //     _input: &HsmDmaBuf,
    //     _output: &mut HsmDmaBuf,
    // ) -> HsmResult<()> {
    //     todo!()
    // }
    //
    // async fn aes_xts_encrypt_in_place(
    //     &self,
    //     _io: &StdHsmIo,
    //     _key: &HsmDmaBuf,
    //     _tweak: &HsmDmaBuf,
    //     _dul: XtsDataUnitLen,
    //     _data: &mut HsmDmaBuf,
    // ) -> HsmResult<()> {
    //     todo!()
    // }
    //
    // async fn aes_xts_decrypt_in_place(
    //     &self,
    //     _io: &StdHsmIo,
    //     _key: &HsmDmaBuf,
    //     _tweak: &HsmDmaBuf,
    //     _dul: XtsDataUnitLen,
    //     _data: &mut HsmDmaBuf,
    // ) -> HsmResult<()> {
    //     todo!()
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_place_cbc_rejects_bad_lengths_before_mutation() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let key = pal.dma_alloc(&io, 32).unwrap();
        key.fill(0x11);
        let message = pal.dma_alloc(&io, 16).unwrap();
        let iv = pal.dma_alloc(&io, 17).unwrap();
        for (msg_len, iv_len) in [(0, 16), (15, 16), (16, 15), (16, 17)] {
            message.fill(0x42);
            iv.fill(0x24);
            assert_eq!(
                pal.aes_cbc_enc_dec_in_place_iv(
                    &io,
                    AesOp::Encrypt,
                    key,
                    &mut message[..msg_len],
                    &mut iv[..iv_len],
                )
                .await,
                Err(HsmError::InvalidArg)
            );
            assert!(message.iter().all(|&b| b == 0x42));
            assert!(iv.iter().all(|&b| b == 0x24));
        }
    }
}
