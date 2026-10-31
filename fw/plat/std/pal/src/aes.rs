// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmAes`], [`HsmAesGcm`], [`HsmAesKw`], and [`HsmAesXts`]
//! implementations for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdAes`](crate::drivers::aes::StdAes)
//! driver. All implemented crypto work is offloaded to the worker pool by
//! the driver. Newly added AES-KW/AES-XTS trait entry points are stubbed
//! with `todo!()` for now.

use core::convert::TryInto;

use super::*;

fn aes_op_is_encrypt(op: HsmAesOp) -> bool {
    matches!(op, HsmAesOp::Encrypt)
}

/// Validates a generic-mode request and returns `(iv_len, data_len)`.
fn generic_lens(mode: HsmAesMode, key_len: usize, input_len: usize) -> HsmResult<(usize, usize)> {
    if !matches!(key_len, 16 | 24 | 32) {
        return Err(HsmError::InvalidArg);
    }
    let data_len = mode.data_len(input_len).ok_or(HsmError::InvalidArg)?;
    Ok((mode.iv_len(), data_len))
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

    async fn aes_encrypt_decrypt(
        &self,
        _io: &StdHsmIo,
        op: HsmAesOp,
        mode: HsmAesMode,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let (iv_len, data_len) = generic_lens(mode, key.len(), input.len())?;
        if output.len() < input.len() {
            return Err(HsmError::InvalidArg);
        }
        let (iv, data) = input.split_at(iv_len);
        let (out, iv_out) = self
            .aes
            .enc_dec(key, aes_op_is_encrypt(op), mode, iv, data)
            .await?;
        output[..data_len].copy_from_slice(&out);
        output[data_len..data_len + iv_len].copy_from_slice(&iv_out);
        Ok(())
    }

    async fn aes_encrypt_decrypt_in_place(
        &self,
        _io: &StdHsmIo,
        op: HsmAesOp,
        mode: HsmAesMode,
        key: &HsmDmaBuf,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let (iv_len, data_len) = generic_lens(mode, key.len(), buf.len())?;
        let (iv, data) = buf.split_at(iv_len);
        let (out, iv_out) = self
            .aes
            .enc_dec(key, aes_op_is_encrypt(op), mode, iv, data)
            .await?;
        buf[..data_len].copy_from_slice(&out);
        buf[data_len..].copy_from_slice(&iv_out);
        Ok(())
    }

    async fn aes_cbc_enc_dec(
        &self,
        _io: &StdHsmIo,
        op: HsmAesOp,
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
        op: HsmAesOp,
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

    async fn aes_ecb_enc_dec(
        &self,
        _io: &StdHsmIo,
        op: HsmAesOp,
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
        op: HsmAesOp,
        key: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let input = data.to_vec();
        self.aes
            .ecb_enc_dec(key, aes_op_is_encrypt(op), &input, data)
            .await
    }
}

impl HsmAesGcm for StdHsmPal {
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
}

impl HsmAesKw for StdHsmPal {
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
}

impl HsmAesXts for StdHsmPal {
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

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// NIST SP 800-38A F.2.1 / F.1.1 / F.3.13 / F.4.1 / F.5.1 (AES-128),
    /// first two blocks, with the expected IV out.
    #[tokio::test]
    async fn generic_modes_match_sp800_38a() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let key = pal.dma_alloc(&io, 16).unwrap();
        key.copy_from_slice(&hex("2b7e151628aed2a6abf7158809cf4f3c"));
        let pt = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let ctr_iv = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let cases = [
            (
                HsmAesMode::Cbc,
                &iv,
                "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2",
                "5086cb9b507219ee95db113a917678b2",
            ),
            (
                HsmAesMode::Ecb,
                &iv,
                "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf",
                "",
            ),
            (
                HsmAesMode::Cfb,
                &iv,
                "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b",
                "c8a64537a0b3a93fcde3cdad9f1ce58b",
            ),
            (
                HsmAesMode::Ofb,
                &iv,
                "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825",
                "d9a4dada0892239f6b8b3d7680e15674",
            ),
            (
                HsmAesMode::Ctr,
                &ctr_iv,
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff",
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdff01",
            ),
        ];
        for (mode, iv, ct, iv_out) in cases {
            let iv = &iv[..mode.iv_len()];
            let (ct, iv_out) = (hex(ct), hex(iv_out));
            let len = iv.len() + pt.len();

            // In place: [IV | pt] -> [ct | IV out].
            let buf = pal.dma_alloc(&io, len).unwrap();
            buf[..iv.len()].copy_from_slice(iv);
            buf[iv.len()..].copy_from_slice(&pt);
            pal.aes_encrypt_decrypt_in_place(&io, HsmAesOp::Encrypt, mode, key, buf)
                .await
                .unwrap();
            assert_eq!(&buf[..pt.len()], &ct[..], "{mode:?} encrypt");
            assert_eq!(&buf[pt.len()..], &iv_out[..], "{mode:?} iv out");

            // Out of place: [IV | ct] -> [pt | IV out].
            let input = pal.dma_alloc(&io, len).unwrap();
            let output = pal.dma_alloc(&io, len).unwrap();
            input[..iv.len()].copy_from_slice(iv);
            input[iv.len()..].copy_from_slice(&ct);
            pal.aes_encrypt_decrypt(&io, HsmAesOp::Decrypt, mode, key, input, output)
                .await
                .unwrap();
            assert_eq!(&output[..pt.len()], &pt[..], "{mode:?} decrypt");
            assert_eq!(&output[pt.len()..], &iv_out[..], "{mode:?} decrypt iv out");
        }
    }

    #[tokio::test]
    async fn generic_rejects_bad_lengths_before_mutation() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let key = pal.dma_alloc(&io, 32).unwrap();
        let bad_key = pal.dma_alloc(&io, 20).unwrap();
        let buf = pal.dma_alloc(&io, 64).unwrap();
        let out = pal.dma_alloc(&io, 64).unwrap();
        let cases: [(HsmAesMode, &HsmDmaBuf, usize); 6] = [
            (HsmAesMode::Cbc, key, 31),
            (HsmAesMode::Ecb, key, 17),
            (HsmAesMode::Cfb, key, 15),
            (HsmAesMode::Ofb, key, 0),
            (HsmAesMode::Ctr, bad_key, 32),
            (HsmAesMode::Ecb, bad_key, 16),
        ];
        for (mode, key, len) in cases {
            buf.fill(0x42);
            assert_eq!(
                pal.aes_encrypt_decrypt_in_place(
                    &io,
                    HsmAesOp::Encrypt,
                    mode,
                    key,
                    &mut buf[..len]
                )
                .await,
                Err(HsmError::InvalidArg),
                "{mode:?} len {len}"
            );
            assert!(buf.iter().all(|&b| b == 0x42));
        }
        // Output shorter than input.
        out.fill(0x24);
        assert_eq!(
            pal.aes_encrypt_decrypt(
                &io,
                HsmAesOp::Encrypt,
                HsmAesMode::Ctr,
                key,
                &buf[..33],
                &mut out[..32]
            )
            .await,
            Err(HsmError::InvalidArg)
        );
        assert!(out.iter().all(|&b| b == 0x24));
    }
}
