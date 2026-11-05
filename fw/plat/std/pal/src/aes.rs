// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmAes`], [`HsmAesGcm`], [`HsmAesKw`], and [`HsmAesXts`]
//! implementations for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdAes`](crate::drivers::aes::StdAes)
//! driver. All implemented crypto work is offloaded to the worker pool by
//! the driver.

use core::convert::TryInto;

use zeroize::Zeroizing;

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

/// Splits a `[padded_AAD | text]` buffer per the `pad_aad` convention
/// into `(aad, text_offset)`.
fn gcm_split_padded(buf: &[u8], aad_len: usize) -> HsmResult<(Option<&[u8]>, usize)> {
    if aad_len == 0 {
        return Ok((None, 0));
    }
    let padded = aad_len
        .checked_next_multiple_of(32)
        .ok_or(HsmError::AesGcmInvalidBufferSize)?;
    if padded > buf.len() {
        return Err(HsmError::AesGcmInvalidBufferSize);
    }
    let start = if (1..=16).contains(&(aad_len % 32)) {
        16
    } else {
        0
    };
    Ok((Some(&buf[start..start + aad_len]), padded))
}

/// Reads `len` host bytes described by the raw SGL descriptor `src`.
fn sgl_read(pal: &StdHsmPal, src: &[u8; 16], len: usize) -> HsmResult<Vec<u8>> {
    crate::drivers::gdma::validate_raw_src(src, len)?;
    let mut buf = vec![0u8; len];
    // SAFETY: std SGL addresses are raw host-process pointers the caller
    // guarantees valid; `validate_raw_src` checked length and null.
    unsafe { pal.gdma.copy_mem_from_host_raw(src, &mut buf) };
    Ok(buf)
}

/// Writes `buf` to the host buffer described by the raw SGL descriptor
/// `dst`.
fn sgl_write(pal: &StdHsmPal, dst: &[u8; 16], buf: &[u8]) -> HsmResult<()> {
    crate::drivers::gdma::validate_raw_src(dst, buf.len())?;
    // SAFETY: as for `sgl_read`.
    unsafe { pal.gdma.copy_mem_to_host_raw(buf, dst) };
    Ok(())
}

impl HsmAes for StdHsmPal {
    async fn aes_gen_key(&self, _io: &StdHsmIo, key: &mut [u8]) -> HsmResult<()> {
        self.aes.gen_key(key).await
    }

    async fn aes_enc_dec(
        &self,
        _io: &StdHsmIo,
        op: HsmAesOp,
        mode: HsmAesMode,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let (iv_len, data_len) = generic_lens(mode, key.len(), input.len())?;
        let Some(output) = output else {
            return Ok(input.len());
        };
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
        Ok(input.len())
    }

    async fn aes_enc_dec_in_place(
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

    async fn gcm_encrypt_sgl(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        len: usize,
        src: &[u8; 16],
        dst: &[u8; 16],
        tag: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let iv = gcm_iv(iv)?;
        let tag = gcm_tag_mut(tag)?;
        crate::drivers::gdma::validate_raw_src(dst, len)?;
        let input = sgl_read(self, src, len)?;
        let (aad, off) = gcm_split_padded(&input, aad_len)?;
        let mut output = input.clone();
        self.aes
            .gcm_encrypt(key, iv, aad, &input[off..], &mut output[off..], tag)
            .await?;
        sgl_write(self, dst, &output)
    }

    async fn gcm_decrypt_sgl(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        len: usize,
        tag: &HsmDmaBuf,
        src: &[u8; 16],
        dst: &[u8; 16],
    ) -> HsmResult<()> {
        let iv = gcm_iv(iv)?;
        let tag = gcm_tag(tag)?;
        crate::drivers::gdma::validate_raw_src(dst, len)?;
        let input = sgl_read(self, src, len)?;
        let (aad, off) = gcm_split_padded(&input, aad_len)?;
        let mut output = input.clone();
        self.aes
            .gcm_decrypt(key, iv, aad, tag, &input[off..], &mut output[off..])
            .await?;
        sgl_write(self, dst, &output)
    }
}

impl HsmAesKw for StdHsmPal {
    async fn aes_kw_wrap(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        self.aes.kw_wrap(key, input, output.map(|o| &mut **o)).await
    }

    async fn aes_kw_wrap_in_place(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<usize> {
        let input = Zeroizing::new(buf.get(8..).ok_or(HsmError::InvalidArg)?.to_vec());
        self.aes.kw_wrap(key, &input, Some(&mut **buf)).await
    }

    async fn aes_kw_unwrap(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        self.aes
            .kw_unwrap(key, input, output.map(|o| &mut **o))
            .await
    }

    async fn aes_kw_unwrap_in_place(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<usize> {
        let input = buf.to_vec();
        self.aes.kw_unwrap(key, &input, Some(&mut **buf)).await
    }

    async fn aes_kwp_wrap(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        self.aes
            .kwp_wrap(key, input, output.map(|o| &mut **o))
            .await
    }

    async fn aes_kwp_wrap_in_place(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        data_len: usize,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<usize> {
        let end = data_len.checked_add(8).ok_or(HsmError::InvalidArg)?;
        let input = Zeroizing::new(buf.get(8..end).ok_or(HsmError::InvalidArg)?.to_vec());
        self.aes.kwp_wrap(key, &input, Some(&mut **buf)).await
    }

    async fn aes_kwp_unwrap(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        self.aes
            .kwp_unwrap(key, input, output.map(|o| &mut **o))
            .await
    }

    async fn aes_kwp_unwrap_in_place(
        &self,
        _io: &StdHsmIo,
        key: &HsmDmaBuf,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<usize> {
        let input = buf.to_vec();
        self.aes.kwp_unwrap(key, &input, Some(&mut **buf)).await
    }
}

impl HsmAesXts for StdHsmPal {
    async fn aes_xts_gen_key(&self, _io: &StdHsmIo, key: &mut [u8]) -> HsmResult<()> {
        if key.len() != HSM_AES_XTS_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        let (k1, k2) = key.split_at_mut(HSM_AES_XTS_KEY_LEN / 2);
        self.aes.gen_key(k1).await?;
        loop {
            self.aes.gen_key(k2).await?;
            if k1 != k2 {
                return Ok(());
            }
        }
    }

    async fn aes_xts_enc_dec_sgl(
        &self,
        _io: &StdHsmIo,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        tweak: &HsmDmaBuf,
        len: usize,
        dul: usize,
        src: &[u8; 16],
        dst: &[u8; 16],
    ) -> HsmResult<()> {
        if key.len() != HSM_AES_XTS_KEY_LEN || tweak.len() != HSM_AES_XTS_TWEAK_LEN {
            return Err(HsmError::InvalidArg);
        }
        let (k1, k2) = key.split_at(HSM_AES_XTS_KEY_LEN / 2);
        if k1 == k2 {
            return Err(HsmError::InvalidArg);
        }
        if dul < 16 || !dul.is_multiple_of(16) || len == 0 || !len.is_multiple_of(dul) {
            return Err(HsmError::AesXtsInvalidBufferSize);
        }
        let mut t = [0u8; 16];
        t[..HSM_AES_XTS_TWEAK_LEN].copy_from_slice(tweak);
        let first = u128::from_le_bytes(t);
        // The tweak after the last unit must still fit in 64 bits (no
        // wraparound), matching the reference XTS implementation.
        if first + (len / dul) as u128 > u128::from(u64::MAX) {
            return Err(HsmError::AesXtsInvalidBufferSize);
        }
        crate::drivers::gdma::validate_raw_src(dst, len)?;
        let mut data = sgl_read(self, src, len)?;
        self.aes
            .xts_crypt(k1, k2, aes_op_is_encrypt(op), t, dul, &mut data)
            .await?;
        sgl_write(self, dst, &data)
    }
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
            pal.aes_enc_dec_in_place(&io, HsmAesOp::Encrypt, mode, key, buf)
                .await
                .unwrap();
            assert_eq!(&buf[..pt.len()], &ct[..], "{mode:?} encrypt");
            assert_eq!(&buf[pt.len()..], &iv_out[..], "{mode:?} iv out");

            // Out of place: [IV | ct] -> [pt | IV out].
            let input = pal.dma_alloc(&io, len).unwrap();
            let output = pal.dma_alloc(&io, len).unwrap();
            input[..iv.len()].copy_from_slice(iv);
            input[iv.len()..].copy_from_slice(&ct);
            output.fill(0x5a);
            assert_eq!(
                pal.aes_enc_dec(&io, HsmAesOp::Decrypt, mode, key, input, None)
                    .await,
                Ok(len),
                "{mode:?} query"
            );
            assert!(output.iter().all(|&b| b == 0x5a));
            assert_eq!(
                pal.aes_enc_dec(&io, HsmAesOp::Decrypt, mode, key, input, Some(&mut *output))
                    .await,
                Ok(len)
            );
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
                pal.aes_enc_dec_in_place(&io, HsmAesOp::Encrypt, mode, key, &mut buf[..len])
                    .await,
                Err(HsmError::InvalidArg),
                "{mode:?} len {len}"
            );
            assert!(buf.iter().all(|&b| b == 0x42));
        }
        // Output shorter than input.
        out.fill(0x24);
        assert_eq!(
            pal.aes_enc_dec(
                &io,
                HsmAesOp::Encrypt,
                HsmAesMode::Ctr,
                key,
                &buf[..33],
                Some(&mut out[..32])
            )
            .await,
            Err(HsmError::InvalidArg)
        );
        assert!(out.iter().all(|&b| b == 0x24));
        // Query mode validates the input too.
        assert_eq!(
            pal.aes_enc_dec(
                &io,
                HsmAesOp::Encrypt,
                HsmAesMode::Cbc,
                key,
                &buf[..31],
                None
            )
            .await,
            Err(HsmError::InvalidArg)
        );
    }

    #[tokio::test]
    async fn kw_matches_rfc3394_in_and_out_of_place() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);

        // RFC 3394 §4.1: 128 bits of key data with a 128-bit KEK.
        let key = pal.dma_alloc(&io, 16).unwrap();
        key.copy_from_slice(&hex("000102030405060708090a0b0c0d0e0f"));
        let pt = hex("00112233445566778899aabbccddeeff");
        let ct = hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");

        let input = pal.dma_alloc(&io, pt.len()).unwrap();
        input.copy_from_slice(&pt);
        let output = pal.dma_alloc(&io, ct.len()).unwrap();
        assert_eq!(pal.aes_kw_wrap(&io, key, input, None).await, Ok(ct.len()));
        assert_eq!(
            pal.aes_kw_wrap(&io, key, input, Some(&mut *output)).await,
            Ok(ct.len())
        );
        assert_eq!(&output[..], &ct[..]);

        // In place: [reserved | pt] -> ct.
        let buf = pal.dma_alloc(&io, ct.len()).unwrap();
        buf[8..].copy_from_slice(&pt);
        assert_eq!(pal.aes_kw_wrap_in_place(&io, key, buf).await, Ok(ct.len()));
        assert_eq!(&buf[..], &ct[..]);

        let plain = pal.dma_alloc(&io, pt.len()).unwrap();
        assert_eq!(
            pal.aes_kw_unwrap(&io, key, output, None).await,
            Ok(pt.len())
        );
        assert_eq!(
            pal.aes_kw_unwrap(&io, key, output, Some(&mut *plain)).await,
            Ok(pt.len())
        );
        assert_eq!(&plain[..], &pt[..]);

        assert_eq!(
            pal.aes_kw_unwrap_in_place(&io, key, buf).await,
            Ok(pt.len())
        );
        assert_eq!(&buf[..pt.len()], &pt[..]);

        output[0] ^= 1;
        assert_eq!(
            pal.aes_kw_unwrap_in_place(&io, key, output).await,
            Err(HsmError::AesUnwrapFailed)
        );
        assert_eq!(
            pal.aes_kw_wrap_in_place(&io, key, &mut buf[..8]).await,
            Err(HsmError::InvalidArg)
        );
    }

    #[tokio::test]
    async fn kwp_matches_rfc5649_in_and_out_of_place() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);

        // RFC 5649 §6 vectors plus an 8-byte boundary case checked with
        // OpenSSL AES-192-ECB over [AIV | plaintext].
        let key = pal.dma_alloc(&io, 24).unwrap();
        key.copy_from_slice(&hex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"));
        let cases = [
            (
                "c37b7e6492584340bed12207808941155068f738",
                "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
            ),
            ("466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f"),
            ("0001020304050607", "ebc0330864fe681ead53d839b34b9c66"),
        ];
        for (pt, ct) in cases {
            let (pt, ct) = (hex(pt), hex(ct));

            let input = pal.dma_alloc(&io, pt.len()).unwrap();
            input.copy_from_slice(&pt);
            let output = pal.dma_alloc(&io, ct.len()).unwrap();
            assert_eq!(pal.aes_kwp_wrap(&io, key, input, None).await, Ok(ct.len()));
            assert_eq!(
                pal.aes_kwp_wrap(&io, key, input, Some(&mut *output)).await,
                Ok(ct.len())
            );
            assert_eq!(&output[..], &ct[..]);

            // In place: [reserved | pt | pad room] -> ct, with spare tail.
            let buf = pal.dma_alloc(&io, ct.len() + 8).unwrap();
            buf.fill(0xee);
            buf[8..8 + pt.len()].copy_from_slice(&pt);
            assert_eq!(
                pal.aes_kwp_wrap_in_place(&io, key, pt.len(), buf).await,
                Ok(ct.len())
            );
            assert_eq!(&buf[..ct.len()], &ct[..]);

            let plain = pal.dma_alloc(&io, ct.len() - 8).unwrap();
            assert_eq!(
                pal.aes_kwp_unwrap(&io, key, output, None).await,
                Ok(ct.len() - 8)
            );
            assert_eq!(
                pal.aes_kwp_unwrap(&io, key, output, Some(&mut *plain))
                    .await,
                Ok(pt.len())
            );
            assert_eq!(&plain[..pt.len()], &pt[..]);

            let wrapped = &mut buf[..ct.len()];
            assert_eq!(
                pal.aes_kwp_unwrap_in_place(&io, key, wrapped).await,
                Ok(pt.len())
            );
            assert_eq!(&wrapped[..pt.len()], &pt[..]);

            output[0] ^= 1;
            assert_eq!(
                pal.aes_kwp_unwrap_in_place(&io, key, output).await,
                Err(HsmError::AesUnwrapFailed)
            );
            assert_eq!(
                pal.aes_kwp_wrap_in_place(&io, key, pt.len(), &mut buf[..ct.len() - 1])
                    .await,
                Err(HsmError::InvalidArg)
            );
        }
    }

    fn test_pal() -> (StdHsmPal, StdHsmIo) {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        (pal, io)
    }

    fn dma<'a>(pal: &'a StdHsmPal, io: &'a StdHsmIo, bytes: &[u8]) -> &'a mut HsmDmaBuf {
        let buf = pal.dma_alloc(io, bytes.len()).unwrap();
        buf.copy_from_slice(bytes);
        buf
    }

    fn sgl(buf: &[u8]) -> [u8; 16] {
        let mut d = [0u8; 16];
        d[..8].copy_from_slice(&(buf.as_ptr() as usize as u64).to_le_bytes());
        d[8..12].copy_from_slice(&(buf.len() as u32).to_le_bytes());
        d
    }

    /// GCM spec test case 16 (AES-256, 20-byte AAD, 60-byte text) over
    /// host SGL descriptors with the padded-AAD layout.
    #[tokio::test]
    async fn gcm_sgl_matches_test_case_16() {
        let (pal, io) = test_pal();
        let key = dma(
            &pal,
            &io,
            &hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
        );
        let iv = dma(&pal, &io, &hex("cafebabefacedbaddecaf888"));
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let ct = hex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        );
        // aad_len % 32 == 20 -> `[AAD | zeros(12)]`.
        let mut input = aad.clone();
        input.resize(32, 0);
        input.extend_from_slice(&pt);
        let len = input.len();
        let output = vec![0u8; len];

        let tag = pal.dma_alloc(&io, 16).unwrap();
        pal.gcm_encrypt_sgl(
            &io,
            key,
            iv,
            aad.len(),
            len,
            &sgl(&input),
            &sgl(&output),
            tag,
        )
        .await
        .unwrap();
        assert_eq!(&output[32..], &ct[..]);
        assert_eq!(&tag[..], &hex("76fc6ece0f4e1768cddf8853bb2d551b")[..]);

        let plain = vec![0u8; len];
        pal.gcm_decrypt_sgl(
            &io,
            key,
            iv,
            aad.len(),
            len,
            tag,
            &sgl(&output),
            &sgl(&plain),
        )
        .await
        .unwrap();
        assert_eq!(&plain[32..], &pt[..]);

        // Tampered AAD fails authentication.
        let mut bad = output.clone();
        bad[0] ^= 1;
        assert_eq!(
            pal.gcm_decrypt_sgl(&io, key, iv, aad.len(), len, tag, &sgl(&bad), &sgl(&plain))
                .await,
            Err(HsmError::AesGcmDecryptTagDoesNotMatch)
        );
        // A descriptor that does not describe `len` bytes is rejected.
        assert_eq!(
            pal.gcm_encrypt_sgl(
                &io,
                key,
                iv,
                aad.len(),
                len,
                &sgl(&input[1..]),
                &sgl(&output),
                tag
            )
            .await,
            Err(HsmError::InvalidArg)
        );
    }

    #[tokio::test]
    async fn xts_sgl_round_trips_and_uses_tweak() {
        let (pal, io) = test_pal();
        let key = pal.dma_alloc(&io, HSM_AES_XTS_KEY_LEN).unwrap();
        pal.aes_xts_gen_key(&io, key).await.unwrap();
        assert_ne!(&key[..32], &key[32..]);
        let tweak = dma(&pal, &io, &7u64.to_le_bytes());
        let pt: Vec<u8> = (0..64u8).collect();
        let enc = HsmAesOp::Encrypt;

        let ct = vec![0u8; pt.len()];
        pal.aes_xts_enc_dec_sgl(&io, enc, key, tweak, pt.len(), 64, &sgl(&pt), &sgl(&ct))
            .await
            .unwrap();
        assert_ne!(ct, pt);

        let other = vec![0u8; pt.len()];
        let tweak2 = dma(&pal, &io, &8u64.to_le_bytes());
        pal.aes_xts_enc_dec_sgl(&io, enc, key, tweak2, pt.len(), 64, &sgl(&pt), &sgl(&other))
            .await
            .unwrap();
        assert_ne!(other, ct);

        let back = vec![0u8; pt.len()];
        let dec = HsmAesOp::Decrypt;
        pal.aes_xts_enc_dec_sgl(&io, dec, key, tweak, pt.len(), 64, &sgl(&ct), &sgl(&back))
            .await
            .unwrap();
        assert_eq!(back, pt);
    }

    #[tokio::test]
    async fn xts_sgl_multi_unit_matches_per_unit() {
        let (pal, io) = test_pal();
        let key = pal.dma_alloc(&io, HSM_AES_XTS_KEY_LEN).unwrap();
        pal.aes_xts_gen_key(&io, key).await.unwrap();
        let pt: Vec<u8> = (0..128u8).collect();
        let enc = HsmAesOp::Encrypt;

        let tweak = dma(&pal, &io, &5u64.to_le_bytes());
        let all = vec![0u8; pt.len()];
        pal.aes_xts_enc_dec_sgl(&io, enc, key, tweak, pt.len(), 32, &sgl(&pt), &sgl(&all))
            .await
            .unwrap();

        for (i, unit) in pt.chunks(32).enumerate() {
            let tw = dma(&pal, &io, &(5 + i as u64).to_le_bytes());
            let one = vec![0u8; 32];
            pal.aes_xts_enc_dec_sgl(&io, enc, key, tw, 32, 32, &sgl(unit), &sgl(&one))
                .await
                .unwrap();
            assert_eq!(&all[i * 32..(i + 1) * 32], &one[..]);
        }
    }

    #[tokio::test]
    async fn xts_sgl_rejects_bad_inputs() {
        let (pal, io) = test_pal();
        let tweak = dma(&pal, &io, &[0u8; HSM_AES_XTS_TWEAK_LEN]);
        let mut good = [0x11u8; HSM_AES_XTS_KEY_LEN];
        good[32..].fill(0x22);
        let good = dma(&pal, &io, &good);
        let equal_halves = dma(&pal, &io, &[0x11u8; HSM_AES_XTS_KEY_LEN]);
        let short_tweak = dma(&pal, &io, &[0u8; 16]);
        let enc = HsmAesOp::Encrypt;

        let buf = [0u8; 32];
        let out = [0u8; 32];
        for (key, tweak) in [(&*equal_halves, &*tweak), (&*good, &*short_tweak)] {
            assert_eq!(
                pal.aes_xts_enc_dec_sgl(&io, enc, key, tweak, 32, 32, &sgl(&buf), &sgl(&out))
                    .await,
                Err(HsmError::InvalidArg)
            );
        }
        for len in [0, 8, 24] {
            assert_eq!(
                pal.aes_xts_enc_dec_sgl(&io, enc, good, tweak, len, 16, &sgl(&buf), &sgl(&out))
                    .await,
                Err(HsmError::AesXtsInvalidBufferSize)
            );
        }
        // A bad data-unit length, or a tweak that would overflow across
        // the data units, is rejected.
        let max_tweak = dma(&pal, &io, &u64::MAX.to_le_bytes());
        for (tw, len, dul) in [
            (&*tweak, 32, 0),
            (&*tweak, 32, 24),
            (&*tweak, 48, 32),
            (&*max_tweak, 32, 16),
            (&*max_tweak, 16, 16),
        ] {
            assert_eq!(
                pal.aes_xts_enc_dec_sgl(&io, enc, good, tw, len, dul, &sgl(&buf), &sgl(&out))
                    .await,
                Err(HsmError::AesXtsInvalidBufferSize)
            );
        }
        // A descriptor that does not describe `len` bytes is rejected.
        assert_eq!(
            pal.aes_xts_enc_dec_sgl(&io, enc, good, tweak, 32, 32, &sgl(&buf[..16]), &sgl(&out))
                .await,
            Err(HsmError::InvalidArg)
        );
    }
}
