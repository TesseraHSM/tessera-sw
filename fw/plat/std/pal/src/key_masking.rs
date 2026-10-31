// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

impl HsmKeyMasking for StdHsmPal {
    fn key_mask_len(&self, aad_len: usize, payload_len: usize) -> HsmResult<(usize, u8)> {
        if !aad_len.is_multiple_of(32) {
            return Err(HsmError::InvalidArg);
        }
        let pad = (16 - payload_len % 16) % 16;
        let len = aad_len
            .checked_add(payload_len)
            .and_then(|n| n.checked_add(pad))
            .and_then(|n| n.checked_add(32))
            .ok_or(HsmError::InvalidArg)?;
        Ok((len, pad as u8))
    }

    async fn key_mask_in_place(
        &self,
        io: &Self::Io,
        masking_key: &HsmDmaBuf,
        aad_len: usize,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        validate(masking_key, aad_len, data.len())?;
        let tag_at = data.len() - 16;
        let (body, tag) = data.split_at_mut(tag_at);
        let (iv, body) = body.split_at_mut(16);
        self.rng_fill_bytes(io, &mut iv[..12])?;
        iv[12..].copy_from_slice(&[0, 0, 0, 1]);
        self.gcm_encrypt_in_place(io, masking_key, &iv[..12], aad_len, body, tag)
            .await
    }

    async fn key_unmask_in_place(
        &self,
        io: &Self::Io,
        masking_key: &HsmDmaBuf,
        aad_len: usize,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        validate(masking_key, aad_len, data.len())?;
        let tag_at = data.len() - 16;
        let (body, tag) = data.split_at_mut(tag_at);
        let (iv, body) = body.split_at_mut(16);
        self.gcm_decrypt_in_place(io, masking_key, &iv[..12], aad_len, tag, body)
            .await
    }
}

fn validate(key: &HsmDmaBuf, aad_len: usize, len: usize) -> HsmResult<()> {
    if key.len() != 32 {
        return Err(HsmError::InvalidKeyLength);
    }
    if !aad_len.is_multiple_of(32)
        || len.checked_sub(32).is_none_or(|n| aad_len > n)
        || !(len - 32 - aad_len).is_multiple_of(16)
        || len - 32 - aad_len > i32::MAX as usize
        || aad_len > i32::MAX as usize
    {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tsra_crypto::AesGcmAlgo;
    use tsra_crypto::AesKey;
    use tsra_crypto::DecryptOp;
    use tsra_crypto::ImportableKey;

    use super::*;

    fn fixture() -> (StdHsmPal, StdHsmIo) {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        (pal, io)
    }

    #[tokio::test]
    async fn key_mask_roundtrip_preserves_layout_and_matches_standard_gcm() {
        let (pal, io) = fixture();
        let key = pal.dma_alloc(&io, 32).unwrap();
        key.fill(0x35);
        let aes_key = AesKey::from_bytes(key).unwrap();

        for (aad_len, payload_len) in [
            (0, 0),
            (32, 1),
            (32, 15),
            (32, 16),
            (32, 17),
            (32, 24),
            (64, 68),
            (192, 48),
        ] {
            let (len, pad) = pal.key_mask_len(aad_len, payload_len).unwrap();
            assert_eq!(pad as usize, (16 - payload_len % 16) % 16);
            assert_eq!(len, 32 + aad_len + payload_len + pad as usize);
            let data = pal.dma_alloc(&io, len).unwrap();
            data.fill(0);
            data[16..16 + aad_len].fill(0xa5);
            data[16 + aad_len..16 + aad_len + payload_len].fill(0x42);
            let mut expected = vec![0x42; payload_len];
            expected.resize(payload_len + pad as usize, 0);

            pal.key_mask_in_place(&io, key, aad_len, data)
                .await
                .unwrap();
            assert_eq!(&data[12..16], &[0, 0, 0, 1]);
            assert!(data[16..16 + aad_len].iter().all(|&b| b == 0xa5));
            let nonce = data[..12].to_vec();
            let tag = data[len - 16..].to_vec();
            let mut reference = vec![0; expected.len()];
            let mut decrypt =
                AesGcmAlgo::for_decrypt(&nonce, &tag, Some(&data[16..16 + aad_len])).unwrap();
            decrypt
                .decrypt(
                    &aes_key,
                    &data[16 + aad_len..len - 16],
                    Some(&mut reference),
                )
                .unwrap();
            assert_eq!(reference, expected);

            data[12..16].fill(0xff);
            pal.key_unmask_in_place(&io, key, aad_len, data)
                .await
                .unwrap();
            assert_eq!(&data[..12], nonce.as_slice());
            assert!(data[12..16].iter().all(|&b| b == 0xff));
            assert!(data[16..16 + aad_len].iter().all(|&b| b == 0xa5));
            assert_eq!(&data[16 + aad_len..len - 16], expected.as_slice());
            assert_eq!(&data[len - 16..], tag.as_slice());
        }
    }

    #[tokio::test]
    async fn key_mask_rejects_tampering_and_wrong_key() {
        let (pal, io) = fixture();
        let key = pal.dma_alloc(&io, 32).unwrap();
        key.fill(0x35);
        let aad_len = 32;
        let (len, _) = pal.key_mask_len(aad_len, 24).unwrap();
        let data = pal.dma_alloc(&io, len).unwrap();
        data.fill(0x42);
        pal.key_mask_in_place(&io, key, aad_len, data)
            .await
            .unwrap();
        let masked = data.to_vec();

        for at in [0, 16, 16 + aad_len, len - 1] {
            data.copy_from_slice(&masked);
            data[at] ^= 1;
            assert_eq!(
                pal.key_unmask_in_place(&io, key, aad_len, data).await,
                Err(HsmError::AesGcmDecryptTagDoesNotMatch),
            );
        }
        data.copy_from_slice(&masked);
        key[0] ^= 1;
        assert_eq!(
            pal.key_unmask_in_place(&io, key, aad_len, data).await,
            Err(HsmError::AesGcmDecryptTagDoesNotMatch),
        );
    }

    #[tokio::test]
    async fn key_mask_rejects_invalid_lengths_before_mutation() {
        let (pal, io) = fixture();
        let key = pal.dma_alloc(&io, 32).unwrap();
        key.fill(0x35);
        let data = pal.dma_alloc(&io, 96).unwrap();
        for (len, aad_len) in [
            (0, 0),
            (11, 0),
            (27, 0),
            (28, 1),
            (32, 16),
            (64, 1),
            (64, 16),
            (96, 48),
            (63, 16),
            (64, 37),
            (64, usize::MAX),
        ] {
            data.fill(0x42);
            assert_eq!(
                pal.key_mask_in_place(&io, key, aad_len, &mut data[..len])
                    .await,
                Err(HsmError::InvalidArg),
            );
            assert_eq!(
                pal.key_unmask_in_place(&io, key, aad_len, &mut data[..len])
                    .await,
                Err(HsmError::InvalidArg),
            );
            assert!(data.iter().all(|&b| b == 0x42));
        }
        for key_len in [0, 16, 24, 31] {
            assert_eq!(
                pal.key_mask_in_place(&io, &key[..key_len], 0, data).await,
                Err(HsmError::InvalidKeyLength),
            );
            assert_eq!(
                pal.key_unmask_in_place(&io, &key[..key_len], 0, data).await,
                Err(HsmError::InvalidKeyLength),
            );
            assert!(data.iter().all(|&b| b == 0x42));
        }
        for (aad_len, payload_len) in [
            (1, 0),
            (15, 16),
            (16, 16),
            (48, 16),
            (usize::MAX, 1),
            (0, usize::MAX),
            (usize::MAX - 31, 1),
        ] {
            assert_eq!(
                pal.key_mask_len(aad_len, payload_len),
                Err(HsmError::InvalidArg)
            );
        }
    }
}
