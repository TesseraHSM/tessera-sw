// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key masking through the selected Uno GCM backend.

use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyMasking;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;

use super::gcm::GCM_IV_LEN;
use super::gcm::GCM_TAG_LEN;
use crate::UnoHsmPal;

impl HsmKeyMasking for UnoHsmPal {
    fn key_mask_len(&self, aad_len: usize, payload_len: usize) -> HsmResult<(usize, u8)> {
        if !aad_len.is_multiple_of(32) {
            return Err(HsmError::InvalidArg);
        }
        let pad = (16 - payload_len % 16) % 16;
        let len = aad_len
            .checked_add(payload_len)
            .and_then(|n| n.checked_add(pad))
            .and_then(|n| n.checked_add(16 + GCM_TAG_LEN))
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
        validate_key_mask(masking_key, aad_len, data.len())?;
        let tag_at = data.len() - GCM_TAG_LEN;
        let (body, tag) = data.split_at_mut(tag_at);
        let (iv, body) = body.split_at_mut(16);
        self.rng_fill_bytes(io, &mut iv[..GCM_IV_LEN])?;
        iv[GCM_IV_LEN..].copy_from_slice(&[0, 0, 0, 1]);
        self.gcm_encrypt_in_place_impl(io, masking_key, &iv[..GCM_IV_LEN], aad_len, body, tag)
            .await
    }

    async fn key_unmask_in_place(
        &self,
        io: &Self::Io,
        masking_key: &HsmDmaBuf,
        aad_len: usize,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        validate_key_mask(masking_key, aad_len, data.len())?;
        let tag_at = data.len() - GCM_TAG_LEN;
        let (body, tag) = data.split_at_mut(tag_at);
        let (iv, body) = body.split_at_mut(16);
        self.gcm_decrypt_in_place_impl(io, masking_key, &iv[..GCM_IV_LEN], aad_len, tag, body)
            .await
    }
}

fn validate_key_mask(key: &HsmDmaBuf, aad_len: usize, len: usize) -> HsmResult<()> {
    if key.len() != 32 {
        return Err(HsmError::InvalidKeyLength);
    }
    if !aad_len.is_multiple_of(32)
        || len
            .checked_sub(16 + GCM_TAG_LEN)
            .is_none_or(|n| aad_len > n)
        || !(len - 16 - GCM_TAG_LEN - aad_len).is_multiple_of(16)
    {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tsra_fw_hsm_pal_traits::HsmDmaBuf;

    #[test]
    #[allow(unsafe_code)]
    fn key_mask_requires_32_byte_aad_alignment() {
        let key = [0; 32];
        // SAFETY: Validation only reads the key length, without submitting DMA.
        let key = unsafe { HsmDmaBuf::from_raw(&key) };
        for aad_len in [16, 48] {
            assert_eq!(
                super::validate_key_mask(key, aad_len, 32 + aad_len + 16),
                Err(super::HsmError::InvalidArg),
            );
        }
        for aad_len in [0, 32, 64, 192] {
            assert_eq!(
                super::validate_key_mask(key, aad_len, 32 + aad_len + 16),
                Ok(()),
            );
        }
    }
}
