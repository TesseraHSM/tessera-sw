// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `RsaVerify` hashes a raw OOB message and verifies its signature
//! using the public component of a caller-held masked RSA private key.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::RsaPadding;
use tsra_fw_ddi_tbor_types::TborRsaVerifyReq;
use tsra_fw_ddi_tbor_types::TborRsaVerifyResp;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::from_pal::rsa_key;
use super::rsa_sign::hash_algo;
use super::rsa_sign::validate_padding_salt_presence;
use super::rsa_sign::validate_salt;
use super::resolve_masking_key;
use super::validate_active_session;

pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut tsra_fw_hsm_pal_traits::HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let salt_len = TborRsaVerifyReq::decode(cmd_buf.request())?.salt_len();
        let req = TborRsaVerifyReq::decode_mut(cmd_buf.request_mut())?;
        if usize::from(req.message_len) > 8192 {
            return Err(HsmError::InvalidArg);
        }
        let algo = hash_algo(HashAlgo(req.hash_algo))?;
        let padding = RsaPadding(req.padding);
        validate_padding_salt_presence(padding, salt_len)?;
        let sess_id = HsmSessId::from(u16::from(req.session_id));
        validate_active_session(pal, io, sess_id)?;

        let scope = peek_scope(req.masked_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let view = unmask(pal, io, masking_key, req.masked_key).await?;
        let key_type = rsa_key(view.key_kind)?;
        if !view.key_attrs.verify() {
            return Err(HsmError::InvalidPermissions);
        }
        let salt_len = validate_salt(
            padding,
            salt_len,
            key_type.modulus_len(),
            algo.digest_len(),
        )?;
        if req.signature.len() != key_type.modulus_len() {
            return Err(HsmError::InvalidArg);
        }
        let message_len = usize::from(req.message_len);
        let message_index = usize::from(req.message_index);
        if message_len == 0 && message_index != 0 {
            return Err(HsmError::InvalidArg);
        }

        let digest = alloc.dma_alloc_zeroed(algo.digest_len())?;
        let digest_len = pal
            .hash_oob(
                io,
                algo,
                message_len,
                message_index,
                HsmDigestForm::Standard,
                digest,
            )
            .await?;
        if digest_len != algo.digest_len() {
            return Err(HsmError::InternalError);
        }

        let public_len = pal.rsa_priv_pub_key(io, view.target_key, None)?;
        let expected_public_len = key_type
            .modulus_len()
            .checked_add(4)
            .ok_or(HsmError::InvalidArg)?;
        if public_len != expected_public_len {
            return Err(HsmError::InternalError);
        }
        let public_key = alloc.dma_alloc_zeroed(public_len)?;
        if pal.rsa_priv_pub_key(io, view.target_key, Some(public_key))? != public_len {
            return Err(HsmError::InternalError);
        }

        let valid = match salt_len {
            Some(salt_len) => {
                pal.rsa_pss_verify(
                    io,
                    key_type.pub_variant(),
                    algo,
                    public_key,
                    digest,
                    salt_len,
                    req.signature,
                )
                .await?
            }
            None => {
                pal.rsa_pkcs1_verify(
                    io,
                    key_type.pub_variant(),
                    algo,
                    public_key,
                    digest,
                    req.signature,
                )
                .await?
            }
        };
        if !valid {
            return Err(HsmError::RsaVerifyFailed);
        }
        drop(view);
        drop(req);
        let frame = TborRsaVerifyResp::encode(cmd_buf.buffer_mut(), 0, false)?.finish();
        Ok(frame.as_bytes().len())
    })
    .await
}
