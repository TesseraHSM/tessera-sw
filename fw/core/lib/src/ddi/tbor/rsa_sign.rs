// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `RsaSign` hashes a raw OOB message and signs it with a caller-held
//! masked RSA private key.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::RsaPadding;
use tsra_fw_ddi_tbor_types::TborRsaSignReq;
use tsra_fw_ddi_tbor_types::TborRsaSignResp;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::from_pal::rsa_key;
use super::resolve_masking_key;
use super::validate_active_session;

pub(super) fn hash_algo(algo: HashAlgo) -> HsmResult<HsmHashAlgo> {
    match algo {
        HashAlgo::Sha256 => Ok(HsmHashAlgo::Sha256),
        HashAlgo::Sha384 => Ok(HsmHashAlgo::Sha384),
        HashAlgo::Sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidArg),
    }
}

pub(super) fn validate_salt(
    padding: RsaPadding,
    salt_len: Option<u16>,
    key_len: usize,
    digest_len: usize,
) -> HsmResult<Option<usize>> {
    validate_padding_salt_presence(padding, salt_len)?;
    match (padding, salt_len) {
        (RsaPadding::Pss, Some(salt_len)) => {
            let em_bits = key_len
                .checked_mul(8)
                .and_then(|bits| bits.checked_sub(1))
                .ok_or(HsmError::InvalidArg)?;
            let em_len = em_bits.checked_add(7).ok_or(HsmError::InvalidArg)? / 8;
            let max_salt = em_len
                .checked_sub(digest_len)
                .and_then(|len| len.checked_sub(2))
                .ok_or(HsmError::InvalidArg)?;
            let salt_len = usize::from(salt_len);
            if salt_len > max_salt {
                return Err(HsmError::InvalidArg);
            }
            Ok(Some(salt_len))
        }
        (RsaPadding::Pkcs1v15, None) => Ok(None),
        _ => Err(HsmError::InvalidArg),
    }
}

pub(super) fn validate_padding_salt_presence(
    padding: RsaPadding,
    salt_len: Option<u16>,
) -> HsmResult<()> {
    match (padding, salt_len) {
        (RsaPadding::Pss, Some(_)) | (RsaPadding::Pkcs1v15, None) => Ok(()),
        _ => Err(HsmError::InvalidArg),
    }
}

pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut tsra_fw_hsm_pal_traits::HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let salt_len = TborRsaSignReq::decode(cmd_buf.request())?.salt_len();
        let req = TborRsaSignReq::decode_mut(cmd_buf.request_mut())?;
        if usize::from(req.message_len) > 8192 {
            return Err(HsmError::InvalidArg);
        }
        let algo = hash_algo(HashAlgo(req.hash_algo))?;
        let padding = RsaPadding(req.padding);
        validate_padding_salt_presence(padding, salt_len)?;
        let message_len = usize::from(req.message_len);
        let message_index = usize::from(req.message_index);
        if message_len == 0 && message_index != 0 {
            return Err(HsmError::InvalidArg);
        }
        let sess_id = HsmSessId::from(u16::from(req.session_id));
        validate_active_session(pal, io, sess_id)?;

        let scope = peek_scope(req.masked_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let view = unmask(pal, io, masking_key, req.masked_key).await?;
        let key_type = rsa_key(view.key_kind)?;
        if !view.key_attrs.sign() {
            return Err(HsmError::InvalidPermissions);
        }
        let salt_len = validate_salt(padding, salt_len, key_type.modulus_len(), algo.digest_len())?;
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

        let signature = alloc.dma_alloc_zeroed(key_type.modulus_len())?;
        let written = match salt_len {
            Some(salt_len) => {
                pal.rsa_pss_sign(
                    io,
                    key_type,
                    algo,
                    view.target_key,
                    digest,
                    salt_len,
                    Some(signature),
                )
                .await?
            }
            None => {
                pal.rsa_pkcs1_sign(io, key_type, algo, view.target_key, digest, Some(signature))
                    .await?
            }
        };
        if written != key_type.modulus_len() {
            return Err(HsmError::InternalError);
        }

        cmd_buf.encode_response(|buf| {
            let frame = TborRsaSignResp::encode(buf, 0, false)?
                .signature(&signature[..written])?
                .finish();
            Ok(frame.as_bytes().len())
        })
    })
    .await
}
