// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR RSA signing and verification over a raw OOB message using a
//! caller-held masked RSA private key.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::RsaPadding;
use tsra_fw_ddi_tbor_types::TborRsaSignReq;
use tsra_fw_ddi_tbor_types::TborRsaSignResp;
use tsra_fw_ddi_tbor_types::TborRsaVerifyReq;
use tsra_fw_ddi_tbor_types::TborRsaVerifyResp;
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
    match (padding, salt_len) {
        (RsaPadding::Pss, Some(salt_len)) => {
            // PSS requires full-width moduli at the PAL, so ceil((modBits - 1) / 8) is key_len.
            let max_salt = key_len
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
    verify: bool,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let salt_len = if verify {
            TborRsaVerifyReq::decode(cmd_buf.request())?.salt_len()
        } else {
            TborRsaSignReq::decode(cmd_buf.request())?.salt_len()
        };
        let (session_id, algo, padding, message_len, message_index, masked_key, signature) =
            if verify {
                let req = TborRsaVerifyReq::decode_mut(cmd_buf.request_mut())?;
                (
                    req.session_id,
                    HashAlgo(req.hash_algo),
                    RsaPadding(req.padding),
                    req.message_len,
                    req.message_index,
                    req.masked_key,
                    Some(req.signature),
                )
            } else {
                let req = TborRsaSignReq::decode_mut(cmd_buf.request_mut())?;
                (
                    req.session_id,
                    HashAlgo(req.hash_algo),
                    RsaPadding(req.padding),
                    req.message_len,
                    req.message_index,
                    req.masked_key,
                    None,
                )
            };
        let message_len = usize::from(message_len);
        let message_index = usize::from(message_index);
        if message_len > 8192 {
            return Err(HsmError::InvalidArg);
        }
        let algo = hash_algo(algo)?;
        validate_padding_salt_presence(padding, salt_len)?;
        if message_len == 0 && message_index != 0 {
            return Err(HsmError::InvalidArg);
        }
        let sess_id = HsmSessId::from(u16::from(session_id));
        validate_active_session(pal, io, sess_id)?;

        let scope = peek_scope(masked_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let view = unmask(pal, io, masking_key, masked_key).await?;
        let key_type = rsa_key(view.key_kind)?;
        let permitted = if verify {
            view.key_attrs.verify()
        } else {
            view.key_attrs.sign()
        };
        if !permitted {
            return Err(HsmError::InvalidPermissions);
        }
        let salt_len = validate_salt(padding, salt_len, key_type.modulus_len(), algo.digest_len())?;
        if signature.is_some_and(|signature| signature.len() != key_type.modulus_len()) {
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

        if let Some(signature) = signature {
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
                        signature,
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
                        signature,
                    )
                    .await?
                }
            };
            if !valid {
                return Err(HsmError::RsaVerifyFailed);
            }
            return cmd_buf.encode_response(|buf| {
                let frame = TborRsaVerifyResp::encode_for_request(buf, 0, false)?.finish();
                Ok(frame.as_bytes().len())
            });
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
            let frame = TborRsaSignResp::encode_for_request(buf, 0, false)?
                .signature(&signature[..written])?
                .finish();
            Ok(frame.as_bytes().len())
        })
    })
    .await
}
