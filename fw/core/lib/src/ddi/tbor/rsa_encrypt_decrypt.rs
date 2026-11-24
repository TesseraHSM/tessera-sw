// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `RsaEncryptDecrypt` command handler.
//!
//! Padded RSA operations run entirely on-device using an authenticated,
//! caller-held masked private key. Encryption derives the public key from
//! that private key; decryption uses it directly. No state is persisted.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::RsaEncryptDecryptOp;
use tsra_fw_ddi_tbor_types::RsaEncryptPadding;
use tsra_fw_ddi_tbor_types::TborRsaEncryptDecryptReq;
use tsra_fw_ddi_tbor_types::TborRsaEncryptDecryptResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use zeroize::Zeroize;

use super::from_pal::rsa_key;
use super::resolve_masking_key;
use super::validate_active_session;

/// Handle a TBOR `RsaEncryptDecrypt` request.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let (api_rev, sess_id, op, padding, hash) = {
            let base = cmd_buf.request().as_ptr() as usize;
            let req = TborRsaEncryptDecryptReq::decode(cmd_buf.request())?;
            let sess_id = HsmSessId::from(u16::from(req.session_id()));
            validate_active_session(pal, io, sess_id)?;

            let op = match req.op() {
                RsaEncryptDecryptOp::Encrypt => RsaEncryptDecryptOp::Encrypt,
                RsaEncryptDecryptOp::Decrypt => RsaEncryptDecryptOp::Decrypt,
                _ => return Err(HsmError::InvalidArg),
            };
            let padding = match req.padding() {
                RsaEncryptPadding::Oaep => RsaEncryptPadding::Oaep,
                RsaEncryptPadding::Pkcs1v15 => RsaEncryptPadding::Pkcs1v15,
                _ => return Err(HsmError::InvalidArg),
            };
            let hash = match (padding, req.hash_algo()) {
                (RsaEncryptPadding::Oaep, Some(value)) => Some(match HashAlgo(value) {
                    HashAlgo::Sha256 => HsmHashAlgo::Sha256,
                    HashAlgo::Sha384 => HsmHashAlgo::Sha384,
                    HashAlgo::Sha512 => HsmHashAlgo::Sha512,
                    _ => return Err(HsmError::InvalidArg),
                }),
                (RsaEncryptPadding::Oaep, None) => return Err(HsmError::InvalidArg),
                (RsaEncryptPadding::Pkcs1v15, None) => None,
                (RsaEncryptPadding::Pkcs1v15, Some(_)) => {
                    return Err(HsmError::InvalidArg);
                }
                _ => return Err(HsmError::InvalidArg),
            };
            if padding == RsaEncryptPadding::Pkcs1v15 && !req.label().is_empty() {
                return Err(HsmError::InvalidArg);
            }

            let offset = |ptr: *const u8| (ptr as usize).checked_sub(base);
            let label_at = offset(req.label().as_ptr()).ok_or(HsmError::InvalidArg)?;
            let input_at = offset(req.input().as_ptr()).ok_or(HsmError::InvalidArg)?;
            let key_at = offset(req.masked_key().as_ptr()).ok_or(HsmError::InvalidArg)?;
            let label_end = label_at
                .checked_add(req.label().len())
                .ok_or(HsmError::InvalidArg)?;
            let expected_input = label_end
                .checked_add(3)
                .map(|value| value & !3)
                .ok_or(HsmError::InvalidArg)?;
            let input_end = input_at
                .checked_add(req.input().len())
                .ok_or(HsmError::InvalidArg)?;
            let expected_key = input_end
                .checked_add(3)
                .map(|value| value & !3)
                .ok_or(HsmError::InvalidArg)?;
            let payload_start =
                tsra_fw_ddi_tbor::REQ_HEADER_LEN + TborRsaEncryptDecryptReq::TOC_COUNT * 4;
            if label_at != payload_start || input_at != expected_input || key_at != expected_key {
                return Err(HsmError::TborNonCanonicalLayout);
            }
            (req.api_rev(), sess_id, op, padding, hash)
        };

        let (label, input, private_key) = {
            let req = TborRsaEncryptDecryptReq::decode_mut(cmd_buf.request_mut())?;
            (req.label, req.input, req.masked_key)
        };

        let scope = peek_scope(private_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let view = unmask(pal, io, masking_key, private_key).await?;
        let key_type = rsa_key(view.key_kind)?;
        let permitted = match op {
            RsaEncryptDecryptOp::Encrypt => view.key_attrs.encrypt(),
            RsaEncryptDecryptOp::Decrypt => view.key_attrs.decrypt(),
            _ => return Err(HsmError::InvalidArg),
        };
        if !permitted {
            return Err(HsmError::InvalidPermissions);
        }

        let k = key_type.modulus_len();
        let max_plaintext = match padding {
            RsaEncryptPadding::Oaep => {
                k.saturating_sub(2 * hash.ok_or(HsmError::InvalidArg)?.digest_len() + 2)
            }
            RsaEncryptPadding::Pkcs1v15 => k - 11,
            _ => return Err(HsmError::InvalidArg),
        };
        match op {
            RsaEncryptDecryptOp::Encrypt if input.len() <= max_plaintext => {}
            RsaEncryptDecryptOp::Decrypt if input.len() == k => {}
            _ => return Err(HsmError::InvalidArg),
        }
        if op == RsaEncryptDecryptOp::Decrypt
            && pal.rsa_priv_pub_key(io, view.target_key, None)? != k + 4
        {
            return Err(HsmError::InternalError);
        }

        let output = alloc.dma_alloc(if op == RsaEncryptDecryptOp::Encrypt {
            k
        } else {
            512
        })?;
        let operation = match (op, padding) {
            (RsaEncryptDecryptOp::Encrypt, RsaEncryptPadding::Oaep) => {
                let hash = hash.ok_or(HsmError::InvalidArg)?;
                let pub_len = pal.rsa_priv_pub_key(io, view.target_key, None)?;
                if pub_len != k + 4 {
                    return Err(HsmError::InternalError);
                }
                let public_key = alloc.dma_alloc(pub_len)?;
                let written = pal.rsa_priv_pub_key(io, view.target_key, Some(public_key))?;
                if written != pub_len {
                    return Err(HsmError::InternalError);
                }
                pal.rsa_oaep_encrypt(
                    io,
                    key_type.pub_variant(),
                    hash,
                    public_key,
                    input,
                    label,
                    Some(output),
                )
                .await
            }
            (RsaEncryptDecryptOp::Encrypt, RsaEncryptPadding::Pkcs1v15) => {
                let pub_len = pal.rsa_priv_pub_key(io, view.target_key, None)?;
                if pub_len != k + 4 {
                    return Err(HsmError::InternalError);
                }
                let public_key = alloc.dma_alloc(pub_len)?;
                let written = pal.rsa_priv_pub_key(io, view.target_key, Some(public_key))?;
                if written != pub_len {
                    return Err(HsmError::InternalError);
                }
                pal.rsa_pkcs1_encrypt(io, key_type.pub_variant(), public_key, input, Some(output))
                    .await
            }
            (RsaEncryptDecryptOp::Decrypt, RsaEncryptPadding::Oaep) => {
                let hash = hash.ok_or(HsmError::InvalidArg)?;
                pal.rsa_oaep_decrypt(
                    io,
                    key_type,
                    hash,
                    view.target_key,
                    input,
                    label,
                    Some(output),
                )
                .await
            }
            (RsaEncryptDecryptOp::Decrypt, RsaEncryptPadding::Pkcs1v15) => {
                pal.rsa_pkcs1_decrypt(io, key_type, view.target_key, input, Some(output))
                    .await
            }
            _ => return Err(HsmError::InvalidArg),
        };
        let actual_len = match operation {
            Ok(actual_len) => actual_len,
            Err(HsmError::InvalidArg | HsmError::RsaDecryptFailed)
                if op == RsaEncryptDecryptOp::Decrypt =>
            {
                return Err(HsmError::RsaDecryptFailed);
            }
            Err(error) => return Err(error),
        };
        if (op == RsaEncryptDecryptOp::Encrypt && actual_len != k)
            || actual_len > max_plaintext && op == RsaEncryptDecryptOp::Decrypt
            || actual_len > output.len()
        {
            return Err(HsmError::InternalError);
        }

        cmd_buf.request_mut().zeroize();
        cmd_buf.encode_response(|buf| {
            let frame = TborRsaEncryptDecryptResp::encode(buf, api_rev, 0, false)?
                .output(&output[..actual_len])?
                .finish();
            Ok(frame.as_bytes().len())
        })
    })
    .await
}
