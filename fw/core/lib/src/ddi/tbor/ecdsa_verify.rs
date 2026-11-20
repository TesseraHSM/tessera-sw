// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR message-level ECDSA verification using a caller-held masked key.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::TborEcdsaVerifyReq;
use tsra_fw_ddi_tbor_types::TborEcdsaVerifyResp;
use tsra_fw_ddi_tbor_types::ECDSA_MESSAGE_MAX_LEN;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::from_pal::ecc_private_curve;
use super::resolve_masking_key;
use super::validate_active_session;

fn hash_algo(algo: HashAlgo) -> HsmResult<HsmHashAlgo> {
    match algo {
        HashAlgo::Sha256 => Ok(HsmHashAlgo::Sha256),
        HashAlgo::Sha384 => Ok(HsmHashAlgo::Sha384),
        HashAlgo::Sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidArg),
    }
}

fn validate_signature(curve: HsmEccCurve, signature: &[u8], pad: usize) -> HsmResult<()> {
    let lane_len = curve.wire_coord_len(pad);
    let raw_len = curve.priv_key_len();
    if signature.len() != lane_len * 2 {
        return Err(HsmError::InvalidArg);
    }
    let (r, s) = signature.split_at(lane_len);
    if r.get(raw_len..)
        .is_none_or(|padding| padding.iter().any(|&byte| byte != 0))
        || s.get(raw_len..)
            .is_none_or(|padding| padding.iter().any(|&byte| byte != 0))
    {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Handle a TBOR `EcdsaVerify` request.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let request_base = cmd_buf.request().as_ptr() as usize;
    let (curve, key_at, key_len, signature_at, signature_len, algo, message_index, message_len) = {
        let req = TborEcdsaVerifyReq::decode_mut(cmd_buf.request_mut())?;
        let algo = hash_algo(HashAlgo(req.hash_algo))?;
        let message_len = usize::from(req.message_len);
        let message_index = usize::from(req.message_index);
        if message_len > ECDSA_MESSAGE_MAX_LEN || (message_len == 0 && message_index != 0) {
            return Err(HsmError::InvalidArg);
        }

        let sess_id = HsmSessId::from(u16::from(req.session_id));
        validate_active_session(pal, io, sess_id)?;
        let scope = peek_scope(req.masked_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let view = unmask(pal, io, masking_key, req.masked_key).await?;
        let curve = ecc_private_curve(view.key_kind)?;
        if view.target_key.len() != curve.wire_priv_key_len(P::ECC_COORD_PAD) {
            return Err(HsmError::InvalidArg);
        }
        if !view.key_attrs.sign() && !view.key_attrs.verify() {
            return Err(HsmError::InvalidPermissions);
        }
        validate_signature(curve, req.signature, P::ECC_COORD_PAD)?;

        let key_at = (view.target_key.as_ptr() as usize)
            .checked_sub(request_base)
            .ok_or(HsmError::InvalidArg)?;
        let signature_at = (req.signature.as_ptr() as usize)
            .checked_sub(request_base)
            .ok_or(HsmError::InvalidArg)?;
        (
            curve,
            key_at,
            view.target_key.len(),
            signature_at,
            req.signature.len(),
            algo,
            message_index,
            message_len,
        )
    };

    let input = pal.dma_alloc_zeroed(io, curve.ecdsa_verify_input_len(algo, P::ECC_COORD_PAD))?;
    pal.hash_oob(
        io,
        algo,
        message_len,
        message_index,
        HsmDigestForm::Operand,
        &mut input[signature_len..signature_len + algo.digest_len()],
    )
    .await?;

    let buffer = cmd_buf.buffer_mut();
    let key_end = key_at.checked_add(key_len).ok_or(HsmError::InvalidArg)?;
    let signature_end = signature_at
        .checked_add(signature_len)
        .ok_or(HsmError::InvalidArg)?;
    if key_end > signature_at || signature_end > buffer.len() {
        return Err(HsmError::TborNonCanonicalLayout);
    }
    let (_, after_key_start) = buffer.split_at(key_at);
    let (key, after_key) = after_key_start.split_at(key_len);
    let signature_offset = signature_at
        .checked_sub(key_end)
        .ok_or(HsmError::TborNonCanonicalLayout)?;
    let (_, after_signature_offset) = after_key.split_at(signature_offset);
    let (signature, _) = after_signature_offset.split_at(signature_len);

    input[..signature_len].copy_from_slice(signature);

    let pub_key_len = pal.ecc_priv_pub_key(io, key, None).await?;
    if pub_key_len != curve.wire_pub_key_len(P::ECC_COORD_PAD) {
        return Err(HsmError::InternalError);
    }
    let pub_key_backing_len = pub_key_len.checked_add(7).ok_or(HsmError::InvalidArg)? & !7;
    let pub_key_backing = pal.dma_alloc_zeroed(io, pub_key_backing_len)?;
    let (pub_key, _) = pub_key_backing.split_at_mut(pub_key_len);
    let derived_len = pal.ecc_priv_pub_key(io, key, Some(pub_key)).await?;
    if derived_len != pub_key_len {
        return Err(HsmError::InternalError);
    }
    if !pal.ecc_verify(io, curve, algo, pub_key, input).await? {
        return Err(HsmError::EccVerifyFailed);
    }

    cmd_buf.encode_response(|buf| {
        let frame = TborEcdsaVerifyResp::encode_for_request(buf, 0, false)?.finish();
        Ok(frame.as_bytes().len())
    })
}
