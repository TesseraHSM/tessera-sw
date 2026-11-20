// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR message-level ECDSA signing with a caller-held masked private key.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::TborEcdsaSignReq;
use tsra_fw_ddi_tbor_types::TborEcdsaSignResp;
use tsra_fw_ddi_tbor_types::ECDSA_MESSAGE_MAX_LEN;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmEcdsaNonce;
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

/// Handle a TBOR `EcdsaSign` request.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let request_base = cmd_buf.request().as_ptr() as usize;
    let (curve, key_at, key_len, algo, message_index, message_len) = {
        let req = TborEcdsaSignReq::decode_mut(cmd_buf.request_mut())?;
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
        if !view.key_attrs.sign() {
            return Err(HsmError::InvalidPermissions);
        }
        let key_at = (view.target_key.as_ptr() as usize)
            .checked_sub(request_base)
            .ok_or(HsmError::InvalidArg)?;
        (
            curve,
            key_at,
            view.target_key.len(),
            algo,
            message_index,
            message_len,
        )
    };

    let lane_len = curve.wire_coord_len(P::ECC_COORD_PAD);
    let input = pal.dma_alloc_zeroed(io, curve.ecdsa_sign_input_len(algo, P::ECC_COORD_PAD))?;
    pal.hash_oob(
        io,
        algo,
        message_len,
        message_index,
        HsmDigestForm::Operand,
        &mut input[lane_len..lane_len + algo.digest_len()],
    )
    .await?;

    let signature_len = curve.wire_sig_len(P::ECC_COORD_PAD);
    let signature = pal.dma_alloc_zeroed(io, signature_len)?;
    let key_end = key_at.checked_add(key_len).ok_or(HsmError::InvalidArg)?;
    let buffer = cmd_buf.buffer_mut();
    if key_end > buffer.len() {
        return Err(HsmError::TborNonCanonicalLayout);
    }
    let (_, after_key_start) = buffer.split_at(key_at);
    let (key, _) = after_key_start.split_at(key_len);
    let written = pal
        .ecc_sign(
            io,
            curve,
            algo,
            key,
            HsmEcdsaNonce::Generated,
            input,
            Some(signature),
        )
        .await?;
    if written != signature_len {
        return Err(HsmError::InternalError);
    }
    cmd_buf.encode_response(|buf| {
        let frame = TborEcdsaSignResp::encode_for_request(buf, 0, false)?
            .signature(&signature[..signature_len])?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
