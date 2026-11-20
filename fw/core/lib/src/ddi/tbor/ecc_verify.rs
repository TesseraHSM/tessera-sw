// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EccVerify` command handler.
//!
//! Authenticates a caller-held masked ECC private key, derives its public
//! key on-device, and verifies a precomputed digest without persisting state.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::TborEccVerifyReq;
use tsra_fw_ddi_tbor_types::TborEccVerifyResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::ecc_hash_from_selector;
use super::from_pal::ecc_private_curve;
use super::resolve_masking_key;
use super::validate_active_session;

/// Handle a TBOR `EccVerify` request.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    {
        let req = TborEccVerifyReq::decode_mut(cmd_buf.request_mut())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id));
        validate_active_session(pal, io, sess_id)?;

        let hash = ecc_hash_from_selector(HashAlgo(req.hash_algo)).ok_or(HsmError::InvalidArg)?;
        let scope = peek_scope(req.masked_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let view = unmask(pal, io, masking_key, req.masked_key).await?;
        let curve = ecc_private_curve(view.key_kind)?;
        if !view.key_attrs.sign() && !view.key_attrs.verify() {
            return Err(HsmError::InvalidPermissions);
        }

        if view.target_key.len() != curve.wire_priv_key_len(P::ECC_COORD_PAD) {
            return Err(HsmError::InvalidArg);
        }

        let coord_len = curve.wire_coord_len(P::ECC_COORD_PAD);
        let digest_len = hash.digest_len();
        let signature_len = curve.wire_sig_len(P::ECC_COORD_PAD);
        let packed_len = curve.ecdsa_verify_input_len(hash, P::ECC_COORD_PAD);
        if req.input.len() != packed_len {
            return Err(HsmError::InvalidArg);
        }

        let raw_coord_len = curve.priv_key_len();
        if coord_len > raw_coord_len {
            let r_padding = req
                .input
                .get(raw_coord_len..coord_len)
                .ok_or(HsmError::InvalidArg)?;
            let s_padding = req
                .input
                .get(coord_len + raw_coord_len..signature_len)
                .ok_or(HsmError::InvalidArg)?;
            if r_padding.iter().any(|&byte| byte != 0) || s_padding.iter().any(|&byte| byte != 0) {
                return Err(HsmError::InvalidArg);
            }
        }
        let digest_padding = req
            .input
            .get(signature_len + digest_len..packed_len)
            .ok_or(HsmError::InvalidArg)?;
        if digest_padding.iter().any(|&byte| byte != 0) {
            return Err(HsmError::InvalidArg);
        }

        let public_len = curve.wire_pub_key_len(P::ECC_COORD_PAD);
        pal.alloc_scoped_async(io, async |alloc| {
            let public_key = alloc.dma_alloc_zeroed(public_len)?;
            let written = pal
                .ecc_priv_pub_key(io, view.target_key, Some(public_key))
                .await?;
            if written != public_len {
                return Err(HsmError::InternalError);
            }
            if !pal
                .ecc_verify(io, curve, hash, public_key, req.input)
                .await?
            {
                return Err(HsmError::EccVerifyFailed);
            }
            Ok(())
        })
        .await?;
    }

    cmd_buf.encode_response(|buf| {
        let frame = TborEccVerifyResp::encode_for_request(buf, 0, false)?.finish();
        Ok(frame.as_bytes().len())
    })
}
