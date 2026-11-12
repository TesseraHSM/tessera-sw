// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaSign` command handler.
//!
//! Signs a host-supplied message with a caller-held **masked** ML-DSA key
//! (from [`MlDsaGenerateKey`](super::mldsa_generate_key)).  The key is
//! unmasked on-device, the signature is produced on a fastpath core, and
//! nothing is persisted: the caller holds the masked blob and passes it
//! back each time.
//!
//! The wire ships seed-only keys, so the caller never handles an expanded
//! key.  The blob carries the 32-byte `xi` seed followed by the expanded
//! secret key, and the fastpath core signs with the expanded half
//! directly rather than re-deriving the key pair (`f0bf65c4`).
//!
//! The PAL consumes the tail-aligned expanded key before replacing the
//! envelope prefix with the signature at its final response offset.
//!
//! The request carries the 64-byte message representative `μ` rather than a
//! message, as `EccSign` carries a digest.  `μ` already binds the FIPS 204
//! context string, so no context is passed on.  `hedge` selects hedged or
//! deterministic signing, as PKCS#11's `CK_HEDGE_TYPE` does, and is checked
//! before the key is unmasked.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::MlDsaHedge;
use tsra_fw_ddi_tbor_types::TborMlDsaSignReq;
use tsra_fw_ddi_tbor_types::TborMlDsaSignResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmMlDsaHedge;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsg;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsgType;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::from_pal::mldsa_param;
use super::resolve_masking_key;
use super::validate_active_session;
use crate::ddi::tbor::mldsa_generate_key::MLDSA_SEED_LEN;

/// Map the wire hedge variant onto the PAL's; unknown values are invalid.
fn mldsa_hedge(hedge: MlDsaHedge) -> HsmResult<HsmMlDsaHedge> {
    match hedge {
        MlDsaHedge::Preferred => Ok(HsmMlDsaHedge::Preferred),
        MlDsaHedge::Required => Ok(HsmMlDsaHedge::Required),
        MlDsaHedge::Deterministic => Ok(HsmMlDsaHedge::Deterministic),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Handle a TBOR `MlDsaSign` request.
///
/// Persists nothing and takes no partition lock: it reads the caller's
/// key, signs, and returns.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    async {
        let base = cmd_buf.request().as_ptr() as usize;
        let sig_len = {
            let req = TborMlDsaSignReq::decode_mut(cmd_buf.request_mut())?;
            let sess_id = HsmSessId::from(u16::from(req.session_id));
            validate_active_session(pal, io, sess_id)?;

            let hedge = mldsa_hedge(MlDsaHedge(req.hedge))?;
            let data_start = tsra_fw_ddi_tbor::REQ_HEADER_LEN + TborMlDsaSignReq::TOC_COUNT * 4;
            let masked_at = req.masked_key.as_ptr() as usize;
            if masked_at.checked_sub(base) != Some(data_start) {
                return Err(HsmError::InvalidArg);
            }

            // Resolve the envelope's tag-bound scope before unmasking.
            let scope = peek_scope(req.masked_key)?;
            let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;

            // Unmask in place. The AAD carries the parameter set, so the kind
            // comes from the envelope rather than being inferred from length.
            // A key of another type is rejected before its permissions are
            // checked, as `EccSign` does.
            let view = unmask(pal, io, masking_key, req.masked_key).await?;
            let param = mldsa_param(view.key_kind)?;
            if !view.key_attrs.sign() {
                return Err(HsmError::InvalidPermissions);
            }
            let sig_len = param.sig_len();
            let sec_len = param.sk_len();
            if view.target_key.len() != MLDSA_SEED_LEN + sec_len {
                return Err(HsmError::InvalidArg);
            }
            let key_end = (view.target_key.as_ptr() as usize)
                .checked_sub(masked_at)
                .and_then(|at| at.checked_add(view.target_key.len()))
                .ok_or(HsmError::InvalidArg)?;
            if key_end > req.masked_key.len() || key_end < sig_len {
                return Err(HsmError::InvalidArg);
            }
            let msg = HsmMlDsaMsg::new(HsmMlDsaMsgType::ExternalMu, 0, req.mu)?;
            pal.mldsa_sign_in_place(io, param, &mut req.masked_key[..key_end], hedge, msg)
                .await?
        };
        let buffer = cmd_buf.buffer_mut();
        let frame = TborMlDsaSignResp::encode(buffer, 0, false)?
            .signature_existing(sig_len)?
            .finish();
        Ok(frame.as_bytes().len())
    }
    .await
}
