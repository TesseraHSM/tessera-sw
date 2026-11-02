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

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::TborMlDsaSignReq;
use tsra_fw_ddi_tbor_types::TborMlDsaSignResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::resolve_masking_key;
use super::validate_active_session;
use crate::ddi::tbor::mldsa_generate_key::mldsa_sec_key_len;
use crate::ddi::tbor::mldsa_generate_key::MLDSA_SEED_LEN;

/// Signature length per ML-DSA parameter set (FIPS 204 Table 2).
fn mldsa_sig_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlDsa44Seed => Ok(2420),
        HsmVaultKeyKind::MlDsa65Seed => Ok(3309),
        HsmVaultKeyKind::MlDsa87Seed => Ok(4627),
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

            if req.ctx.len() > 255 {
                return Err(HsmError::InvalidArg);
            }
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
            let view = unmask(pal, io, masking_key, req.masked_key).await?;
            let kind = view.key_kind;
            if !view.key_attrs.sign() {
                return Err(HsmError::InvalidPermissions);
            }
            let sig_len = mldsa_sig_len(kind)?;
            let sec_len = mldsa_sec_key_len(kind)?;
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
            pal.mldsa_sign_in_place(
                io,
                kind,
                &mut req.masked_key[..key_end],
                req.message,
                req.ctx,
            )
            .await?;
            sig_len
        };
        let buffer = cmd_buf.buffer_mut();
        let frame = TborMlDsaSignResp::encode(buffer, 0, false)?
            .signature_existing(sig_len)?
            .finish();
        Ok(frame.as_bytes().len())
    }
    .await
}
