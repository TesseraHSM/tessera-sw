// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `RsaModExp` command handler.
//!
//! Within an open session, perform the RSA private-key primitive
//! `x = y^d mod n` using a caller-held **masked** RSA private key
//! (imported via [`UnwrapKey`](super::unwrap_key) with the RSA / RSA-CRT
//! key class).  The key is unmasked **in place** in the request buffer (no
//! scratch copy), its modulus size / CRT form recovered from the blob's
//! key kind, and the result written straight into the reserved response
//! slot.  This is the raw modular exponentiation underlying RSA decrypt /
//! sign — the host applies and removes any padding.  This is the TBOR
//! analogue of MBOR `RsaModExp`, keyed by a masked blob instead of a vault
//! id.  There is no TBOR RSA key generation; RSA keys enter the device
//! only through `UnwrapKey`.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::RsaOp;
use tsra_fw_ddi_tbor_types::TborRsaModExpReq;
use tsra_fw_ddi_tbor_types::TborRsaModExpResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::from_pal::rsa_key;
use super::resolve_masking_key;
use super::validate_active_session;

/// Handle a TBOR `RsaModExp` request.
///
/// No partition lock or undo log is required: the command reads no mutable
/// partition state and **persists nothing** — it unmasks the caller's key,
/// computes `y^d mod n`, and replaces the input integer with its result.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let base = cmd_buf.request().as_ptr() as usize;
    let output_len = {
        let req = TborRsaModExpReq::decode_mut(cmd_buf.request_mut())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id));
        validate_active_session(pal, io, sess_id)?;
        let require_sign = match RsaOp(req.op_type) {
            RsaOp::Sign => true,
            RsaOp::Decrypt => false,
            _ => return Err(HsmError::InvalidArg),
        };
        let scope = peek_scope(req.masked_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let view = unmask(pal, io, masking_key, req.masked_key).await?;
        let key_type = rsa_key(view.key_kind)?;
        let permitted = if require_sign {
            view.key_attrs.sign()
        } else {
            view.key_attrs.decrypt()
        };
        if !permitted {
            return Err(HsmError::InvalidPermissions);
        }

        if req.y.len() != key_type.modulus_len() {
            return Err(HsmError::InvalidArg);
        }
        let data_start = tsra_fw_ddi_tbor::REQ_HEADER_LEN + TborRsaModExpReq::TOC_COUNT * 4;
        if (req.y.as_ptr() as usize).checked_sub(base) != Some(data_start) {
            return Err(HsmError::InvalidArg);
        }
        pal.mod_exp_priv_in_place(io, key_type, view.target_key, req.y)
            .await?;
        req.y.len()
    };

    cmd_buf.encode_response(|buf| {
        let frame = TborRsaModExpResp::encode(buf, 0, false)?
            .x_existing(output_len)?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
