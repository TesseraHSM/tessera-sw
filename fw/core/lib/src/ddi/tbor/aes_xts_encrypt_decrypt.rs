// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesXtsEncryptDecrypt` command handler.
//!
//! Within an open session, AES-256-XTS encrypt or decrypt one or more
//! data units (`dul` bytes each, tweak incrementing per unit) of host data under a caller-held **masked** XTS key (from
//! [`AesXtsGenerateKey`](super::aes_xts_generate_key)).  The key is
//! unmasked **in place** in the request buffer (verifying the AEAD tag).
//! The data travels out of band: the OOB descriptor page holds an **in**
//! and an **out** SGL Data Block (`data_len` bytes each), which the AES
//! engine reads / writes host to host.  Nothing is persisted.
//!
//! The key must be [`HsmVaultKeyKind::AesXts512`] (`InvalidKeyType`
//! otherwise) and carry the permission matching the direction
//! (`InvalidPermissions` otherwise).

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::TborAesXtsEncryptDecryptReq;
use tsra_fw_ddi_tbor_types::TborAesXtsEncryptDecryptResp;
use tsra_fw_ddi_tbor_types::XTS_DATA_MAX_LEN;
use tsra_fw_hsm_oob::read_oob_desc;
use tsra_fw_hsm_oob::OobPtr;
use tsra_fw_hsm_pal_traits::HsmAesOp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::aes_encrypt_decrypt::pal_aes_op;
use super::resolve_masking_key;
use super::validate_active_session;

/// Handle a TBOR `AesXtsEncryptDecrypt` request.
///
/// No partition lock or undo log is required: the command persists
/// nothing.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
    oob: Option<OobPtr>,
) -> HsmResult<usize> {
    let oob = oob.ok_or(HsmError::InvalidArg)?;
    let req = TborAesXtsEncryptDecryptReq::decode(cmd_buf.request())?;
    let base = cmd_buf.request().as_ptr() as usize;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    validate_active_session(pal, io, sess_id)?;
    let op = pal_aes_op(req.op())?;

    let data_len = usize::from(req.data_len());
    let dul = usize::from(req.dul());
    if data_len > XTS_DATA_MAX_LEN {
        return Err(HsmError::InvalidArg);
    }
    let in_index = usize::from(req.in_index());
    let out_index = usize::from(req.out_index());

    let offset = |p: *const u8| (p as usize).checked_sub(base);
    let tweak_off = offset(req.tweak().as_ptr()).ok_or(HsmError::InvalidArg)?;
    let tweak_len = req.tweak().len();
    let key_off = offset(req.masked_key().as_ptr()).ok_or(HsmError::InvalidArg)?;
    let key_len = req.masked_key().len();
    if tweak_off + tweak_len > key_off {
        return Err(HsmError::InvalidArg);
    }

    let src = read_oob_desc(pal, io, &oob, in_index).await?;
    let dst = read_oob_desc(pal, io, &oob, out_index).await?;

    cmd_buf.response(TborAesXtsEncryptDecryptResp::MAX_ENCODED_SIZE)?;

    // In bounds: decode bounded every field within the request, and the
    // tweak ends at or before the masked key.
    let (head, tail) = cmd_buf.request_mut().split_at_mut(key_off);
    let masked_key = &mut tail[..key_len];
    let tweak = &head[tweak_off..tweak_off + tweak_len];

    let scope = peek_scope(masked_key)?;
    let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
    let view = unmask(pal, io, masking_key, masked_key).await?;
    if view.key_kind != HsmVaultKeyKind::AesXts512 {
        return Err(HsmError::InvalidKeyType);
    }
    let permitted = match op {
        HsmAesOp::Encrypt => view.key_attrs.encrypt(),
        HsmAesOp::Decrypt => view.key_attrs.decrypt(),
    };
    if !permitted {
        return Err(HsmError::InvalidPermissions);
    }

    pal.aes_xts_enc_dec_sgl(io, op, view.target_key, tweak, data_len, dul, &src, &dst)
        .await?;

    Ok(
        TborAesXtsEncryptDecryptResp::encode(cmd_buf.buffer_mut(), 0, false)?
            .finish()
            .len(),
    )
}
