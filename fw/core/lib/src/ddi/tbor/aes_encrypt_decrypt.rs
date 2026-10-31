// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesEncryptDecrypt` command handler.
//!
//! Within an open session, AES encrypt or decrypt a host-supplied message
//! in CBC, ECB, CFB-128, OFB or CTR mode using a caller-held **masked** AES
//! key (the `masked_key` from [`AesGenerateKey`](super::aes_generate_key)
//! or imported via [`UnwrapKey`](super::unwrap_key)).  The masked key's
//! scope is read from its cleartext, tag-bound metadata to select the
//! masking key; the key is unmasked **in place** in the request buffer
//! (verifying the AEAD tag).  The request's contiguous `[iv | msg]` bytes
//! are transformed in place by the PAL into `[msg | iv out]`, which is the
//! response payload at the same offset — and nothing is persisted.  The
//! recovered key is wiped.  This is the TBOR analogue of MBOR
//! `AesEncryptDecrypt` (CBC / ECB only), keyed by a masked blob rather than
//! a vault `key_id`.
//!
//! The key must be a non-bulk AES kind (`InvalidKeyType` otherwise) and
//! must carry the permission matching the direction (`encrypt` for
//! `Encrypt`, `decrypt` for `Decrypt`; `InvalidPermissions` otherwise).
//! Available to both Crypto-Officer and Crypto-User sessions.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::AesMode;
use tsra_fw_ddi_tbor_types::AesOp;
use tsra_fw_ddi_tbor_types::TborAesEncryptDecryptReq;
use tsra_fw_ddi_tbor_types::TborAesEncryptDecryptResp;
use tsra_fw_ddi_tbor_types::AES_MSG_MAX_LEN;
use tsra_fw_hsm_pal_traits::HsmAesMode;
use tsra_fw_hsm_pal_traits::HsmAesOp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::resolve_masking_key;
use super::validate_active_session;

/// Map the wire [`AesOp`] onto the PAL [`HsmAesOp`].  An unrecognized
/// discriminant is rejected with [`HsmError::InvalidArg`].
fn pal_aes_op(op: AesOp) -> HsmResult<HsmAesOp> {
    match op {
        AesOp::Encrypt => Ok(HsmAesOp::Encrypt),
        AesOp::Decrypt => Ok(HsmAesOp::Decrypt),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Map the wire [`AesMode`] onto the PAL [`HsmAesMode`].  An unrecognized
/// discriminant is rejected with [`HsmError::InvalidArg`].
fn pal_aes_mode(mode: AesMode) -> HsmResult<HsmAesMode> {
    match mode {
        AesMode::Cbc => Ok(HsmAesMode::Cbc),
        AesMode::Ecb => Ok(HsmAesMode::Ecb),
        AesMode::Cfb => Ok(HsmAesMode::Cfb),
        AesMode::Ofb => Ok(HsmAesMode::Ofb),
        AesMode::Ctr => Ok(HsmAesMode::Ctr),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Require an unmasked key to be a non-bulk AES kind (128 / 192 / 256).
/// The XTS / GCM bulk kinds are not valid for this transform.
fn assert_aes_kind(kind: HsmVaultKeyKind) -> HsmResult<()> {
    match kind {
        HsmVaultKeyKind::Aes128 | HsmVaultKeyKind::Aes192 | HsmVaultKeyKind::Aes256 => Ok(()),
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Handle a TBOR `AesEncryptDecrypt` request.
///
/// No partition lock or undo log is required: the command reads no mutable
/// partition state and **persists nothing** — it unmasks the caller's key
/// and transforms the message in place, retaining its final response offset.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    async {
        let req = TborAesEncryptDecryptReq::decode(cmd_buf.request())?;
        let base = cmd_buf.request().as_ptr() as usize;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        validate_active_session(pal, io, sess_id)?;
        let op = pal_aes_op(req.op())?;
        let mode = pal_aes_mode(req.mode())?;

        let iv_len = req.iv().len();
        let msg_len = req.msg().len();
        if iv_len != mode.iv_len()
            || msg_len == 0
            || msg_len > AES_MSG_MAX_LEN
            || mode.data_len(iv_len + msg_len) != Some(msg_len)
        {
            return Err(HsmError::InvalidArg);
        }
        let data_start = tsra_fw_ddi_tbor::REQ_HEADER_LEN + TborAesEncryptDecryptReq::TOC_COUNT * 4;
        let region_end = data_start + iv_len + msg_len;
        // `[iv | msg]` must be contiguous at the payload start so it can be
        // transformed in place into the response `[msg | iv]`.
        let offset = |p: *const u8| (p as usize).checked_sub(base);
        let key_off = offset(req.masked_key().as_ptr()).ok_or(HsmError::InvalidArg)?;
        let key_len = req.masked_key().len();
        if (iv_len != 0 && offset(req.iv().as_ptr()) != Some(data_start))
            || offset(req.msg().as_ptr()) != Some(data_start + iv_len)
            || key_off < region_end
        {
            return Err(HsmError::InvalidArg);
        }

        // In bounds: decode bounded every field within the request, and
        // `[iv | msg]` ends at or before the masked key.
        let (head, tail) = cmd_buf.request_mut().split_at_mut(key_off);
        let masked_key = &mut tail[..key_len];
        let data = &mut head[data_start..region_end];

        let scope = peek_scope(masked_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let view = unmask(pal, io, masking_key, masked_key).await?;
        assert_aes_kind(view.key_kind)?;
        let permitted = match op {
            HsmAesOp::Encrypt => view.key_attrs.encrypt(),
            HsmAesOp::Decrypt => view.key_attrs.decrypt(),
        };
        if !permitted {
            return Err(HsmError::InvalidPermissions);
        }
        pal.aes_enc_dec_in_place(io, op, mode, view.target_key, data)
            .await?;

        Ok(
            TborAesEncryptDecryptResp::encode(cmd_buf.buffer_mut(), 0, false)?
                .msg_existing(msg_len)?
                .iv_existing(iv_len)?
                .finish()
                .len(),
        )
    }
    .await
}
