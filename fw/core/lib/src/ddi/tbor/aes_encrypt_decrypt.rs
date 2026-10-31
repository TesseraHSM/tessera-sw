// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesEncryptDecrypt` command handler.
//!
//! Within an open session, AES-CBC encrypt or decrypt a host-supplied
//! message using a caller-held **masked** AES key (the `masked_key` from
//! [`AesGenerateKey`](super::aes_generate_key) or imported via
//! [`UnwrapKey`](super::unwrap_key)).  The masked key's scope is read from
//! its cleartext, tag-bound metadata to select the masking key; the key is
//! unmasked **in place** in the request buffer (verifying the AEAD tag),
//! the AES-CBC transform updates the request message and chaining IV in
//! place before they become the response — and nothing is persisted. The
//! recovered key is wiped. This is the TBOR analogue of MBOR
//! `AesEncryptDecrypt`, keyed by a masked blob rather than a vault `key_id`.
//!
//! The key must be a non-bulk AES kind (`InvalidKeyType` otherwise) and
//! must carry the permission matching the direction (`encrypt` for
//! `Encrypt`, `decrypt` for `Decrypt`; `InvalidPermissions` otherwise).
//! Available to both Crypto-Officer and Crypto-User sessions.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::AesOp;
use tsra_fw_ddi_tbor_types::TborAesEncryptDecryptReq;
use tsra_fw_ddi_tbor_types::TborAesEncryptDecryptResp;
use tsra_fw_ddi_tbor_types::AES_IV_LEN;
use tsra_fw_ddi_tbor_types::AES_MSG_MAX_LEN;
use tsra_fw_hsm_pal_traits::HsmAesOp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::resolve_masking_key;
use super::validate_active_session;

/// AES-CBC block size in bytes — also the required IV length.
const AES_BLOCK_LEN: usize = AES_IV_LEN;

/// Map the wire [`AesOp`] onto the PAL [`HsmAesOp`].  An unrecognized
/// discriminant is rejected with [`HsmError::InvalidArg`].
fn pal_aes_op(op: AesOp) -> HsmResult<HsmAesOp> {
    match op {
        AesOp::Encrypt => Ok(HsmAesOp::Encrypt),
        AesOp::Decrypt => Ok(HsmAesOp::Decrypt),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Require an unmasked key to be a non-bulk AES kind (128 / 192 / 256).
/// The XTS / GCM bulk kinds are not valid for the CBC transform.
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
        let base = cmd_buf.request().as_ptr() as usize;
        let req = TborAesEncryptDecryptReq::decode_mut(cmd_buf.request_mut())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id));
        validate_active_session(pal, io, sess_id)?;
        let op = pal_aes_op(AesOp(req.op))?;

        if req.iv.len() != AES_BLOCK_LEN
            || req.msg.is_empty()
            || !req.msg.len().is_multiple_of(AES_BLOCK_LEN)
            || req.msg.len() > AES_MSG_MAX_LEN
        {
            return Err(HsmError::InvalidArg);
        }
        let msg_len = req.msg.len();
        let data_start = tsra_fw_ddi_tbor::REQ_HEADER_LEN + TborAesEncryptDecryptReq::TOC_COUNT * 4;
        // Noncanonical offsets cannot be compacted without moving the message.
        if (req.msg.as_ptr() as usize).checked_sub(base) != Some(data_start)
            || (req.iv.as_ptr() as usize).checked_sub(base) != Some(data_start + msg_len)
        {
            return Err(HsmError::InvalidArg);
        }

        let scope = peek_scope(req.masked_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let view = unmask(pal, io, masking_key, req.masked_key).await?;
        assert_aes_kind(view.key_kind)?;
        let permitted = match op {
            HsmAesOp::Encrypt => view.key_attrs.encrypt(),
            HsmAesOp::Decrypt => view.key_attrs.decrypt(),
        };
        if !permitted {
            return Err(HsmError::InvalidPermissions);
        }
        pal.aes_cbc_enc_dec_in_place_iv(io, op, view.target_key, req.msg, req.iv)
            .await?;

        Ok(
            TborAesEncryptDecryptResp::encode(cmd_buf.buffer_mut(), 0, false)?
                .msg_existing(msg_len)?
                .iv_existing(AES_BLOCK_LEN)?
                .finish()
                .len(),
        )
    }
    .await
}
