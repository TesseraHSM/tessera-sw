// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesGcmEncryptDecrypt` command handler.
//!
//! Within an open session, AES-256-GCM encrypt or decrypt host data under
//! a caller-held **masked** AES-256 key (from
//! [`AesGenerateKey`](super::aes_generate_key)).  The key is unmasked
//! **in place** in the request buffer (verifying the AEAD tag).  The data
//! travels out of band: the OOB descriptor page holds an **in** and an
//! **out** SGL Data Block (`[padded AAD | text]`, `data_len` bytes each),
//! which the AES engine reads / writes host to host.  An empty message
//! (`data_len == 0`) needs no OOB page; only the tag is computed.  The request's
//! contiguous `[iv | tag]` bytes become the response at the same offset.
//! Nothing is persisted.
//!
//! The key must be [`HsmVaultKeyKind::Aes256`] (`InvalidKeyType`
//! otherwise) and carry the permission matching the direction
//! (`InvalidPermissions` otherwise).  A device-generated IV is valid for
//! encrypt only.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::GcmIvSource;
use tsra_fw_ddi_tbor_types::TborAesGcmEncryptDecryptReq;
use tsra_fw_ddi_tbor_types::TborAesGcmEncryptDecryptResp;
use tsra_fw_ddi_tbor_types::GCM_DATA_MAX_LEN;
use tsra_fw_ddi_tbor_types::GCM_IV_LEN;
use tsra_fw_ddi_tbor_types::GCM_TAG_LEN;
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

/// Length of the AAD region at the start of the in / out blocks: the AAD
/// padded up to a 32-byte boundary (0 when there is no AAD).
fn padded_aad_len(aad_len: usize) -> Option<usize> {
    if aad_len == 0 {
        Some(0)
    } else {
        aad_len.checked_next_multiple_of(32)
    }
}

/// Handle a TBOR `AesGcmEncryptDecrypt` request.
///
/// No partition lock or undo log is required: the command persists
/// nothing.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
    oob: Option<OobPtr>,
) -> HsmResult<usize> {
    let req = TborAesGcmEncryptDecryptReq::decode(cmd_buf.request())?;
    let base = cmd_buf.request().as_ptr() as usize;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    validate_active_session(pal, io, sess_id)?;
    let op = pal_aes_op(req.op())?;
    let device_iv = match req.iv_source() {
        GcmIvSource::Host => false,
        GcmIvSource::Device if op == HsmAesOp::Encrypt => true,
        _ => return Err(HsmError::InvalidArg),
    };

    let aad_len = usize::from(req.aad_len());
    let data_len = usize::from(req.data_len());
    let padded = padded_aad_len(aad_len).ok_or(HsmError::InvalidArg)?;
    if data_len > GCM_DATA_MAX_LEN || padded > data_len {
        return Err(HsmError::InvalidArg);
    }
    let in_index = usize::from(req.in_index());
    let out_index = usize::from(req.out_index());

    // `[iv | tag]` must be contiguous at the payload start so it can be
    // returned in place as the response `[iv | tag]`.
    let data_start = tsra_fw_ddi_tbor::REQ_HEADER_LEN + TborAesGcmEncryptDecryptReq::TOC_COUNT * 4;
    let region_end = data_start + GCM_IV_LEN + GCM_TAG_LEN;
    let offset = |p: *const u8| (p as usize).checked_sub(base);
    let key_off = offset(req.masked_key().as_ptr()).ok_or(HsmError::InvalidArg)?;
    let key_len = req.masked_key().len();
    if offset(req.iv().as_ptr()) != Some(data_start)
        || offset(req.tag().as_ptr()) != Some(data_start + GCM_IV_LEN)
        || key_off < region_end
    {
        return Err(HsmError::InvalidArg);
    }

    // An empty message (no AAD, no text) carries no OOB data; only the
    // tag is computed.
    let descs = if data_len == 0 {
        None
    } else {
        let oob = oob.ok_or(HsmError::InvalidArg)?;
        Some((
            read_oob_desc(pal, io, &oob, in_index).await?,
            read_oob_desc(pal, io, &oob, out_index).await?,
        ))
    };

    cmd_buf.response(TborAesGcmEncryptDecryptResp::MAX_ENCODED_SIZE)?;

    // In bounds: decode bounded every field within the request, and
    // `[iv | tag]` ends at or before the masked key.
    let (head, tail) = cmd_buf.request_mut().split_at_mut(key_off);
    let masked_key = &mut tail[..key_len];
    let (iv, rest) = head[data_start..].split_at_mut(GCM_IV_LEN);
    let (tag, rest) = rest.split_at_mut(GCM_TAG_LEN);
    let empty = &mut rest[..0];

    let scope = peek_scope(masked_key)?;
    let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
    let view = unmask(pal, io, masking_key, masked_key).await?;
    if view.key_kind != HsmVaultKeyKind::Aes256 {
        return Err(HsmError::InvalidKeyType);
    }
    let permitted = match op {
        HsmAesOp::Encrypt => view.key_attrs.encrypt(),
        HsmAesOp::Decrypt => view.key_attrs.decrypt(),
    };
    if !permitted {
        return Err(HsmError::InvalidPermissions);
    }

    if device_iv {
        pal.rng_fill_bytes(io, iv)?;
    }
    let key = view.target_key;
    match (op, descs) {
        (HsmAesOp::Encrypt, Some((src, dst))) => {
            pal.gcm_encrypt_sgl(io, key, iv, aad_len, data_len, &src, &dst, tag)
                .await?
        }
        (HsmAesOp::Decrypt, Some((src, dst))) => {
            pal.gcm_decrypt_sgl(io, key, iv, aad_len, data_len, tag, &src, &dst)
                .await?
        }
        (HsmAesOp::Encrypt, None) => pal.gcm_encrypt_in_place(io, key, iv, 0, empty, tag).await?,
        (HsmAesOp::Decrypt, None) => pal.gcm_decrypt_in_place(io, key, iv, 0, tag, empty).await?,
    }

    Ok(
        TborAesGcmEncryptDecryptResp::encode(cmd_buf.buffer_mut(), 0, false)?
            .iv_existing(GCM_IV_LEN)?
            .tag_existing(GCM_TAG_LEN)?
            .finish()
            .len(),
    )
}
