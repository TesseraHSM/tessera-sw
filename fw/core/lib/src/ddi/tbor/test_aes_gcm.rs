// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `TestAesGcm` command handler (test-only, feature `tbor-test-cmds`).
//!
//! AES-256-GCM encrypts or decrypts the request `data` under the raw
//! request `key` through the PAL's in-place [`HsmAes`] GCM methods — the
//! same path firmware key masking takes, on Uno the BCP (CDMA) engine — so
//! the platform's GCM can be exercised and measured end to end on the
//! regular HSM command path. Out
//! of session; nothing is persisted. The command is an encryption oracle
//! under host-chosen keys, which is why it is compiled only with
//! `tbor-test-cmds`.
//!
//! The PAL works on a `[padded_AAD | text]` buffer, so the handler formats
//! one in a scratch DMA buffer, transforms it in place, copies the text
//! into the response, and wipes the scratch. The text moves on the DMA
//! engine: CP1 reads the DMA heap uncached, so a CPU copy of kilobytes would
//! cost more than the encryption.
//!
//! [`HsmAes`]: tsra_fw_hsm_pal_traits::HsmAes

use tsra_fw_core_crypto_gcm_buf::format_gcm_buf;
use tsra_fw_core_crypto_gcm_buf::padded_aad_len;
use tsra_fw_ddi_tbor_types::AesOp;
use tsra_fw_ddi_tbor_types::TborTestAesGcmReq;
use tsra_fw_ddi_tbor_types::TborTestAesGcmResp;
use tsra_fw_ddi_tbor_types::TEST_AES_GCM_TAG_LEN;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;

/// Handle a TBOR `TestAesGcm` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborTestAesGcmReq::decode(req_buf)?;
    let encrypt = match req.op() {
        AesOp::Encrypt => true,
        AesOp::Decrypt => false,
        _ => return Err(HsmError::InvalidArg),
    };
    let (key, iv, aad, data, tag) = (req.key(), req.iv(), req.aad(), req.data(), req.tag());

    if let Some(resp) = direct(pal, io, req_buf, encrypt, key, iv, aad, data, tag).await? {
        return Ok(resp);
    }

    let aad_len = aad.len();
    let text_len = data.len();
    let pad = padded_aad_len(aad_len);
    let buf_len = pad + text_len;

    // `[padded_AAD | text]`; at least one byte so an all-empty request
    // still gets a valid allocation. The IV varies the buffer's offset in
    // 4-byte steps, so tests cover each alignment the PAL may be handed.
    let shift = 4 * usize::from(iv.first().copied().unwrap_or(0) & 3);
    let raw = pal.dma_alloc(io, shift + buf_len.max(1))?;
    let work = &mut raw[shift..];
    format_gcm_buf(aad, &[], &mut work[..pad]);
    dma_copy(pal, io, data, &mut work[pad..buf_len]).await;

    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborTestAesGcmResp::encode(buf, 0, false)?
            .data_reserve(text_len)?
            .tag_reserve(TEST_AES_GCM_TAG_LEN)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;

    // The view is scoped so its borrow of `resp` ends before `resp` is
    // returned.
    let result = {
        let out = TborTestAesGcmResp::decode_mut(resp)?;
        let buf = &mut work[..buf_len];
        let result = if encrypt {
            pal.gcm_encrypt_in_place(io, key, iv, aad_len, buf, out.tag)
                .await
        } else {
            out.tag.copy_from_slice(tag);
            pal.gcm_decrypt_in_place(io, key, iv, aad_len, tag, buf)
                .await
        };
        if result.is_ok() {
            dma_copy(pal, io, &buf[pad..], out.data).await;
        }
        result
    };

    raw.zeroize();
    result.map(|()| &*resp)
}

/// Runs the request in one engine pass straight from the request into the
/// response, when the request's `[AAD | data]` already is the
/// `[padded_AAD | text]` layout the engine reads: AAD that needs no padding
/// immediately followed by whole blocks of data, word-aligned. Returns
/// `None`, having done nothing, otherwise.
///
/// The engine writes the AAD through ahead of the text, so the response
/// is allocated behind `pad` bytes of headroom for it; the frame header and
/// TOC it overwrites are saved and put back.
#[allow(clippy::too_many_arguments)]
async fn direct<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
    encrypt: bool,
    key: &DmaBuf,
    iv: &DmaBuf,
    aad: &DmaBuf,
    data: &DmaBuf,
    tag: &DmaBuf,
) -> HsmResult<Option<&'p DmaBuf>> {
    let (aad_len, text_len) = (aad.len(), data.len());
    let pad = padded_aad_len(aad_len);
    let src_off = aad.as_ptr() as usize - req_buf.as_ptr() as usize;
    if pad != aad_len
        || text_len == 0
        || !text_len.is_multiple_of(16)
        || data.as_ptr() as usize != aad.as_ptr() as usize + aad_len
        || !(aad.as_ptr() as usize).is_multiple_of(4)
    {
        return Ok(None);
    }
    let src = &req_buf[src_off..src_off + pad + text_len];

    let raw = pal.dma_alloc_var(io, |buf| {
        let frame = TborTestAesGcmResp::encode(
            buf.get_mut(pad..).ok_or(HsmError::NotEnoughSpace)?,
            0,
            false,
        )?
        .data_reserve(text_len)?
        .tag_reserve(TEST_AES_GCM_TAG_LEN)?
        .finish();
        Ok(pad + frame.as_bytes().len())
    })?;
    let base = raw.as_ptr() as usize;
    let (data_off, tag_off) = {
        let out = TborTestAesGcmResp::decode_mut(&mut raw[pad..])?;
        (
            out.data.as_ptr() as usize - base,
            out.tag.as_ptr() as usize - base,
        )
    };
    let mut head = [0u8; 32];
    let head = head
        .get_mut(..data_off - pad)
        .ok_or(HsmError::InternalError)?;
    head.copy_from_slice(&raw[pad..data_off]);

    let (front, back) = raw.split_at_mut(data_off + text_len);
    let dst = &mut front[data_off - pad..];
    let out_tag = &mut back[tag_off - (data_off + text_len)..][..TEST_AES_GCM_TAG_LEN];
    let result = if encrypt {
        pal.gcm_encrypt(io, key, iv, aad_len, src, dst, out_tag)
            .await
    } else {
        out_tag.copy_from_slice(tag);
        pal.gcm_decrypt(io, key, iv, aad_len, tag, src, dst).await
    };
    raw[pad..data_off].copy_from_slice(head);
    result.map(|()| Some(&raw[pad..]))
}

/// Copy `src` to the same-length `dst` on the DMA engine, or on the CPU if
/// the engine refuses (it rejects empty copies).
async fn dma_copy<P: HsmPal>(pal: &P, io: &impl HsmIo, src: &DmaBuf, dst: &mut DmaBuf) {
    if src.is_empty() || pal.copy_mem(io, src, dst).await.is_err() {
        dst.copy_from_slice(src);
    }
}
