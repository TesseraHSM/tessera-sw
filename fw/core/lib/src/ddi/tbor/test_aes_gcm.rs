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

/// Copy `src` to the same-length `dst` on the DMA engine, or on the CPU if
/// the engine refuses (it rejects empty copies).
async fn dma_copy<P: HsmPal>(pal: &P, io: &impl HsmIo, src: &DmaBuf, dst: &mut DmaBuf) {
    if src.is_empty() || pal.copy_mem(io, src, dst).await.is_err() {
        dst.copy_from_slice(src);
    }
}
