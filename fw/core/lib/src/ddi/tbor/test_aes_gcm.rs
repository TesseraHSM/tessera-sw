// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `TestAesGcm` command handler (test-only, feature `tbor-test-cmds`).
//!
//! AES-256-GCM encrypts or decrypts the request `data` under the raw
//! request `key` through the PAL's [`HsmAes`] in-place GCM methods, so a
//! platform GCM engine can be exercised end to end on the regular HSM
//! command path. Out of session; nothing is persisted. The command is an
//! encryption oracle under host-chosen keys, which is why it is compiled
//! only with `tbor-test-cmds`.
//!
//! The PAL takes a `[padded_AAD | text]` buffer, so the handler formats
//! one in a scratch DMA buffer, transforms it in place, copies the text
//! into the response, and wipes the scratch.
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
    // still gets a valid allocation.
    let work = pal.dma_alloc(io, buf_len.max(1))?;
    format_gcm_buf(aad, data, &mut work[..buf_len]);

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
        let result = if encrypt {
            pal.gcm_encrypt_in_place(io, key, iv, aad_len, &mut work[..buf_len], out.tag)
                .await
        } else {
            out.tag.copy_from_slice(tag);
            pal.gcm_decrypt_in_place(io, key, iv, aad_len, tag, &mut work[..buf_len])
                .await
        };
        if result.is_ok() {
            out.data.copy_from_slice(&work[pad..buf_len]);
        }
        result
    };

    work.zeroize();
    result.map(|()| &*resp)
}
