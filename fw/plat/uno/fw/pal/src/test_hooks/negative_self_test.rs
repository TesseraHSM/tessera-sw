// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TestAction 9: run one HSM or Admin/FP periodic CAST now.
//!
//! The request is accepted with `tsra_test_hooks`; the selected CAST fails
//! only when `fips_validation_hooks` is also enabled.

use embassy_time::Duration;
use embassy_time::with_timeout;
use tsra_fw_ddi_mbor_derive::Ddi;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

use super::common::ReqHdr;
use super::test_action;
use crate::UnoHsmIo;
use crate::ipc::IPC_MESSAGE_LENGTH;
use crate::ipc::IpcMessageStatusCode;
use crate::ipc::encode_negative_self_test;
use crate::ipc::negative_self_test_response_status;
use crate::pal::IpcChannel;
use crate::pal::UnoHsmPal;
use crate::self_test::negative::NegativeTarget;
use crate::self_test::negative::{self};

#[derive(Ddi)]
#[ddi(map)]
struct NegativeSelfTestReq {
    #[ddi(id = 1)]
    neg_test_id: u32,
}

pub(super) async fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &UnoHsmIo,
    hdr: &ReqHdr,
    decoder: &mut tsra_fw_ddi_mbor::MborDecoder<'_>,
    field_count: u8,
    request_len: usize,
) -> HsmResult<&'p HsmDmaBuf> {
    let request: NegativeSelfTestReq =
        test_action::decode_payload(decoder, field_count, request_len)?;
    let target = negative::classify(request.neg_test_id)?;
    let response = test_action::encode_success(pal, io, hdr)?;
    if pal.negative_cast_pending.replace(true) {
        return Err(HsmError::PendingIo);
    }

    match target {
        NegativeTarget::Hsm(test) => {
            if pal.negative_cast.try_send(test).is_err() {
                tsra_fw_uno_fault::enter_self_test_error_state(
                    request.neg_test_id,
                    0,
                    HsmError::PendingIo,
                );
            }
        }
        NegativeTarget::Admin => {
            let req = encode_negative_self_test(request.neg_test_id);
            let mut resp = [0u32; IPC_MESSAGE_LENGTH];
            // A timed-out in-flight IPC send cannot be cancelled and reused.
            if with_timeout(
                Duration::from_secs(30),
                pal.ipc
                    .send(IpcChannel::AdminRequest as u8, &req, &mut resp),
            )
            .await
            .is_err()
            {
                tsra_fw_uno_fault::enter_self_test_error_state(
                    request.neg_test_id,
                    0,
                    HsmError::CryptoTimeout,
                );
            }
            let status = negative_self_test_response_status(&resp, request.neg_test_id)
                .unwrap_or_else(|_| {
                    tsra_fw_uno_fault::enter_self_test_error_state(
                        request.neg_test_id,
                        0,
                        HsmError::IpcResponseDecodeError,
                    )
                });
            if status != u32::from(IpcMessageStatusCode::Success) {
                pal.negative_cast_pending.set(false);
                return Err(HsmError::IpcResponseFailure);
            }
            // Without fault injection the Admin CAST passes; allow another request.
            #[cfg(not(feature = "fips_validation_hooks"))]
            pal.negative_cast_pending.set(false);
        }
    }
    Ok(response)
}
