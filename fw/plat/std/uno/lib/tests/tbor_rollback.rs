// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Drives the Uno IO pipeline (`Hsm::handle_io`) with a real `StdHsmPal`
// to check that TBOR errors and failed completions roll back pending sessions.

use tsra_fw_ddi_tbor_types as types;
use tsra_fw_hsm_core::Hsm;
use tsra_fw_hsm_io::CmdDword;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::SessionFlags;
use tsra_fw_hsm_io::SqeBuilder;
use tsra_fw_hsm_io::CQE_DWORDS;
use tsra_fw_hsm_io::OP_TBOR;
use tsra_fw_hsm_io::SQE_DWORDS;
use tsra_fw_hsm_pal_std_uno::HsmIoRequest;
use tsra_fw_hsm_pal_std_uno::HsmPartId;
use tsra_fw_hsm_pal_std_uno::StdHsmPal;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmPartPropId;
use tsra_fw_hsm_pal_traits::HsmPartitionManager;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionManager;
use tsra_fw_hsm_pal_traits::HsmSessionState;
use tsra_fw_hsm_undo::UNDO_LOG_SIZE;

/// Core's crate-private `SessionCtrl::Open` session-control value.
const SESSION_CTRL_OPEN: u8 = 1;

/// Core's crate-private `HostStatus::ALLOC_ERR` CQE host status.
const HOST_STATUS_ALLOC_ERR: u16 = 0x0C9;

#[repr(align(4096))]
struct HostPage([u8; 4096]);

#[allow(unsafe_code)]
fn response_bytes(bytes: &[u8]) -> &HsmDmaBuf {
    // SAFETY: the std PAL uses ordinary process memory, without device DMA.
    unsafe { HsmDmaBuf::from_raw(bytes) }
}

#[test]
#[allow(clippy::unwrap_used)]
fn tbor_errors_and_failed_completions_rollback_pending_sessions() {
    std::thread::Builder::new()
        // Match the std firmware executor's stack for the unoptimized IO future.
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(check_tbor_rollback());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[allow(clippy::unwrap_used)]
async fn check_tbor_rollback() {
    let (tx, rx) = async_channel::bounded(1);
    let hsm = Hsm::new(StdHsmPal::new(rx, tokio::runtime::Handle::current()));
    hsm.pal().part_alloc_internal(0, 1).await.unwrap();
    hsm.pal().part_enable_internal(0).await.unwrap();
    let mut committed_session = None;

    for attempt in 0..10 {
        let short_response = attempt < 8;
        let fail_completion = attempt == 8;
        let mut request = HostPage([0; 4096]);
        let mut response = HostPage([0xA5; 4096]);
        let request_len = types::TborSessionOpenInitReq::encode(&mut request.0)
            .unwrap()
            .psk_id(types::PskId::CryptoUser)
            .unwrap()
            .session_type(types::SessionKind(0))
            .unwrap()
            .suite_id(types::SuiteId(1))
            .unwrap()
            .pk_init(&[0; 97])
            .unwrap()
            .finish()
            .len();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(HsmIoRequest::cmd(
            HsmPartId::from(0u8),
            0,
            0,
            SqeBuilder::new()
                .cmd(CmdDword::new().with_op(OP_TBOR))
                .buf_lens(request_len as u32, if short_response { 12 } else { 4096 })
                .src_prp1(request.0.as_ptr() as u64)
                .dst_prp1(response.0.as_mut_ptr() as u64)
                .session_flags(SessionFlags::new().with_ctrl(SESSION_CTRL_OPEN))
                .build(),
            reply_tx,
        ))
        .await
        .unwrap();
        let io = hsm.pal().poll_io().await.unwrap();
        if attempt > 0 {
            hsm.pal()
                .alloc_scoped(&io, |alloc| -> HsmResult<()> {
                    let reused =
                        alloc.dma_alloc(UNDO_LOG_SIZE + request_len.next_multiple_of(4))?;
                    assert!(
                        reused.iter().all(|&b| b == 0),
                        "previous IO was not scrubbed"
                    );
                    Ok(())
                })
                .unwrap();
        }
        for id in 0u16..8 {
            assert!(
                matches!(
                    hsm.pal().session_state(&io, HsmSessId::from(id)),
                    HsmSessionState::Invalid
                ),
                "session {id} remained live before attempt {attempt}"
            );
        }
        if attempt == 0 {
            hsm.pal()
                .dma_alloc(&io, 16384 - UNDO_LOG_SIZE - 100)
                .unwrap()
                .fill(0xA5);
        }
        let mut pk_init = [0; 97];
        pk_init[0] = 4;
        pk_init[1..].copy_from_slice(
            hsm.pal()
                .part_prop_get_bytes(&io, HsmPartPropId::PART_ID_ECC_PUB_KEY)
                .unwrap(),
        );
        types::TborSessionOpenInitReq::encode(&mut request.0)
            .unwrap()
            .psk_id(types::PskId::CryptoUser)
            .unwrap()
            .session_type(types::SessionKind(0))
            .unwrap()
            .suite_id(types::SuiteId(1))
            .unwrap()
            .pk_init(&pk_init)
            .unwrap()
            .finish();
        let reply_rx = if fail_completion {
            drop(reply_rx);
            None
        } else {
            Some(reply_rx)
        };
        hsm.handle_io(io).await;
        if let Some(reply_rx) = reply_rx {
            let mut raw = reply_rx.await.unwrap();
            let cqe = Cqe::try_from(&mut raw[..CQE_DWORDS]).unwrap();
            if attempt == 0 {
                assert_eq!(cqe.status(), HOST_STATUS_ALLOC_ERR);
                assert!(response.0.iter().all(|&b| b == 0xA5));
                continue;
            }
            assert_eq!(cqe.status(), 0, "attempt {attempt}");
            let len = usize::from(cqe.dst_len());
            assert!(response.0[len..].iter().all(|&b| b == 0xA5));
            if short_response {
                let frame =
                    tsra_fw_ddi_tbor::ResponseView::parse(response_bytes(&response.0[..len]))
                        .unwrap();
                assert_eq!(
                    frame.status(),
                    HsmError::TborBufferTooSmall.0,
                    "attempt {attempt}"
                );
                assert_eq!(len, 12);
                assert!(!cqe.dw0().session_id_valid());
            } else {
                let frame =
                    types::TborSessionOpenInitResp::decode(response_bytes(&response.0[..len]))
                        .unwrap();
                assert!(cqe.dw0().session_id_valid());
                assert_eq!(cqe.dw1().session_id(), u16::from(frame.session_id()));
                committed_session = Some(HsmSessId::from(u16::from(frame.session_id())));
            }
        } else {
            types::TborSessionOpenInitResp::decode(response_bytes(&response.0)).unwrap();
        }
    }

    let (reply_tx, _) = tokio::sync::oneshot::channel();
    tx.send(HsmIoRequest::cmd(
        HsmPartId::from(0u8),
        0,
        0,
        [0; SQE_DWORDS],
        reply_tx,
    ))
    .await
    .unwrap();
    let io = hsm.pal().poll_io().await.unwrap();
    let id = committed_session.unwrap();
    assert!(matches!(
        hsm.pal().session_state(&io, id),
        HsmSessionState::Pending
    ));
    hsm.pal().session_destroy(&io, id).await.unwrap();
    hsm.pal().drop_io(io).await.unwrap();
}
