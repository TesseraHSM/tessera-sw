// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::future::Future;
use std::task::Context;
use std::task::Waker;

use tsra_fw_ddi_tbor_types::TborKeyReportReq;
use tsra_fw_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use tsra_fw_hsm_core::Hsm;
use tsra_fw_hsm_io::CmdDword;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::SessionFlags;
use tsra_fw_hsm_io::SqeBuilder;
use tsra_fw_hsm_io::CQE_DWORDS;
use tsra_fw_hsm_io::OP_TBOR;
use tsra_fw_hsm_io::SQE_DWORDS;
use tsra_fw_hsm_pal_std::HsmIoRequest;
use tsra_fw_hsm_pal_std::HsmPartId;
use tsra_fw_hsm_pal_std::StdHsmPal;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmPartitionLock;

#[repr(align(4096))]
struct HostPage([u8; 4096]);

#[test]
fn key_report_waits_for_credential_transaction_before_default_psk_gate() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(check_credential_guard());
        })
        .expect("test thread")
        .join()
        .expect("test result");
}

async fn check_credential_guard() {
    let (tx, rx) = async_channel::bounded(1);
    let hsm = Hsm::new(StdHsmPal::new(rx, tokio::runtime::Handle::current()));
    hsm.pal()
        .part_alloc_internal(0, 1)
        .await
        .expect("partition");
    hsm.pal().part_enable_internal(0).await.expect("enable");
    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
    tx.send(HsmIoRequest::cmd(
        HsmPartId::from(0u8),
        0,
        0,
        [0; SQE_DWORDS],
        reply_tx,
    ))
    .await
    .expect("control IO");
    let control_io = hsm.pal().poll_io().await.expect("poll control IO");
    let credential_guard = hsm
        .pal()
        .partition_lock(&control_io)
        .await
        .expect("credential transaction");

    let mut request = HostPage([0; 4096]);
    let mut response = HostPage([0xA5; 4096]);
    let request_len = TborKeyReportReq::encode(&mut request.0)
        .expect("encode")
        .session_id(0u16.into())
        .expect("session id")
        .masked_key(&[])
        .expect("masked key")
        .report_data(&[0; KEY_REPORT_DATA_LEN])
        .expect("report data")
        .auth_envelope(&[])
        .expect("auth envelope")
        .finish()
        .len();
    let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
    tx.send(HsmIoRequest::cmd(
        HsmPartId::from(0u8),
        0,
        0,
        SqeBuilder::new()
            .cmd(CmdDword::new().with_op(OP_TBOR))
            .buf_lens(request_len as u32, 4096)
            .src_prp1(request.0.as_ptr() as u64)
            .dst_prp1(response.0.as_mut_ptr() as u64)
            .session_flags(SessionFlags::new().with_ctrl(3).with_id_valid(true))
            .build(),
        reply_tx,
    ))
    .await
    .expect("KeyReport IO");
    let io = hsm.pal().poll_io().await.expect("poll KeyReport");
    let mut handler = std::pin::pin!(hsm.handle_io(io));
    // The std PAL's inbound DMA is synchronous, so the first suspension
    // must be the credential guard, not an earlier DMA operation.
    assert!(handler
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert!(matches!(
        reply_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    drop(credential_guard);
    handler.await;
    let mut completion = reply_rx.await.expect("KeyReport completion after unlock");
    let cqe = completion
        .first_chunk_mut::<CQE_DWORDS>()
        .expect("command CQE");
    assert_eq!(Cqe::from(cqe).status(), 0);
    hsm.pal()
        .drop_io(control_io)
        .await
        .expect("drop control IO");
}
