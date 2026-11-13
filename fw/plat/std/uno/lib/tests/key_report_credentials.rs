// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Drives the Uno IO pipeline (`Hsm::handle_io`) with a real `StdHsmPal`.

use std::time::Duration;

use tsra_crypto::*;
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
use tsra_fw_hsm_pal_std_uno::HsmIoRequest;
use tsra_fw_hsm_pal_std_uno::HsmPartId;
use tsra_fw_hsm_pal_std_uno::StdHsmPal;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmPartitionLock;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionManager;
use tsra_fw_hsm_pal_traits::HsmSessionRole;
use tsra_fw_hsm_pal_traits::SESSION_AUTH_BINDING_LEN;
use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_IV_LEN;
use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_KEY_LEN;

/// Core's crate-private `SessionCtrl::InSession` session-control value.
const SESSION_CTRL_IN_SESSION: u8 = 3;

/// VM→HSM transport key of the session the test installs.
const H2M_KEY: [u8; SESSION_TRANSPORT_KEY_LEN] = [0x11; SESSION_TRANSPORT_KEY_LEN];

#[repr(align(4096))]
struct HostPage([u8; 4096]);

/// Installs an Active CO session whose VM→HSM transport key is
/// [`H2M_KEY`], returning its id.
async fn install_session(
    pal: &StdHsmPal,
    io: &<StdHsmPal as tsra_fw_hsm_pal_traits::HsmIoTypes>::Io,
) -> HsmSessId {
    let blank = pal.dma_alloc(io, 1).expect("handshake state");
    let id = pal
        .session_create_pending(io, HsmSessionRole::CryptoOfficer, blank)
        .await
        .expect("pending session");
    let key = |fill: u8, len: usize| {
        let buf = pal.dma_alloc(io, len).expect("session key");
        buf.fill(fill);
        &*buf
    };
    let h2m = pal.dma_alloc(io, SESSION_TRANSPORT_KEY_LEN).expect("h2m");
    h2m.copy_from_slice(&H2M_KEY);
    pal.session_promote(
        io,
        id,
        &[0; 8],
        key(0x22, 32),
        key(0x33, 32),
        key(0, SESSION_AUTH_BINDING_LEN),
        h2m,
        key(0x44, SESSION_TRANSPORT_KEY_LEN),
    )
    .await
    .expect("promote session");
    id
}

/// Seals `msg` into `out` as an Uno transport frame
/// (`ct ‖ iv ‖ tag`, block-padded, no AAD), returning the frame length.
fn seal_frame(msg: &[u8], out: &mut [u8]) -> usize {
    let pt_len = (msg.len() + 1).next_multiple_of(16);
    let mut pt = vec![0u8; pt_len];
    pt[..msg.len()].copy_from_slice(msg);
    pt[pt_len - 1] = (pt_len - 1 - msg.len()) as u8;
    let iv = [0x5a; SESSION_TRANSPORT_IV_LEN];
    let key = AesKey::from_bytes(&H2M_KEY).expect("transport key");
    let mut algo = AesGcmAlgo::for_encrypt(&iv, None).expect("gcm");
    algo.encrypt(&key, &pt, Some(&mut out[..pt_len]))
        .expect("seal");
    out[pt_len..pt_len + iv.len()].copy_from_slice(&iv);
    let tag = algo.tag();
    out[pt_len + iv.len()..pt_len + iv.len() + tag.len()].copy_from_slice(tag);
    pt_len + iv.len() + tag.len()
}

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
    let session = install_session(hsm.pal(), &control_io).await;
    let credential_guard = hsm
        .pal()
        .partition_lock(&control_io)
        .await
        .expect("credential transaction");

    let mut msg = [0u8; 2048];
    let mut request = HostPage([0; 4096]);
    let mut response = HostPage([0xA5; 4096]);
    let msg_len = TborKeyReportReq::encode(&mut msg)
        .expect("encode")
        .session_id(u16::from(session).into())
        .expect("session id")
        .masked_key(&[])
        .expect("masked key")
        .report_data(&[0; KEY_REPORT_DATA_LEN])
        .expect("report data")
        .auth_envelope(&[])
        .expect("auth envelope")
        .finish()
        .len();
    let request_len = seal_frame(&msg[..msg_len], &mut request.0);
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
            .session_flags(
                SessionFlags::new()
                    .with_ctrl(SESSION_CTRL_IN_SESSION)
                    .with_id_valid(true),
            )
            .session_id(u16::from(session))
            .build(),
        reply_tx,
    ))
    .await
    .expect("KeyReport IO");
    let io = hsm.pal().poll_io().await.expect("poll KeyReport");
    let mut handler = std::pin::pin!(hsm.handle_io(io));
    // Opening the sealed frame suspends on the std PAL's crypto workers,
    // so drive the handler with a real waker until it parks on the
    // credential guard.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), handler.as_mut())
            .await
            .is_err(),
        "KeyReport completed while the credential transaction was held"
    );
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
