// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Drives the Uno IO pipeline (`Hsm::handle_io`) with a real `StdHsmPal`.

use std::time::Duration;

use tsra_crypto::*;
use tsra_fw_ddi_tbor_types::TborKeyReportReq;
use tsra_fw_ddi_tbor_types::TborPskChangeReq;
use tsra_fw_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use tsra_fw_hsm_bulk::BulkCqe;
use tsra_fw_hsm_bulk::BulkDir;
use tsra_fw_hsm_bulk::BulkParams;
use tsra_fw_hsm_bulk::BulkSqe;
use tsra_fw_hsm_bulk::GcmParams;
use tsra_fw_hsm_core::Hsm;
use tsra_fw_hsm_io::sealed::SessionTransportBinding;
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
use tsra_fw_hsm_pal_traits::HsmApiRevision;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmIoKind;
use tsra_fw_hsm_pal_traits::HsmPartitionLock;
use tsra_fw_hsm_pal_traits::HsmSessCtrl;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionManager;
use tsra_fw_hsm_pal_traits::HsmSessionRole;
use tsra_fw_hsm_pal_traits::APP_ID_LEN;
use tsra_fw_hsm_pal_traits::DEFAULT_PSK_CU;
use tsra_fw_hsm_pal_traits::SESSION_AUTH_BINDING_LEN;
use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_IV_LEN;
use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_KEY_LEN;
use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_SALT_LEN;
use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_SECRET_LEN;

/// Core's crate-private `SessionCtrl::InSession` session-control value.
const SESSION_CTRL_IN_SESSION: u8 = 3;

/// VM→HSM transport key of the session the test installs.
const H2M_KEY: [u8; SESSION_TRANSPORT_KEY_LEN] = [0x11; SESSION_TRANSPORT_KEY_LEN];

/// VM→HSM nonce salt of the session the test installs.
const H2M_SALT: [u8; SESSION_TRANSPORT_SALT_LEN] = [0x5a; SESSION_TRANSPORT_SALT_LEN];

#[repr(align(4096))]
struct HostPage([u8; 4096]);

/// Installs an Active session whose VM→HSM transport key and salt are
/// [`H2M_KEY`] and [`H2M_SALT`], returning its id.
async fn install_session(
    pal: &StdHsmPal,
    io: &<StdHsmPal as tsra_fw_hsm_pal_traits::HsmIoTypes>::Io,
    role: HsmSessionRole,
) -> HsmSessId {
    let blank = pal.dma_alloc(io, 1).expect("handshake state");
    let id = pal
        .session_create_pending(io, role, blank)
        .await
        .expect("pending session");
    let key = |fill: u8, len: usize| {
        let buf = pal.dma_alloc(io, len).expect("session key");
        buf.fill(fill);
        &*buf
    };
    let h2m = pal
        .dma_alloc(io, SESSION_TRANSPORT_SECRET_LEN)
        .expect("h2m");
    let (h2m_key, h2m_salt) = h2m.split_at_mut(SESSION_TRANSPORT_KEY_LEN);
    h2m_key.copy_from_slice(&H2M_KEY);
    h2m_salt.copy_from_slice(&H2M_SALT);
    let psk = tsra_fw_hsm_core::part_state::part_psk(
        pal,
        io,
        u8::from(role == HsmSessionRole::CryptoUser),
    )
    .expect("current partition credential");
    let binding = pal
        .dma_alloc(io, SESSION_AUTH_BINDING_LEN)
        .expect("binding");
    binding[..4].copy_from_slice(&u32::from(role == HsmSessionRole::CryptoUser).to_le_bytes());
    binding[4..4 + APP_ID_LEN].copy_from_slice(&psk[..APP_ID_LEN]);
    HashAlgo::sha384()
        .hash(psk, Some(&mut binding[4 + APP_ID_LEN..]))
        .expect("credential digest");
    pal.session_promote(
        io,
        id,
        &[0; 8],
        HsmApiRevision::new(1, 1),
        key(0x22, 32),
        key(0x33, 32),
        binding,
        h2m,
        key(0x44, SESSION_TRANSPORT_SECRET_LEN),
    )
    .await
    .expect("promote session");
    id
}

/// Seals `msg` into `out` as an Uno transport frame
/// (`ct ‖ iv ‖ tag`, block-padded, request-bound AAD, `iv = salt ‖ seq`),
/// returning the frame length.
fn seal_frame(msg: &[u8], session: HsmSessId, seq: u64, out: &mut [u8]) -> usize {
    let pt_len = (msg.len() + 1).next_multiple_of(16);
    let mut pt = vec![0u8; pt_len];
    pt[..msg.len()].copy_from_slice(msg);
    pt[pt_len - 1] = (pt_len - 1 - msg.len()) as u8;
    let mut iv = [0u8; SESSION_TRANSPORT_IV_LEN];
    iv[..SESSION_TRANSPORT_SALT_LEN].copy_from_slice(&H2M_SALT);
    iv[SESSION_TRANSPORT_SALT_LEN..].copy_from_slice(&seq.to_be_bytes());
    let key = AesKey::from_bytes(&H2M_KEY).expect("transport key");
    let aad = SessionTransportBinding::uno(u16::from(session), HsmSessCtrl::InSession, iv)
        .expect("request binding")
        .aad(false);
    let mut algo = AesGcmAlgo::for_encrypt(&iv, Some(&aad)).expect("gcm");
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
    let session = install_session(hsm.pal(), &control_io, HsmSessionRole::CryptoOfficer).await;
    let credential_guard = hsm
        .pal()
        .partition_lock(&control_io)
        .await
        .expect("credential transaction");

    let mut msg = [0u8; 2048];
    let mut request = HostPage([0; 4096]);
    let mut response = HostPage([0xA5; 4096]);
    let msg_len = TborKeyReportReq::encode(&mut msg, (1, 1))
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
    let request_len = seal_frame(&msg[..msg_len], session, 0, &mut request.0);
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

#[test]
fn psk_change_failed_completion_restores_default_and_allows_same_session_retry() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(check_psk_change_rollback());
        })
        .expect("test thread")
        .join()
        .expect("test result");
}

async fn check_psk_change_rollback() {
    let (tx, rx) = async_channel::bounded(1);
    let hsm = Hsm::new(StdHsmPal::new(rx, tokio::runtime::Handle::current()));
    hsm.pal()
        .part_alloc_internal(0, 1)
        .await
        .expect("partition");
    hsm.pal().part_enable_internal(0).await.expect("enable");
    let (reply_tx, _) = tokio::sync::oneshot::channel();
    tx.send(HsmIoRequest::cmd(
        HsmPartId::from(0u8),
        0,
        0,
        [0; SQE_DWORDS],
        reply_tx,
    ))
    .await
    .expect("control IO");
    let control_io = hsm.pal().poll_io().await.expect("control IO");
    let session = install_session(hsm.pal(), &control_io, HsmSessionRole::CryptoUser).await;
    assert_bulk_rejected(&hsm, &tx, session, HsmError::DefaultPskMustRotate).await;
    let aad = tsra_fw_ddi_tbor_types::build_psk_change_aad(u16::from(session));
    let key = AesKey::from_bytes(&[0x22; 32]).expect("parameter key");
    let alg = aead_envelope::AeadAlg::AesGcm256;
    let mut envelope = [0; tsra_fw_ddi_tbor_types::PSK_CHANGE_ENVELOPE_LEN];
    aead_envelope::seal(
        alg,
        &key,
        &vec![0x55; alg.iv_len()],
        &aad,
        &[0xA5; 32],
        Some(&mut envelope),
    )
    .expect("PSK envelope");

    for fail_completion in [true, false] {
        let mut msg = [0; 512];
        let msg_len = TborPskChangeReq::encode(&mut msg, (1, 1))
            .expect("encode")
            .session_id(u16::from(session).into())
            .expect("session id")
            .psk_envelope(&envelope)
            .expect("PSK envelope")
            .finish()
            .len();
        let mut request = HostPage([0; 4096]);
        let mut response = HostPage([0; 4096]);
        let len = seal_frame(
            &msg[..msg_len],
            session,
            u64::from(!fail_completion),
            &mut request.0,
        );
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(HsmIoRequest::cmd(
            HsmPartId::from(0u8),
            0,
            0,
            SqeBuilder::new()
                .cmd(CmdDword::new().with_op(OP_TBOR))
                .buf_lens(len as u32, 4096)
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
        .expect("rotation IO");
        let io = hsm.pal().poll_io().await.expect("rotation IO");
        let reply_rx = if fail_completion {
            drop(reply_rx);
            None
        } else {
            Some(reply_rx)
        };
        hsm.handle_io(io).await;
        if let Some(reply_rx) = reply_rx {
            let mut raw = reply_rx.await.expect("rotation completion");
            let cqe = Cqe::try_from(&mut raw[..CQE_DWORDS]).expect("CQE");
            assert_eq!(cqe.status(), 0);
        }
        let expected = if fail_completion {
            &DEFAULT_PSK_CU
        } else {
            &[0xA5; 32]
        };
        assert_eq!(
            hsm.pal()
                .session_psk_changed(&control_io, session)
                .expect("consumed flag"),
            !fail_completion,
        );
        let binding = hsm
            .pal()
            .session_auth_binding(&control_io, session)
            .expect("binding");
        assert!(
            binding[4..4 + APP_ID_LEN] == expected[..APP_ID_LEN],
            "binding follows committed PSK"
        );
        assert_eq!(
            tsra_fw_hsm_core::part_state::part_psk(hsm.pal(), &control_io, 1)
                .expect("partition CU PSK"),
            expected.as_slice()
        );
        assert_bulk_rejected(
            &hsm,
            &tx,
            session,
            if fail_completion {
                HsmError::DefaultPskMustRotate
            } else {
                HsmError::KeyNotFound
            },
        )
        .await;
    }

    async fn assert_bulk_rejected(
        hsm: &Hsm<StdHsmPal>,
        tx: &async_channel::Sender<HsmIoRequest>,
        session: HsmSessId,
        error: HsmError,
    ) {
        let sqe = BulkSqe {
            dir: BulkDir::Encrypt,
            cid: 0,
            session_id: u16::from(session),
            short_app_id: 0,
            src_len: 0,
            src_addr: 0,
            dst_len: 0,
            dst_addr: 0,
            params: BulkParams::Gcm(GcmParams {
                key_id: u32::MAX,
                aad_len: 0,
                aligned_aad_len: 0,
                tag: [0; 16],
                iv: [0; 12],
                tail: None,
            }),
        }
        .encode();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(HsmIoRequest {
            pid: HsmPartId::from(0u8),
            qid: 1,
            qidx: 0,
            kind: HsmIoKind::Bulk,
            sqe,
            tx: reply_tx,
        })
        .await
        .expect("bulk IO");
        let io = hsm.pal().poll_io().await.expect("bulk IO");
        hsm.handle_io(io).await;
        let cqe = reply_rx.await.expect("bulk completion");
        assert_eq!(
            cqe,
            BulkCqe::error(&sqe, 1, error).encode(),
            "bulk credential policy must distinguish restricted sessions from current credentials"
        );
    }
    hsm.pal()
        .session_destroy(&control_io, session)
        .await
        .expect("destroy session");
    let session = install_session(hsm.pal(), &control_io, HsmSessionRole::CryptoUser).await;
    assert_bulk_rejected(&hsm, &tx, session, HsmError::KeyNotFound).await;
    hsm.pal()
        .session_destroy(&control_io, session)
        .await
        .expect("destroy current-credential session");
    hsm.pal()
        .drop_io(control_io)
        .await
        .expect("drop control IO");
}
