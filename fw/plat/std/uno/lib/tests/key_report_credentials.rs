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
use tsra_fw_hsm_pal_traits::HsmEcc;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
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

#[test]
fn typed_reports_sign_verify_and_reject_wrong_kind_or_tampering() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(check_typed_reports());
        })
        .expect("test thread")
        .join()
        .expect("test result");
}

async fn check_typed_reports() {
    use tsra_fw_core_crypto_key_report::parse_report;
    use tsra_fw_core_crypto_key_report::report;
    use tsra_fw_core_crypto_key_report::verify_report;
    use tsra_fw_core_crypto_key_report::AttestedPubKey;
    use tsra_fw_core_crypto_key_report::KeyReportParams;
    use tsra_fw_core_crypto_key_report::ReportKind;
    use tsra_fw_core_crypto_key_report::ReportParams;
    use tsra_fw_core_crypto_key_report::ReportView;
    use tsra_fw_core_crypto_key_report::TransferReportParams;
    use tsra_fw_core_crypto_key_report::KEY_REPORT_MAX_LEN;

    let (tx, rx) = async_channel::bounded(1);
    let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
    pal.part_alloc_internal(0, 1).await.expect("partition");
    pal.part_enable_internal(0).await.expect("enable");
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
    let io = pal.poll_io().await.expect("poll IO");
    let private = pal.dma_alloc_zeroed(&io, 48).expect("private key");
    private[0] = 1;
    let public = pal.dma_alloc(&io, 96).expect("public key");
    pal.ecc_pub_from_priv(&io, HsmEccCurve::P384, private, Some(public))
        .await
        .expect("derive public key");
    let fields = pal.dma_alloc(&io, 48 * 4 + 16 + 128 + 16).expect("fields");
    fields.fill(0x55);
    let encoded = pal.dma_alloc(&io, KEY_REPORT_MAX_LEN).expect("report");

    for kind in [
        ReportKind::PublicKey,
        ReportKind::Darc,
        ReportKind::SdBackup,
    ] {
        pal.alloc_scoped_async(&io, async |alloc| {
            let transfer = TransferReportParams {
                source_pid_key_id: &fields[..48],
                recipient_key_id: &fields[48..96],
                envelope_hash: &fields[96..144],
            };
            let params = match kind {
                ReportKind::PublicKey => ReportParams::PublicKey(KeyReportParams {
                    key: AttestedPubKey::Ecc {
                        curve: HsmEccCurve::P384,
                        x: &public[..48],
                        y: &public[48..],
                    },
                    flags: u32::MAX,
                    app_uuid: &fields[192..208],
                    report_data: &fields[208..336],
                    vm_launch_id: &fields[336..352],
                    policy_hash: Some(&fields[144..192]),
                }),
                ReportKind::Darc => ReportParams::Darc(transfer),
                ReportKind::SdBackup => ReportParams::SdBackup {
                    transfer: tsra_fw_core_crypto_key_report::SdBackupReportParams {
                        source_pid_spki_thumbprint: transfer.source_pid_key_id,
                        recipient_spki_thumbprint: transfer.recipient_key_id,
                        envelope_hash: transfer.envelope_hash,
                    },
                    policy_hash: &fields[144..192],
                },
            };
            let size = report(&pal, &io, alloc, &params, private, None)
                .await
                .expect("query report size");
            let mut short = [0xA5; 1];
            assert!(pal
                .alloc_scoped_async(&io, async |scratch| {
                    report(&pal, &io, scratch, &params, private, Some(&mut short)).await
                })
                .await
                .is_err());
            assert_eq!(short, [0xA5]);
            let written = report(&pal, &io, alloc, &params, private, Some(encoded))
                .await
                .expect("sign report");
            assert_eq!(written, size);
            assert_eq!(parse_report(&encoded[..size]).expect("parse").kind(), kind);
            assert!(
                verify_report(&pal, &io, alloc, &encoded[..size], public, kind)
                    .await
                    .expect("verify report")
            );
            let base = encoded.as_ptr() as usize;
            let offsets = match parse_report(&encoded[..size]).expect("parse signed fields") {
                ReportView::PublicKey(view) => vec![view.report_data.as_ptr() as usize - base],
                ReportView::Darc(view) => vec![
                    view.source_pid_key_id.as_ptr() as usize - base,
                    view.recipient_key_id.as_ptr() as usize - base,
                    view.envelope_hash.as_ptr() as usize - base,
                ],
                ReportView::SdBackup {
                    transfer,
                    policy_hash,
                } => vec![
                    transfer.envelope_hash.as_ptr() as usize - base,
                    policy_hash.as_ptr() as usize - base,
                ],
            };
            for offset in offsets {
                encoded[offset] ^= 1;
                assert!(!pal
                    .alloc_scoped_async(&io, async |scratch| {
                        verify_report(&pal, &io, scratch, &encoded[..size], public, kind).await
                    })
                    .await
                    .expect("verify changed payload"));
                encoded[offset] ^= 1;
            }
            let wrong_kind = if kind == ReportKind::Darc {
                ReportKind::SdBackup
            } else {
                ReportKind::Darc
            };
            assert!(
                verify_report(&pal, &io, alloc, &encoded[..size], public, wrong_kind)
                    .await
                    .is_err()
            );
            encoded[size - 1] ^= 1;
            assert!(
                !verify_report(&pal, &io, alloc, &encoded[..size], public, kind)
                    .await
                    .expect("verify changed signature")
            );
            Ok::<_, tsra_fw_hsm_pal_traits::HsmError>(())
        })
        .await
        .expect("report scope");
    }

    pal.alloc_scoped_async(&io, async |alloc| {
        let params = ReportParams::SdBackup {
            transfer: tsra_fw_core_crypto_key_report::SdBackupReportParams {
                source_pid_spki_thumbprint: &fields[..48],
                recipient_spki_thumbprint: &fields[48..96],
                envelope_hash: &fields[96..144],
            },
            policy_hash: &fields[144..191],
        };
        assert!(report(&pal, &io, alloc, &params, private, None)
            .await
            .is_err());
        Ok::<_, tsra_fw_hsm_pal_traits::HsmError>(())
    })
    .await
    .expect("invalid report scope");
    pal.drop_io(io).await.expect("drop IO");
}

#[test]
fn p384_transfer_reports_bind_encryption_identity_kind_and_policy() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(check_transfer_bindings());
        })
        .expect("test thread")
        .join()
        .expect("test result");
}

async fn check_transfer_bindings() {
    use tsra_crypto::EccCurve;
    use tsra_crypto::EccPublicKey;
    use tsra_crypto::ExportableKey;
    use tsra_crypto::HashAlgo;
    use tsra_crypto::HashOpContext;
    use tsra_crypto::Hasher;
    use tsra_fw_core_crypto_key_report::report;
    use tsra_fw_core_crypto_key_report::transfer::open_transfer;
    use tsra_fw_core_crypto_key_report::transfer::p384_key_id;
    use tsra_fw_core_crypto_key_report::transfer::parse_transfer_envelope;
    use tsra_fw_core_crypto_key_report::transfer::sd_spki_thumbprint;
    use tsra_fw_core_crypto_key_report::transfer::seal_transfer;
    use tsra_fw_core_crypto_key_report::transfer::transfer_envelope_hash;
    use tsra_fw_core_crypto_key_report::transfer::transfer_report_params;
    use tsra_fw_core_crypto_key_report::transfer::verify_transfer;
    use tsra_fw_core_crypto_key_report::transfer::TransferHeader;
    use tsra_fw_core_crypto_key_report::transfer::TransferOpenConfig;
    use tsra_fw_core_crypto_key_report::transfer::TransferVerifyConfig;
    use tsra_fw_core_crypto_key_report::ReportKind;
    use tsra_fw_core_crypto_key_report::ReportParams;
    use tsra_fw_core_crypto_key_report::KEY_REPORT_MAX_LEN;
    use tsra_fw_hsm_byte_order::pair_to_be;
    use tsra_fw_hsm_pal_traits::HsmDmaBuf;
    use tsra_fw_hsm_pal_traits::HsmEccPct;

    let (tx, rx) = async_channel::bounded(1);
    let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
    pal.part_alloc_internal(0, 1).await.expect("partition");
    pal.part_enable_internal(0).await.expect("enable");
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
    let io = pal.poll_io().await.expect("poll IO");
    let keys = pal
        .dma_alloc_zeroed(&io, 3 * (48 + 97))
        .expect("key fixtures");
    for i in 0..3 {
        let key = &mut keys[i * 145..(i + 1) * 145];
        let (private, public) = key.split_at_mut(48);
        public[0] = 4;
        pal.ecc_gen_keypair(
            &io,
            HsmEccCurve::P384,
            HsmEccPct::KeyAgreement,
            Some((private, &mut public[1..])),
        )
        .await
        .expect("generate P384 key pair");
        pair_to_be::<StdHsmPal>(HsmEccCurve::P384, &mut public[1..]).expect("SEC1 coordinates");
    }
    let source_private = &keys[..48];
    let source_public = &keys[48..145];
    let recipient_private = &keys[145..193];
    let recipient_public = &keys[193..290];
    let wrong_public = &keys[338..435];
    let ids = pal.dma_alloc(&io, 96).expect("key identifiers");
    let (source_id_out, recipient_id_out) = ids.split_at_mut(48);
    for (public, id) in [
        (source_public, source_id_out),
        (recipient_public, recipient_id_out),
    ] {
        pal.alloc_scoped_async(&io, async |alloc| {
            p384_key_id(&pal, &io, public, id, alloc).await
        })
        .await
        .expect("derive key identifier");
        let mut hash = Hasher::hash_init(HashAlgo::sha384()).expect("independent hash");
        hash.update(b"TSRA-P384-KEY-v1").expect("key domain");
        hash.update(public).expect("public key");
        let mut expected = [0; 48];
        hash.finish(Some(&mut expected)).expect("key ID hash");
        assert_eq!(&**id, expected);
    }
    let source_id: &[u8; 48] = ids[..48].as_ref().try_into().expect("source ID");
    let recipient_id: &[u8; 48] = ids[48..].as_ref().try_into().expect("recipient ID");
    let sd_ids = pal.dma_alloc(&io, 96).expect("SD SPKI thumbprints");
    let (sd_source, sd_recipient) = sd_ids.split_at_mut(48);
    for (public, thumbprint) in [(source_public, sd_source), (recipient_public, sd_recipient)] {
        pal.alloc_scoped_async(&io, async |alloc| {
            sd_spki_thumbprint(&pal, &io, public, thumbprint, alloc).await
        })
        .await
        .expect("derive SD SPKI thumbprint");
        let spki = EccPublicKey::from_coordinates(EccCurve::P384, &public[1..49], &public[49..])
            .expect("public key")
            .to_vec()
            .expect("DER SPKI");
        let mut hash = Hasher::hash_init(HashAlgo::sha384()).expect("independent SPKI hash");
        hash.update(&spki).expect("SPKI bytes");
        let mut expected = [0; 48];
        hash.finish(Some(&mut expected)).expect("SPKI thumbprint");
        assert_eq!(&**thumbprint, expected);
    }
    assert_ne!(&**ids, &**sd_ids);
    let policy = [0x55; 48];
    let wrong_policy = [0x66; 48];
    let encoded_report = pal.dma_alloc(&io, KEY_REPORT_MAX_LEN).expect("report");

    let sign = async |envelope: &HsmDmaBuf, output: &mut HsmDmaBuf| {
        pal.alloc_scoped_async(&io, async |alloc| {
            use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
            let digest = alloc.dma_alloc(48)?;
            transfer_envelope_hash(&pal, &io, envelope, digest, alloc).await?;
            let mut hash = Hasher::hash_init(HashAlgo::sha384()).expect("independent hash");
            hash.update(b"TSRA-XFER-HASH-v1").expect("envelope domain");
            hash.update(envelope).expect("envelope bytes");
            let mut expected = [0; 48];
            hash.finish(Some(&mut expected)).expect("envelope hash");
            assert_eq!(&**digest, expected);
            let params = transfer_report_params(envelope, digest)?;
            report(&pal, &io, alloc, &params, source_private, Some(output)).await
        })
        .await
    };
    let verify =
        async |cfg: &TransferVerifyConfig<'_>, envelope: &HsmDmaBuf, report: &HsmDmaBuf| {
            pal.alloc_scoped_async(&io, async |alloc| {
                verify_transfer(&pal, &io, cfg, envelope, report, alloc)
                    .await
                    .map(|_| ())
            })
            .await
        };
    for header in [
        TransferHeader::Darc {
            source_pid_key_id: source_id,
            recipient_key_id: recipient_id,
        },
        TransferHeader::SdBackup {
            source_pid_spki_thumbprint: sd_ids[..48]
                .as_ref()
                .try_into()
                .expect("source SPKI thumbprint"),
            recipient_spki_thumbprint: sd_ids[48..]
                .as_ref()
                .try_into()
                .expect("recipient SPKI thumbprint"),
            policy_hash: &policy,
        },
    ] {
        let secret = pal.dma_alloc(&io, header.plaintext_len()).expect("secret");
        secret.fill(0xA5);
        let envelope = pal.dma_alloc(&io, header.envelope_len()).expect("envelope");
        pal.alloc_scoped_async(&io, async |alloc| {
            seal_transfer(
                &pal,
                &io,
                &header,
                recipient_public,
                secret,
                envelope,
                alloc,
            )
            .await
        })
        .await
        .expect("HPKE Base seal");
        let report_len = sign(envelope, encoded_report).await.expect("sign transfer");
        let mut cfg = TransferVerifyConfig {
            expected_kind: header.kind(),
            signer_public_key: source_public,
            recipient_public_key: recipient_public,
            expected_policy_hash: header.policy_hash(),
        };
        verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .expect("verify transfer");
        let plaintext = pal.dma_alloc(&io, secret.len()).expect("plaintext");
        plaintext.fill(0xCC);
        let open_cfg = TransferOpenConfig {
            verification: TransferVerifyConfig { ..cfg },
            recipient_private_key: recipient_private,
        };
        assert_eq!(
            pal.alloc_scoped_async(&io, async |alloc| {
                open_transfer(
                    &pal,
                    &io,
                    &open_cfg,
                    envelope,
                    &encoded_report[..report_len],
                    plaintext,
                    alloc,
                )
                .await
            })
            .await
            .expect("open verified transfer"),
            secret.len()
        );
        assert_eq!(&**plaintext, &**secret);

        let header_len = parse_transfer_envelope(envelope)
            .expect("view")
            .header_bytes
            .len();
        let mut offsets = vec![17, 65, header_len + 1, header_len + 97, envelope.len() - 1];
        if header.kind() == ReportKind::SdBackup {
            offsets.push(113);
        }
        for offset in offsets {
            envelope[offset] ^= 1;
            assert!(verify(&cfg, envelope, &encoded_report[..report_len])
                .await
                .is_err());
            plaintext.fill(0xCC);
            assert!(pal
                .alloc_scoped_async(&io, async |alloc| {
                    open_transfer(
                        &pal,
                        &io,
                        &open_cfg,
                        envelope,
                        &encoded_report[..report_len],
                        plaintext,
                        alloc,
                    )
                    .await
                })
                .await
                .is_err());
            assert!(plaintext.iter().all(|byte| *byte == 0xCC));
            envelope[offset] ^= 1;
        }
        encoded_report[report_len - 1] ^= 1;
        assert!(verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .is_err());
        encoded_report[report_len - 1] ^= 1;
        cfg.recipient_public_key = wrong_public;
        assert!(verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .is_err());
        cfg.recipient_public_key = recipient_public;
        cfg.signer_public_key = wrong_public;
        assert!(verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .is_err());
        cfg.signer_public_key = source_public;
        for wrong_kind in [
            ReportKind::PublicKey,
            if header.kind() == ReportKind::Darc {
                ReportKind::SdBackup
            } else {
                ReportKind::Darc
            },
        ] {
            cfg.expected_kind = wrong_kind;
            assert!(verify(&cfg, envelope, &encoded_report[..report_len])
                .await
                .is_err());
        }
        cfg.expected_kind = header.kind();
        cfg.expected_policy_hash = Some(&wrong_policy);
        assert!(verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .is_err());
        cfg.expected_policy_hash = None;
        verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .expect("no receiver-policy equality requirement");

        // Even correctly signed reports must agree with the envelope fields.
        for bad_claim in 0..if header.kind() == ReportKind::Darc {
            3
        } else {
            4
        } {
            let bad_len = pal
                .alloc_scoped_async(&io, async |alloc| {
                    use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
                    let digest = alloc.dma_alloc(48)?;
                    transfer_envelope_hash(&pal, &io, envelope, digest, alloc).await?;
                    let mut params = transfer_report_params(envelope, digest)?;
                    match &mut params {
                        ReportParams::Darc(transfer) => match bad_claim {
                            0 => transfer.source_pid_key_id = &ids[48..],
                            1 => transfer.recipient_key_id = &ids[..48],
                            2 => transfer.envelope_hash = &ids[..48],
                            _ => {}
                        },
                        ReportParams::SdBackup {
                            transfer,
                            policy_hash,
                        } => {
                            if bad_claim == 3 {
                                *policy_hash = &ids[..48];
                            }
                            match bad_claim {
                                0 => transfer.source_pid_spki_thumbprint = &sd_ids[48..],
                                1 => transfer.recipient_spki_thumbprint = &sd_ids[..48],
                                2 => transfer.envelope_hash = &sd_ids[..48],
                                _ => {}
                            }
                        }
                        ReportParams::PublicKey(_) => unreachable!("operation envelope"),
                    }
                    report(
                        &pal,
                        &io,
                        alloc,
                        &params,
                        source_private,
                        Some(encoded_report),
                    )
                    .await
                })
                .await
                .expect("sign mismatched claim");
            assert!(verify(&cfg, envelope, &encoded_report[..bad_len])
                .await
                .is_err());
        }

        // A newly signed digest cannot rescue ciphertext sealed with an old
        // header: HPKE info/AAD must authenticate the header independently.
        if header.kind() == ReportKind::SdBackup {
            envelope[113] ^= 1;
            let resigned_len = sign(envelope, encoded_report)
                .await
                .expect("sign changed policy");
            verify(&cfg, envelope, &encoded_report[..resigned_len])
                .await
                .expect("valid new signature/bindings");
            let changed_cfg = TransferOpenConfig {
                verification: cfg,
                recipient_private_key: recipient_private,
            };
            plaintext.fill(0xCC);
            assert!(pal
                .alloc_scoped_async(&io, async |alloc| {
                    open_transfer(
                        &pal,
                        &io,
                        &changed_cfg,
                        envelope,
                        &encoded_report[..resigned_len],
                        plaintext,
                        alloc,
                    )
                    .await
                })
                .await
                .is_err());
            assert!(plaintext.iter().all(|byte| *byte == 0xCC));
        }

        envelope.fill(0xCC);
        assert!(pal
            .alloc_scoped_async(&io, async |alloc| {
                seal_transfer(&pal, &io, &header, wrong_public, secret, envelope, alloc).await
            })
            .await
            .is_err());
        assert!(envelope.iter().all(|byte| *byte == 0xCC));
        assert!(pal
            .alloc_scoped_async(&io, async |alloc| {
                seal_transfer(
                    &pal,
                    &io,
                    &header,
                    recipient_public,
                    &secret[..secret.len() - 1],
                    envelope,
                    alloc,
                )
                .await
            })
            .await
            .is_err());
        assert!(envelope.iter().all(|byte| *byte == 0xCC));
    }
    pal.drop_io(io).await.expect("drop IO");
}
