// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tsra_ddi_sock_proto::ProtoError;
use tsra_ddi_sock_proto::ResponseFrame;

use super::Connection;
use super::SocketHsm;

async fn write_response(
    stream: &mut TcpStream,
    response: &ResponseFrame,
) -> Result<(), ProtoError> {
    let body = response.encode()?;
    stream.write_u32_le(body.len() as u32).await?;
    stream.write_all(&body).await?;
    Ok(())
}

async fn serve_connection(mut stream: TcpStream, hsm: Arc<SocketHsm>) -> Result<(), String> {
    let connection = Connection::new(hsm);
    loop {
        let Some(request) = super::read_request_with_timeout(&mut stream).await? else {
            return Ok(());
        };
        let response =
            match tokio::time::timeout(super::CONNECTION_READ_TIMEOUT, connection.execute(request))
                .await
            {
                Ok(result) => result?,
                Err(_elapsed) => return Ok(()),
            };
        tokio::time::timeout(
            super::CONNECTION_READ_TIMEOUT,
            write_response(&mut stream, &response),
        )
        .await
        .map_err(|_elapsed| "failed to write DDI response: timed out".to_string())?
        .map_err(|error| format!("failed to write DDI response: {error}"))?;
    }
}

fn spawn_connection(
    stream: TcpStream,
    peer: SocketAddr,
    hsm: &Arc<SocketHsm>,
) -> Result<(), String> {
    stream
        .set_nodelay(true)
        .map_err(|error| format!("failed to configure TCP connection: {error}"))?;
    let hsm = Arc::clone(hsm);
    tokio::spawn(async move {
        if let Err(error) = serve_connection(stream, hsm).await {
            tracing::warn!(%peer, %error, "TCP client failed");
        }
    });
    Ok(())
}

async fn run_server(listener: TcpListener, hsm: Arc<SocketHsm>) -> Result<(), String> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept TCP connection: {error}"))?;
        spawn_connection(stream, peer, &hsm)?;
    }
}

fn bind(address: &str) -> Result<(std::net::TcpListener, SocketAddr), String> {
    let listener = std::net::TcpListener::bind(address)
        .map_err(|error| format!("failed to bind TCP listener at {address}: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("failed to configure TCP listener: {error}"))?;
    let bound_address = listener
        .local_addr()
        .map_err(|error| format!("failed to query TCP listener address: {error}"))?;
    Ok((listener, bound_address))
}

fn serve(
    listener: std::net::TcpListener,
    bound_address: SocketAddr,
    on_listening: impl FnOnce(&super::Listening),
    first: Option<(std::net::TcpStream, SocketAddr)>,
) -> Result<(), String> {
    super::run_with_hsm(|hsm| async move {
        let listener = TcpListener::from_std(listener)
            .map_err(|error| format!("failed to register TCP listener: {error}"))?;
        super::init_partition(&hsm).await?;
        on_listening(&super::Listening::new(format!("tcp://{bound_address}")));
        if let Some((stream, peer)) = first {
            let stream = TcpStream::from_std(stream)
                .map_err(|error| format!("failed to register TCP connection: {error}"))?;
            spawn_connection(stream, peer, &hsm)?;
        }
        run_server(listener, hsm).await
    })
}

/// Blocks until the first client connects, so the HSM is only booted for
/// processes that use it. Background HSM crypto racing the process's exit
/// (OpenSSL's library destructors) would otherwise crash short-lived
/// processes that never talk to the HSM.
fn accept_first(
    listener: &std::net::TcpListener,
) -> Result<(std::net::TcpStream, SocketAddr), String> {
    listener
        .set_nonblocking(false)
        .map_err(|error| format!("failed to configure TCP listener: {error}"))?;
    let (stream, peer) = listener
        .accept()
        .map_err(|error| format!("failed to accept TCP connection: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("failed to configure TCP listener: {error}"))?;
    stream
        .set_nonblocking(true)
        .map_err(|error| format!("failed to configure TCP connection: {error}"))?;
    Ok((stream, peer))
}

pub(super) fn run(
    address: &str,
    on_listening: impl FnOnce(&super::Listening),
) -> Result<(), String> {
    let (listener, bound_address) = bind(address)?;
    if !bound_address.ip().is_loopback() {
        tracing::warn!(
            %bound_address,
            "This unauthenticated test server is listening outside loopback"
        );
    }
    serve(listener, bound_address, on_listening, None)
}

/// Start the server in this process on an ephemeral loopback TCP port.
///
/// The listener is bound before returning, so clients may connect
/// immediately. The HSM is booted and its partition set up when the first
/// client connects; clients are served once that completes. The server
/// runs on a background thread for the rest of the process lifetime. Call at
/// most once per process: the emulated HSM is process-global.
pub fn spawn_loopback() -> Result<SocketAddr, String> {
    spawn_loopback_with(|_| {})
}

/// [`spawn_loopback`], calling `on_bound` with the bound address before the
/// server thread is spawned.
pub(crate) fn spawn_loopback_with(on_bound: impl FnOnce(SocketAddr)) -> Result<SocketAddr, String> {
    let (listener, bound_address) = bind("127.0.0.1:0")?;
    on_bound(bound_address);
    std::thread::Builder::new()
        .name("tsra-ddi-sock-server".into())
        .spawn(move || {
            let result = accept_first(&listener)
                .and_then(|first| serve(listener, bound_address, |_| {}, Some(first)));
            if let Err(error) = result {
                tracing::error!(%error, "TSRA DDI socket server failed");
            }
        })
        .map_err(|error| format!("failed to start server thread: {error}"))?;
    Ok(bound_address)
}

#[cfg(test)]
mod tests {
    use std::sync::Weak;
    use std::time::Duration;
    use std::time::Instant;

    use tsra_crypto::EccPublicKey;
    use tsra_crypto::ImportableKey;
    use tsra_ddi_interface::Ddi;
    use tsra_ddi_interface::DdiAesGcmParams;
    use tsra_ddi_interface::DdiDev;
    use tsra_ddi_interface::DdiError;
    use tsra_ddi_mbor_types::*;
    use tsra_ddi_sock::DdiSock;
    use tsra_ddi_sock::DdiSockDev;
    use tsra_ddi_sock_proto::OobItem;
    use tsra_ddi_sock_proto::Request;
    use tsra_ddi_sock_proto::RequestFrame;
    use tsra_ddi_tbor_types::SESSION_SEED_LEN;
    use tsra_ddi_tbor_types::TborGetCertChainInfoReq;
    use tsra_ddi_tbor_types::TborGetCertReq;
    use tsra_ddi_tbor_types::TborOpReq;
    use tsra_ddi_tbor_types::TborPskChangeReq;
    use tsra_ddi_tbor_types::TborSessionCloseReq;
    use tsra_ddi_tbor_types::TborSessionOpenFinishReq;
    use tsra_ddi_tbor_types::TborSessionOpenInitReq;
    use tsra_ddi_tbor_types::TborStatus;
    use tsra_session_ex_crypto::*;
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    use super::*;

    fn tbor<R: TborOpReq>(device: &DdiSockDev, request: &R) -> R::OpResp {
        device
            .exec_op_tbor(request, None, &mut None)
            .expect("TBOR command")
    }

    fn open_init(device: &DdiSockDev, psk_id: u8) -> TborSessionOpenFinishReq {
        open_init_with_exported(device, psk_id).0
    }

    fn open_init_with_exported(
        device: &DdiSockDev,
        psk_id: u8,
    ) -> (TborSessionOpenFinishReq, Vec<u8>) {
        let chain = tbor(device, &TborGetCertChainInfoReq::new(0));
        let leaf = tbor(device, &TborGetCertReq::new(0, chain.num_certs - 1));
        let cert = X509Certificate::from_der(&leaf.certificate).expect("partition certificate");
        let pk_hsm =
            EccPublicKey::from_bytes(&cert.get_public_key_der().expect("partition public key"))
                .expect("decode partition public key");
        let pk_hsm_sec1 = ec_pub_to_sec1(&pk_hsm).expect("partition SEC1 key");
        let ephemeral = generate_vm_ephemeral().expect("VM ephemeral");
        let request = TborSessionOpenInitReq {
            psk_id,
            session_type: u8::from(psk_id == 0),
            pk_init: ephemeral.pk_sec1,
            ..Default::default()
        };
        let response = tbor(device, &request);
        let info = build_hpke_info(request.psk_id, request.session_type, request.suite_id);
        let exported = receive_exported(
            &ephemeral.sk,
            &ephemeral.pk,
            &pk_hsm,
            &response.pk_resp,
            &info,
            default_psk(request.psk_id).expect("default PSK"),
            &[request.psk_id],
        )
        .expect("HPKE export");
        verify_phase1_mac(
            &exported,
            response.session_id,
            &ephemeral.pk_sec1,
            &pk_hsm_sec1,
            &response.pk_resp,
            &response.mac_resp,
        )
        .expect("phase 1 MAC");
        let param_key = derive_param_key(&exported).expect("parameter key");
        let finish = TborSessionOpenFinishReq {
            session_id: response.session_id,
            mac_fin: build_phase2_mac(
                &exported,
                response.session_id,
                &ephemeral.pk_sec1,
                &pk_hsm_sec1,
                &response.pk_resp,
            )
            .expect("phase 2 MAC"),
            seed_envelope: seal_seed_envelope(&param_key, &[0x5A; SESSION_SEED_LEN])
                .expect("seed envelope")
                .try_into()
                .expect("seed envelope length"),
        };
        (finish, exported)
    }

    fn with_session_clients(test: impl FnOnce(String, Arc<SocketHsm>) + Send + 'static) {
        let _guard = crate::test_partition_lock();
        let hsm = crate::test_hsm();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
            let endpoint = format!("tcp://{}", listener.local_addr().expect("address"));
            let serving = tokio::spawn(run_server(listener, Arc::clone(&hsm)));
            let client_hsm = Arc::clone(&hsm);
            let clients = tokio::task::spawn_blocking(move || test(endpoint, client_hsm));
            tokio::time::timeout(Duration::from_secs(30), clients)
                .await
                .expect("session clients complete")
                .expect("session client task");
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if hsm.sessions.read().await.is_empty() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("all client sessions cleaned up");
            serving.abort();
        });
    }

    fn generation(hsm: &SocketHsm, id: u16) -> Weak<()> {
        Arc::downgrade(
            &hsm.sessions
                .blocking_read()
                .get(&id)
                .expect("session owner")
                .generation,
        )
    }

    fn wait_for_cleanup(generation: Weak<()>) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while generation.upgrade().is_some() {
            assert!(Instant::now() < deadline, "disconnect cleanup timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn assert_not_owned<R: TborOpReq>(device: &DdiSockDev, request: &R) {
        assert!(matches!(
            device.exec_op_tbor(request, None, &mut None),
            Err(DdiError::DdiStatus(
                DdiStatus::FileHandleSessionIdDoesNotMatch
            ))
        ));
    }

    fn bulk_error(device: &DdiSockDev, session_id: u16) -> DdiError {
        device
            .exec_op_fp_gcm(
                DdiAesOp::Encrypt,
                DdiAesGcmParams {
                    key_id: u32::MAX,
                    iv: [0; 12],
                    aad: None,
                    tag: None,
                    session_id,
                    short_app_id: 0,
                },
                vec![0; 16],
            )
            .expect_err("unallocated bulk key")
    }

    #[test]
    fn bulk_rejects_pending_and_failed_finish_sessions() {
        with_session_clients(|endpoint, hsm| {
            let owner = DdiSock::default()
                .open_dev(&endpoint)
                .expect("owner socket");
            owner.erase().expect("initial reset");
            let mut pending = open_init(&owner, 0);
            assert!(matches!(
                bulk_error(&owner, pending.session_id),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));

            pending.mac_fin[0] ^= 1;
            assert!(matches!(
                owner.exec_op_tbor(&pending, None, &mut None),
                Err(DdiError::TborStatus(status)) if status == TborStatus::SessionAuthFailure
            ));
            assert!(
                !hsm.sessions
                    .blocking_read()
                    .contains_key(&pending.session_id)
            );
            assert!(matches!(
                bulk_error(&owner, pending.session_id),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));

            let replacement = open_init(&owner, 0);
            tbor(&owner, &replacement);
            assert!(matches!(
                bulk_error(&owner, replacement.session_id),
                DdiError::FpError(status)
                    if status == u32::from(tsra_fw_hsm_bulk::sts::INVALID_FIELD_GCM)
            ));
        });
    }

    #[test]
    fn bulk_rejects_reset_session_until_authenticated_again() {
        with_session_clients(|endpoint, hsm| {
            let owner = DdiSock::default()
                .open_dev(&endpoint)
                .expect("owner socket");
            owner.erase().expect("initial reset");
            let session = open_init(&owner, 0);
            tbor(&owner, &session);
            let lease = generation(&hsm, session.session_id);
            assert!(matches!(
                bulk_error(&owner, session.session_id),
                DdiError::FpError(status)
                    if status == u32::from(tsra_fw_hsm_bulk::sts::INVALID_FIELD_GCM)
            ));

            owner.erase().expect("reset");
            assert!(matches!(
                bulk_error(&owner, session.session_id),
                DdiError::DdiStatus(DdiStatus::SessionNeedsRenegotiation)
            ));
            drop(owner);
            wait_for_cleanup(lease);

            let owner = DdiSock::default()
                .open_dev(&endpoint)
                .expect("replacement socket");
            let replacement = open_init(&owner, 0);
            tbor(&owner, &replacement);
            assert!(matches!(
                bulk_error(&owner, replacement.session_id),
                DdiError::FpError(status)
                    if status == u32::from(tsra_fw_hsm_bulk::sts::INVALID_FIELD_GCM)
            ));
        });
    }

    #[test]
    fn cancelled_oob_submission_completes_before_disconnect_cleanup() {
        use tsra_ddi_interface::TborOobItem;
        use tsra_ddi_tbor_test_harness::SessionHandshake;
        use tsra_ddi_tbor_test_harness::encrypt_mach_seed_envelope;
        use tsra_ddi_tbor_test_harness::encrypt_psk_envelope;
        use tsra_ddi_tbor_test_harness::x509_fixture::PotaFixture;
        use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
        use tsra_ddi_tbor_types::CertDescriptor;
        use tsra_ddi_tbor_types::PartPolicy;
        use tsra_ddi_tbor_types::PolicyKeyKind;
        use tsra_ddi_tbor_types::PolicyPubKey;
        use tsra_ddi_tbor_types::TborAesGcmEncryptDecryptReq;
        use tsra_ddi_tbor_types::TborAesGcmEncryptDecryptResp;
        use tsra_ddi_tbor_types::TborAesGenerateKeyReq;
        use tsra_ddi_tbor_types::TborPartFinalReq;
        use tsra_ddi_tbor_types::TborPartInitReq;
        use tsra_ddi_tbor_types::TborResp;

        let _guard = crate::test_partition_lock();
        let hsm = crate::test_hsm();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
            let endpoint = format!("tcp://{}", listener.local_addr().expect("address"));
            let server = Arc::clone(&hsm);
            let serving = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept client");
                serve_connection(stream, server).await
            });
            let (prepared_tx, prepared_rx) = tokio::sync::oneshot::channel();
            let (submit_tx, submit_rx) = tokio::sync::oneshot::channel();
            let client_hsm = Arc::clone(&hsm);
            let client = tokio::task::spawn_blocking(move || {
                let device = DdiSock::default()
                    .open_dev(&endpoint)
                    .expect("client socket");
                device.erase().expect("initial reset");
                let (pending, exported) = open_init_with_exported(&device, 0);
                let finished = tbor(&device, &pending);
                let param_key = derive_param_key(&exported).expect("parameter key");
                let session = SessionHandshake {
                    session_id: pending.session_id,
                    psk_id: 0,
                    session_type: tsra_ddi_tbor_types::SessionType::Authenticated,
                    exported: exported.into(),
                    param_key,
                    bmk_session: finished.bmk_session,
                };
                tbor(
                    &device,
                    &TborPskChangeReq {
                        session_id: session.session_id,
                        psk_envelope: encrypt_psk_envelope(&session, &[0xA5; 32])
                            .expect("PSK envelope"),
                    },
                );
                let pota = PotaFixture::generate();
                let mut policy = PartPolicy::zeroed();
                policy.version.major = 1;
                policy.pota_pub_key = PolicyPubKey::new(PolicyKeyKind::Ecc384, 96, pota.raw_pub());
                policy.sata_pub_key = policy.pota_pub_key;
                let init = tbor(
                    &device,
                    &TborPartInitReq {
                        session_id: session.session_id,
                        mach_seed_envelope: encrypt_mach_seed_envelope(&session, &[0x5A; 32])
                            .expect("machine seed envelope"),
                        part_policy: policy.clone(),
                        pota_thumbprint: *pota.thumbprint(),
                        sata_thumbprint: [0x5A; 48],
                        ..Default::default()
                    },
                );
                let chain = pota.chain_for(&pta_pub_from_csr(&init.pta_csr));
                let certs = chain.der_items();
                let final_request = TborPartFinalReq {
                    session_id: session.session_id,
                    part_policy: policy,
                    cert_descriptors: certs
                        .iter()
                        .enumerate()
                        .map(|(index, cert)| CertDescriptor {
                            index: u8::try_from(index).expect("certificate index"),
                            length: u16::try_from(cert.len())
                                .expect("certificate length")
                                .into(),
                        })
                        .collect(),
                    ..Default::default()
                };
                device
                    .exec_op_tbor(&final_request, Some(&certs), &mut None)
                    .expect("finalize partition");
                let key = tbor(
                    &device,
                    &TborAesGenerateKeyReq {
                        session_id: session.session_id,
                        scope: 3,
                        key_size: tsra_ddi_tbor_types::AES_KEY_SIZE_256,
                        key_usage: tsra_ddi_tbor_types::KEY_USAGE_ENCRYPT
                            | tsra_ddi_tbor_types::KEY_USAGE_DECRYPT,
                        ..Default::default()
                    },
                );
                let request = TborAesGcmEncryptDecryptReq {
                    session_id: session.session_id,
                    op: tsra_ddi_tbor_types::AES_OP_ENCRYPT,
                    iv_source: tsra_ddi_tbor_types::GCM_IV_SOURCE_HOST,
                    aad_len: 0,
                    data_len: 16,
                    in_index: 0,
                    out_index: 1,
                    iv: vec![0x11; 12],
                    tag: vec![0; 16],
                    masked_key: key.masked_key,
                };
                let input = [0x42; 16];
                let mut output = [0; 16];
                let expected = device
                    .exec_op_tbor_oob(
                        &request,
                        &mut [TborOobItem::In(&input), TborOobItem::Out(&mut output)],
                        &mut None,
                    )
                    .expect("reference OOB encryption");
                assert_ne!(output, input);
                prepared_tx
                    .send((
                        expected,
                        output,
                        generation(&client_hsm, session.session_id),
                    ))
                    .expect("submission preparation");
                submit_rx.blocking_recv().expect("submit cancelled request");
                assert!(
                    device
                        .exec_op_tbor_oob(
                            &request,
                            &mut [TborOobItem::In(&input), TborOobItem::Out(&mut output)],
                            &mut None,
                        )
                        .is_err(),
                    "cancelled connection must not return the discarded response"
                );
            });

            let (expected, output, lease) =
                tokio::time::timeout(Duration::from_secs(30), prepared_rx)
                    .await
                    .expect("prepare OOB submission")
                    .expect("prepared client");
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
            let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
            *hsm.submission_probe.lock().await = Some(crate::SubmissionProbe {
                started: started_tx,
                resume: resume_rx,
                completed: completed_tx,
            });
            submit_tx.send(()).expect("start submission");
            tokio::time::timeout(Duration::from_secs(10), started_rx)
                .await
                .expect("submission reached DMA handoff")
                .expect("submission started");
            serving.abort();
            assert!(
                serving
                    .await
                    .expect_err("cancel connection waiter")
                    .is_cancelled()
            );
            assert!(
                lease.upgrade().is_some(),
                "cleanup must wait for firmware completion"
            );
            resume_tx.send(()).expect("allow firmware completion");
            let response = tokio::time::timeout(Duration::from_secs(10), completed_rx)
                .await
                .expect("firmware completes after cancellation")
                .expect("submission completion");
            assert_eq!(response.status, 0);
            let mut raw = crate::cqe_dwords(&response.cqe);
            assert_eq!(tsra_fw_hsm_io::Cqe::from(&mut raw).status(), 0);
            assert_eq!(
                TborAesGcmEncryptDecryptResp::decode_response(&response.payload)
                    .expect("DMA destination response"),
                expected
            );
            assert_eq!(response.oob_items, vec![output.to_vec()]);
            tokio::time::timeout(Duration::from_secs(10), async {
                while lease.upgrade().is_some() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("disconnect cleanup after completion");
            client.await.expect("disconnected client task");
        });
    }

    #[test]
    fn session_commands_reject_foreign_connection_ownership() {
        with_session_clients(|endpoint, _hsm| {
            let owner = DdiSock::default()
                .open_dev(&endpoint)
                .expect("owner socket");
            owner.erase().expect("initial reset");
            let pending = open_init(&owner, 0);
            let foreign = DdiSock::default()
                .open_dev(&endpoint)
                .expect("foreign socket");
            assert_not_owned(&foreign, &pending);
            tbor(&owner, &pending);
            assert_not_owned(
                &foreign,
                &TborPskChangeReq {
                    session_id: pending.session_id,
                    ..Default::default()
                },
            );
            assert_not_owned(
                &foreign,
                &TborSessionCloseReq {
                    session_id: pending.session_id,
                },
            );
            let delete = DdiDeleteKeyCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::DeleteKey,
                    rev: None,
                    sess_id: Some(pending.session_id),
                },
                data: DdiDeleteKeyReq { key_id: 0 },
                ext: None,
            };
            assert!(matches!(
                foreign.exec_op_mbor(&delete, &mut None),
                Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch
                ))
            ));
            let close = DdiCloseSessionCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::CloseSession,
                    rev: None,
                    sess_id: Some(pending.session_id),
                },
                data: DdiCloseSessionReq {},
                ext: None,
            };
            assert!(matches!(
                foreign.exec_op_mbor(&close, &mut None),
                Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch
                ))
            ));
            tbor(
                &owner,
                &TborSessionCloseReq {
                    session_id: pending.session_id,
                },
            );
        });
    }

    #[test]
    fn failed_finish_disconnect_flushes_already_destroyed_slot() {
        with_session_clients(|endpoint, hsm| {
            let owner = DdiSock::default()
                .open_dev(&endpoint)
                .expect("owner socket");
            owner.erase().expect("initial reset");
            let mut pending = open_init(&owner, 0);
            let lease = generation(&hsm, pending.session_id);
            pending.mac_fin[0] ^= 1;
            assert!(matches!(
                owner.exec_op_tbor(&pending, None, &mut None),
                Err(DdiError::TborStatus(status)) if status == TborStatus::SessionAuthFailure
            ));
            drop(owner);
            wait_for_cleanup(lease);
        });
    }

    #[test]
    fn one_connection_can_own_multiple_sessions() {
        with_session_clients(|endpoint, _hsm| {
            let owner = DdiSock::default()
                .open_dev(&endpoint)
                .expect("owner socket");
            owner.erase().expect("initial reset");
            let co = open_init(&owner, 0);
            tbor(&owner, &co);
            let cu = open_init(&owner, 1);
            tbor(&owner, &cu);
            assert_ne!(co.session_id, cu.session_id);
            for session_id in [co.session_id, cu.session_id] {
                tbor(&owner, &TborSessionCloseReq { session_id });
            }
        });
    }

    #[test]
    fn disconnected_pending_owner_cannot_close_reused_active_slot() {
        with_session_clients(|endpoint, hsm| {
            for reset in [false, true] {
                let first = DdiSock::default()
                    .open_dev(&endpoint)
                    .expect("first socket");
                first.erase().expect("initial reset");
                let pending = open_init(&first, 0);
                let first_generation = generation(&hsm, pending.session_id);
                let second = DdiSock::default()
                    .open_dev(&endpoint)
                    .expect("second socket");
                if reset {
                    second.erase().expect("reset discards pending slot");
                }
                let replacement = open_init(&second, 0);
                assert_eq!(replacement.session_id, pending.session_id);
                assert_not_owned(&first, &replacement);
                tbor(&second, &replacement);
                assert_not_owned(
                    &first,
                    &TborSessionCloseReq {
                        session_id: replacement.session_id,
                    },
                );

                drop(first);
                wait_for_cleanup(first_generation);
                tbor(
                    &second,
                    &TborSessionCloseReq {
                        session_id: replacement.session_id,
                    },
                );
            }
        });
    }

    #[test]
    fn replacement_bootstrap_waits_for_delayed_disconnect_cleanup() {
        with_session_clients(|endpoint, hsm| {
            let first = DdiSock::default()
                .open_dev(&endpoint)
                .expect("first socket");
            first.erase().expect("initial reset");
            let session = open_init(&first, 0);
            tbor(&first, &session);

            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
            *hsm.cleanup_probe.blocking_lock() = Some(crate::CleanupProbe {
                started: started_tx,
                resume: resume_rx,
            });
            drop(first);
            started_rx.blocking_recv().expect("cleanup is delayed");
            std::thread::scope(|scope| {
                let (reset_tx, reset_rx) = std::sync::mpsc::channel();
                let replacement = scope.spawn(move || {
                    let device = DdiSock::default()
                        .open_dev(&endpoint)
                        .expect("replacement socket");
                    device.erase().expect("replacement reset");
                    reset_tx.send(()).expect("reset notification");
                    let session = open_init(&device, 0);
                    tbor(&device, &session);
                    tbor(
                        &device,
                        &TborSessionCloseReq {
                            session_id: session.session_id,
                        },
                    );
                });
                let early_reset = reset_rx.recv_timeout(Duration::from_millis(100));
                resume_tx.send(()).expect("release disconnect cleanup");
                assert!(
                    matches!(early_reset, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
                    "replacement reset must not bypass delayed cleanup"
                );
                replacement.join().expect("replacement bootstrap");
            });
        });
    }

    #[test]
    fn reset_preserves_active_ownership_for_disconnect_cleanup() {
        with_session_clients(|endpoint, hsm| {
            let first = DdiSock::default()
                .open_dev(&endpoint)
                .expect("first socket");
            first.erase().expect("initial reset");
            let pending = open_init(&first, 0);
            tbor(&first, &pending);
            let first_generation = generation(&hsm, pending.session_id);
            let second = DdiSock::default()
                .open_dev(&endpoint)
                .expect("second socket");
            second.erase().expect("reset preserves renegotiation slot");

            drop(first);
            wait_for_cleanup(first_generation);
            let pending = open_init(&second, 0);
            tbor(&second, &pending);
            tbor(
                &second,
                &TborSessionCloseReq {
                    session_id: pending.session_id,
                },
            );
        });
    }

    #[test]
    fn serves_concurrent_connections_on_the_same_partition() {
        let _guard = crate::test_partition_lock();
        let hsm = crate::test_hsm();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
            let endpoint = format!("tcp://{}", listener.local_addr().expect("address"));
            let serving = tokio::spawn(run_server(listener, hsm));
            let clients = tokio::task::spawn_blocking(move || {
                std::thread::scope(|scope| {
                    let mut workers = Vec::new();
                    for _ in 0..4 {
                        let endpoint = &endpoint;
                        workers.push(scope.spawn(move || {
                            let device = DdiSock::default().open_dev(endpoint).expect("TCP device");
                            let request = DdiGetApiRevCmdReq {
                                hdr: DdiReqHdr {
                                    op: DdiOp::GetApiRev,
                                    rev: None,
                                    sess_id: None,
                                },
                                data: DdiGetApiRevReq {},
                                ext: None,
                            };
                            for _ in 0..3 {
                                let response =
                                    device.exec_op_mbor(&request, &mut None).expect("GetApiRev");
                                assert!(response.data.max.major >= response.data.min.major);
                            }
                        }));
                    }
                    for worker in workers {
                        worker.join().expect("worker");
                    }
                });
            });
            tokio::time::timeout(Duration::from_secs(30), clients)
                .await
                .expect("clients complete")
                .expect("client task");
            serving.abort();
        });
    }

    #[test]
    fn rejects_invalid_dma_and_oob_fields() {
        let _guard = crate::test_partition_lock();
        let hsm = crate::test_hsm();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            for (src_len, dst_cap, oob) in [
                (1, 4096, [0; 3]),
                (0, 0, [0; 3]),
                (0, 8193, [0; 3]),
                (0, 4096, [0x1000, 0, 16]),
            ] {
                let mut request = Request {
                    sqe: vec![0; 16],
                    payload: Vec::new(),
                    oob_items: Vec::new(),
                    tail: Vec::new(),
                };
                request.sqe[1] = src_len;
                request.sqe[6] = dst_cap;
                request.sqe[13..=15].copy_from_slice(&oob);
                let response = super::super::execute_request(&hsm, request).await;
                assert_eq!(response.status, super::super::TRANSPORT_INVALID_REQUEST);
                assert!(response.payload.is_empty());
            }
            for (count, oob_len) in [(1, 0), (1, 32), (65, 1040)] {
                let mut request = Request {
                    sqe: vec![0; 16],
                    payload: Vec::new(),
                    oob_items: vec![OobItem::In(vec![1]); count],
                    tail: Vec::new(),
                };
                request.sqe[0] = 2;
                request.sqe[6] = 4096;
                request.sqe[15] = oob_len;
                let response = super::super::execute_request(&hsm, request).await;
                assert_eq!(response.status, super::super::TRANSPORT_INVALID_REQUEST);
            }
        });
    }

    #[test]
    fn reset_waits_for_inflight_execution_and_survives_connection_cancellation() {
        let _guard = crate::test_partition_lock();
        let hsm = crate::test_hsm();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let active_submission = hsm.execution.read().await;
            let server = Arc::clone(&hsm);
            let connection = tokio::spawn(super::super::execute_frame(server, RequestFrame::Reset));
            tokio::time::timeout(Duration::from_secs(5), async {
                while hsm.execution.try_read().is_ok() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("reset is waiting on active submissions");
            assert!(!connection.is_finished());
            connection.abort();
            assert!(
                connection
                    .await
                    .expect_err("cancel connection")
                    .is_cancelled()
            );
            drop(active_submission);
            let completed = tokio::time::timeout(Duration::from_secs(10), hsm.execution.write())
                .await
                .expect("owned reset completes after connection cancellation");
            drop(completed);
            assert!(matches!(
                super::super::execute_frame(Arc::clone(&hsm), RequestFrame::Reset).await,
                ResponseFrame::Reset { status: 0 }
            ));
        });
    }

    #[test]
    fn idle_timeout_disconnects_one_client_but_preserves_an_active_peer() {
        let _guard = crate::test_partition_lock();
        let hsm = crate::test_hsm();
        // Pausing `Instant::now` requires `current_thread`; letting `sleep`
        // auto-advance through the idle deadline is what makes it practical
        // to actually let that deadline expire (rather than waiting out the
        // real 5-minute window) in a test.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("paused runtime");
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
            let endpoint = format!("tcp://{}", listener.local_addr().expect("address"));
            let serving = tokio::spawn(run_server(listener, Arc::clone(&hsm)));

            let idle_endpoint = endpoint.clone();
            let (idle_device, idle_session_id) = tokio::task::spawn_blocking(move || {
                let device = DdiSock::default()
                    .open_dev(&idle_endpoint)
                    .expect("idle device");
                device.erase().expect("initial reset");
                let session = open_init(&device, 0);
                tbor(&device, &session);
                (device, session.session_id)
            })
            .await
            .expect("idle session opened");

            let active_endpoint = endpoint.clone();
            let (mut active_device, active_session_id) = tokio::task::spawn_blocking(move || {
                let device = DdiSock::default()
                    .open_dev(&active_endpoint)
                    .expect("active device");
                // A distinct PSK ID (CryptoUser, slots 1..=7) so this session
                // doesn't contend with the idle connection's CO slot (0).
                let session = open_init(&device, 1);
                tbor(&device, &session);
                (device, session.session_id)
            })
            .await
            .expect("active session opened");

            assert!(hsm.sessions.read().await.contains_key(&idle_session_id));
            assert!(hsm.sessions.read().await.contains_key(&active_session_id));
            // `generation()` uses `blocking_read()`, which panics if called
            // directly on this (non-blocking-pool) async task, so read the
            // lock the ordinary async way instead.
            let idle_generation = Arc::downgrade(
                &hsm.sessions
                    .read()
                    .await
                    .get(&idle_session_id)
                    .expect("idle session owner")
                    .generation,
            );

            // Run most, but not all, of the idle window: neither connection
            // has gone idle long enough to be reclaimed yet.
            tokio::time::sleep(super::super::IDLE_WAIT_TIMEOUT - Duration::from_secs(1)).await;
            assert!(hsm.sessions.read().await.contains_key(&idle_session_id));
            assert!(hsm.sessions.read().await.contains_key(&active_session_id));

            // The "active" connection keeps talking, resetting its own
            // idle-wait deadline; the "idle" connection sends nothing further
            // from here on.
            active_device = tokio::task::spawn_blocking(move || {
                tbor(&active_device, &TborGetCertChainInfoReq::new(0));
                active_device
            })
            .await
            .expect("active connection stays busy");

            // Elapse most (but comfortably less than all) of a second idle
            // window. The idle connection's original deadline (never reset)
            // is now long past, while the active connection's deadline
            // (reset a moment ago) still has a healthy margin left, so only
            // the idle one must be reclaimed.
            tokio::time::sleep(super::super::IDLE_WAIT_TIMEOUT / 2).await;

            // Disconnect cleanup runs on a task spawned from `Connection`'s
            // `Drop`, so it may not have completed the instant the idle
            // deadline elapses. `wait_for_cleanup` polls with real
            // `std::time::Instant`/`std::thread::sleep`, not tokio's paused
            // clock, so run it inside `spawn_blocking`: that both lets it
            // observe genuine real-world progress and inhibits the paused
            // clock's auto-advance while it does. A busy-poll driven by
            // `tokio::task::yield_now` instead would race the auto-advance
            // heuristic and can overshoot straight past the active
            // connection's own (later) deadline.
            tokio::task::spawn_blocking(move || wait_for_cleanup(idle_generation))
                .await
                .expect("idle connection's session is cleaned up");
            assert!(
                !hsm.sessions.read().await.contains_key(&idle_session_id),
                "an idle connection's session must be cleaned up once its deadline elapses"
            );
            assert!(
                hsm.sessions.read().await.contains_key(&active_session_id),
                "a separate, actively used connection's session must not be affected"
            );

            // The surviving session must still be fully usable, not merely
            // present in the ownership map.
            tokio::task::spawn_blocking(move || {
                tbor(&active_device, &TborGetCertChainInfoReq::new(0));
            })
            .await
            .expect("active session still usable after the peer's idle disconnect");

            drop(idle_device);
            serving.abort();
        });
    }
}
