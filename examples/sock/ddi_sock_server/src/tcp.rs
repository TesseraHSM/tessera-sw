// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use std::io;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tsra_ddi_sock_proto::MAX_FRAME;
use tsra_ddi_sock_proto::ProtoError;
use tsra_ddi_sock_proto::RequestFrame;
use tsra_ddi_sock_proto::ResponseFrame;

use super::Connection;
use super::SocketHsm;

async fn read_request(stream: &mut TcpStream) -> Result<RequestFrame, ProtoError> {
    let length = stream.read_u32_le().await?;
    if length > MAX_FRAME {
        return Err(ProtoError::TooLarge(length));
    }
    let mut body = vec![0; length as usize];
    stream.read_exact(&mut body).await?;
    RequestFrame::decode(&body)
}

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
        let request = match read_request(&mut stream).await {
            Ok(request) => request,
            Err(ProtoError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(format!("failed to read DDI request: {error}")),
        };
        let response = connection.execute(request).await?;
        write_response(&mut stream, &response)
            .await
            .map_err(|error| format!("failed to write DDI response: {error}"))?;
    }
}

async fn run_server(listener: TcpListener, hsm: Arc<SocketHsm>) -> Result<(), String> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept TCP connection: {error}"))?;
        stream
            .set_nodelay(true)
            .map_err(|error| format!("failed to configure TCP connection: {error}"))?;
        let hsm = Arc::clone(&hsm);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, hsm).await {
                eprintln!("TCP client {peer} failed: {error}");
            }
        });
    }
}

pub(super) fn run(address: &str) -> Result<(), String> {
    let listener = std::net::TcpListener::bind(address)
        .map_err(|error| format!("failed to bind TCP listener at {address}: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("failed to configure TCP listener: {error}"))?;
    let bound_address = listener
        .local_addr()
        .map_err(|error| format!("failed to query TCP listener address: {error}"))?;
    if !bound_address.ip().is_loopback() {
        eprintln!("Warning: this unauthenticated test server is listening outside loopback");
    }
    super::run_with_hsm(|hsm| async move {
        let listener = TcpListener::from_std(listener)
            .map_err(|error| format!("failed to register TCP listener: {error}"))?;
        super::init_partition(&hsm).await?;
        println!("TSRA DDI server listening on tcp://{bound_address}; partition 10");
        run_server(listener, hsm).await
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Weak;
    use std::time::Duration;
    use std::time::Instant;

    use tsra_crypto::EccPublicKey;
    use tsra_crypto::ImportableKey;
    use tsra_ddi_interface::Ddi;
    use tsra_ddi_interface::DdiDev;
    use tsra_ddi_interface::DdiError;
    use tsra_ddi_mbor_types::*;
    use tsra_ddi_sock::DdiSock;
    use tsra_ddi_sock::DdiSockDev;
    use tsra_ddi_sock_proto::Request;
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
        TborSessionOpenFinishReq {
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
        }
    }

    fn with_session_clients(test: impl FnOnce(String, Arc<SocketHsm>) + Send + 'static) {
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
            let clients = tokio::task::spawn_blocking(move || test(endpoint, hsm));
            tokio::time::timeout(Duration::from_secs(30), clients)
                .await
                .expect("session clients complete")
                .expect("session client task");
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
                    sqe: [0; 16],
                    payload: Vec::new(),
                    oob_items: Vec::new(),
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
                    sqe: [0; 16],
                    payload: Vec::new(),
                    oob_items: vec![vec![1]; count],
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
}
