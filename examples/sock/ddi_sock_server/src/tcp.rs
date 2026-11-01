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
    use std::time::Duration;

    use tsra_ddi_interface::Ddi;
    use tsra_ddi_interface::DdiDev;
    use tsra_ddi_mbor_types::*;
    use tsra_ddi_sock::DdiSock;
    use tsra_ddi_sock_proto::Request;

    use super::*;

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
                (0, 4097, [0; 3]),
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
