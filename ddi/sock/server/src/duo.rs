// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Duo (API revision 2.x) submissions: 128 B SQE / 64 B CQE carrying plain
//! TBOR, session-encrypted TBOR or a session flush. There is no bulk queue.
//!
//! Session ownership is tracked from the plain `SessionOpenInit` response,
//! the only one that reveals a session ID. Secure close is encrypted, so a
//! closed session stays leased until its owner flushes it, disconnects
//! (flush is idempotent) or another connection opens the reused slot.

use std::sync::Arc;

use tsra_ddi_sock_proto::Request;
use tsra_ddi_sock_proto::RequestFrame;
use tsra_ddi_sock_proto::Response;
use tsra_ddi_sock_proto::ResponseFrame;
use tsra_ddi_sock_proto::TRANSPORT_SESSION_NOT_OWNED;
use tsra_ddi_tbor_types::TBOR_OP_SESSION_OPEN_INIT;
use tsra_ddi_tbor_types::TborResp;
use tsra_ddi_tbor_types::TborSessionOpenInitResp;
use tsra_ddi_tbor_types::codec::RequestView;
use tsra_fw_hsm_io::duo::DuoCmdDword;
use tsra_fw_hsm_io::duo::DuoCqeDw15;
use tsra_fw_hsm_io::duo::DuoOp;
use tsra_fw_hsm_io::duo::DuoRawSqe;
use tsra_fw_hsm_io::duo::DuoSqe;
use tsra_fw_hsm_io::duo::DuoSqeBuilder;
use tsra_fw_hsm_std_duo::StdHsm as DuoHsm;

use super::*;

/// CQE dword holding the destination length written.
const CQE_DST_LEN: usize = 11;

/// CQE dword holding the completion status ([`DuoCqeDw15`]).
const CQE_STATUS: usize = 15;

/// Whether both the transport and the device reported success.
fn succeeded(response: &Response) -> bool {
    response.status == 0
        && response
            .cqe
            .get(CQE_STATUS)
            .is_some_and(|&dw| DuoCqeDw15::from(dw).status() == 0)
}

fn rejected(status: u32) -> ResponseFrame {
    ResponseFrame::Submit(transport_error(status))
}

/// Runs a Duo submission for a connection, enforcing and recording session
/// ownership.
pub(super) async fn execute_submission(
    server: Arc<SocketHsm>,
    state: &mut ConnectionState,
    request: RequestFrame,
) -> ResponseFrame {
    let RequestFrame::Submit(submission) = &request else {
        return execute_frame(server, request).await;
    };
    let Ok(sqe) = <&DuoRawSqe>::try_from(submission.sqe.as_slice()) else {
        return rejected(TRANSPORT_INVALID_REQUEST);
    };
    let sqe = DuoSqe::from(sqe);
    let session_id = sqe.session_id();
    let open_init = RequestView::parse(&submission.payload)
        .is_ok_and(|view| view.opcode() == TBOR_OP_SESSION_OPEN_INIT);
    match sqe.op() {
        // The session's GCM keys already bind secure traffic to its owner;
        // this just fails foreign IDs early, like Uno.
        Ok(DuoOp::TborSecure) => {
            let sessions = server.sessions.read().await;
            if !state.owns_session(session_id, &sessions) {
                return rejected(TRANSPORT_SESSION_NOT_OWNED);
            }
            // Keep the allocation pinned until firmware completes.
            let response = execute_frame(Arc::clone(&server), request).await;
            drop(sessions);
            response
        }
        Ok(DuoOp::FlushSession) => {
            let mut sessions = server.sessions.write().await;
            if !state.owns_session(session_id, &sessions) {
                return rejected(TRANSPORT_SESSION_NOT_OWNED);
            }
            let response = execute_frame(Arc::clone(&server), request).await;
            if let ResponseFrame::Submit(response) = &response
                && succeeded(response)
            {
                sessions.remove(&session_id);
                state.sessions.retain(|session| session.id != session_id);
            }
            response
        }
        Ok(DuoOp::Tbor) if open_init => {
            // Serialize slot allocation with ownership publication.
            let mut sessions = server.sessions.write().await;
            let response = execute_frame(Arc::clone(&server), request).await;
            if let ResponseFrame::Submit(response) = &response
                && succeeded(response)
                && let Ok(init) = TborSessionOpenInitResp::decode_response(&response.payload)
            {
                // A reused slot moves to this connection; the previous
                // owner's lease goes stale.
                let id = init.session_id;
                let generation = Arc::new(());
                sessions.insert(
                    id,
                    SessionOwner {
                        generation: Arc::clone(&generation),
                        state: SessionState::Active,
                    },
                );
                state.sessions.retain(|session| session.id != id);
                state.sessions.push(SessionLease { id, generation });
            }
            response
        }
        _ => execute_frame(server, request).await,
    }
}

/// Flushes a disconnected client's session. The caller holds the ownership
/// write lock.
pub(super) async fn close_session(server: Arc<SocketHsm>, id: u16) -> Result<(), String> {
    let sqe = DuoSqeBuilder::new()
        .cmd(DuoCmdDword::new().with_op(DuoOp::FlushSession as u8))
        .session_id(id)
        .build();
    let response = execute_frame(
        server,
        RequestFrame::Submit(Request {
            sqe: sqe.to_vec(),
            payload: Vec::new(),
            oob_items: Vec::new(),
            tail: Vec::new(),
        }),
    )
    .await;
    match response {
        ResponseFrame::Submit(response) if succeeded(&response) => Ok(()),
        ResponseFrame::Submit(response) => Err(format!(
            "disconnect session flush failed: transport={}, device={}",
            response.status,
            response
                .cqe
                .get(CQE_STATUS)
                .map_or(0, |&dw| DuoCqeDw15::from(dw).status())
        )),
        ResponseFrame::Reset { .. } | ResponseFrame::Discover(_) => {
            Err("unexpected disconnect session-flush response".into())
        }
    }
}

/// Re-homes a Duo SQE's buffers into server memory and submits it. Client
/// buffer addresses must be zero.
pub(super) async fn execute(server: &SocketHsm, hsm: &DuoHsm, request: Request) -> Response {
    let Ok(mut sqe) = <DuoRawSqe>::try_from(request.sqe.as_slice()) else {
        return transport_error(TRANSPORT_INVALID_REQUEST);
    };
    let (src_len, dst_cap, oob_len) = {
        let view = DuoSqe::from(&sqe);
        (
            view.src_len() as usize,
            view.dst_len() as usize,
            view.oob_len(),
        )
    };
    if sqe[2..4].iter().any(|&word| word != 0)
        || sqe[7..11].iter().any(|&word| word != 0)
        || sqe[12..16].iter().any(|&word| word != 0)
        || !oob_items_valid(&request.oob_items, oob_len)
        || src_len != request.payload.len()
        || src_len > DMA_BUF_SIZE
        || dst_cap > DMA_BUF_SIZE
    {
        return transport_error(TRANSPORT_INVALID_REQUEST);
    }

    let mut staged = Staged::new(&request.payload, request.oob_items);
    patch_prp1(&mut sqe, 7, staged.src_addr(0));
    patch_prp1(&mut sqe, 12, staged.dst_addr(0));
    if src_len > DMA_PAGE_SIZE {
        patch_prp1(&mut sqe, 9, staged.src_addr(DMA_PAGE_SIZE));
    }
    if dst_cap > DMA_PAGE_SIZE {
        patch_prp1(&mut sqe, 14, staged.dst_addr(DMA_PAGE_SIZE));
    }
    if let Some(page) = staged.oob_page_addr() {
        patch_prp1(&mut sqe, 2, page);
    }

    let _execution = server.execution.read().await;
    let cqe = match hsm.io(sqe, HSM_PARTITION_ID, 0, 0).await {
        Ok(cqe) => cqe,
        Err(error) => {
            tracing::error!(?error, "StdHsm Duo request failed");
            return transport_error(TRANSPORT_HSM_ERROR);
        }
    };
    let dst_len = cqe[CQE_DST_LEN] as usize;
    if dst_len > dst_cap {
        return transport_error(TRANSPORT_HSM_ERROR);
    }
    staged.into_response(cqe.to_vec(), dst_len)
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborApiRevReq;
    use tsra_ddi_tbor_types::TborApiRevResp;
    use tsra_ddi_tbor_types::TborOpReq;
    use tsra_ddi_tbor_types::TborSessionOpenInitReq;
    use tsra_session_ex_crypto::SessionInitiator;
    use tsra_session_ex_crypto::SessionSuite;

    use super::*;
    use crate::test_duo_hsm as duo_hsm;

    fn run(test: impl std::future::Future<Output = ()>) {
        // Partition setup blocks on its own runtime, so it must run first.
        duo_hsm();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(test);
    }

    fn sqe(op: DuoOp, session_id: u16, src_len: usize) -> Vec<u32> {
        DuoSqeBuilder::new()
            .cmd(DuoCmdDword::new().with_op(op as u8))
            .session_id(session_id)
            .buf_lens(src_len as u32, MAX_DMA_BUFFER)
            .build()
            .to_vec()
    }

    fn tbor(op: DuoOp, session_id: u16, request: &impl TborOpReq) -> RequestFrame {
        let mut buf = [0u8; 1024];
        let payload = request.encode_request(&mut buf).expect("encode").to_vec();
        RequestFrame::Submit(Request {
            sqe: sqe(op, session_id, payload.len()),
            payload,
            oob_items: Vec::new(),
            tail: Vec::new(),
        })
    }

    fn flush(session_id: u16) -> RequestFrame {
        RequestFrame::Submit(Request {
            sqe: sqe(DuoOp::FlushSession, session_id, 0),
            payload: Vec::new(),
            oob_items: Vec::new(),
            tail: Vec::new(),
        })
    }

    async fn submit(connection: &Connection, request: RequestFrame) -> Response {
        match connection.execute(request).await.expect("execute") {
            ResponseFrame::Submit(response) => response,
            other => panic!("unexpected response {other:?}"),
        }
    }

    async fn open_init(connection: &Connection) -> u16 {
        let request = TborSessionOpenInitReq {
            psk_id: 0,
            pk_init: SessionInitiator::generate(SessionSuite::EcdhP384)
                .expect("ephemeral")
                .pk_init()
                .to_vec(),
            ..Default::default()
        };
        let response = submit(connection, tbor(DuoOp::Tbor, 0, &request)).await;
        assert!(succeeded(&response));
        TborSessionOpenInitResp::decode_response(&response.payload)
            .expect("open_init response")
            .session_id
    }

    #[test]
    fn api_rev_reports_duo_range() {
        run(async {
            let connection = Connection::new(duo_hsm());
            let response = submit(&connection, tbor(DuoOp::Tbor, 0, &TborApiRevReq)).await;
            assert!(succeeded(&response));
            assert_eq!(response.cqe.len(), 16);
            let rev = TborApiRevResp::decode_response(&response.payload).expect("ApiRev");
            assert_eq!((rev.min_major.get(), rev.max_major.get()), (2, 2));
        });
    }

    #[test]
    fn sessions_are_owned_by_the_opening_connection() {
        run(async {
            let owner = Connection::new(duo_hsm());
            let other = Connection::new(duo_hsm());
            let id = open_init(&owner).await;

            let secure = tbor(DuoOp::TborSecure, id, &TborApiRevReq);
            assert_eq!(
                submit(&other, secure).await.status,
                TRANSPORT_SESSION_NOT_OWNED
            );
            assert_eq!(
                submit(&other, flush(id)).await.status,
                TRANSPORT_SESSION_NOT_OWNED
            );

            assert!(succeeded(&submit(&owner, flush(id)).await));
            // The flush released the lease.
            assert_eq!(
                submit(&owner, flush(id)).await.status,
                TRANSPORT_SESSION_NOT_OWNED
            );
        });
    }

    #[test]
    fn client_buffer_addresses_are_rejected() {
        run(async {
            let connection = Connection::new(duo_hsm());
            let RequestFrame::Submit(mut request) = tbor(DuoOp::Tbor, 0, &TborApiRevReq) else {
                unreachable!()
            };
            request.sqe[7] = 0x1000;
            let response = submit(&connection, RequestFrame::Submit(request)).await;
            assert_eq!(response.status, TRANSPORT_INVALID_REQUEST);
        });
    }
}
