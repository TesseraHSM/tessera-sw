// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TCP, Unix domain socket, and Linux VSOCK server backed by an in-process
//! HSM emulator.
//!
//! Run `cargo run -p ddi_sock_server -- tcp://127.0.0.1:1234` on Windows or Linux.
//! Without arguments, Windows uses TCP loopback and Linux uses VSOCK port 1234.
//! All connections share partition 10. Linux VSOCK clients connect to
//! `vsock://CID:1234`, where CID is the server guest's VSOCK context ID.
//! On Unix-like platforms, `unix://PATH` listens on an AF_UNIX stream socket
//! at `PATH` (the file is removed and recreated if it already exists).
//! This unauthenticated test transport is for trusted, isolated environments;
//! it is not a production service. Emulator state is lost when the server exits.
//! OOB bytes are re-homed into server-owned SGL descriptors, and bulk
//! (fast-path AES-GCM/XTS) buffers into server-owned SGL data. Sideband reset
//! disables and re-enables this endpoint's partition, coordinated across all
//! connections. Independent root/leaf instances need separate server processes.

#[cfg(feature = "test-args")]
mod test_args;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[cfg(feature = "test-args")]
pub use test_args::TEST_ARGS_ENV;
#[cfg(feature = "test-args")]
pub use test_args::TestArgs;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tsra_ddi_mbor_types::DdiDecoder;
use tsra_ddi_mbor_types::DdiOp;
use tsra_ddi_mbor_types::DdiReopenSessionResp;
use tsra_ddi_mbor_types::DdiReqHdr;
use tsra_ddi_mbor_types::DdiRespHdr;
use tsra_ddi_mbor_types::DdiStatus;
use tsra_ddi_sock_proto::MAX_DMA_BUFFER;
use tsra_ddi_sock_proto::MAX_FRAME;
use tsra_ddi_sock_proto::MAX_OOB_ITEM;
use tsra_ddi_sock_proto::MAX_OOB_ITEMS;
use tsra_ddi_sock_proto::OobItem;
use tsra_ddi_sock_proto::Request;
use tsra_ddi_sock_proto::RequestFrame;
use tsra_ddi_sock_proto::Response;
use tsra_ddi_sock_proto::ResponseFrame;
use tsra_ddi_sock_proto::TRANSPORT_SESSION_NEEDS_RENEGOTIATION;
use tsra_ddi_sock_proto::TRANSPORT_SESSION_NOT_OWNED;
use tsra_ddi_tbor_types::SessionControlKind;
use tsra_ddi_tbor_types::TBOR_OP_SESSION_OPEN_FINISH;
use tsra_ddi_tbor_types::TborResp;
use tsra_ddi_tbor_types::TborSessionOpenFinishResp;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::codec::RequestView;
use tsra_fw_hsm_bulk::BLOCK_LEN;
use tsra_fw_hsm_bulk::BULK_SQE_DWORDS;
use tsra_fw_hsm_bulk::BulkCqe;
use tsra_fw_hsm_bulk::BulkParams;
use tsra_fw_hsm_bulk::BulkSqe;
use tsra_fw_hsm_bulk::RawBulkSqe;
use tsra_fw_hsm_io::CmdDword;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::CqeDw0;
use tsra_fw_hsm_io::CqeDw1;
use tsra_fw_hsm_io::OP_FLUSH;
use tsra_fw_hsm_io::OP_MBOR;
use tsra_fw_hsm_io::OP_TBOR;
use tsra_fw_hsm_io::SessionFlags;
use tsra_fw_hsm_io::SqeBuilder;
use tsra_fw_hsm_std::StdHsm;

// This crate's own unit tests build their own `StdHsm`, so they never
// autostart one.
#[cfg(all(feature = "autostart", not(test)))]
mod autostart;
#[cfg(all(feature = "autostart", not(test)))]
pub use autostart::autostarted;
mod tcp;
#[cfg(unix)]
mod unix;

pub use tcp::spawn_loopback;

const HSM_PARTITION_ID: u8 = 10;
const HSM_BULK_QID: u16 = 1;
const DMA_PAGE_SIZE: usize = 4096;
const DMA_BUF_SIZE: usize = MAX_DMA_BUFFER as usize;
const TRANSPORT_INVALID_REQUEST: u32 = 1;
const TRANSPORT_HSM_ERROR: u32 = 2;

/// Upper bound on how long a connection may sit idle before the *next*
/// request frame's length prefix starts arriving. A healthy client
/// reasonably leaves a connection idle between commands, so this is
/// intentionally far more generous than [`CONNECTION_READ_TIMEOUT`] -
/// every backend here serves connections concurrently, so this timeout
/// exists only to reclaim resources (the spawned task, and any
/// sessions this connection owns) from a client that vanished without
/// closing its socket (e.g. a network partition), not to protect other
/// clients' fairness.
const IDLE_WAIT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Upper bound on how long it may take to complete an already-started
/// frame: reading the rest of its body, executing it, and writing the
/// response. Kept far tighter than [`IDLE_WAIT_TIMEOUT`] so a peer that
/// starts a frame and then stalls or slow-drips it cannot hold the
/// connection (and any sessions it owns) open indefinitely.
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Reads one [`RequestFrame`] from `stream`, honoring the idle/active
/// timeout split: only the wait for the length prefix's *first* byte
/// uses [`IDLE_WAIT_TIMEOUT`] — once that byte has arrived the peer is
/// mid-request, not idle, so every remaining read (the rest of the
/// prefix, then the body) uses the tighter [`CONNECTION_READ_TIMEOUT`].
/// Applying the idle timeout to the whole 4-byte prefix would let a
/// client that sends one byte and then stalls hold the connection (and
/// any sessions it owns) open for the full idle window instead of the
/// advertised active timeout. Returns `Ok(None)` for every condition
/// that should be treated as a clean disconnect: an idle-wait timeout,
/// clean EOF, or a stall once a frame has started arriving.
async fn read_request_with_timeout<S>(stream: &mut S) -> Result<Option<RequestFrame>, String>
where
    S: AsyncRead + Unpin,
{
    let mut length_buf = [0u8; 4];
    match tokio::time::timeout(IDLE_WAIT_TIMEOUT, stream.read_exact(&mut length_buf[..1])).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(Err(error)) => return Err(format!("failed to read DDI request length: {error}")),
        Err(_elapsed) => return Ok(None),
    }
    match tokio::time::timeout(
        CONNECTION_READ_TIMEOUT,
        stream.read_exact(&mut length_buf[1..]),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(Err(error)) => return Err(format!("failed to read DDI request length: {error}")),
        Err(_elapsed) => return Ok(None),
    }
    let length = u32::from_le_bytes(length_buf);
    if length > MAX_FRAME {
        return Err(format!("request frame too large: {length}"));
    }
    let mut body = vec![0; length as usize];
    match tokio::time::timeout(CONNECTION_READ_TIMEOUT, stream.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(Err(error)) => return Err(format!("failed to read DDI request body: {error}")),
        Err(_elapsed) => return Ok(None),
    }
    RequestFrame::decode(&body)
        .map(Some)
        .map_err(|error| format!("failed to decode DDI request: {error}"))
}

#[repr(align(4096))]
struct DmaBuf<const N: usize>([u8; N]);

struct SocketHsm {
    hsm: Arc<StdHsm>,
    execution: tokio::sync::RwLock<()>,
    sessions: tokio::sync::RwLock<HashMap<u16, SessionOwner>>,
    pending_cleanups: AtomicUsize,
    cleanup_completed: tokio::sync::Notify,
    #[cfg(test)]
    submission_probe: tokio::sync::Mutex<Option<SubmissionProbe>>,
    #[cfg(test)]
    cleanup_probe: tokio::sync::Mutex<Option<CleanupProbe>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Pending,
    Active,
    NeedsRenegotiation,
}

struct SessionOwner {
    generation: Arc<()>,
    state: SessionState,
}

#[cfg(test)]
struct SubmissionProbe {
    started: tokio::sync::oneshot::Sender<()>,
    resume: tokio::sync::oneshot::Receiver<()>,
    completed: tokio::sync::oneshot::Sender<Response>,
}

#[cfg(test)]
struct CleanupProbe {
    started: tokio::sync::oneshot::Sender<()>,
    resume: tokio::sync::oneshot::Receiver<()>,
}

struct SessionLease {
    id: u16,
    generation: Arc<()>,
}

impl SessionLease {
    fn is_current(&self, sessions: &HashMap<u16, SessionOwner>) -> bool {
        sessions
            .get(&self.id)
            .is_some_and(|owner| Arc::ptr_eq(&owner.generation, &self.generation))
    }
}

impl SocketHsm {
    fn new(hsm: Arc<StdHsm>) -> Self {
        Self {
            hsm,
            execution: tokio::sync::RwLock::new(()),
            sessions: tokio::sync::RwLock::new(HashMap::new()),
            pending_cleanups: AtomicUsize::new(0),
            cleanup_completed: tokio::sync::Notify::new(),
            #[cfg(test)]
            submission_probe: tokio::sync::Mutex::new(None),
            #[cfg(test)]
            cleanup_probe: tokio::sync::Mutex::new(None),
        }
    }

    async fn wait_for_cleanup(&self) {
        loop {
            let completed = self.cleanup_completed.notified();
            tokio::pin!(completed);
            completed.as_mut().enable();
            if self.pending_cleanups.load(Ordering::Acquire) == 0 {
                return;
            }
            completed.await;
        }
    }
}

struct CleanupCompletion(Arc<SocketHsm>);

impl Drop for CleanupCompletion {
    fn drop(&mut self) {
        if self.0.pending_cleanups.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.cleanup_completed.notify_waiters();
        }
    }
}

struct Connection {
    server: Arc<SocketHsm>,
    state: Arc<tokio::sync::Mutex<ConnectionState>>,
}

#[derive(Default)]
struct ConnectionState {
    sessions: Vec<SessionLease>,
    closed: bool,
}

impl ConnectionState {
    fn owns_session(&self, id: u16, sessions: &HashMap<u16, SessionOwner>) -> bool {
        self.sessions
            .iter()
            .any(|session| session.id == id && session.is_current(sessions))
    }
}

impl Connection {
    fn new(server: Arc<SocketHsm>) -> Self {
        Self {
            server,
            state: Arc::new(tokio::sync::Mutex::new(ConnectionState::default())),
        }
    }

    async fn execute(&self, request: RequestFrame) -> Result<ResponseFrame, String> {
        let server = Arc::clone(&self.server);
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            server.wait_for_cleanup().await;
            // Disconnect cleanup must wait for any in-flight open/close to
            // complete and record its CQE, even if its waiter was cancelled.
            let mut state = state.lock().await;
            if state.closed {
                return Err("connection closed before submission".into());
            }
            let RequestFrame::Submit(submission) = &request else {
                return Ok(execute_frame(server, request).await);
            };
            if submission.sqe.len() == BULK_SQE_DWORDS {
                // Partition-scoped bulk keys do not validate session state in
                // firmware, so ownership alone is insufficient here.
                let session_id = BulkSqe::parse(&submission.sqe).map(|sqe| sqe.session_id);
                let sessions = server.sessions.read().await;
                if let Ok(id) = session_id {
                    let session_state = state
                        .owns_session(id, &sessions)
                        .then(|| sessions.get(&id).map(|owner| owner.state))
                        .flatten();
                    let rejection = match session_state {
                        Some(SessionState::Active) => None,
                        // Report a reset-invalidated session like firmware
                        // would, so clients renegotiate and retry.
                        Some(SessionState::NeedsRenegotiation) => {
                            Some(TRANSPORT_SESSION_NEEDS_RENEGOTIATION)
                        }
                        _ => Some(TRANSPORT_SESSION_NOT_OWNED),
                    };
                    if let Some(status) = rejection {
                        return Ok(ResponseFrame::Submit(transport_error(status)));
                    }
                }
                let response = execute_frame(Arc::clone(&server), request).await;
                drop(sessions);
                return Ok(response);
            }
            let op = CmdDword::from(submission.sqe[0]).op();
            let session_flags = SessionFlags::from(submission.sqe[11]);
            let session_id = submission.sqe[12] as u16;
            let session_ctrl = session_flags.ctrl();
            let scoped = session_ctrl == u8::from(SessionControlKind::InSession)
                || session_ctrl == u8::from(SessionControlKind::Close);
            if scoped && !session_flags.id_valid() {
                return Ok(ResponseFrame::Submit(transport_error(
                    TRANSPORT_INVALID_REQUEST,
                )));
            }
            let finish = op == OP_TBOR
                && RequestView::parse(&submission.payload)
                    .is_ok_and(|view| view.opcode() == TBOR_OP_SESSION_OPEN_FINISH);
            let reopen = op == OP_MBOR
                && DdiDecoder::new(&submission.payload, false)
                    .decode_hdr::<DdiReqHdr>()
                    .is_ok_and(|hdr| hdr.op == DdiOp::ReopenSession);
            let lifecycle = session_ctrl == u8::from(SessionControlKind::Open)
                || session_ctrl == u8::from(SessionControlKind::Close)
                || op == OP_FLUSH
                || finish
                || reopen;
            if !lifecycle {
                if !scoped {
                    return Ok(execute_frame(server, request).await);
                }
                let sessions = server.sessions.read().await;
                if !state.owns_session(session_id, &sessions) {
                    return Ok(ResponseFrame::Submit(transport_error(
                        TRANSPORT_SESSION_NOT_OWNED,
                    )));
                }
                // Keep this allocation pinned until firmware completes without
                // serializing ordinary commands on other connections.
                let response = execute_frame(Arc::clone(&server), request).await;
                drop(sessions);
                return Ok(response);
            }
            // Serialize slot mutations through firmware completion and ownership
            // publication; ordinary in-session commands can still run concurrently.
            let mut sessions = server.sessions.write().await;
            if (scoped || reopen) && !state.owns_session(session_id, &sessions) {
                return Ok(ResponseFrame::Submit(transport_error(
                    TRANSPORT_SESSION_NOT_OWNED,
                )));
            }
            let response = execute_frame(Arc::clone(&server), request).await;
            if let ResponseFrame::Submit(response) = &response {
                let mut raw = cqe_dwords(&response.cqe);
                let cqe = Cqe::from(&mut raw);
                let flags = CqeDw0::from(response.cqe[0]);
                if response.status == 0 && cqe.status() == 0 && flags.session_id_valid() && !reopen
                {
                    let id = CqeDw1::from(response.cqe[1]).session_id();
                    if flags.session_closed() {
                        sessions.remove(&id);
                        state.sessions.retain(|session| session.id != id);
                    } else {
                        // Allocation identity is independent of the reusable slot ID.
                        let generation = Arc::new(());
                        sessions.insert(
                            id,
                            SessionOwner {
                                generation: Arc::clone(&generation),
                                state: if op == OP_TBOR {
                                    SessionState::Pending
                                } else {
                                    SessionState::Active
                                },
                            },
                        );
                        state.sessions.retain(|session| session.id != id);
                        state.sessions.push(SessionLease { id, generation });
                    }
                }
                if response.status == 0 && cqe.status() == 0 && reopen {
                    // Reopen re-keys an existing slot without publishing a CQE
                    // session ID. Only its successful MBOR body reactivates the lease.
                    let mut decoder = DdiDecoder::new(&response.payload, false);
                    if decoder.decode_hdr::<DdiRespHdr>().is_ok_and(|hdr| {
                        hdr.op == DdiOp::ReopenSession
                            && hdr.status == DdiStatus::Success
                            && hdr.sess_id == Some(session_id)
                    }) && decoder
                        .decode_data::<DdiReopenSessionResp>()
                        .is_ok_and(|data| data.sess_id == session_id)
                        && let Some(owner) = sessions.get_mut(&session_id)
                    {
                        owner.state = SessionState::Active;
                    }
                }
                if response.status == 0
                    && cqe.status() == 0
                    && finish
                    && TborSessionOpenFinishResp::decode_response(&response.payload).is_ok()
                    && let Some(owner) = sessions.get_mut(&session_id)
                {
                    owner.state = SessionState::Active;
                } else if response.status == 0
                    && finish
                    && matches!(
                        TborSessionOpenFinishResp::decode_response(&response.payload),
                        Err(tsra_ddi_tbor_types::codec::DecodeError::FwError(status))
                            if status == TborStatus::SessionAuthFailure.0
                    )
                    && sessions
                        .get(&session_id)
                        .is_some_and(|owner| owner.state == SessionState::Pending)
                {
                    sessions.remove(&session_id);
                    state.sessions.retain(|session| session.id != session_id);
                }
            }
            Ok(response)
        })
        .await
        .map_err(|error| format!("connection execution task failed: {error}"))?
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let server = Arc::clone(&self.server);
        let state = Arc::clone(&self.state);
        // Register synchronously: replacement requests must observe cleanup
        // even before the spawned task first runs.
        server.pending_cleanups.fetch_add(1, Ordering::AcqRel);
        let completion = CleanupCompletion(Arc::clone(&server));
        tokio::spawn(async move {
            let _completion = completion;
            #[cfg(test)]
            if let Some(probe) = server.cleanup_probe.lock().await.take() {
                probe.started.send(()).expect("cleanup probe listener");
                probe.resume.await.expect("cleanup probe resume");
            }
            let mut state = state.lock().await;
            state.closed = true;
            let mut sessions = server.sessions.write().await;
            for session in state.sessions.drain(..) {
                if !session.is_current(&sessions) {
                    continue;
                }
                // Keep the ownership check atomic with the firmware close so
                // another connection cannot replace this slot between them.
                match close_session(Arc::clone(&server), session.id).await {
                    Ok(()) => {
                        sessions.remove(&session.id);
                    }
                    Err(error) => {
                        tracing::error!(%error, "Disconnected client session cleanup failed");
                    }
                }
            }
        });
    }
}

async fn close_session(server: Arc<SocketHsm>, id: u16) -> Result<(), String> {
    // Driver-style flush is idempotent if a failed handshake already
    // destroyed its Pending slot. Caller holds the ownership write lock.
    let sqe = SqeBuilder::new()
        .cmd(CmdDword::new().with_op(OP_FLUSH))
        .buf_lens(0, MAX_DMA_BUFFER)
        .session_flags(
            SessionFlags::new()
                .with_ctrl(u8::from(SessionControlKind::Close))
                .with_id_valid(true),
        )
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
    let ResponseFrame::Submit(response) = response else {
        return Err("unexpected disconnect session-close response".into());
    };
    let mut raw = cqe_dwords(&response.cqe);
    let cqe = Cqe::from(&mut raw);
    if response.status != 0 || cqe.status() != 0 {
        return Err(format!(
            "disconnect session-close failed: transport={}, device={}",
            response.status,
            cqe.status()
        ));
    }
    Ok(())
}

fn patch_prp1(sqe: &mut [u32; 16], low_dword: usize, address: u64) {
    sqe[low_dword] = address as u32;
    sqe[low_dword + 1] = (address >> 32) as u32;
}

/// Copies a normal-queue CQE out of a response; transport errors carry zeros.
fn cqe_dwords(cqe: &[u32]) -> [u32; 4] {
    cqe.try_into().unwrap_or_default()
}

fn transport_error(status: u32) -> Response {
    Response {
        status,
        cqe: vec![0; 4],
        payload: Vec::new(),
        oob_items: Vec::new(),
        tail: Vec::new(),
    }
}

async fn execute_request(server: &SocketHsm, request: Request) -> Response {
    match <RawBulkSqe>::try_from(request.sqe.as_slice()) {
        Ok(sqe) => execute_bulk(server, sqe, request).await,
        Err(_) => execute_normal(server, request).await,
    }
}

/// Runs a fast-path AES-GCM/XTS request. Client buffer addresses in the SQE
/// are placeholders and are replaced with server-owned buffers.
async fn execute_bulk(server: &SocketHsm, raw: RawBulkSqe, request: Request) -> Response {
    let mut sqe = match BulkSqe::parse(&raw) {
        Ok(sqe) => sqe,
        Err(error) => {
            return Response {
                status: 0,
                cqe: BulkCqe::error(&raw, HSM_BULK_QID, error).encode().to_vec(),
                payload: Vec::new(),
                oob_items: Vec::new(),
                tail: Vec::new(),
            };
        }
    };
    let tail_len = match &sqe.params {
        BulkParams::Gcm(gcm) => gcm.tail.map_or(0, |tail| usize::from(tail.len)),
        BulkParams::Xts(_) => 0,
    };
    if !request.oob_items.is_empty()
        || request.payload.len() != sqe.src_len as usize
        || request.tail.len() != tail_len
    {
        return transport_error(TRANSPORT_INVALID_REQUEST);
    }

    let src = request.payload;
    let mut dst = vec![0u8; sqe.dst_len as usize];
    let mut tail = [0u8; BLOCK_LEN as usize];
    tail[..tail_len].copy_from_slice(&request.tail);
    sqe.src_addr = src.as_ptr() as u64;
    sqe.dst_addr = dst.as_mut_ptr() as u64;
    if let BulkParams::Gcm(gcm) = &mut sqe.params
        && let Some(gcm_tail) = &mut gcm.tail
    {
        // Firmware reads the tail input and writes its output in place.
        gcm_tail.src = tail.as_mut_ptr() as u64;
        gcm_tail.dst = gcm_tail.src;
    }

    let _execution = server.execution.read().await;
    let cqe = match server
        .hsm
        .bulk_io(sqe.encode(), HSM_PARTITION_ID, HSM_BULK_QID, 0)
        .await
    {
        Ok(cqe) => cqe,
        Err(error) => {
            tracing::error!(?error, "StdHsm bulk request failed");
            return transport_error(TRANSPORT_HSM_ERROR);
        }
    };
    drop(src);
    Response {
        status: 0,
        cqe: cqe.to_vec(),
        payload: dst,
        oob_items: Vec::new(),
        tail: tail[..tail_len].to_vec(),
    }
}

async fn execute_normal(server: &SocketHsm, request: Request) -> Response {
    let Ok(mut sqe) = <[u32; 16]>::try_from(request.sqe.as_slice()) else {
        return transport_error(TRANSPORT_INVALID_REQUEST);
    };
    let src_len = sqe[1] as usize;
    let dst_cap = sqe[6] as usize;
    if sqe[2..6].iter().any(|&word| word != 0)
        || sqe[7..11].iter().any(|&word| word != 0)
        || sqe[13..15].iter().any(|&word| word != 0)
        || request.oob_items.len() > MAX_OOB_ITEMS
        || request
            .oob_items
            .iter()
            .any(|item| item.is_empty() || item.len() > MAX_OOB_ITEM as usize)
        || sqe[15] as usize != request.oob_items.len() * 16
        || (!request.oob_items.is_empty() && sqe[0] & 0x3ff != 2)
        || src_len != request.payload.len()
        || src_len > DMA_BUF_SIZE
        || dst_cap == 0
        || dst_cap > DMA_BUF_SIZE
    {
        return transport_error(TRANSPORT_INVALID_REQUEST);
    }

    let mut src = Box::new(DmaBuf([0; DMA_BUF_SIZE]));
    let mut dst = Box::new(DmaBuf([0; DMA_BUF_SIZE]));
    let mut oob_page = Box::new(DmaBuf([0; DMA_PAGE_SIZE]));
    src.0[..src_len].copy_from_slice(&request.payload);
    let mut oob: Vec<(bool, Vec<u8>)> = request
        .oob_items
        .into_iter()
        .map(|item| match item {
            OobItem::In(bytes) => (false, bytes),
            OobItem::Out(len) => (true, vec![0; len as usize]),
        })
        .collect();
    for (index, (_, item)) in oob.iter_mut().enumerate() {
        let off = index * 16;
        oob_page.0[off..off + 8].copy_from_slice(&(item.as_mut_ptr() as u64).to_le_bytes());
        oob_page.0[off + 8..off + 12].copy_from_slice(&(item.len() as u32).to_le_bytes());
    }

    patch_prp1(&mut sqe, 2, src.0.as_ptr() as u64);
    patch_prp1(&mut sqe, 7, dst.0.as_mut_ptr() as u64);
    if src_len > DMA_PAGE_SIZE {
        patch_prp1(&mut sqe, 4, src.0[DMA_PAGE_SIZE..].as_ptr() as u64);
    }
    if dst_cap > DMA_PAGE_SIZE {
        patch_prp1(&mut sqe, 9, dst.0[DMA_PAGE_SIZE..].as_mut_ptr() as u64);
    }
    if !oob.is_empty() {
        patch_prp1(&mut sqe, 13, oob_page.0.as_ptr() as u64);
    }

    let _execution = server.execution.read().await;
    #[cfg(test)]
    let completion = if let Some(probe) = server.submission_probe.lock().await.take() {
        probe.started.send(()).expect("submission observer");
        probe.resume.await.expect("resume submission");
        Some(probe.completed)
    } else {
        None
    };
    let cqe = match server.hsm.io(sqe, HSM_PARTITION_ID, 0, 0).await {
        Ok(cqe) => cqe,
        Err(error) => {
            tracing::error!(?error, "StdHsm request failed");
            return transport_error(TRANSPORT_HSM_ERROR);
        }
    };
    let dst_len = (cqe[0] & 0xffff) as usize;
    if dst_len > dst_cap {
        return transport_error(TRANSPORT_HSM_ERROR);
    }

    let response = Response {
        status: 0,
        cqe: cqe.to_vec(),
        payload: dst.0[..dst_len].to_vec(),
        oob_items: oob
            .into_iter()
            .filter_map(|(out, item)| out.then_some(item))
            .collect(),
        tail: Vec::new(),
    };
    #[cfg(test)]
    if let Some(completion) = completion {
        completion
            .send(response.clone())
            .expect("submission completion observer");
    }
    response
}

async fn execute_frame(server: Arc<SocketHsm>, request: RequestFrame) -> ResponseFrame {
    let reset = matches!(&request, RequestFrame::Reset);
    // Own every DMA buffer and the execution gate until firmware completes,
    // even if the connection task is cancelled while awaiting this task.
    match tokio::spawn(async move {
        match request {
            RequestFrame::Submit(request) => {
                ResponseFrame::Submit(execute_request(&server, request).await)
            }
            RequestFrame::Reset => {
                let mut sessions = server.sessions.write().await;
                let _execution = server.execution.write().await;
                let result = async {
                    server.hsm.part_disable(HSM_PARTITION_ID).await?;
                    // NSSR discards Pending slots but preserves Active slots
                    // for renegotiation, including their connection ownership.
                    sessions.retain(|_, owner| owner.state != SessionState::Pending);
                    for owner in sessions.values_mut() {
                        owner.state = SessionState::NeedsRenegotiation;
                    }
                    server.hsm.part_enable(HSM_PARTITION_ID).await
                }
                .await;
                let status = match result {
                    Ok(()) => 0,
                    Err(error) => {
                        tracing::error!(?error, "StdHsm reset failed");
                        TRANSPORT_HSM_ERROR
                    }
                };
                ResponseFrame::Reset { status }
            }
        }
    })
    .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "StdHsm execution task failed");
            if reset {
                ResponseFrame::Reset {
                    status: TRANSPORT_HSM_ERROR,
                }
            } else {
                ResponseFrame::Submit(transport_error(TRANSPORT_HSM_ERROR))
            }
        }
    }
}

/// Number of resource bits the std platform accepts in a partition mask.
const MAX_RESOURCES: u32 = 65;

/// Sets `count` contiguous resource bits starting at [`HSM_PARTITION_ID`],
/// wrapping at [`MAX_RESOURCES`], so a count of 1 yields `1 << 10`.
fn part_res_mask(count: u32) -> u128 {
    (0..count).fold(0u128, |mask, i| {
        mask | 1u128 << ((HSM_PARTITION_ID as u32 + i) % MAX_RESOURCES)
    })
}

/// How many vault tables (resources) the served partition is allocated:
/// the `resource_count` key of `TSRA_TEST_ARGS` (`1..=MAX_RESOURCES`) with
/// the `test-args` feature, otherwise 1.
fn resource_count() -> Result<u32, String> {
    #[cfg(feature = "test-args")]
    if let Some(count) = TestArgs::from_env().resource_count {
        return if (1..=MAX_RESOURCES).contains(&count) {
            Ok(count)
        } else {
            Err(format!(
                "TSRA_TEST_ARGS resource_count={count} must be 1..={MAX_RESOURCES}"
            ))
        };
    }
    Ok(1)
}

async fn init_partition(server: &SocketHsm) -> Result<(), String> {
    server
        .hsm
        .part_alloc(HSM_PARTITION_ID, part_res_mask(resource_count()?))
        .await
        .map_err(|error| format!("failed to allocate HSM partition: {error:?}"))?;
    server
        .hsm
        .part_enable(HSM_PARTITION_ID)
        .await
        .map_err(|error| format!("failed to enable HSM partition: {error:?}"))
}

fn run_with_hsm<F>(serve: impl FnOnce(Arc<SocketHsm>) -> F) -> Result<(), String>
where
    F: std::future::Future<Output = Result<(), String>>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("failed to create Tokio runtime: {error}"))?;
    // The Embassy executor is process-global and its destructor cannot terminate
    // it. Retain an owner until process exit so errors can reach main without
    // hanging in StdHsm::drop.
    static HSM: std::sync::OnceLock<Arc<SocketHsm>> = std::sync::OnceLock::new();
    let hsm = HSM.get_or_init(|| {
        Arc::new(SocketHsm::new(Arc::new(StdHsm::with_tokio(
            runtime.handle().clone(),
        ))))
    });
    runtime.block_on(serve(Arc::clone(hsm)))
}

#[cfg(test)]
fn test_partition_lock() -> parking_lot::MutexGuard<'static, ()> {
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    LOCK.lock()
}

#[cfg(test)]
fn test_hsm() -> Arc<SocketHsm> {
    static HSM: std::sync::LazyLock<Arc<SocketHsm>> =
        std::sync::LazyLock::new(|| Arc::new(SocketHsm::new(Arc::new(StdHsm::new()))));
    static PARTITION: std::sync::LazyLock<()> = std::sync::LazyLock::new(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("partition setup runtime");
        runtime
            .block_on(init_partition(&HSM))
            .expect("partition setup");
    });
    std::sync::LazyLock::force(&PARTITION);
    Arc::clone(&HSM)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::raw::c_int;
    use std::sync::Arc;

    use tokio::io::unix::AsyncFd;
    use tsra_ddi_sock_proto::MAX_FRAME;
    use tsra_ddi_sock_proto::ProtoError;
    #[cfg(test)]
    use tsra_ddi_sock_proto::Request;
    use tsra_ddi_sock_proto::RequestFrame;
    #[cfg(test)]
    use tsra_ddi_sock_proto::Response;
    use tsra_ddi_sock_proto::ResponseFrame;

    use super::Connection;
    #[cfg(test)]
    use super::DMA_BUF_SIZE;
    #[cfg(test)]
    use super::DMA_PAGE_SIZE;
    use super::SocketHsm;
    #[cfg(test)]
    use super::TRANSPORT_INVALID_REQUEST;

    const AF_VSOCK: c_int = 40;
    const SOCK_STREAM: c_int = 1;
    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0x800;
    const VMADDR_CID_ANY: u32 = u32::MAX;
    const VSOCK_PORT: u32 = 1234;

    #[repr(C)]
    struct SockAddrVm {
        family: u16,
        reserved: u16,
        port: u32,
        cid: u32,
        zero: [u8; 4],
    }

    struct Socket {
        fd: c_int,
    }

    impl Socket {
        fn new_nonblocking(fd: c_int) -> io::Result<Self> {
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let socket = Self { fd };
            let flags = sys::fcntl_get_flags(fd);
            if flags < 0 || sys::fcntl_set_flags(fd, flags | O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(socket)
        }

        #[allow(unsafe_code)]
        fn into_async_fd(self) -> io::Result<AsyncFd<Self>> {
            // SAFETY: Socket owns its descriptor, never replaces it, and closes it only on drop.
            unsafe { AsyncFd::register(self) }.map_err(Into::into)
        }

        fn accept(&self) -> io::Result<Self> {
            Self::new_nonblocking(sys::accept(self.fd))
        }

        fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
            let received = sys::read(self.fd, buffer);
            if received < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(received as usize)
            }
        }

        fn write(&self, buffer: &[u8]) -> io::Result<usize> {
            let written = sys::write(self.fd, buffer);
            if written < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(written as usize)
            }
        }
    }

    impl AsRawFd for Socket {
        fn as_raw_fd(&self) -> c_int {
            self.fd
        }
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            sys::close(self.fd);
        }
    }

    #[allow(unsafe_code)]
    mod sys {
        use std::os::raw::c_int;
        use std::os::raw::c_void;

        use super::SockAddrVm;

        pub fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int {
            // SAFETY: The arguments are plain integers and socket reports errors through its return value.
            unsafe { c_socket(domain, socket_type, protocol) }
        }

        pub fn bind(socket: c_int, address: &SockAddrVm) -> c_int {
            // SAFETY: address points to a valid C-compatible SockAddrVm for the duration of the call.
            unsafe { c_bind(socket, address, std::mem::size_of::<SockAddrVm>() as u32) }
        }

        pub fn listen(socket: c_int, backlog: c_int) -> c_int {
            // SAFETY: The arguments are plain integers and listen reports errors through its return value.
            unsafe { c_listen(socket, backlog) }
        }

        pub fn accept(socket: c_int) -> c_int {
            // SAFETY: Null address pointers are permitted when the peer address is not requested.
            unsafe { c_accept(socket, std::ptr::null_mut(), std::ptr::null_mut()) }
        }

        pub fn read(fd: c_int, buffer: &mut [u8]) -> isize {
            // SAFETY: The mutable slice supplies a valid writable buffer of the provided length.
            unsafe { c_read(fd, buffer.as_mut_ptr().cast(), buffer.len()) }
        }

        pub fn write(fd: c_int, buffer: &[u8]) -> isize {
            // SAFETY: The slice supplies a valid readable buffer of the provided length.
            unsafe { c_write(fd, buffer.as_ptr().cast(), buffer.len()) }
        }

        pub fn fcntl_get_flags(fd: c_int) -> c_int {
            // SAFETY: F_GETFL takes no variadic argument and reports invalid descriptors as errors.
            unsafe { c_fcntl(fd, super::F_GETFL) }
        }

        pub fn fcntl_set_flags(fd: c_int, flags: c_int) -> c_int {
            // SAFETY: F_SETFL requires one integer variadic argument, supplied here as flags.
            unsafe { c_fcntl(fd, super::F_SETFL, flags) }
        }

        pub fn close(fd: c_int) {
            // SAFETY: close accepts any integer descriptor and reports invalid descriptors as errors.
            unsafe {
                c_close(fd);
            }
        }

        unsafe extern "C" {
            #[link_name = "socket"]
            fn c_socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
            #[link_name = "bind"]
            fn c_bind(socket: c_int, address: *const SockAddrVm, address_len: u32) -> c_int;
            #[link_name = "listen"]
            fn c_listen(socket: c_int, backlog: c_int) -> c_int;
            #[link_name = "accept"]
            fn c_accept(socket: c_int, address: *mut c_void, address_len: *mut u32) -> c_int;
            #[link_name = "read"]
            fn c_read(fd: c_int, buffer: *mut c_void, count: usize) -> isize;
            #[link_name = "write"]
            fn c_write(fd: c_int, buffer: *const c_void, count: usize) -> isize;
            #[link_name = "fcntl"]
            fn c_fcntl(fd: c_int, command: c_int, ...) -> c_int;
            #[link_name = "close"]
            fn c_close(fd: c_int) -> c_int;
        }
    }

    async fn read_exact(stream: &AsyncFd<Socket>, mut buffer: &mut [u8]) -> io::Result<()> {
        while !buffer.is_empty() {
            let mut ready = stream.readable().await?;
            match ready.try_io(|inner| inner.get_ref().read(buffer)) {
                Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(Ok(count)) => buffer = &mut buffer[count..],
                Ok(Err(error)) => return Err(error),
                Err(_) => {}
            }
        }
        Ok(())
    }

    async fn write_all(stream: &AsyncFd<Socket>, mut buffer: &[u8]) -> io::Result<()> {
        while !buffer.is_empty() {
            let mut ready = stream.writable().await?;
            match ready.try_io(|inner| inner.get_ref().write(buffer)) {
                Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(Ok(count)) => buffer = &buffer[count..],
                Ok(Err(error)) => return Err(error),
                Err(_) => {}
            }
        }
        Ok(())
    }

    async fn read_request(stream: &AsyncFd<Socket>) -> Result<Option<RequestFrame>, String> {
        // Only the wait for the first prefix byte uses the generous idle
        // timeout; once it arrives the peer is mid-request, not idle, so
        // the rest of the prefix (and the body) uses the tighter active
        // timeout. See `read_request_with_timeout` for why.
        let mut length = [0; 4];
        match tokio::time::timeout(
            super::IDLE_WAIT_TIMEOUT,
            read_exact(stream, &mut length[..1]),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Ok(Err(error)) => return Err(format!("failed to read DDI request length: {error}")),
            Err(_elapsed) => return Ok(None),
        }
        match tokio::time::timeout(
            super::CONNECTION_READ_TIMEOUT,
            read_exact(stream, &mut length[1..]),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Ok(Err(error)) => return Err(format!("failed to read DDI request length: {error}")),
            Err(_elapsed) => return Ok(None),
        }
        let length = u32::from_le_bytes(length);
        if length > MAX_FRAME {
            return Err(format!("request frame too large: {length}"));
        }
        let mut body = vec![0; length as usize];
        match tokio::time::timeout(
            super::CONNECTION_READ_TIMEOUT,
            read_exact(stream, &mut body),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Ok(Err(error)) => return Err(format!("failed to read DDI request body: {error}")),
            Err(_elapsed) => return Ok(None),
        }
        RequestFrame::decode(&body)
            .map(Some)
            .map_err(|error| format!("failed to decode DDI request: {error}"))
    }

    async fn write_response(
        stream: &AsyncFd<Socket>,
        response: &ResponseFrame,
    ) -> Result<(), ProtoError> {
        let body = response.encode()?;
        write_all(stream, &(body.len() as u32).to_le_bytes()).await?;
        write_all(stream, &body).await?;
        Ok(())
    }

    async fn serve_connection(stream: AsyncFd<Socket>, hsm: Arc<SocketHsm>) -> Result<(), String> {
        let connection = Connection::new(hsm);
        loop {
            let Some(request) = read_request(&stream).await? else {
                return Ok(());
            };
            let response = match tokio::time::timeout(
                super::CONNECTION_READ_TIMEOUT,
                connection.execute(request),
            )
            .await
            {
                Ok(result) => result?,
                Err(_elapsed) => return Ok(()),
            };
            match tokio::time::timeout(
                super::CONNECTION_READ_TIMEOUT,
                write_response(&stream, &response),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(format!("failed to write DDI response: {error}")),
                Err(_elapsed) => return Ok(()),
            }
        }
    }

    fn bind_listener() -> Result<Socket, String> {
        let listener = Socket::new_nonblocking(sys::socket(AF_VSOCK, SOCK_STREAM, 0))
            .map_err(|error| format!("failed to create vsock listener: {error}"))?;
        let address = SockAddrVm {
            family: AF_VSOCK as u16,
            reserved: 0,
            port: VSOCK_PORT,
            cid: VMADDR_CID_ANY,
            zero: [0; 4],
        };
        if sys::bind(listener.fd, &address) < 0 {
            return Err(format!(
                "failed to bind vsock listener: {}",
                io::Error::last_os_error()
            ));
        }
        if sys::listen(listener.fd, 16) < 0 {
            return Err(format!(
                "failed to listen on vsock: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(listener)
    }

    async fn run_server(
        hsm: Arc<SocketHsm>,
        listener: Socket,
        on_listening: impl FnOnce(&super::Listening),
    ) -> Result<(), String> {
        let listener = listener
            .into_async_fd()
            .map_err(|error| format!("failed to register vsock listener: {error}"))?;
        super::init_partition(&hsm).await?;

        on_listening(&super::Listening::new(format!("vsock://*:{VSOCK_PORT}")));
        loop {
            let stream = loop {
                let mut ready = listener
                    .readable()
                    .await
                    .map_err(|error| format!("failed to poll vsock listener: {error}"))?;
                match ready.try_io(|inner| inner.get_ref().accept()) {
                    Ok(Ok(stream)) => break stream,
                    Ok(Err(error)) => return Err(format!("failed to accept connection: {error}")),
                    Err(_) => {}
                }
            };
            let stream = stream
                .into_async_fd()
                .map_err(|error| format!("failed to register vsock connection: {error}"))?;
            let hsm = Arc::clone(&hsm);
            tokio::spawn(async move {
                if let Err(error) = serve_connection(stream, hsm).await {
                    tracing::warn!(%error, "VSOCK client connection failed");
                }
            });
        }
    }

    pub(super) fn run(on_listening: impl FnOnce(&super::Listening)) -> Result<(), String> {
        run_with_listener(bind_listener()?, on_listening)
    }

    fn run_with_listener(
        listener: Socket,
        on_listening: impl FnOnce(&super::Listening),
    ) -> Result<(), String> {
        super::run_with_hsm(|hsm| run_server(hsm, listener, on_listening))
    }

    #[cfg(test)]
    mod tests {
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        use tsra_ddi_mbor_types::*;

        use super::*;

        #[test]
        fn server_errors_return_after_hsm_startup() {
            const CHILD_ENV: &str = "TSRA_TEST_SOCKET_SERVER_ERROR_CHILD";
            if std::env::var_os(CHILD_ENV).is_none() {
                let mut child =
                    std::process::Command::new(std::env::current_exe().expect("test binary"))
                        .args([
                            "--exact",
                            "linux::tests::server_errors_return_after_hsm_startup",
                        ])
                        .env(CHILD_ENV, "1")
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .expect("run child test");
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                loop {
                    if let Some(status) = child.try_wait().expect("child status") {
                        assert!(status.success(), "server error child failed: {status}");
                        return;
                    }
                    if std::time::Instant::now() >= deadline {
                        child.kill().expect("stop hung child");
                        child.wait().expect("reap child");
                        panic!("server error path hung after HSM startup");
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }

            let (socket, peer) = UnixStream::pair().expect("socket pair");
            drop(peer);
            // A readable socket that is not a listener forces accept to fail
            // after partition setup, without requiring VSOCK support.
            let listener = Socket::new_nonblocking(socket.into_raw_fd()).expect("test socket");
            let error = run_with_listener(listener, |_| {}).expect_err("accept must fail");
            assert!(error.starts_with("failed to accept connection:"), "{error}");
        }

        #[test]
        fn serves_repeated_requests_after_invalid_dma_and_oob_fields() {
            let _guard = crate::test_partition_lock();
            let hsm = crate::test_hsm();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let (mut client, server) = UnixStream::pair().expect("socket pair");
                client
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .expect("read timeout");
                client
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .expect("write timeout");
                let server = Socket::new_nonblocking(server.into_raw_fd()).expect("server socket");
                let server = server.into_async_fd().expect("async server");
                let serving = tokio::spawn(serve_connection(server, hsm));

                tokio::task::spawn_blocking(move || {
                    let mut payload = vec![0; DMA_PAGE_SIZE];
                    let len = DdiEncoder::encode_parts(
                        DdiReqHdr {
                            op: DdiOp::GetApiRev,
                            rev: None,
                            sess_id: None,
                        },
                        DdiGetApiRevReq {},
                        &mut payload,
                        false,
                    )
                    .expect("encode GetApiRev");
                    payload.truncate(len);
                    let mut request = Request {
                        sqe: vec![0; 16],
                        payload,
                        oob_items: Vec::new(),
                        tail: Vec::new(),
                    };
                    request.sqe[1] = len as u32;
                    request.sqe[6] = DMA_PAGE_SIZE as u32;

                    for (src_len, dst_cap) in
                        [(len + 1, DMA_PAGE_SIZE), (len, 0), (len, DMA_BUF_SIZE + 1)]
                    {
                        request.sqe[1] = src_len as u32;
                        request.sqe[6] = dst_cap as u32;
                        request.write_to(&mut client).expect("send invalid request");
                        let response = Response::read_from(&mut client).expect("error response");
                        assert_eq!(response.status, TRANSPORT_INVALID_REQUEST);
                        assert!(response.payload.is_empty());
                    }

                    request.sqe[1] = len as u32;
                    request.sqe[6] = DMA_PAGE_SIZE as u32;
                    for oob in [[0x1000, 0, 16], [0x1000, 0, 0], [0, 1, 0], [0, 0, 16]] {
                        request.sqe[13..=15].copy_from_slice(&oob);
                        request.write_to(&mut client).expect("send unsupported OOB");
                        let response = Response::read_from(&mut client).expect("OOB rejection");
                        assert_eq!(response.status, TRANSPORT_INVALID_REQUEST);
                        assert!(response.payload.is_empty());
                    }
                    request.sqe[13..=15].fill(0);
                    for id in 1..=3 {
                        request.sqe[0] = id << 16;
                        request.write_to(&mut client).expect("send GetApiRev");
                        let response =
                            Response::read_from(&mut client).expect("GetApiRev response");
                        assert_eq!(response.status, 0);
                        assert_eq!(response.cqe[3] & 0xffff, id);
                        assert_eq!((response.cqe[3] >> 17) & 0x7ff, 0);
                        assert_eq!((response.cqe[0] & 0xffff) as usize, response.payload.len());
                        let mut decoder = DdiDecoder::new(&response.payload, false);
                        let header: DdiRespHdr = decoder.decode_hdr().expect("response header");
                        assert_eq!(header.op, DdiOp::GetApiRev);
                        assert_eq!(header.status, DdiStatus::Success);
                        let revision: DdiGetApiRevResp =
                            decoder.decode_data().expect("API revision");
                        assert!(revision.max.major >= revision.min.major);
                    }
                })
                .await
                .expect("client task");
                tokio::time::timeout(Duration::from_secs(10), serving)
                    .await
                    .expect("server observes disconnect")
                    .expect("server task")
                    .expect("clean disconnect");
            });
        }
    }
}

/// A server that is ready for clients, reported to the callback of [`run`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listening {
    /// Endpoint clients connect to, e.g. `tcp://127.0.0.1:1234`.
    pub endpoint: String,
    /// HSM partition served to every connection.
    pub partition: u8,
}

impl Listening {
    fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            partition: HSM_PARTITION_ID,
        }
    }
}

impl std::fmt::Display for Listening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; partition {}", self.endpoint, self.partition)
    }
}

/// Run the server using the endpoint from the command line, calling
/// `on_listening` once it accepts clients.
pub fn run(on_listening: impl FnOnce(&Listening)) -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| {
        if cfg!(target_os = "linux") {
            "vsock://*:1234".to_owned()
        } else {
            "tcp://127.0.0.1:1234".to_owned()
        }
    });
    if args.next().is_some() {
        return Err(
            "usage: ddi_sock_server [tcp://HOST:PORT | unix://PATH | vsock://*:1234]".into(),
        );
    }
    if let Some(address) = endpoint.strip_prefix("tcp://") {
        tcp::run(address, on_listening)
    } else if let Some(path) = endpoint.strip_prefix("unix://") {
        #[cfg(unix)]
        {
            unix::run(path, on_listening)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err("unix:// requires a Unix-like platform; use tcp://127.0.0.1:1234".into())
        }
    } else if endpoint == "vsock://*:1234" {
        #[cfg(target_os = "linux")]
        {
            linux::run(on_listening)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("VSOCK requires Linux; use tcp://127.0.0.1:1234 on Windows".into())
        }
    } else {
        Err(
            "unsupported listener endpoint; use tcp://HOST:PORT, unix://PATH, or vsock://*:1234"
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[test]
    fn part_res_mask_starts_at_partition_and_wraps() {
        assert_eq!(part_res_mask(1), 1u128 << HSM_PARTITION_ID);
        assert_eq!(part_res_mask(4), 0b1111u128 << HSM_PARTITION_ID);
        let all = part_res_mask(MAX_RESOURCES);
        assert_eq!(all.count_ones(), MAX_RESOURCES);
        assert_eq!(all >> MAX_RESOURCES, 0);
    }

    #[test]
    fn shared_test_hsm_initializes_partition_once() {
        let _guard = test_partition_lock();
        let hsm = test_hsm();
        let worker = std::thread::spawn(test_hsm);
        let other = worker.join().expect("fixture worker");
        assert!(Arc::ptr_eq(&hsm, &other));
    }

    /// Builds a paused-time, single-threaded runtime: pausing `Instant::now`
    /// requires `current_thread`, and letting a `sleep` auto-advance through
    /// the idle/active deadlines (rather than real wall-clock time) is what
    /// makes it practical to actually let those deadlines expire in a test.
    fn paused_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("paused runtime")
    }

    #[test]
    fn read_request_with_timeout_disconnects_an_idle_connection() {
        paused_runtime().block_on(async {
            let (mut server, _client) = tokio::io::duplex(64);
            let read = tokio::spawn(async move { read_request_with_timeout(&mut server).await });
            // Nothing is ever written: the idle-wait deadline must elapse and
            // be treated as a clean disconnect, not an error.
            tokio::time::sleep(IDLE_WAIT_TIMEOUT).await;
            let frame = read.await.expect("read task").expect("no I/O error");
            assert!(
                frame.is_none(),
                "an idle connection must be treated as a clean disconnect"
            );
        });
    }

    #[test]
    fn read_request_with_timeout_disconnects_a_stalled_mid_frame_connection() {
        paused_runtime().block_on(async {
            let (mut server, mut client) = tokio::io::duplex(64);
            let read = tokio::spawn(async move { read_request_with_timeout(&mut server).await });
            // Send only the frame length prefix's first byte: once it
            // arrives the peer is mid-request (no longer idle), so the rest
            // of the read must be bound by the tighter active timeout, not
            // the far more generous idle one.
            client
                .write_all(&[0])
                .await
                .expect("write first length byte");
            tokio::time::sleep(CONNECTION_READ_TIMEOUT).await;
            let frame = read.await.expect("read task").expect("no I/O error");
            assert!(
                frame.is_none(),
                "a stalled mid-frame peer must be disconnected once the active timeout elapses"
            );
        });
    }
}
