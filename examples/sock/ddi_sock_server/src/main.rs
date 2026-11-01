// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TCP and Linux VSOCK server backed by an in-process HSM emulator.
//!
//! Run `cargo run -p ddi_sock_server -- tcp://127.0.0.1:1234` on Windows or Linux.
//! Without arguments, Windows uses TCP loopback and Linux uses VSOCK port 1234.
//! All connections share partition 10. Linux VSOCK clients connect to
//! `vsock://CID:1234`, where CID is the server guest's VSOCK context ID.
//! This unauthenticated test transport is for trusted, isolated environments;
//! it is not a production service. Emulator state is lost when the server exits.
//! OOB bytes are re-homed into server-owned SGL descriptors. Sideband reset
//! disables and re-enables this endpoint's partition, coordinated across all
//! connections. Independent root/leaf instances need separate server processes.

use std::sync::Arc;

use tsra_ddi_sock_proto::MAX_OOB_ITEM;
use tsra_ddi_sock_proto::MAX_OOB_ITEMS;
use tsra_ddi_sock_proto::Request;
use tsra_ddi_sock_proto::RequestFrame;
use tsra_ddi_sock_proto::Response;
use tsra_ddi_sock_proto::ResponseFrame;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::TborResp;
use tsra_ddi_tbor_types::TborSessionCloseReq;
use tsra_ddi_tbor_types::TborSessionCloseResp;
use tsra_fw_hsm_io::CmdDword;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::CqeDw0;
use tsra_fw_hsm_io::CqeDw1;
use tsra_fw_hsm_io::OP_TBOR;
use tsra_fw_hsm_io::SessionFlags;
use tsra_fw_hsm_io::SqeBuilder;
use tsra_fw_hsm_std::StdHsm;

mod tcp;

const HSM_PARTITION_ID: u8 = 10;
const DMA_PAGE_SIZE: usize = 4096;
const TRANSPORT_INVALID_REQUEST: u32 = 1;
const TRANSPORT_HSM_ERROR: u32 = 2;

#[repr(align(4096))]
struct DmaPage([u8; DMA_PAGE_SIZE]);

struct SocketHsm {
    hsm: Arc<StdHsm>,
    execution: tokio::sync::RwLock<()>,
}

impl SocketHsm {
    fn new(hsm: Arc<StdHsm>) -> Self {
        Self {
            hsm,
            execution: tokio::sync::RwLock::new(()),
        }
    }
}

struct Connection {
    server: Arc<SocketHsm>,
    state: Arc<tokio::sync::Mutex<ConnectionState>>,
}

#[derive(Default)]
struct ConnectionState {
    sessions: Vec<u16>,
    closed: bool,
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
            // Disconnect cleanup must wait for any in-flight open/close to
            // complete and record its CQE, even if its waiter was cancelled.
            let mut state = state.lock().await;
            if state.closed {
                return Err("connection closed before submission".into());
            }
            let response = execute_frame(server, request).await;
            if let ResponseFrame::Submit(response) = &response {
                let mut raw = response.cqe;
                let cqe = Cqe::from(&mut raw);
                let flags = CqeDw0::from(response.cqe[0]);
                if response.status == 0 && cqe.status() == 0 && flags.session_id_valid() {
                    let id = CqeDw1::from(response.cqe[1]).session_id();
                    if flags.session_closed() {
                        state.sessions.retain(|&session| session != id);
                    } else if !state.sessions.contains(&id) {
                        state.sessions.push(id);
                    }
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
        tokio::spawn(async move {
            let mut state = state.lock().await;
            state.closed = true;
            for id in state.sessions.drain(..) {
                if let Err(error) = close_session(Arc::clone(&server), id).await {
                    eprintln!("disconnected client session cleanup failed: {error}");
                }
            }
        });
    }
}

async fn close_session(server: Arc<SocketHsm>, id: u16) -> Result<(), String> {
    let mut payload = vec![0; DMA_PAGE_SIZE];
    let len = TborSessionCloseReq { session_id: id }
        .encode_request(&mut payload)
        .map_err(|error| format!("encode disconnect session close: {error:?}"))?
        .len();
    payload.truncate(len);
    let sqe = SqeBuilder::new()
        .cmd(CmdDword::new().with_op(OP_TBOR))
        .buf_lens(len as u32, DMA_PAGE_SIZE as u32)
        .session_flags(
            SessionFlags::new()
                .with_ctrl(u8::from(tsra_ddi_tbor_types::SessionControlKind::Close))
                .with_id_valid(true),
        )
        .session_id(id)
        .build();
    let response = execute_frame(
        server,
        RequestFrame::Submit(Request {
            sqe,
            payload,
            oob_items: Vec::new(),
        }),
    )
    .await;
    let ResponseFrame::Submit(response) = response else {
        return Err("unexpected disconnect session-close response".into());
    };
    let mut raw = response.cqe;
    let cqe = Cqe::from(&mut raw);
    if response.status != 0 || cqe.status() != 0 {
        return Err(format!(
            "disconnect session-close failed: transport={}, device={}",
            response.status,
            cqe.status()
        ));
    }
    TborSessionCloseResp::decode_response(&response.payload)
        .map_err(|error| format!("disconnect session-close rejected: {error:?}"))?;
    Ok(())
}

fn patch_prp1(sqe: &mut [u32; 16], low_dword: usize, address: u64) {
    sqe[low_dword] = address as u32;
    sqe[low_dword + 1] = (address >> 32) as u32;
}

fn transport_error(status: u32) -> Response {
    Response {
        status,
        cqe: [0; 4],
        payload: Vec::new(),
    }
}

async fn execute_request(server: &SocketHsm, request: Request) -> Response {
    let src_len = request.sqe[1] as usize;
    let dst_cap = request.sqe[6] as usize;
    if request.sqe[2..6].iter().any(|&word| word != 0)
        || request.sqe[7..11].iter().any(|&word| word != 0)
        || request.sqe[13..15].iter().any(|&word| word != 0)
        || request.oob_items.len() > MAX_OOB_ITEMS
        || request
            .oob_items
            .iter()
            .any(|item| item.is_empty() || item.len() > MAX_OOB_ITEM as usize)
        || request.sqe[15] as usize != request.oob_items.len() * 16
        || (!request.oob_items.is_empty() && request.sqe[0] & 0x3ff != 2)
        || src_len != request.payload.len()
        || src_len > DMA_PAGE_SIZE
        || dst_cap == 0
        || dst_cap > DMA_PAGE_SIZE
    {
        return transport_error(TRANSPORT_INVALID_REQUEST);
    }

    let mut src = Box::new(DmaPage([0; DMA_PAGE_SIZE]));
    let mut dst = Box::new(DmaPage([0; DMA_PAGE_SIZE]));
    let mut oob_page = Box::new(DmaPage([0; DMA_PAGE_SIZE]));
    src.0[..src_len].copy_from_slice(&request.payload);
    for (index, item) in request.oob_items.iter().enumerate() {
        let off = index * 16;
        oob_page.0[off..off + 8].copy_from_slice(&(item.as_ptr() as u64).to_le_bytes());
        oob_page.0[off + 8..off + 12].copy_from_slice(&(item.len() as u32).to_le_bytes());
    }

    let mut sqe = request.sqe;
    patch_prp1(&mut sqe, 2, src.0.as_ptr() as u64);
    patch_prp1(&mut sqe, 7, dst.0.as_mut_ptr() as u64);
    if !request.oob_items.is_empty() {
        patch_prp1(&mut sqe, 13, oob_page.0.as_ptr() as u64);
    }

    let _execution = server.execution.read().await;
    let cqe = match server.hsm.io(sqe, HSM_PARTITION_ID, 0, 0).await {
        Ok(cqe) => cqe,
        Err(error) => {
            eprintln!("StdHsm request failed: {error:?}");
            return transport_error(TRANSPORT_HSM_ERROR);
        }
    };
    let dst_len = (cqe[0] & 0xffff) as usize;
    if dst_len > dst_cap {
        return transport_error(TRANSPORT_HSM_ERROR);
    }

    Response {
        status: 0,
        cqe,
        payload: dst.0[..dst_len].to_vec(),
    }
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
                let _execution = server.execution.write().await;
                let result = async {
                    server.hsm.part_disable(HSM_PARTITION_ID).await?;
                    server.hsm.part_enable(HSM_PARTITION_ID).await
                }
                .await;
                let status = match result {
                    Ok(()) => 0,
                    Err(error) => {
                        eprintln!("StdHsm reset failed: {error:?}");
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
            eprintln!("StdHsm execution task failed: {error}");
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

async fn init_partition(server: &SocketHsm) -> Result<(), String> {
    server
        .hsm
        .part_alloc(HSM_PARTITION_ID, 1u128 << HSM_PARTITION_ID)
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

    async fn read_request(stream: &AsyncFd<Socket>) -> Result<RequestFrame, ProtoError> {
        let mut length = [0; 4];
        read_exact(stream, &mut length).await?;
        let length = u32::from_le_bytes(length);
        if length > MAX_FRAME {
            return Err(ProtoError::TooLarge(length));
        }
        let mut body = vec![0; length as usize];
        read_exact(stream, &mut body).await?;
        RequestFrame::decode(&body)
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
            let request = match read_request(&stream).await {
                Ok(request) => request,
                Err(ProtoError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(error) => return Err(format!("failed to read DDI request: {error}")),
            };
            let response = connection.execute(request).await?;
            write_response(&stream, &response)
                .await
                .map_err(|error| format!("failed to write DDI response: {error}"))?;
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

    async fn run_server(hsm: Arc<SocketHsm>, listener: Socket) -> Result<(), String> {
        let listener = listener
            .into_async_fd()
            .map_err(|error| format!("failed to register vsock listener: {error}"))?;
        super::init_partition(&hsm).await?;

        println!("TSRA DDI server listening on vsock port {VSOCK_PORT}");
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
            println!("DDI client connected");
            let hsm = Arc::clone(&hsm);
            tokio::spawn(async move {
                if let Err(error) = serve_connection(stream, hsm).await {
                    eprintln!("DDI client connection failed: {error}");
                } else {
                    println!("DDI client disconnected");
                }
            });
        }
    }

    pub(super) fn run() -> Result<(), String> {
        run_with_listener(bind_listener()?)
    }

    fn run_with_listener(listener: Socket) -> Result<(), String> {
        super::run_with_hsm(|hsm| run_server(hsm, listener))
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
            let error = run_with_listener(listener).expect_err("accept must fail");
            assert!(error.starts_with("failed to accept connection:"), "{error}");
        }

        #[test]
        fn serves_repeated_requests_after_invalid_dma_and_oob_fields() {
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
                        sqe: [0; 16],
                        payload,
                        oob_items: Vec::new(),
                    };
                    request.sqe[1] = len as u32;
                    request.sqe[6] = DMA_PAGE_SIZE as u32;

                    for (src_len, dst_cap) in
                        [(len + 1, DMA_PAGE_SIZE), (len, 0), (len, DMA_PAGE_SIZE + 1)]
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

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| {
        if cfg!(target_os = "linux") {
            "vsock://*:1234".to_owned()
        } else {
            "tcp://127.0.0.1:1234".to_owned()
        }
    });
    if args.next().is_some() {
        return Err("usage: ddi_sock_server [tcp://HOST:PORT | vsock://*:1234]".into());
    }
    if let Some(address) = endpoint.strip_prefix("tcp://") {
        tcp::run(address)
    } else if endpoint == "vsock://*:1234" {
        #[cfg(target_os = "linux")]
        {
            linux::run()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("VSOCK requires Linux; use tcp://127.0.0.1:1234 on Windows".into())
        }
    } else {
        Err("unsupported listener endpoint; use tcp://HOST:PORT or vsock://*:1234".into())
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("TSRA DDI socket server failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_test_hsm_initializes_partition_once() {
        let hsm = test_hsm();
        let worker = std::thread::spawn(test_hsm);
        let other = worker.join().expect("fixture worker");
        assert!(Arc::ptr_eq(&hsm, &other));
    }
}
