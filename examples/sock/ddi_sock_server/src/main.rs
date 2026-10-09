// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Linux VSOCK server backed by an in-process HSM emulator.
//!
//! Run `cargo run -p ddi_sock_server` in a VSOCK-capable Linux guest. The server
//! listens on port 1234 and uses partition 10. Clients connect to
//! `vsock://CID:1234`, where CID is this guest's VSOCK context ID.
//! This unauthenticated test transport is for trusted, isolated environments;
//! it is not a production service. Emulator state is lost when the server exits.
//! Requests with OOB pointers or lengths are rejected: this wire format cannot
//! transfer descriptor arrays or the buffers they reference.

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::raw::c_int;
    use std::sync::Arc;

    use tokio::io::unix::AsyncFd;
    use tsra_ddi_sock_proto::MAX_FRAME;
    use tsra_ddi_sock_proto::ProtoError;
    use tsra_ddi_sock_proto::Request;
    use tsra_ddi_sock_proto::Response;
    use tsra_fw_hsm_std::StdHsm;

    const AF_VSOCK: c_int = 40;
    const SOCK_STREAM: c_int = 1;
    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0x800;
    const VMADDR_CID_ANY: u32 = u32::MAX;
    const VSOCK_PORT: u32 = 1234;
    const HSM_PARTITION_ID: u8 = 10;
    const DMA_PAGE_SIZE: usize = 4096;
    const TRANSPORT_INVALID_REQUEST: u32 = 1;
    const TRANSPORT_HSM_ERROR: u32 = 2;

    #[repr(C)]
    struct SockAddrVm {
        family: u16,
        reserved: u16,
        port: u32,
        cid: u32,
        zero: [u8; 4],
    }

    #[repr(align(4096))]
    struct DmaPage([u8; DMA_PAGE_SIZE]);

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

    async fn execute_request(hsm: &StdHsm, request: Request) -> Response {
        let src_len = request.sqe[1] as usize;
        let dst_cap = request.sqe[6] as usize;
        if request.sqe[13..=15].iter().any(|&word| word != 0)
            || src_len != request.payload.len()
            || src_len > DMA_PAGE_SIZE
            || dst_cap == 0
            || dst_cap > DMA_PAGE_SIZE
        {
            return transport_error(TRANSPORT_INVALID_REQUEST);
        }

        let mut src = Box::new(DmaPage([0; DMA_PAGE_SIZE]));
        let mut dst = Box::new(DmaPage([0; DMA_PAGE_SIZE]));
        src.0[..src_len].copy_from_slice(&request.payload);

        let mut sqe = request.sqe;
        patch_prp1(&mut sqe, 2, src.0.as_ptr() as u64);
        patch_prp1(&mut sqe, 7, dst.0.as_mut_ptr() as u64);

        let cqe = match hsm.io(sqe, HSM_PARTITION_ID, 0, 0).await {
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

    async fn read_request(stream: &AsyncFd<Socket>) -> Result<Request, ProtoError> {
        let mut length = [0; 4];
        read_exact(stream, &mut length).await?;
        let length = u32::from_le_bytes(length);
        if length > MAX_FRAME {
            return Err(ProtoError::TooLarge(length));
        }
        let mut body = vec![0; length as usize];
        read_exact(stream, &mut body).await?;
        Request::decode(&body)
    }

    async fn write_response(
        stream: &AsyncFd<Socket>,
        response: &Response,
    ) -> Result<(), ProtoError> {
        let body = response.encode()?;
        write_all(stream, &(body.len() as u32).to_le_bytes()).await?;
        write_all(stream, &body).await?;
        Ok(())
    }

    async fn serve_connection(stream: AsyncFd<Socket>, hsm: Arc<StdHsm>) -> Result<(), String> {
        loop {
            let request = match read_request(&stream).await {
                Ok(request) => request,
                Err(ProtoError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(error) => return Err(format!("failed to read DDI request: {error}")),
            };
            let response = execute_request(&hsm, request).await;
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

    async fn run_server(hsm: Arc<StdHsm>, listener: Socket) -> Result<(), String> {
        let listener = AsyncFd::new(listener)
            .map_err(|error| format!("failed to register vsock listener: {error}"))?;
        hsm.part_alloc(HSM_PARTITION_ID, 1u128 << HSM_PARTITION_ID)
            .await
            .map_err(|error| format!("failed to allocate HSM partition: {error:?}"))?;
        hsm.part_enable(HSM_PARTITION_ID)
            .await
            .map_err(|error| format!("failed to enable HSM partition: {error:?}"))?;

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
            let stream = AsyncFd::new(stream)
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
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_io()
            .enable_time()
            .build()
            .map_err(|error| format!("failed to create Tokio runtime: {error}"))?;
        // The Embassy executor is process-global and its destructor cannot terminate
        // it. Retain an owner until process exit so errors can reach main without
        // hanging in StdHsm::drop.
        static HSM: std::sync::OnceLock<Arc<StdHsm>> = std::sync::OnceLock::new();
        let hsm = HSM.get_or_init(|| Arc::new(StdHsm::with_tokio(runtime.handle().clone())));
        runtime.block_on(run_server(Arc::clone(hsm), listener))
    }

    #[cfg(test)]
    mod tests {
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        use tsra_ddi_mbor_types::*;

        use super::*;

        // StdHsm's Embassy executor is process-global, as in its integration tests.
        static HSM: std::sync::LazyLock<Arc<StdHsm>> =
            std::sync::LazyLock::new(|| Arc::new(StdHsm::new()));

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
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime");
            let hsm = Arc::clone(&HSM);
            runtime.block_on(async {
                hsm.part_alloc(HSM_PARTITION_ID, 1u128 << HSM_PARTITION_ID)
                    .await
                    .expect("allocate partition");
                hsm.part_enable(HSM_PARTITION_ID)
                    .await
                    .expect("enable partition");

                let (mut client, server) = UnixStream::pair().expect("socket pair");
                client
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .expect("read timeout");
                client
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .expect("write timeout");
                let server = Socket::new_nonblocking(server.into_raw_fd()).expect("server socket");
                let server = AsyncFd::new(server).expect("async server");
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

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), String> {
    Err("the DDI VSOCK server requires Linux".into())
}

#[cfg(target_os = "linux")]
use linux::run;

fn main() {
    if let Err(error) = run() {
        eprintln!("TSRA DDI socket server failed: {error}");
        std::process::exit(1);
    }
}
