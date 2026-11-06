// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Socket DDI transport — device handle and request execution.

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
#[cfg(target_os = "linux")]
use std::os::fd::IntoRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

#[cfg(target_os = "linux")]
use nix::sys::socket::connect;
#[cfg(target_os = "linux")]
use nix::sys::socket::send;
#[cfg(target_os = "linux")]
use nix::sys::socket::socket;
#[cfg(target_os = "linux")]
use nix::sys::socket::AddressFamily;
#[cfg(target_os = "linux")]
use nix::sys::socket::MsgFlags;
#[cfg(target_os = "linux")]
use nix::sys::socket::SockFlag;
#[cfg(target_os = "linux")]
use nix::sys::socket::SockType;
#[cfg(target_os = "linux")]
use nix::sys::socket::VsockAddr;
use parking_lot::Mutex;
use tsra_ddi_interface::DdiAesGcmParams;
use tsra_ddi_interface::DdiAesGcmResult;
use tsra_ddi_interface::DdiAesXtsParams;
use tsra_ddi_interface::DdiAesXtsResult;
use tsra_ddi_interface::DdiCookie;
use tsra_ddi_interface::DdiDev;
use tsra_ddi_interface::DdiError;
use tsra_ddi_interface::DdiResult;
use tsra_ddi_interface::TborOobItem;
use tsra_ddi_mbor_codec::MborDecode;
use tsra_ddi_mbor_codec::MborDecoder;
use tsra_ddi_mbor_codec::MborEncode;
use tsra_ddi_mbor_codec::MborEncoder;
use tsra_ddi_mbor_types::DdiAesOp;
use tsra_ddi_mbor_types::DdiApiRev;
use tsra_ddi_mbor_types::DdiCloseSessionCmdReq;
use tsra_ddi_mbor_types::DdiCloseSessionReq;
use tsra_ddi_mbor_types::DdiDecoder;
use tsra_ddi_mbor_types::DdiDeviceKind;
use tsra_ddi_mbor_types::DdiOp;
use tsra_ddi_mbor_types::DdiOpReq;
use tsra_ddi_mbor_types::DdiReqHdr;
use tsra_ddi_mbor_types::DdiRespHdr;
use tsra_ddi_mbor_types::DdiRespSessionId;
use tsra_ddi_mbor_types::DdiStatus;
use tsra_ddi_mbor_types::MborError;
use tsra_ddi_mbor_types::SessionControlKind;
use tsra_ddi_sock_proto::OobItem;
use tsra_ddi_sock_proto::ProtoError;
use tsra_ddi_sock_proto::Request;
use tsra_ddi_sock_proto::RequestFrame;
use tsra_ddi_sock_proto::Response;
use tsra_ddi_sock_proto::ResponseFrame;
use tsra_ddi_sock_proto::MAX_DMA_BUFFER;
use tsra_ddi_sock_proto::MAX_OOB_ITEM;
use tsra_ddi_sock_proto::MAX_OOB_ITEMS;
use tsra_ddi_sock_proto::TRANSPORT_SESSION_NOT_OWNED;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::TborResp;
use tsra_fw_hsm_bulk::BulkCqe;
use tsra_fw_hsm_bulk::BulkDir;
use tsra_fw_hsm_bulk::BulkParams;
use tsra_fw_hsm_bulk::BulkSqe;
use tsra_fw_hsm_bulk::GcmParams;
use tsra_fw_hsm_bulk::GcmTail;
use tsra_fw_hsm_bulk::RawBulkCqe;
use tsra_fw_hsm_bulk::XtsDul;
use tsra_fw_hsm_bulk::XtsParams;
use tsra_fw_hsm_bulk::BLOCK_LEN;
use tsra_fw_hsm_bulk::GCM_AAD_ALIGN;
use tsra_fw_hsm_io::CmdDword;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::RawCqe;
use tsra_fw_hsm_io::SessionFlags;
use tsra_fw_hsm_io::SqeBuilder;
use tsra_fw_hsm_io::OP_MBOR;
use tsra_fw_hsm_io::OP_TBOR;

/// Environment variable naming a `tcp://HOST:PORT`, Unix socket, or Linux VSOCK endpoint.
pub const SOCK_PATH_ENV: &str = "TSRA_DDI_SOCK";

/// Default endpoint when [`SOCK_PATH_ENV`] is unset on Unix.
#[cfg(unix)]
pub const DEFAULT_SOCK_PATH: &str = "/tmp/tsra-ddi.sock";

/// Default endpoint when [`SOCK_PATH_ENV`] is unset on non-Unix targets.
#[cfg(not(unix))]
pub const DEFAULT_SOCK_PATH: &str = "tcp://127.0.0.1:1234";

/// Request/response capacity advertised to the server, including PQC commands.
const DST_CAP: u32 = MAX_DMA_BUFFER;

enum SocketStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(target_os = "linux")]
    Vsock(VsockStream),
}

impl SocketStream {
    /// Set (or, with `None`, clear) a read deadline, regardless of
    /// transport. Used to bound the best-effort leaked-session cleanup
    /// ([`DdiSockDev::close_leaked_session_locked`]) so an unresponsive
    /// peer can't hold the stream mutex forever.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(timeout),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_read_timeout(timeout),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => stream.set_read_timeout(timeout),
        }
    }

    /// Set (or, with `None`, clear) a write deadline, regardless of
    /// transport. Paired with [`Self::set_read_timeout`] by
    /// [`DeadlineBound`] so a blocked `write` (e.g. a full send buffer
    /// because the peer isn't draining it) can't hold the best-effort
    /// leaked-session cleanup past its deadline either.
    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_write_timeout(timeout),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_write_timeout(timeout),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => stream.set_write_timeout(timeout),
        }
    }
}

/// Wraps an already-locked [`SocketStream`] so every `Read`/`Write`
/// call made through it is bounded by one absolute `deadline`, rather
/// than each individual `recv`/`send` syscall getting its own
/// independent timeout window.
///
/// Used by [`DdiSockDev::close_leaked_session_locked`]: the framing
/// reader's `read_exact` can call through here several times for one
/// logical response, and a peer trickling in a byte just before each
/// per-call timeout could otherwise stall the whole cleanup — and
/// therefore the shared stream mutex, since cleanup runs with it held
/// — far longer than `CLEANUP_TIMEOUT`. Each call instead computes the
/// time left before `deadline`, arms the stream's native timeout with
/// just that remainder, and fails immediately once it's exhausted.
struct DeadlineBound<'a> {
    stream: &'a mut SocketStream,
    deadline: Instant,
}

impl DeadlineBound<'_> {
    /// Time remaining before `deadline`, or a `TimedOut` error once
    /// it's passed.
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "cleanup exchange exceeded its deadline",
                )
            })
    }
}

impl Read for DeadlineBound<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buf)
    }
}

impl Write for DeadlineBound<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Read for SocketStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buf),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => stream.read(buf),
        }
    }
}

impl Write for SocketStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buf),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => stream.flush(),
        }
    }
}

#[cfg(target_os = "linux")]
struct VsockStream {
    fd: std::os::fd::RawFd,
}

#[cfg(target_os = "linux")]
impl VsockStream {
    /// Set (or, with `None`, clear) a receive- or send-side timeout
    /// (`SO_RCVTIMEO` / `SO_SNDTIMEO`) on the raw `AF_VSOCK` socket.
    /// Neither `std` nor `nix` 0.26 expose a safe wrapper for either
    /// option on a bare fd, so it's set directly via `libc`.
    #[allow(unsafe_code)]
    fn set_timeout(&mut self, opt: libc::c_int, timeout: Option<Duration>) -> std::io::Result<()> {
        let tv = match timeout {
            Some(d) => {
                // A positive duration under one microsecond truncates to
                // an all-zero `timeval` via `subsec_micros()`, which the
                // kernel treats identically to `None` (disable the
                // timeout, block indefinitely) rather than "expire
                // immediately". Round such tiny positive remainders up
                // to one microsecond so the timeout stays armed; `std`'s
                // own `TcpStream`/`UnixStream` timeout setters apply the
                // same clamp for this reason.
                let d = d.max(Duration::from_micros(1));
                libc::timeval {
                    tv_sec: d.as_secs() as libc::time_t,
                    tv_usec: libc::suseconds_t::from(d.subsec_micros()),
                }
            }
            // A zeroed timeval disables the timeout (block indefinitely),
            // matching `SO_RCVTIMEO`/`SO_SNDTIMEO`'s documented default.
            None => libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        };
        // SAFETY: `self.fd` is a valid, open socket for the lifetime of
        // `self` (closed only by `Drop`); `tv` is a valid, correctly
        // sized `timeval` for the duration of this call.
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                opt,
                std::ptr::addr_of!(tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_timeout(libc::SO_RCVTIMEO, timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_timeout(libc::SO_SNDTIMEO, timeout)
    }

    fn connect(cid: u32, port: u32) -> std::io::Result<Self> {
        let fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(std::io::Error::from)?
        .into_raw_fd();

        if let Err(error) = connect(fd, &VsockAddr::new(cid, port)) {
            let _ = nix::unistd::close(fd);
            return Err(std::io::Error::from(error));
        }
        Ok(Self { fd })
    }
}

#[cfg(target_os = "linux")]
impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        nix::unistd::read(self.fd, buf).map_err(std::io::Error::from)
    }
}

#[cfg(target_os = "linux")]
impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        send(self.fd, buf, MsgFlags::MSG_NOSIGNAL).map_err(std::io::Error::from)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for VsockStream {
    fn drop(&mut self) {
        let _ = nix::unistd::close(self.fd);
    }
}

fn parse_vsock_endpoint(path: &str) -> std::io::Result<Option<(u32, u32)>> {
    let Some(address) = path.strip_prefix("vsock://") else {
        return Ok(None);
    };
    let Some((cid, port)) = address.split_once(':') else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vsock endpoint must have the form vsock://CID:PORT",
        ));
    };
    if cid.is_empty() || port.is_empty() || port.contains(':') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vsock endpoint must have the form vsock://CID:PORT",
        ));
    }
    let cid = cid
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid vsock CID"))?;
    let port = port
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid vsock port"))?;
    if port == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vsock port must be nonzero",
        ));
    }
    Ok(Some((cid, port)))
}

/// Resolve the configured socket path from the environment or default.
pub(crate) fn socket_path() -> String {
    std::env::var(SOCK_PATH_ENV).unwrap_or_else(|_| DEFAULT_SOCK_PATH.to_owned())
}

/// Deadline for the best-effort leaked-session `CloseSession` cleanup
/// (see [`DdiSockDev::close_leaked_session_locked`]). Bounds how long an
/// unresponsive peer can hold the stream mutex; on expiry the connection
/// is retired rather than reused.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// A connected socket DDI device.
///
/// Wraps a single TCP, Unix-domain, or Linux VSOCK connection to the server. Requests
/// are serialized through a mutex, so the synchronous trait methods can be
/// shared across threads while each request/response exchange stays atomic.
/// Clones share the same connection and sessions; disconnect cleanup runs only
/// after the last clone is dropped.
#[derive(Clone)]
pub struct DdiSockDev {
    stream: Arc<Mutex<SocketStream>>,
    cmd_counter: Arc<AtomicU16>,
    device_kind: DdiDeviceKind,
    // Set once a best-effort leaked-session cleanup exchange (see
    // `close_leaked_session_locked`) fails (timeout or any other error):
    // a late or partially-consumed response for that exchange may still
    // be unread on the wire, so reusing the stream for any further
    // request risks reading that stale response instead. Every clone
    // shares this flag (and the stream), so every clone is retired
    // together rather than only the one that observed the failure.
    retired: Arc<AtomicBool>,
    // The cleanup failure that caused `retired` to be set, if any,
    // described as a string (so it's cheap to clone out of the mutex
    // without requiring `DdiError` itself to implement `Clone`). Read by
    // `retired_err` to report the actual cause — not always a timeout —
    // behind every subsequent request on a retired connection.
    retired_cause: Arc<Mutex<Option<String>>>,
}

impl std::fmt::Debug for DdiSockDev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdiSockDev")
            .field("device_kind", &self.device_kind)
            .finish_non_exhaustive()
    }
}

/// Outcome of [`DdiSockDev::close_leaked_session_locked`].
enum CloseLeakedSessionOutcome {
    /// The cleanup either wasn't attempted (e.g. a local encode failure
    /// before any I/O) or succeeded with a fully-read, well-formed
    /// response; the stream had no exchange left outstanding and is
    /// safe for the next caller to reuse.
    Done,
    /// The cleanup's `CloseSession` exchange hit `CLEANUP_TIMEOUT`, or
    /// failed with any other I/O or protocol error, before a complete
    /// response was confirmed read (e.g. an oversized response whose
    /// framing reader consumes only the length prefix before erroring
    /// out, leaving the body unread on the wire). Either way a late or
    /// partially-consumed response may still arrive, so the stream can
    /// no longer be trusted to pair reads with the request that caused
    /// them; the connection is conservatively retired instead of
    /// reused. Carries a description of the actual failure, so a
    /// subsequent request on the retired connection can report it
    /// instead of always claiming a timeout.
    Unusable(String),
}

impl DdiSockDev {
    /// Connect to the server at `path` (a Unix socket path, `tcp://HOST:PORT`,
    /// or `vsock://CID:PORT` endpoint).
    pub(crate) fn connect(path: &str) -> DdiResult<Self> {
        let stream = if let Some(address) = path.strip_prefix("tcp://") {
            let stream = TcpStream::connect(address).map_err(DdiError::IoError)?;
            stream.set_nodelay(true).map_err(DdiError::IoError)?;
            SocketStream::Tcp(stream)
        } else {
            match parse_vsock_endpoint(path).map_err(DdiError::IoError)? {
                Some((cid, port)) => {
                    #[cfg(target_os = "linux")]
                    {
                        SocketStream::Vsock(
                            VsockStream::connect(cid, port).map_err(DdiError::IoError)?,
                        )
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = (cid, port);
                        return Err(DdiError::IoError(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "vsock endpoints require Linux",
                        )));
                    }
                }
                None => {
                    #[cfg(unix)]
                    {
                        SocketStream::Unix(UnixStream::connect(path).map_err(DdiError::IoError)?)
                    }
                    #[cfg(not(unix))]
                    {
                        return Err(DdiError::IoError(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "this platform requires a tcp://HOST:PORT endpoint",
                        )));
                    }
                }
            }
        };
        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            cmd_counter: Arc::new(AtomicU16::new(1)),
            // The firmware reports a physical device, so the host codec
            // runs its physical-mode encode/decode hooks (matching emu).
            device_kind: DdiDeviceKind::Physical,
            retired: Arc::new(AtomicBool::new(false)),
            retired_cause: Arc::new(Mutex::new(None)),
        })
    }

    fn next_cmd_id(&self) -> u16 {
        self.cmd_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Error returned for any request on a connection the best-effort
    /// leaked-session cleanup has already retired (see `retired`).
    /// Describes the actual cleanup failure (if one was recorded via
    /// `retired_cause`) rather than always claiming a timeout — the
    /// cleanup can also fail with an ordinary I/O error or a malformed
    /// response, and the earlier flat "cleanup timeout" wording would
    /// misdirect anyone diagnosing one of those cases.
    fn retired_err(&self) -> DdiError {
        let cause = self.retired_cause.lock().clone();
        let message = match cause {
            Some(cause) => {
                format!("connection retired after a leaked-session cleanup failure: {cause}")
            }
            None => "connection retired after a leaked-session cleanup".to_owned(),
        };
        DdiError::IoError(std::io::Error::new(std::io::ErrorKind::BrokenPipe, message))
    }

    /// Mark the connection retired, recording `cause` so a subsequent
    /// `retired_err()` describes the actual cleanup failure instead of a
    /// generic message. The cause is stored before the flag is set so
    /// any caller that observes `retired == true` (via `Acquire`) can
    /// always read it back.
    fn retire(&self, cause: String) {
        *self.retired_cause.lock() = Some(cause);
        self.retired.store(true, Ordering::Release);
    }

    /// Exchange one submission with the server over an already-locked
    /// `stream`.
    ///
    /// Maps a nonzero transport status to a [`DdiError`].
    fn exchange_locked<RW: Read + Write>(stream: &mut RW, req: &Request) -> DdiResult<Response> {
        let resp: Response = {
            req.write_to(&mut *stream).map_err(map_proto_err)?;
            Response::read_from(&mut *stream).map_err(map_proto_err)?
        };

        // Transport-level status (e.g. server DMA allocation failure).
        match resp.status {
            0 => Ok(resp),
            TRANSPORT_SESSION_NOT_OWNED => Err(DdiError::DdiStatus(
                DdiStatus::FileHandleSessionIdDoesNotMatch,
            )),
            status => Err(DdiError::DdiError(status)),
        }
    }

    /// Exchange one submission with the server.
    ///
    /// Maps a nonzero transport status to a [`DdiError`].
    fn exchange(&self, req: &Request) -> DdiResult<Response> {
        if self.retired.load(Ordering::Acquire) {
            return Err(self.retired_err());
        }
        let mut stream = self.stream.lock();
        // A cleanup running on another clone of this handle could have
        // retired the connection (and poisoned `stream`'s framing) in
        // the gap between the check above and acquiring the lock;
        // recheck now, before any I/O, so a request can't slip in on a
        // stream whose cleanup response hasn't been consumed yet.
        if self.retired.load(Ordering::Acquire) {
            return Err(self.retired_err());
        }
        Self::exchange_locked(&mut *stream, req)
    }

    /// Build a submission entry, exchange it with the server, and return
    /// the response body bytes plus the bytes of each [`OobItem::Out`].
    ///
    /// Locks `self.stream` for the duration of the exchange and delegates
    /// to [`Self::submit_locked`]. Used by paths (e.g. `exec_op_tbor`)
    /// that don't need to hold the lock across any additional
    /// post-processing.
    fn submit(
        &self,
        op: u16,
        session_ctrl: u8,
        session_id: Option<u16>,
        payload: Vec<u8>,
        oob_items: Vec<OobItem>,
    ) -> DdiResult<(Vec<u8>, Vec<Vec<u8>>)> {
        if self.retired.load(Ordering::Acquire) {
            return Err(self.retired_err());
        }
        let cmd_id = self.next_cmd_id();
        let mut stream = self.stream.lock();
        // See `exchange`'s matching recheck: a cleanup on another clone
        // may have retired the connection after the check above but
        // before this lock was acquired.
        if self.retired.load(Ordering::Acquire) {
            return Err(self.retired_err());
        }
        Self::submit_locked(
            &mut *stream,
            cmd_id,
            op,
            session_ctrl,
            session_id,
            payload,
            oob_items,
        )
    }

    /// The I/O-only half of a submit: write the request and read the
    /// response over an already-locked `stream`.
    ///
    /// Mirrors the in-process emulator: the client constructs the SQE
    /// (opcode, command id, lengths, session flags) and reads the returned
    /// CQE; the server only re-homes the DMA buffers. The SQE's PRP
    /// address fields are left zero — the server assigns them.
    ///
    /// Maps a nonzero transport status (header) or device status (CQE) to
    /// [`DdiError::DdiError`].
    ///
    /// Takes an already-locked `stream` (rather than locking
    /// `self.stream` itself) so [`DdiDev::exec_op_mbor`] can hold that
    /// lock across the exchange *and* its `OpenSession`/`ReopenSession`
    /// identity check, so a best-effort leaked-session close (see
    /// [`Self::close_leaked_session_locked`]) can reuse the same stream
    /// without racing a concurrent caller's request.
    fn submit_locked<RW: Read + Write>(
        stream: &mut RW,
        cmd_id: u16,
        op: u16,
        session_ctrl: u8,
        session_id: Option<u16>,
        payload: Vec<u8>,
        oob_items: Vec<OobItem>,
    ) -> DdiResult<(Vec<u8>, Vec<Vec<u8>>)> {
        if oob_items.len() > MAX_OOB_ITEMS
            || oob_items
                .iter()
                .any(|item| item.is_empty() || item.len() > MAX_OOB_ITEM as usize)
        {
            return Err(DdiError::InvalidParameter);
        }
        let sqe = SqeBuilder::new()
            .cmd(CmdDword::new().with_op(op).with_id(cmd_id))
            .buf_lens(payload.len() as u32, DST_CAP)
            .oob_len((oob_items.len() * 16) as u32)
            .session_flags(
                SessionFlags::new()
                    .with_ctrl(session_ctrl)
                    .with_id_valid(session_id.is_some()),
            )
            .session_id(session_id.unwrap_or(0))
            .build();

        let req = Request {
            sqe: sqe.to_vec(),
            payload,
            oob_items,
            tail: Vec::new(),
        };
        let resp = Self::exchange_locked(stream, &req)?;

        // Device-level status lives in the completion entry.
        let mut cqe_raw: RawCqe = resp
            .cqe
            .as_slice()
            .try_into()
            .map_err(|_| invalid_data("response CQE is not a command CQE"))?;
        let cqe = Cqe::from(&mut cqe_raw);
        if cqe.status() != 0 {
            return Err(DdiError::DdiError(u32::from(cqe.status())));
        }

        // Each output item must come back exactly once with its requested length.
        let out_lens = req.oob_items.iter().filter_map(|item| match item {
            OobItem::Out(len) => Some(*len as usize),
            OobItem::In(_) => None,
        });
        if !resp.oob_items.iter().map(Vec::len).eq(out_lens) {
            return Err(invalid_data("response OOB items do not match the request"));
        }

        // Don't trust the server's framing for the payload length: the
        // completion entry's `dst_len` is the authoritative count of bytes the
        // firmware wrote. Reject a short payload (the response can't satisfy the
        // reported length) and truncate any trailing bytes so callers never
        // decode past the firmware's output.
        let dst_len = cqe.dst_len() as usize;
        let mut payload = resp.payload;
        // The client advertised a fixed destination capacity (`DST_CAP`) in the
        // SQE, so a CQE reporting more than that is a protocol integrity failure
        // (malicious or buggy server) — reject it before touching the payload.
        if dst_len > DST_CAP as usize {
            return Err(invalid_data(
                "CQE dst_len exceeds requested destination capacity",
            ));
        }
        if payload.len() < dst_len {
            // The server returned fewer bytes than the firmware reported
            // writing: a transport/protocol integrity failure, not a device
            // status. Surface it as malformed data rather than a `0` (success)
            // device status, matching the other protocol-shape errors here.
            return Err(invalid_data("response payload shorter than CQE dst_len"));
        }
        payload.truncate(dst_len);
        Ok((payload, resp.oob_items))
    }

    /// Best-effort cleanup for a session the server reports opening
    /// (header `status == Success`, carrying the new id) whose response
    /// body then fails to decode, or whose header/body session ids
    /// disagree. Issues a raw `CloseSession` for `leaked_id` over the
    /// already-locked `stream`, so the firmware-side slot isn't left live
    /// — nothing local ever recorded it (see the call site in
    /// [`DdiDev::exec_op_mbor`]), so nothing local would otherwise ever
    /// close it either.
    ///
    /// This exchange is bounded by one absolute `CLEANUP_TIMEOUT`
    /// deadline spanning the whole exchange (see [`DeadlineBound`]): a
    /// peer that never answers `CloseSession`, or that trickles bytes
    /// just fast enough to keep renewing a naively per-call timeout,
    /// must not block the caller (or any clone sharing this stream,
    /// since they share the same mutex) past it. Any error from the
    /// exchange — timeout or otherwise — conservatively marks the
    /// stream [`CloseLeakedSessionOutcome::Unusable`] rather than risk
    /// reusing a connection whose framing may be desynced; the original
    /// error is what surfaces to the caller either way.
    fn close_leaked_session_locked(
        stream: &mut SocketStream,
        cmd_id: u16,
        pre_encode: bool,
        leaked_id: u16,
    ) -> CloseLeakedSessionOutcome {
        let req = DdiCloseSessionCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::CloseSession,
                sess_id: Some(leaked_id),
                // A `None` rev here makes the firmware reject this
                // best-effort cleanup outright, permanently leaking the
                // session slot.
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiCloseSessionReq {},
            ext: None,
        };

        let mut buf = vec![0u8; DST_CAP as usize];
        let req_len = {
            let mut enc = MborEncoder::new(buf.as_mut_slice(), pre_encode);
            if req.mbor_encode(&mut enc).is_err() {
                return CloseLeakedSessionOutcome::Done;
            }
            enc.position()
        };
        buf.truncate(req_len);

        let mut bounded = DeadlineBound {
            stream,
            deadline: Instant::now() + CLEANUP_TIMEOUT,
        };
        let result = Self::submit_locked(
            &mut bounded,
            cmd_id,
            OP_MBOR,
            u8::from(SessionControlKind::Close),
            Some(leaked_id),
            buf,
            Vec::new(),
        );
        // Clear any deadline `DeadlineBound` left armed on the
        // underlying stream so ordinary (non-cleanup) exchanges sharing
        // it afterward aren't bounded by it.
        let _ = stream.set_read_timeout(None);
        let _ = stream.set_write_timeout(None);

        match result {
            Ok(_) => CloseLeakedSessionOutcome::Done,
            Err(err) => CloseLeakedSessionOutcome::Unusable(err.to_string()),
        }
    }

    /// Encode a TBOR request, submit it with `oob_items`, and decode the
    /// response. Returns the bytes of each [`OobItem::Out`].
    fn exec_tbor<T: TborOpReq>(
        &self,
        req: &T,
        oob_items: Vec<OobItem>,
    ) -> DdiResult<(T::OpResp, Vec<Vec<u8>>)> {
        // ── 1. Encode the TBOR request.
        let session_ctrl = req.session_ctrl();
        let session_id = req.get_session_id();

        let mut buf = vec![0u8; DST_CAP as usize];
        let req_len = {
            let bytes = req.encode_request(buf.as_mut_slice())?;
            bytes.len()
        };
        buf.truncate(req_len);

        // ── 2. Build the SQE and exchange it over the socket.
        let (resp_buf, out_items) =
            self.submit(OP_TBOR, u8::from(session_ctrl), session_id, buf, oob_items)?;
        if resp_buf.is_empty() {
            return Err(DdiError::DdiError(0));
        }

        // ── 3. Decode the typed response.
        let resp = <T::OpResp>::decode_response(&resp_buf)?;
        Ok((resp, out_items))
    }

    /// Submit a bulk SQE with its source bytes and GCM tail input, and
    /// return the CQE, destination bytes and GCM tail output.
    ///
    /// The SQE's buffer addresses are client-local; the server re-homes
    /// them. A failed CQE maps like the driver's ioctl output: a non-zero
    /// status code to [`DdiError::FpError`], otherwise a non-zero error
    /// code to [`DdiError::FpCmdSpecificError`].
    fn bulk_submit(
        &self,
        sqe: &BulkSqe,
        payload: Vec<u8>,
        tail: Vec<u8>,
    ) -> DdiResult<(BulkCqe, Vec<u8>, Vec<u8>)> {
        let req = Request {
            sqe: sqe.encode().to_vec(),
            payload,
            oob_items: Vec::new(),
            tail,
        };
        let resp = self.exchange(&req)?;
        let raw: RawBulkCqe = resp
            .cqe
            .as_slice()
            .try_into()
            .map_err(|_| invalid_data("response CQE is not a bulk CQE"))?;
        let cqe = BulkCqe::decode(&raw);
        if !cqe.status.is_success() {
            tracing::warn!(
                sts = cqe.status.sts,
                err = cqe.status.err,
                "DdiSock bulk IO failed"
            );
        }
        if cqe.status.sts != 0 {
            Err(DdiError::FpError(u32::from(cqe.status.sts)))?;
        }
        if cqe.status.err != 0 {
            Err(DdiError::FpCmdSpecificError(u32::from(cqe.status.err)))?;
        }
        if resp.payload.len() != sqe.dst_len as usize {
            return Err(invalid_data("bulk response payload length mismatch"));
        }
        Ok((cqe, resp.payload, resp.tail))
    }
}

/// Whether a `ReopenSession` response's header and body both agree with
/// the `requested` session id.
///
/// Both must be present and equal to `requested` — a peer that omits
/// either id, or reports a different one in either place, must not be
/// trusted enough to be returned to the caller (see the call site in
/// [`DdiDev::exec_op_mbor`]). A missing `requested` id (no specific
/// session named) trivially confirms, since there is nothing to check
/// against.
fn reopen_identity_confirmed(
    requested: Option<u16>,
    header_sess_id: Option<u16>,
    body_sess_id: Option<u16>,
) -> bool {
    match requested {
        Some(requested) => header_sess_id == Some(requested) && body_sess_id == Some(requested),
        None => true,
    }
}

/// Whether an `OpenSession` response's header and body agree on the
/// newly assigned session id.
///
/// Unlike `ReopenSession` (where the *requested* id is already known
/// ahead of time, see [`reopen_identity_confirmed`]), `OpenSession` has
/// no id to check against — the server assigns one, and the header and
/// body are the only two independent reports of what it is. Both must be
/// present and equal: a peer that omits either id, or reports a
/// different one in either place, hasn't actually confirmed the new
/// session's id (see the call site in [`DdiDev::exec_op_mbor`]).
fn open_identity_confirmed(header_sess_id: Option<u16>, body_sess_id: Option<u16>) -> bool {
    header_sess_id.is_some() && header_sess_id == body_sess_id
}

/// Picks the id (if any) to best-effort close after an unconfirmed
/// `OpenSession` response (see the call site in [`DdiDev::exec_op_mbor`]).
///
/// Only returns an id when exactly one of the header/body reported one:
/// that lone id is the only candidate for what was actually opened. When
/// both are present they necessarily disagree (a caller only reaches this
/// after [`open_identity_confirmed`] returned `false`), and there's no way
/// to tell whether either one is the slot this call leaked, or an
/// unrelated session this connection already owns — closing the wrong one
/// would destroy a live session instead of cleaning up a leaked one, so
/// this returns `None` rather than guessing.
fn open_session_leaked_id(header_sess_id: Option<u16>, body_sess_id: Option<u16>) -> Option<u16> {
    match (header_sess_id, body_sess_id) {
        (Some(id), None) | (None, Some(id)) => Some(id),
        _ => None,
    }
}

impl DdiDev for DdiSockDev {
    fn device_kind(&self) -> DdiDeviceKind {
        self.device_kind
    }

    fn exec_op_mbor<T: DdiOpReq>(
        &self,
        req: &T,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        if self.retired.load(Ordering::Acquire) {
            return Err(self.retired_err());
        }
        let (pre_encode, post_decode) = match self.device_kind {
            DdiDeviceKind::Physical => (true, true),
            _ => (false, false),
        };

        // ── 1. Encode the DDI request via host MBOR (wire-compat with fw).
        let opcode = req.get_opcode();
        let session_ctrl: SessionControlKind = opcode.into();
        let session_id = req.get_session_id();
        match session_ctrl {
            SessionControlKind::NoSession | SessionControlKind::Open if session_id.is_some() => {
                return Err(DdiError::DdiStatus(DdiStatus::InvalidArg));
            }
            SessionControlKind::InSession | SessionControlKind::Close if session_id.is_none() => {
                return Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch,
                ));
            }
            _ => {}
        }

        let mut buf = vec![0u8; DST_CAP as usize];
        let req_len = {
            let mut enc = MborEncoder::new(buf.as_mut_slice(), pre_encode);
            req.mbor_encode(&mut enc)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?;
            enc.position()
        };
        buf.truncate(req_len);

        // ── 2. Exchange the SQE/CQE and decode the full typed response,
        //    all while holding `self.stream`'s lock, so a best-effort
        //    leaked-session close (step 4/5 below) can reuse the same
        //    stream without an intervening request from another caller.
        let cmd_id = self.next_cmd_id();
        let mut stream = self.stream.lock();
        // See `exchange`'s matching recheck: a cleanup on another
        // clone may have retired the connection after the check at the
        // top of this function but before this lock was acquired.
        if self.retired.load(Ordering::Acquire) {
            return Err(self.retired_err());
        }
        let (resp_buf, _) = Self::submit_locked(
            &mut *stream,
            cmd_id,
            OP_MBOR,
            u8::from(session_ctrl),
            session_id,
            buf,
            Vec::new(),
        )?;
        if resp_buf.is_empty() {
            return Err(DdiError::DdiError(0));
        }

        // ── 3. Decode the response header and check device status.
        let mut hdr_dec = DdiDecoder::new(&resp_buf, post_decode);
        let hdr: DdiRespHdr = hdr_dec
            .decode_hdr()
            .map_err(|_| DdiError::MborError(MborError::DecodeError))?;
        if hdr.status != DdiStatus::Success {
            return Err(DdiError::DdiStatus(hdr.status));
        }

        // ── 4. Decode the typed response (header + body). A server
        //    that already told us (via the header) that it opened a
        //    session, but whose body then fails to decode, has left a
        //    live session this call is about to error out of — with
        //    nothing local ever having recorded it, nothing local would
        //    otherwise ever close it either. Best-effort close it now,
        //    still under this same stream lock, before surfacing the
        //    decode error.
        let mut body_dec = MborDecoder::new(&resp_buf, post_decode);
        let typed_resp = match <T::OpResp>::mbor_decode(&mut body_dec) {
            Ok(resp) => resp,
            Err(_) => {
                if session_ctrl == SessionControlKind::Open {
                    if let Some(leaked_id) = hdr.sess_id {
                        if let CloseLeakedSessionOutcome::Unusable(cause) =
                            Self::close_leaked_session_locked(
                                &mut stream,
                                self.next_cmd_id(),
                                pre_encode,
                                leaked_id,
                            )
                        {
                            self.retire(cause);
                        }
                    }
                }
                return Err(DdiError::MborError(MborError::DecodeError));
            }
        };

        // ── 5. For `ReopenSession`, the request already names the id
        //    being reopened (`session_id`). A conforming peer's header
        //    *and* body (`DdiRespSessionId::resp_session_id`) both echo
        //    that same id back; reject before returning the response in
        //    every other case — a peer that omits either id, or reports
        //    a different one in either place, hasn't actually confirmed
        //    this is the session the caller asked to reopen.
        if opcode == DdiOp::ReopenSession
            && !reopen_identity_confirmed(session_id, hdr.sess_id, typed_resp.resp_session_id())
        {
            return Err(DdiError::DdiStatus(DdiStatus::SessionNotFound));
        }

        // ── 6. For `OpenSession`, the header carries the server-assigned
        //    id and the body independently echoes the same id back. A
        //    peer that omits either id, or reports a different one in
        //    either place, hasn't actually confirmed the new session's
        //    id: treat it the same as a body decode failure — best-effort
        //    close whatever the header told us was opened, and surface a
        //    decode error rather than returning an untrustworthy id to
        //    the caller.
        if session_ctrl == SessionControlKind::Open
            && !open_identity_confirmed(hdr.sess_id, typed_resp.resp_session_id())
        {
            if let Some(leaked_id) =
                open_session_leaked_id(hdr.sess_id, typed_resp.resp_session_id())
            {
                if let CloseLeakedSessionOutcome::Unusable(cause) =
                    Self::close_leaked_session_locked(
                        &mut stream,
                        self.next_cmd_id(),
                        pre_encode,
                        leaked_id,
                    )
                {
                    self.retire(cause);
                }
            }
            return Err(DdiError::MborError(MborError::DecodeError));
        }

        Ok(typed_resp)
    }

    fn exec_op_tbor<T: TborOpReq>(
        &self,
        req: &T,
        oob_items: Option<&[&[u8]]>,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        let oob_items = oob_items
            .unwrap_or(&[])
            .iter()
            .map(|item| OobItem::In(item.to_vec()))
            .collect();
        self.exec_tbor(req, oob_items).map(|(resp, _)| resp)
    }

    /// TBOR exec path with device-writable out-of-band items. Output
    /// buffers travel as lengths; the server returns their contents.
    fn exec_op_tbor_oob<T: TborOpReq>(
        &self,
        req: &T,
        oob_items: &mut [TborOobItem<'_>],
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        let items = oob_items
            .iter()
            .map(|item| match item {
                TborOobItem::In(buf) => Ok(OobItem::In(buf.to_vec())),
                TborOobItem::Out(buf) => u32::try_from(buf.len())
                    .map(OobItem::Out)
                    .map_err(|_| DdiError::InvalidParameter),
            })
            .collect::<DdiResult<Vec<_>>>()?;
        let (resp, out_items) = self.exec_tbor(req, items)?;
        let outputs = oob_items.iter_mut().filter_map(|item| match item {
            TborOobItem::Out(buf) => Some(buf),
            TborOobItem::In(_) => None,
        });
        // `submit` verified one item of the requested length per output.
        for (buf, bytes) in outputs.zip(out_items) {
            buf.copy_from_slice(&bytes);
        }
        Ok(resp)
    }

    /// Runs an AES-GCM fast-path operation through the server's bulk queue.
    ///
    /// Lays the buffers out as the Linux driver does: the AAD zero-padded
    /// to 32 bytes followed by the block-aligned text in the source /
    /// destination buffers, and the final partial block (at most 15 bytes)
    /// in the tail.
    fn exec_op_fp_gcm_slice(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        tag: &mut Option<[u8; 16]>,
        iv: &mut Option<[u8; 12]>,
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        let dir = bulk_dir(mode);
        if dir == BulkDir::Decrypt && gcm_params.tag.is_none() {
            Err(DdiError::DdiStatus(DdiStatus::NoTagProvided))?;
        }
        if dst_buf.len() < src_buf.len() {
            Err(DdiError::InvalidParameter)?;
        }

        let aad = gcm_params.aad.unwrap_or_default();
        let aligned_aad_len = aad.len().div_ceil(GCM_AAD_ALIGN as usize) * GCM_AAD_ALIGN as usize;
        let tail_len = src_buf.len() % BLOCK_LEN as usize;
        let body_len = src_buf.len() - tail_len;

        let mut src = vec![0u8; aligned_aad_len + body_len];
        src[..aad.len()].copy_from_slice(&aad);
        src[aligned_aad_len..].copy_from_slice(&src_buf[..body_len]);
        let tail = src_buf[body_len..].to_vec();

        let sgl_len = u32::try_from(src.len()).map_err(|_| DdiError::InvalidParameter)?;
        let sqe = BulkSqe {
            dir,
            cid: self.next_cmd_id(),
            session_id: gcm_params.session_id,
            short_app_id: gcm_params.short_app_id,
            src_len: sgl_len,
            src_addr: src.as_ptr() as u64,
            dst_len: sgl_len,
            dst_addr: dst_buf.as_ptr() as u64,
            params: BulkParams::Gcm(GcmParams {
                key_id: gcm_params.key_id,
                aad_len: aad.len() as u32,
                aligned_aad_len: aligned_aad_len as u32,
                tag: gcm_params.tag.unwrap_or_default(),
                iv: gcm_params.iv,
                tail: (tail_len > 0).then_some(GcmTail {
                    len: tail_len as u8,
                    src: tail.as_ptr() as u64,
                    dst: tail.as_ptr() as u64,
                }),
            }),
        };
        let (cqe, dst, tail_out) = self.bulk_submit(&sqe, src, tail)?;
        if cqe.data_len != sgl_len
            || cqe.tail_len as usize != tail_len
            || tail_out.len() != tail_len
        {
            Err(DdiError::DdiStatus(DdiStatus::InternalError))?;
        }

        dst_buf[..body_len].copy_from_slice(&dst[aligned_aad_len..]);
        dst_buf[body_len..src_buf.len()].copy_from_slice(&tail_out);
        *tag = Some(cqe.tag);
        *iv = Some(cqe.iv);
        *fips_approved = cqe.fips_approved;
        Ok(src_buf.len())
    }

    fn exec_op_fp_gcm(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesGcmResult, DdiError> {
        let mut data = vec![0u8; src_buf.len()];
        let mut tag = None;
        let mut iv = None;
        let mut fips_approved = false;
        let len = self.exec_op_fp_gcm_slice(
            mode,
            gcm_params,
            &src_buf,
            &mut data,
            &mut tag,
            &mut iv,
            &mut fips_approved,
        )?;
        data.truncate(len);
        Ok(DdiAesGcmResult {
            data,
            tag,
            iv,
            fips_approved,
        })
    }

    /// Runs an AES-XTS fast-path operation through the server's bulk queue.
    fn exec_op_fp_xts_slice(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        if src_buf.is_empty() || dst_buf.len() < src_buf.len() {
            Err(DdiError::InvalidParameter)?;
        }
        let len = u32::try_from(src_buf.len()).map_err(|_| DdiError::InvalidParameter)?;
        let dul = match xts_params.data_unit_len {
            n if n == src_buf.len() => XtsDul::Full,
            512 => XtsDul::B512,
            4096 => XtsDul::B4096,
            8192 => XtsDul::B8192,
            _ => Err(DdiError::InvalidParameter)?,
        };

        let sqe = BulkSqe {
            dir: bulk_dir(mode),
            cid: self.next_cmd_id(),
            session_id: xts_params.session_id,
            short_app_id: xts_params.short_app_id,
            src_len: len,
            src_addr: src_buf.as_ptr() as u64,
            dst_len: len,
            dst_addr: dst_buf.as_ptr() as u64,
            params: BulkParams::Xts(XtsParams {
                dul,
                key_id1: xts_params.key_id1,
                key_id2: xts_params.key_id2,
                tweak: xts_params.tweak,
            }),
        };
        let (cqe, dst, _) = self.bulk_submit(&sqe, src_buf.to_vec(), Vec::new())?;
        let data_len = cqe.data_len as usize;
        if data_len > src_buf.len() {
            Err(DdiError::DdiStatus(DdiStatus::InternalError))?;
        }

        dst_buf[..data_len].copy_from_slice(&dst[..data_len]);
        *fips_approved = cqe.fips_approved;
        Ok(data_len)
    }

    fn exec_op_fp_xts(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesXtsResult, DdiError> {
        let mut data = vec![0u8; src_buf.len()];
        let mut fips_approved = false;
        let len =
            self.exec_op_fp_xts_slice(mode, xts_params, &src_buf, &mut data, &mut fips_approved)?;
        data.truncate(len);
        Ok(DdiAesXtsResult {
            data,
            fips_approved,
        })
    }

    fn erase(&self) -> Result<(), DdiError> {
        if self.retired.load(Ordering::Acquire) {
            return Err(self.retired_err());
        }
        let mut stream = self.stream.lock();
        // See `exchange`'s matching recheck: a cleanup on another clone
        // may have retired the connection after the check above but
        // before this lock was acquired.
        if self.retired.load(Ordering::Acquire) {
            return Err(self.retired_err());
        }
        RequestFrame::Reset
            .write_to(&mut *stream)
            .map_err(map_proto_err)?;
        match ResponseFrame::read_from(&mut *stream).map_err(map_proto_err)? {
            ResponseFrame::Reset { status: 0 } => Ok(()),
            ResponseFrame::Reset { status } => Err(DdiError::DdiError(status)),
            ResponseFrame::Submit(_) => Err(map_proto_err(ProtoError::Malformed(
                "expected reset response",
            ))),
        }
    }
}

fn bulk_dir(mode: DdiAesOp) -> BulkDir {
    if mode == DdiAesOp::Encrypt {
        BulkDir::Encrypt
    } else {
        BulkDir::Decrypt
    }
}

fn invalid_data(msg: &'static str) -> DdiError {
    DdiError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidData, msg))
}

/// Map a wire-protocol error to a [`DdiError`].
fn map_proto_err(e: ProtoError) -> DdiError {
    match e {
        ProtoError::Io(io) => DdiError::IoError(io),
        other => DdiError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            other.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use tsra_ddi_mbor_codec::MborByteArray;
    #[cfg(unix)]
    use tsra_ddi_mbor_codec::MborMap;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiDerPublicKey;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiEncryptedSessionCredential;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiKeyType;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiOpenSessionCmdReq;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiOpenSessionCmdResp;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiOpenSessionReq;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiOpenSessionResp;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiReopenSessionCmdReq;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiReopenSessionCmdResp;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiReopenSessionReq;
    #[cfg(unix)]
    use tsra_ddi_mbor_types::DdiReopenSessionResp;

    use super::*;

    /// A `ReopenSession` response is only trusted when both the shared
    /// header and the op-specific body independently confirm the exact
    /// id that was requested; a mismatch or a missing id in either place
    /// must not be mistaken for confirmation (see `exec_op_mbor`'s use
    /// of this to gate returning the response to the caller).
    #[test]
    fn reopen_identity_confirmed_requires_both_ids_to_match_requested() {
        // Both ids match: confirmed.
        assert!(reopen_identity_confirmed(Some(9), Some(9), Some(9)));
        // Header mismatches the requested id: not confirmed, even though
        // the body matches.
        assert!(!reopen_identity_confirmed(Some(9), Some(1), Some(9)));
        // Body mismatches the requested id: not confirmed, even though
        // the header matches.
        assert!(!reopen_identity_confirmed(Some(9), Some(9), Some(1)));
        // Header id entirely missing: not confirmed.
        assert!(!reopen_identity_confirmed(Some(9), None, Some(9)));
        // Body id entirely missing: not confirmed.
        assert!(!reopen_identity_confirmed(Some(9), Some(9), None));
        // No id was requested at all: trivially confirmed (nothing to
        // check against).
        assert!(reopen_identity_confirmed(None, Some(9), Some(9)));
    }

    /// An `OpenSession` response is only trusted when the shared header
    /// and the op-specific body independently report the *same*
    /// server-assigned id; unlike `ReopenSession` there's no requested id
    /// to check against (see `exec_op_mbor`'s use of this to gate
    /// returning the new session to the caller).
    #[test]
    fn open_identity_confirmed_requires_matching_non_empty_ids() {
        // Both ids agree: confirmed.
        assert!(open_identity_confirmed(Some(9), Some(9)));
        // Header and body disagree: not confirmed.
        assert!(!open_identity_confirmed(Some(9), Some(1)));
        // Header id missing entirely: not confirmed, even if the body
        // reports one.
        assert!(!open_identity_confirmed(None, Some(9)));
        // Body id missing entirely: not confirmed, even if the header
        // reports one.
        assert!(!open_identity_confirmed(Some(9), None));
        // Neither id present: not confirmed.
        assert!(!open_identity_confirmed(None, None));
    }

    /// Best-effort cleanup after an unconfirmed `OpenSession` response
    /// must only target an id when exactly one source reported it; a
    /// header/body disagreement is ambiguous and must not be guessed at,
    /// since the header's id could be an existing session this connection
    /// already owns rather than the one actually leaked.
    #[test]
    fn open_session_leaked_id_only_trusts_a_lone_report() {
        // Header omitted, body reported: close the body's id.
        assert_eq!(open_session_leaked_id(None, Some(9)), Some(9));
        // Body omitted, header reported: close the header's id.
        assert_eq!(open_session_leaked_id(Some(5), None), Some(5));
        // Both present but disagreeing: ambiguous, don't guess.
        assert_eq!(open_session_leaked_id(Some(5), Some(9)), None);
        // Neither present: nothing to clean up.
        assert_eq!(open_session_leaked_id(None, None), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(unsafe_code)]
    fn vsock_write_does_not_raise_sigpipe() {
        const CHILD_ENV: &str = "TSRA_TEST_VSOCK_SIGPIPE_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args(["--exact", "dev::tests::vsock_write_does_not_raise_sigpipe"])
                .env(CHILD_ENV, "1")
                .output()
                .expect("run child test");
            assert!(
                output.status.success(),
                "child failed: {:?}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        // SAFETY: This is an isolated child process; no other test's signal
        // disposition is changed, and SIG_DFL does not install a Rust handler.
        unsafe {
            nix::sys::signal::signal(
                nix::sys::signal::Signal::SIGPIPE,
                nix::sys::signal::SigHandler::SigDfl,
            )
        }
        .expect("restore native application's default SIGPIPE disposition");

        use std::os::fd::IntoRawFd;

        let (client, peer) = UnixStream::pair().expect("socket pair");
        drop(peer);
        // Exercise the same send syscall without requiring a VSOCK-capable host.
        let mut stream = VsockStream {
            fd: client.into_raw_fd(),
        };
        assert_eq!(
            stream
                .write(b"request")
                .expect_err("peer disconnected")
                .kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(unsafe_code)]
    fn vsock_set_timeout_clamps_sub_microsecond_duration_to_nonzero() {
        use std::os::fd::IntoRawFd;

        let (client, _peer) = UnixStream::pair().expect("socket pair");
        let mut stream = VsockStream {
            fd: client.into_raw_fd(),
        };
        stream
            .set_timeout(libc::SO_RCVTIMEO, Some(Duration::from_nanos(1)))
            .expect("set timeout");

        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        // SAFETY: `stream.fd` is a valid, open socket; `tv`/`len` are a
        // valid, correctly sized out-param pair for `getsockopt`.
        let ret = unsafe {
            libc::getsockopt(
                stream.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of_mut!(tv).cast(),
                &mut len,
            )
        };
        assert_eq!(
            ret,
            0,
            "getsockopt failed: {}",
            std::io::Error::last_os_error()
        );
        // A 1ns request must not round down to an all-zero timeval, since
        // the kernel treats that identically to `None` (disable the
        // timeout, block indefinitely) rather than "expire immediately".
        assert!(
            tv.tv_sec != 0 || tv.tv_usec != 0,
            "sub-microsecond timeout was clamped to the all-zero 'no timeout' value"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_stream_preserves_request_response_framing() {
        let (client, mut server) = UnixStream::pair().expect("socket pair");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("read timeout");
        let device = DdiSockDev {
            stream: Arc::new(Mutex::new(SocketStream::Unix(client))),
            cmd_counter: Arc::new(AtomicU16::new(1)),
            device_kind: DdiDeviceKind::Physical,
            retired: Arc::new(AtomicBool::new(false)),
            retired_cause: Arc::new(Mutex::new(None)),
        };
        let peer = std::thread::spawn(move || {
            let request = Request::read_from(&mut server).expect("request");
            assert_eq!(request.payload, b"request");
            assert_eq!(request.sqe[6], DST_CAP);
            Response {
                status: 0,
                cqe: vec![8, 0, 0, 0],
                payload: b"response".to_vec(),
                oob_items: Vec::new(),
                tail: Vec::new(),
            }
            .write_to(&mut server)
            .expect("response");
        });
        assert_eq!(
            device
                .submit(OP_MBOR, 0, None, b"request".to_vec(), Vec::new())
                .expect("submit")
                .0,
            b"response"
        );
        peer.join().expect("peer");
    }

    /// A best-effort leaked-session cleanup whose exchange fails for any
    /// reason — not only `CLEANUP_TIMEOUT` — must retire the connection
    /// rather than report it reusable: a response that failed partway
    /// through (e.g. one whose framing was never fully consumed) can
    /// leave unread bytes behind that the *next* exchange would
    /// otherwise misread as its own response. Dropping the peer makes
    /// the cleanup's write fail immediately with a non-timeout I/O
    /// error, exercising exactly that "ordinary error, no timeout"
    /// path.
    #[cfg(unix)]
    #[test]
    fn close_leaked_session_retires_on_any_cleanup_error_not_just_timeout() {
        let (client, server) = UnixStream::pair().expect("socket pair");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("read timeout");
        // Close the peer so the cleanup's write fails immediately
        // rather than blocking or timing out.
        drop(server);
        let mut stream = SocketStream::Unix(client);
        let outcome = DdiSockDev::close_leaked_session_locked(&mut stream, 1, false, 7);
        assert!(
            matches!(outcome, CloseLeakedSessionOutcome::Unusable(_)),
            "a non-timeout cleanup error must still retire the connection"
        );
    }

    /// `retired_err` must describe the actual cleanup failure that
    /// caused a connection to be retired, not a flat "timeout" message
    /// that would misdirect anyone diagnosing a non-timeout cleanup
    /// error (see `close_leaked_session_retires_on_any_cleanup_error_not_just_timeout`).
    #[cfg(unix)]
    #[test]
    fn retired_err_reports_the_recorded_cleanup_cause() {
        let device = DdiSockDev {
            stream: Arc::new(Mutex::new(SocketStream::Unix(
                UnixStream::pair().expect("socket pair").0,
            ))),
            cmd_counter: Arc::new(AtomicU16::new(1)),
            device_kind: DdiDeviceKind::Physical,
            retired: Arc::new(AtomicBool::new(false)),
            retired_cause: Arc::new(Mutex::new(None)),
        };
        device.retire("disk on fire".to_owned());
        // `DdiError::IoError`'s `Display` is the fixed string "io error"
        // (see `ddi/interface/src/error.rs`); the actual message only
        // shows up via `Debug` (through the wrapped `io::Error`'s own
        // `Debug` impl), so that's what callers trying to diagnose a
        // retired connection would actually see.
        let err = format!("{:?}", device.retired_err());
        assert!(
            err.contains("disk on fire"),
            "retired_err should surface the recorded cause, got: {err}"
        );
    }

    #[cfg(unix)]
    fn zero_byte_array<const N: usize>() -> MborByteArray<N> {
        MborByteArray::new([0u8; N], 0).expect("zero-filled byte array")
    }

    #[cfg(unix)]
    fn dummy_encrypted_session_credential() -> DdiEncryptedSessionCredential {
        DdiEncryptedSessionCredential {
            encrypted_id: zero_byte_array(),
            encrypted_pin: zero_byte_array(),
            encrypted_seed: zero_byte_array(),
            iv: zero_byte_array(),
            nonce: [0u8; 32],
            tag: [0u8; 48],
        }
    }

    #[cfg(unix)]
    fn dummy_der_public_key() -> DdiDerPublicKey {
        DdiDerPublicKey {
            der: zero_byte_array(),
            key_kind: DdiKeyType::Ecc384Public,
        }
    }

    #[cfg(unix)]
    fn dummy_open_session_req() -> DdiOpenSessionCmdReq {
        DdiOpenSessionCmdReq {
            hdr: DdiReqHdr {
                rev: None,
                op: DdiOp::OpenSession,
                sess_id: None,
            },
            data: DdiOpenSessionReq {
                encrypted_credential: dummy_encrypted_session_credential(),
                pub_key: dummy_der_public_key(),
            },
            ext: None,
        }
    }

    #[cfg(unix)]
    fn dummy_reopen_session_req(session_id: u16) -> DdiReopenSessionCmdReq {
        DdiReopenSessionCmdReq {
            hdr: DdiReqHdr {
                rev: None,
                op: DdiOp::ReopenSession,
                sess_id: Some(session_id),
            },
            data: DdiReopenSessionReq {
                encrypted_credential: dummy_encrypted_session_credential(),
                pub_key: dummy_der_public_key(),
                bmk_session: zero_byte_array(),
            },
            ext: None,
        }
    }

    /// Builds a `Virtual` device (so `exec_op_mbor` skips the
    /// `Physical`-only pre-encode/post-decode hooks that would otherwise
    /// require a real DER-encoded ECC key) backed by one end of a
    /// `UnixStream` pair, returning the device and the other end to
    /// drive as the fake peer.
    #[cfg(unix)]
    fn virtual_device_with_peer() -> (DdiSockDev, UnixStream) {
        let (client, server) = UnixStream::pair().expect("socket pair");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let device = DdiSockDev {
            stream: Arc::new(Mutex::new(SocketStream::Unix(client))),
            cmd_counter: Arc::new(AtomicU16::new(1)),
            device_kind: DdiDeviceKind::Virtual,
            retired: Arc::new(AtomicBool::new(false)),
            retired_cause: Arc::new(Mutex::new(None)),
        };
        (device, server)
    }

    /// MBOR-encodes `resp` the same way `exec_op_mbor` would decode it:
    /// a full `CmdResp` map (`hdr`/`data`/optional `ext`).
    #[cfg(unix)]
    fn encode_cmd_resp<R: MborEncode>(resp: &R) -> Vec<u8> {
        let mut buf = vec![0u8; DST_CAP as usize];
        let len = {
            let mut enc = MborEncoder::new(buf.as_mut_slice(), false);
            resp.mbor_encode(&mut enc).expect("encode response");
            enc.position()
        };
        buf.truncate(len);
        buf
    }

    #[cfg(unix)]
    fn write_mbor_response(server: &mut UnixStream, payload: Vec<u8>) {
        let dst_len = payload.len() as u32;
        Response {
            status: 0,
            cqe: vec![dst_len, 0, 0, 0],
            payload,
            oob_items: Vec::new(),
            tail: Vec::new(),
        }
        .write_to(server)
        .expect("write response");
    }

    /// An `OpenSession` response whose header omits the new session's
    /// id (while the body independently reports one) is treated the
    /// same as any other header/body identity mismatch: the response is
    /// rejected, and the id the body alone reported is best-effort
    /// closed as a leaked session (see `open_session_leaked_id`). When
    /// that cleanup succeeds, the connection stays usable.
    #[cfg(unix)]
    #[test]
    fn exec_op_mbor_rejects_open_session_missing_header_id_and_cleans_up_leaked_session() {
        let (device, mut server) = virtual_device_with_peer();
        let peer = std::thread::spawn(move || {
            let _request = Request::read_from(&mut server).expect("open session request");
            let resp = DdiOpenSessionCmdResp {
                hdr: DdiRespHdr {
                    rev: None,
                    op: DdiOp::OpenSession,
                    sess_id: None,
                    status: DdiStatus::Success,
                    fips_approved: false,
                },
                data: DdiOpenSessionResp {
                    sess_id: 7,
                    short_app_id: 0,
                    bmk_session: zero_byte_array(),
                },
                ext: None,
            };
            write_mbor_response(&mut server, encode_cmd_resp(&resp));

            // Expect the best-effort cleanup to close the id the body
            // alone reported, and answer it successfully.
            let cleanup = Request::read_from(&mut server).expect("cleanup close request");
            assert_eq!(
                cleanup.sqe[12] & 0xffff,
                7,
                "cleanup must target the body's leaked id"
            );
            write_mbor_response(&mut server, Vec::new());
        });

        let req = dummy_open_session_req();
        let result = device.exec_op_mbor(&req, &mut None);
        assert!(
            matches!(result, Err(DdiError::MborError(MborError::DecodeError))),
            "expected a decode error for a missing open-session header id, got {result:?}"
        );
        assert!(
            !device.retired.load(Ordering::Acquire),
            "a successful cleanup must not retire the connection"
        );
        peer.join().expect("peer");
    }

    /// A `ReopenSession` response whose header and body both report an
    /// id other than the one requested must be rejected as
    /// `SessionNotFound` — unlike `OpenSession`, there's no best-effort
    /// cleanup here, since the requested session (not whatever the peer
    /// echoed back) is the only id this call has any business touching.
    #[cfg(unix)]
    #[test]
    fn exec_op_mbor_rejects_reopen_session_with_mismatched_ids() {
        let (device, mut server) = virtual_device_with_peer();
        let peer = std::thread::spawn(move || {
            let _request = Request::read_from(&mut server).expect("reopen session request");
            let resp = DdiReopenSessionCmdResp {
                hdr: DdiRespHdr {
                    rev: None,
                    op: DdiOp::ReopenSession,
                    sess_id: Some(9),
                    status: DdiStatus::Success,
                    fips_approved: false,
                },
                data: DdiReopenSessionResp {
                    sess_id: 1,
                    short_app_id: 0,
                    bmk_session: zero_byte_array(),
                },
                ext: None,
            };
            write_mbor_response(&mut server, encode_cmd_resp(&resp));
        });

        let req = dummy_reopen_session_req(9);
        let result = device.exec_op_mbor(&req, &mut None);
        assert!(
            matches!(result, Err(DdiError::DdiStatus(DdiStatus::SessionNotFound))),
            "expected SessionNotFound for mismatched reopen-session ids, got {result:?}"
        );
        assert!(!device.retired.load(Ordering::Acquire));
        peer.join().expect("peer");
    }

    /// A response whose header decodes successfully (reporting a new
    /// session as opened) but whose body is undecodable must still be
    /// rejected as a decode error, and the leaked session it reported
    /// best-effort closed. When that cleanup itself fails, the
    /// connection must be retired rather than left reusable (see
    /// `close_leaked_session_locked`).
    #[cfg(unix)]
    #[test]
    fn exec_op_mbor_retires_connection_when_undecodable_open_session_body_cleanup_fails() {
        let (device, mut server) = virtual_device_with_peer();
        let peer = std::thread::spawn(move || {
            let _request = Request::read_from(&mut server).expect("open session request");

            // Hand-encode a response whose header is valid but whose
            // body entry is a bare bool rather than the nested
            // `DdiOpenSessionResp` map the full `CmdResp` decode
            // expects -- a type mismatch that `decode_hdr` never
            // notices (it only reads the header), but the full body
            // decode rejects.
            let mut buf = vec![0u8; DST_CAP as usize];
            let len = {
                let mut enc = MborEncoder::new(buf.as_mut_slice(), false);
                MborMap(2).mbor_encode(&mut enc).expect("map marker");
                0u8.mbor_encode(&mut enc).expect("hdr key");
                DdiRespHdr {
                    rev: None,
                    op: DdiOp::OpenSession,
                    sess_id: Some(9),
                    status: DdiStatus::Success,
                    fips_approved: false,
                }
                .mbor_encode(&mut enc)
                .expect("hdr value");
                1u8.mbor_encode(&mut enc).expect("data key");
                true.mbor_encode(&mut enc).expect("bogus data value");
                enc.position()
            };
            buf.truncate(len);
            write_mbor_response(&mut server, buf);
            // Drop the peer instead of answering the best-effort
            // cleanup this triggers, so the cleanup fails and the
            // connection is retired.
        });

        let req = dummy_open_session_req();
        let result = device.exec_op_mbor(&req, &mut None);
        assert!(
            matches!(result, Err(DdiError::MborError(MborError::DecodeError))),
            "expected a decode error for an undecodable open-session body, got {result:?}"
        );
        assert!(
            device.retired.load(Ordering::Acquire),
            "a failed cleanup must retire the connection"
        );
        peer.join().expect("peer");
    }

    #[test]
    fn tcp_stream_preserves_request_response_framing() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("TCP listener");
        let endpoint = format!("tcp://{}", listener.local_addr().expect("TCP address"));
        let peer = std::thread::spawn(move || {
            let (mut server, _) = listener.accept().expect("TCP connection");
            server
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("read timeout");
            for _ in 0..2 {
                let request = Request::read_from(&mut server).expect("request");
                assert_eq!(request.payload, b"request");
                assert_eq!(request.sqe[6], DST_CAP);
                Response {
                    status: 0,
                    cqe: vec![8, 0, 0, 0],
                    payload: b"response".to_vec(),
                    oob_items: Vec::new(),
                    tail: Vec::new(),
                }
                .write_to(&mut server)
                .expect("response");
            }
        });
        let device = DdiSockDev::connect(&endpoint).expect("TCP device");
        for _ in 0..2 {
            assert_eq!(
                device
                    .submit(OP_MBOR, 0, None, b"request".to_vec(), Vec::new())
                    .expect("submit")
                    .0,
                b"response"
            );
        }
        peer.join().expect("peer");
    }

    #[test]
    fn cloned_devices_share_connection_and_serialize_requests() {
        const THREADS: usize = 4;
        const REQUESTS_PER_THREAD: u8 = 8;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let endpoint = format!("tcp://{}", listener.local_addr().expect("address"));
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("read timeout");
            let mut command_ids = std::collections::HashSet::new();
            for _ in 0..THREADS * usize::from(REQUESTS_PER_THREAD) {
                let request = Request::read_from(&mut stream).expect("request");
                assert!(command_ids.insert(CmdDword::from_bits(request.sqe[0]).id()));
                Response {
                    status: 0,
                    cqe: vec![request.payload.len() as u32, 0, 0, 0],
                    payload: request.payload,
                    oob_items: Vec::new(),
                    tail: Vec::new(),
                }
                .write_to(&mut stream)
                .expect("response");
            }
            assert_eq!(stream.read(&mut [0]).expect("last clone disconnected"), 0);
        });
        let device = DdiSockDev::connect(&endpoint).expect("device");
        let barrier = Arc::new(std::sync::Barrier::new(THREADS + 1));
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let device = device.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                for request in 0..REQUESTS_PER_THREAD {
                    let payload = vec![thread as u8, request];
                    assert_eq!(
                        device
                            .submit(OP_MBOR, 0, None, payload.clone(), Vec::new())
                            .expect("submit through clone")
                            .0,
                        payload
                    );
                }
            }));
        }
        drop(device);
        barrier.wait();
        for worker in workers {
            worker.join().expect("worker");
        }
        peer.join().expect("peer");
    }

    #[test]
    fn rejects_invalid_tcp_endpoints() {
        for endpoint in ["tcp://", "tcp://localhost", "tcp://127.0.0.1:invalid"] {
            assert!(DdiSockDev::connect(endpoint).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn tcp_transfers_oob_and_reset_on_the_same_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let endpoint = format!("tcp://{}", listener.local_addr().expect("address"));
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("read timeout");
            assert!(matches!(
                RequestFrame::read_from(&mut stream).expect("reset"),
                RequestFrame::Reset
            ));
            ResponseFrame::Reset { status: 0 }
                .write_to(&mut stream)
                .expect("reset result");
            let request = Request::read_from(&mut stream).expect("OOB request");
            assert_eq!(
                request.oob_items,
                [OobItem::In(b"first".to_vec()), OobItem::Out(6)]
            );
            assert_eq!(&request.sqe[13..=15], &[0, 0, 32]);
            for oob_items in [vec![b"output".to_vec()], vec![b"short".to_vec()]] {
                Response {
                    status: 0,
                    cqe: vec![1, 0, 0, 0],
                    payload: vec![1],
                    oob_items,
                    tail: Vec::new(),
                }
                .write_to(&mut stream)
                .expect("response");
                Request::read_from(&mut stream).expect("OOB request");
            }
            Response {
                status: 0,
                cqe: vec![1, 0, 0, 0],
                payload: vec![1],
                oob_items: Vec::new(),
                tail: Vec::new(),
            }
            .write_to(&mut stream)
            .expect("response");
            assert!(matches!(
                RequestFrame::read_from(&mut stream).expect("reset"),
                RequestFrame::Reset
            ));
            ResponseFrame::Reset { status: 2 }
                .write_to(&mut stream)
                .expect("reset failure");
        });
        let device = DdiSockDev::connect(&endpoint).expect("device");
        for items in [
            vec![OobItem::In(Vec::new())],
            vec![OobItem::Out(0)],
            vec![OobItem::In(b"item".to_vec()); MAX_OOB_ITEMS + 1],
        ] {
            assert!(matches!(
                device.submit(OP_TBOR, 0, None, vec![1], items),
                Err(DdiError::InvalidParameter)
            ));
        }
        device.erase().expect("reset");
        let items = || vec![OobItem::In(b"first".to_vec()), OobItem::Out(6)];
        assert_eq!(
            device
                .submit(OP_TBOR, 0, None, vec![1], items())
                .expect("OOB submit"),
            (vec![1], vec![b"output".to_vec()])
        );
        // An output of the wrong length, or a missing output, is rejected.
        for _ in 0..2 {
            assert!(matches!(
                device.submit(OP_TBOR, 0, None, vec![1], items()),
                Err(DdiError::IoError(error)) if error.kind() == std::io::ErrorKind::InvalidData
            ));
        }
        assert!(matches!(device.erase(), Err(DdiError::DdiError(2))));
        peer.join().expect("peer");
    }

    #[cfg(not(unix))]
    #[test]
    fn unix_paths_are_unsupported() {
        assert!(matches!(
            DdiSockDev::connect("/tmp/tsra-ddi.sock"),
            Err(DdiError::IoError(error)) if error.kind() == std::io::ErrorKind::Unsupported
        ));
    }

    #[test]
    fn parses_vsock_endpoint() {
        assert_eq!(
            parse_vsock_endpoint("vsock://4:1234").expect("valid VSOCK endpoint"),
            Some((4, 1234))
        );
        assert_eq!(
            parse_vsock_endpoint("/tmp/ddi.sock").expect("valid Unix path"),
            None
        );
    }

    #[test]
    fn rejects_invalid_vsock_endpoint() {
        for endpoint in [
            "vsock://",
            "vsock://4",
            "vsock://:1234",
            "vsock://4:",
            "vsock://x:1234",
            "vsock://4:0",
            "vsock://4:1234:5",
        ] {
            assert!(parse_vsock_endpoint(endpoint).is_err(), "{endpoint}");
        }
    }
}
