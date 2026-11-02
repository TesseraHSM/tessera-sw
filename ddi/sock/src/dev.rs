// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Socket DDI transport — device handle and request execution.

use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

#[cfg(target_os = "linux")]
use nix::sys::socket::connect;
#[cfg(target_os = "linux")]
use nix::sys::socket::send;
#[cfg(target_os = "linux")]
use nix::sys::socket::shutdown as nix_shutdown;
#[cfg(target_os = "linux")]
use nix::sys::socket::socket;
#[cfg(target_os = "linux")]
use nix::sys::socket::AddressFamily;
#[cfg(target_os = "linux")]
use nix::sys::socket::MsgFlags;
#[cfg(target_os = "linux")]
use nix::sys::socket::Shutdown as NixShutdown;
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
use tsra_ddi_mbor_codec::MborDecode;
use tsra_ddi_mbor_codec::MborDecoder;
use tsra_ddi_mbor_codec::MborEncode;
use tsra_ddi_mbor_codec::MborEncoder;
use tsra_ddi_mbor_types::DdiAesOp;
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
use tsra_ddi_sock_proto::ProtoError;
use tsra_ddi_sock_proto::Request;
use tsra_ddi_sock_proto::Response;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::TborResp;
use tsra_fw_hsm_io::CmdDword;
use tsra_fw_hsm_io::Cqe;
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

/// Response buffer capacity advertised to the server. Fits MBOR and the
/// current TBOR command set; larger responses are future work.
const DST_CAP: u32 = 4096;

enum SocketStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(target_os = "linux")]
    Vsock(VsockStream),
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

impl SocketStream {
    /// Shut down both directions of the connection, so the peer observes
    /// a disconnect before [`DdiSockDev::erase`] dials its replacement
    /// connection (see the call site for why this ordering matters).
    fn shutdown(&self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Both),
            #[cfg(unix)]
            Self::Unix(stream) => stream.shutdown(Shutdown::Both),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => stream.shutdown(),
        }
    }
}

#[cfg(target_os = "linux")]
struct VsockStream {
    fd: std::os::fd::RawFd,
}

#[cfg(target_os = "linux")]
impl VsockStream {
    fn connect(cid: u32, port: u32) -> std::io::Result<Self> {
        let fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(std::io::Error::from)?;

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
impl VsockStream {
    /// Shut down both directions of the connection without invalidating
    /// the underlying fd (the [`Drop`] impl still closes it).
    fn shutdown(&self) -> std::io::Result<()> {
        nix_shutdown(self.fd, NixShutdown::Both).map_err(std::io::Error::from)
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

/// Dial `path` (a Unix socket path, `tcp://HOST:PORT`, or
/// `vsock://CID:PORT` endpoint) and return the resulting stream.
///
/// Factored out of [`DdiSockDev::connect`] so [`DdiSockDev::erase`] can
/// redial the same endpoint without duplicating the transport-selection
/// logic.
fn connect_stream(path: &str) -> DdiResult<SocketStream> {
    if let Some(address) = path.strip_prefix("tcp://") {
        let stream = TcpStream::connect(address).map_err(DdiError::IoError)?;
        stream.set_nodelay(true).map_err(DdiError::IoError)?;
        Ok(SocketStream::Tcp(stream))
    } else {
        match parse_vsock_endpoint(path).map_err(DdiError::IoError)? {
            Some((cid, port)) => {
                #[cfg(target_os = "linux")]
                {
                    Ok(SocketStream::Vsock(
                        VsockStream::connect(cid, port).map_err(DdiError::IoError)?,
                    ))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (cid, port);
                    Err(DdiError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "vsock endpoints require Linux",
                    )))
                }
            }
            None => {
                #[cfg(unix)]
                {
                    Ok(SocketStream::Unix(
                        UnixStream::connect(path).map_err(DdiError::IoError)?,
                    ))
                }
                #[cfg(not(unix))]
                {
                    Err(DdiError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "this platform requires a tcp://HOST:PORT endpoint",
                    )))
                }
            }
        }
    }
}

/// A connected socket DDI device.
///
/// Wraps a single TCP, Unix-domain, or Linux VSOCK connection to the server. Requests
/// are serialized through a mutex, so the synchronous trait methods can be
/// shared across threads while each request/response exchange stays atomic.
pub struct DdiSockDev {
    stream: Mutex<SocketStream>,
    cmd_counter: AtomicU16,
    device_kind: DdiDeviceKind,
    /// The endpoint originally passed to [`Self::connect`], retained so
    /// [`Self::erase`] can redial the same server after disconnecting.
    path: String,
}

impl std::fmt::Debug for DdiSockDev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdiSockDev")
            .field("device_kind", &self.device_kind)
            .finish_non_exhaustive()
    }
}

impl DdiSockDev {
    /// Connect to the server at `path`.
    pub(crate) fn connect(path: &str) -> DdiResult<Self> {
        let stream = connect_stream(path)?;
        Ok(Self {
            stream: Mutex::new(stream),
            cmd_counter: AtomicU16::new(1),
            // The firmware reports a physical device, so the host codec
            // runs its physical-mode encode/decode hooks (matching emu).
            device_kind: DdiDeviceKind::Physical,
            path: path.to_owned(),
        })
    }

    fn next_cmd_id(&self) -> u16 {
        self.cmd_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Build a submission entry, exchange it with the server, and return
    /// the response body bytes.
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
    ) -> DdiResult<Vec<u8>> {
        let cmd_id = self.next_cmd_id();
        let mut stream = self.stream.lock();
        Self::submit_locked(&mut stream, cmd_id, op, session_ctrl, session_id, payload)
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
    fn submit_locked(
        stream: &mut SocketStream,
        cmd_id: u16,
        op: u16,
        session_ctrl: u8,
        session_id: Option<u16>,
        payload: Vec<u8>,
    ) -> DdiResult<Vec<u8>> {
        let sqe = SqeBuilder::new()
            .cmd(CmdDword::new().with_op(op).with_id(cmd_id))
            .buf_lens(payload.len() as u32, DST_CAP)
            .session_flags(
                SessionFlags::new()
                    .with_ctrl(session_ctrl)
                    .with_id_valid(session_id.is_some()),
            )
            .session_id(session_id.unwrap_or(0))
            .build();

        let req = Request {
            sqe,
            payload,
            oob: Vec::new(),
        };

        let resp: Response = {
            req.write_to(&mut *stream).map_err(map_proto_err)?;
            Response::read_from(&mut *stream).map_err(map_proto_err)?
        };

        // Transport-level status (e.g. server DMA allocation failure).
        if resp.status != 0 {
            return Err(DdiError::DdiError(resp.status));
        }

        // Device-level status lives in the completion entry.
        let mut cqe_raw = resp.cqe;
        let cqe = Cqe::from(&mut cqe_raw);
        if cqe.status() != 0 {
            return Err(DdiError::DdiError(u32::from(cqe.status())));
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
            return Err(DdiError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CQE dst_len exceeds requested destination capacity",
            )));
        }
        if payload.len() < dst_len {
            // The server returned fewer bytes than the firmware reported
            // writing: a transport/protocol integrity failure, not a device
            // status. Surface it as malformed data rather than a `0` (success)
            // device status, matching the other protocol-shape errors here.
            return Err(DdiError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response payload shorter than CQE dst_len",
            )));
        }
        payload.truncate(dst_len);
        Ok(payload)
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
    /// Errors are intentionally discarded by the caller: this is a
    /// best-effort reclaim on top of an already-failing exchange, and the
    /// original error is what should surface to the caller either way.
    fn close_leaked_session_locked(
        stream: &mut SocketStream,
        cmd_id: u16,
        pre_encode: bool,
        leaked_id: u16,
    ) -> DdiResult<()> {
        let req = DdiCloseSessionCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::CloseSession,
                sess_id: Some(leaked_id),
                rev: None,
            },
            data: DdiCloseSessionReq {},
            ext: None,
        };

        let mut buf = vec![0u8; DST_CAP as usize];
        let req_len = {
            let mut enc = MborEncoder::new(buf.as_mut_slice(), pre_encode);
            req.mbor_encode(&mut enc)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?;
            enc.position()
        };
        buf.truncate(req_len);

        Self::submit_locked(
            stream,
            cmd_id,
            OP_MBOR,
            u8::from(SessionControlKind::Close),
            Some(leaked_id),
            buf,
        )?;
        Ok(())
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

impl DdiDev for DdiSockDev {
    fn device_kind(&self) -> DdiDeviceKind {
        self.device_kind
    }

    fn exec_op_mbor<T: DdiOpReq>(
        &self,
        req: &T,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        let (pre_encode, post_decode) = match self.device_kind {
            DdiDeviceKind::Physical => (true, true),
            _ => (false, false),
        };

        // ── 1. Encode the DDI request via host MBOR (wire-compat with fw).
        let opcode = req.get_opcode();
        let session_ctrl: SessionControlKind = opcode.into();
        let session_id = req.get_session_id();

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
        //    leaked-session close (step 3/4 below) can reuse the same
        //    stream without an intervening request from another caller.
        let cmd_id = self.next_cmd_id();
        let mut stream = self.stream.lock();
        let resp_buf = Self::submit_locked(
            &mut stream,
            cmd_id,
            OP_MBOR,
            u8::from(session_ctrl),
            session_id,
            buf,
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
                        let _ = Self::close_leaked_session_locked(
                            &mut stream,
                            self.next_cmd_id(),
                            pre_encode,
                            leaked_id,
                        );
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
            if let Some(leaked_id) = hdr.sess_id {
                let _ = Self::close_leaked_session_locked(
                    &mut stream,
                    self.next_cmd_id(),
                    pre_encode,
                    leaked_id,
                );
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
        // The wire protocol has a channel for out-of-band SGL descriptor
        // pages (see `tsra_ddi_sock_proto`'s OOB field and `vsocksrv`'s
        // SGL re-homing), but this client isn't wired to use it yet.
        if oob_items.is_some_and(|items| !items.is_empty()) {
            return Err(DdiError::UnsupportedEncoding);
        }

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
        let resp_buf = self.submit(OP_TBOR, u8::from(session_ctrl), session_id, buf)?;
        if resp_buf.is_empty() {
            return Err(DdiError::DdiError(0));
        }

        // ── 3. Decode the typed response.
        <T::OpResp>::decode_response(&resp_buf).map_err(Into::into)
    }

    // ── Fast-path crypto ops are not supported over the socket transport
    //    yet (v1 carries MBOR/TBOR DDI ops only). ─────────────────────

    fn exec_op_fp_gcm_slice(
        &self,
        _mode: DdiAesOp,
        _gcm_params: DdiAesGcmParams,
        _src_buf: &[u8],
        _dst_buf: &mut [u8],
        _tag: &mut Option<[u8; 16]>,
        _iv: &mut Option<[u8; 12]>,
        _fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))
    }

    fn exec_op_fp_gcm(
        &self,
        _mode: DdiAesOp,
        _gcm_params: DdiAesGcmParams,
        _src_buf: Vec<u8>,
    ) -> Result<DdiAesGcmResult, DdiError> {
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))
    }

    fn exec_op_fp_xts(
        &self,
        _mode: DdiAesOp,
        _xts_params: DdiAesXtsParams,
        _src_buf: Vec<u8>,
    ) -> Result<DdiAesXtsResult, DdiError> {
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))
    }

    fn exec_op_fp_xts_slice(
        &self,
        _mode: DdiAesOp,
        _xts_params: DdiAesXtsParams,
        _src_buf: &[u8],
        _dst_buf: &mut [u8],
        _fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))
    }

    fn erase(&self) -> Result<(), DdiError> {
        // There's no in-band SQE/CQE opcode for a factory reset over this
        // transport. Instead, shut down the current connection and dial
        // a fresh one to the same endpoint: a server that ties partition
        // reset to connection loss (e.g. `vsocksrv`) sees the disconnect
        // and resets before the replacement connection is established.
        let mut stream = self.stream.lock();
        // Best-effort: a peer that already closed its end can make this
        // fail, but the subsequent reconnect is what actually matters.
        let _ = stream.shutdown();
        *stream = connect_stream(&self.path)?;
        Ok(())
    }
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

    #[cfg(unix)]
    #[test]
    fn unix_stream_preserves_request_response_framing() {
        let (client, mut server) = UnixStream::pair().expect("socket pair");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("read timeout");
        let device = DdiSockDev {
            stream: Mutex::new(SocketStream::Unix(client)),
            cmd_counter: AtomicU16::new(1),
            device_kind: DdiDeviceKind::Physical,
            path: String::new(),
        };
        let peer = std::thread::spawn(move || {
            let request = Request::read_from(&mut server).expect("request");
            assert_eq!(request.payload, b"request");
            assert_eq!(request.sqe[6], DST_CAP);
            Response {
                status: 0,
                cqe: [8, 0, 0, 0],
                payload: b"response".to_vec(),
            }
            .write_to(&mut server)
            .expect("response");
        });
        assert_eq!(
            device
                .submit(OP_MBOR, 0, None, b"request".to_vec())
                .expect("submit"),
            b"response"
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
                    cqe: [8, 0, 0, 0],
                    payload: b"response".to_vec(),
                }
                .write_to(&mut server)
                .expect("response");
            }
        });
        let device = DdiSockDev::connect(&endpoint).expect("TCP device");
        for _ in 0..2 {
            assert_eq!(
                device
                    .submit(OP_MBOR, 0, None, b"request".to_vec())
                    .expect("submit"),
                b"response"
            );
        }
        peer.join().expect("peer");
    }

    #[test]
    fn rejects_invalid_tcp_endpoints() {
        for endpoint in ["tcp://", "tcp://localhost", "tcp://127.0.0.1:invalid"] {
            assert!(DdiSockDev::connect(endpoint).is_err(), "{endpoint}");
        }
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
