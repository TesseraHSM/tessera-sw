// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Socket DDI transport — device handle and request execution.

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::sync::Arc;

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
use tsra_ddi_mbor_codec::MborEncoder;
use tsra_ddi_mbor_types::DdiAesOp;
use tsra_ddi_mbor_types::DdiDecoder;
use tsra_ddi_mbor_types::DdiDeviceKind;
use tsra_ddi_mbor_types::DdiOpReq;
use tsra_ddi_mbor_types::DdiRespHdr;
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
        })
    }

    fn next_cmd_id(&self) -> u16 {
        self.cmd_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Exchange one submission with the server.
    ///
    /// Maps a nonzero transport status to a [`DdiError`].
    fn exchange(&self, req: &Request) -> DdiResult<Response> {
        let resp: Response = {
            let mut stream = self.stream.lock();
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

    /// Build a submission entry, exchange it with the server, and return
    /// the response body bytes plus the bytes of each [`OobItem::Out`].
    ///
    /// Mirrors the in-process emulator: the client constructs the SQE
    /// (opcode, command id, lengths, session flags) and reads the returned
    /// CQE; the server only re-homes the DMA buffers. The SQE's PRP
    /// address fields are left zero — the server assigns them.
    ///
    /// Maps a nonzero transport status (header) or device status (CQE) to
    /// [`DdiError::DdiError`].
    fn submit(
        &self,
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
        let cmd_id = self.next_cmd_id();
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
        let resp = self.exchange(&req)?;

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

        // ── 2. Build the SQE and exchange it over the socket.
        let (resp_buf, _) =
            self.submit(OP_MBOR, u8::from(session_ctrl), session_id, buf, Vec::new())?;
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

        // ── 4. Decode the typed response (header + body).
        let mut body_dec = MborDecoder::new(&resp_buf, post_decode);
        <T::OpResp>::mbor_decode(&mut body_dec)
            .map_err(|_| DdiError::MborError(MborError::DecodeError))
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
        let mut stream = self.stream.lock();
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
    use super::*;

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
            stream: Arc::new(Mutex::new(SocketStream::Unix(client))),
            cmd_counter: Arc::new(AtomicU16::new(1)),
            device_kind: DdiDeviceKind::Physical,
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
