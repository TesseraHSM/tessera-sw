// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - TSRA Emulator - Device Module.

// Allowed because the page-aligned scratch buffer below uses the unsafe
// `std::alloc` interface and raw-pointer slice construction. The unsafe
// surface is contained to [`AlignedBuf`] and the SQE pointer encoding.
#![allow(unsafe_code)]

use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use parking_lot::Condvar;
use parking_lot::Mutex;
use parking_lot::RwLock;
use tokio::runtime::Handle;
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
use tsra_ddi_mbor_types::DdiApiRev;
use tsra_ddi_mbor_types::DdiCloseSessionCmdReq;
use tsra_ddi_mbor_types::DdiCloseSessionReq;
use tsra_ddi_mbor_types::DdiDecoder;
use tsra_ddi_mbor_types::DdiDeviceKind;
use tsra_ddi_mbor_types::DdiOp;
use tsra_ddi_mbor_types::DdiOpReq;
use tsra_ddi_mbor_types::DdiOpenSessionCmdResp;
use tsra_ddi_mbor_types::DdiReqHdr;
use tsra_ddi_mbor_types::DdiRespHdr;
use tsra_ddi_mbor_types::DdiStatus;
use tsra_ddi_mbor_types::MborError;
use tsra_ddi_mbor_types::SessionControlKind;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::TborResp;
use tsra_ddi_tbor_types::TborStatus;
use tsra_fw_hsm_bulk::BulkCqe;
use tsra_fw_hsm_bulk::BulkDir;
use tsra_fw_hsm_bulk::BulkParams;
use tsra_fw_hsm_bulk::BulkSqe;
use tsra_fw_hsm_bulk::GcmParams;
use tsra_fw_hsm_bulk::GcmTail;
use tsra_fw_hsm_bulk::XtsDul;
use tsra_fw_hsm_bulk::XtsParams;
use tsra_fw_hsm_bulk::BLOCK_LEN;
use tsra_fw_hsm_bulk::GCM_AAD_ALIGN;
use tsra_fw_hsm_io::CmdDword;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::RawSqe;
use tsra_fw_hsm_io::SessionFlags;
use tsra_fw_hsm_io::SqeBuilder;
use tsra_fw_hsm_io::OP_MBOR;
use tsra_fw_hsm_io::OP_TBOR;
use tsra_fw_hsm_std::StdHsm;

/// Path returned by [`DdiEmu::dev_info_list`](crate::DdiEmu::dev_info_list).
///
/// Pass this path to [`DdiEmu::open_dev`](crate::DdiEmu::open_dev) to open
/// the emulator device.
pub const EMU_DEVICE_PATH: &str = "/dev/tsra-emu";

/// Hard-coded partition index used by the emulator.
///
/// All IOs submitted via [`DdiEmuDev`] target this partition. Its
/// resource mask starts at this bit; see [`emu_part_res_mask`].
const EMU_PID: u8 = 10;

/// Environment variable selecting how many vault tables (resources) the
/// emulator partition is allocated. Accepts `1..=EMU_MAX_RESOURCES`;
/// defaults to 1 when unset.
pub const EMU_RESOURCE_COUNT_ENV: &str = "TSRA_EMU_RESOURCE_COUNT";

/// Number of resource bits the std platform accepts in a partition mask.
const EMU_MAX_RESOURCES: u32 = 65;

/// Resource bitmask passed to [`StdHsm::part_alloc`].
///
/// Sets `count` contiguous bits starting at [`EMU_PID`], wrapping at
/// [`EMU_MAX_RESOURCES`], so a count of 1 yields `1 << EMU_PID`.
fn emu_part_res_mask(count: u32) -> u128 {
    (0..count).fold(0u128, |mask, i| {
        mask | 1u128 << ((EMU_PID as u32 + i) % EMU_MAX_RESOURCES)
    })
}

/// Reads [`EMU_RESOURCE_COUNT_ENV`]; unset means 1.
fn emu_resource_count() -> DdiResult<u32> {
    let Ok(value) = std::env::var(EMU_RESOURCE_COUNT_ENV) else {
        return Ok(1);
    };
    match value.trim().parse::<u32>() {
        Ok(count) if (1..=EMU_MAX_RESOURCES).contains(&count) => Ok(count),
        _ => {
            tracing::error!(
                ?value,
                env = EMU_RESOURCE_COUNT_ENV,
                max = EMU_MAX_RESOURCES,
                "DdiEmuDev: invalid resource count"
            );
            Err(DdiError::InvalidParameter)
        }
    }
}

/// Size of the scratch buffers used for DDI request/response DMA.
///
/// Sized to the firmware's 8-KiB transport bound rather than a single
/// 4-KiB page. The std PAL copies to and from host memory through raw
/// pointers without checking the destination length -- it cannot, the
/// address is opaque to it -- so a response larger than this buffer is
/// written past the end of the allocation rather than rejected. At one
/// page that happened for every PQC response: ML-DSA-44 key generation
/// returns 4212 bytes, which corrupted the process heap.
///
/// The largest response the schemas allow is ML-DSA-87 key generation
/// (a 5060-byte masked key plus a 2592-byte public key and the
/// which fits here with room to spare.
const SCRATCH_LEN: usize = 8192;

/// Bulk queue id fast-path IOs are submitted on.
const EMU_BULK_QID: u16 = 1;

/// Size of one NVMe SGL Data Block descriptor in the out-of-band page.
const OOB_ENTRY_LEN: usize = 16;

/// Page size enforced by the firmware platform.
const PAGE_4K: usize = 4096;

/// Upper bound on the best-effort session close run from `Drop`.
const CLOSE_ON_DROP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Process-wide rolling SQE command identifier.
///
/// The CQE echoes back the cmd_id in `DW3 [15:0]`; we use a unique value
/// per IO mostly for diagnostic correlation.
static CMD_COUNTER: AtomicU16 = AtomicU16::new(1);

/// Quiesces IO across [`DdiEmuDev::erase`], like the driver does across
/// NSSR: IOs hold a read guard, erase holds the write guard. Without it an
/// IO racing the partition disable/enable fails with `InternalError`
/// instead of seeing either the old or the reset partition.
static RESET_FENCE: RwLock<()> = RwLock::new(());

/// Per-handle session bookkeeping.
#[derive(Debug, Default)]
struct SessionState {
    session_id: Option<u16>,
    short_app_id: Option<u8>,
}

/// DDI Implementation - TSRA Emulator device handle.
///
/// Each `DdiEmuDev` shares the process-global [`StdHsm`] and tokio runtime
/// instantiated by [`DdiEmu`](crate::DdiEmu). State that is unique to the
/// handle (the open session id) lives in [`SessionState`].
///
/// `Clone` matches the sibling backends (`DdiNixDev`, `DdiWinDev`);
/// cloning produces another handle to the same `StdHsm`
/// and shares the same session table.
#[derive(Clone, Debug)]
pub struct DdiEmuDev {
    hsm: Arc<StdHsm>,
    handle: Handle,
    session: Arc<Mutex<SessionState>>,
    device_kind: DdiDeviceKind,
}

impl DdiEmuDev {
    /// Open the emulator device.
    ///
    /// Validates the path and [`EMU_RESOURCE_COUNT_ENV`], then performs a
    /// best-effort `part_alloc` + `part_enable` for the emulator partition. Both
    /// operations are idempotent — on a second open they return errors
    /// (already allocated / already enabled), which we deliberately
    /// ignore. Real partition failures surface on the first IO.
    pub(crate) fn open(hsm: Arc<StdHsm>, handle: Handle, path: &str) -> DdiResult<Self> {
        if path != EMU_DEVICE_PATH {
            tracing::warn!(
                ?path,
                expected = EMU_DEVICE_PATH,
                "DdiEmuDev: path mismatch"
            );
            return Err(DdiError::DeviceNotFound);
        }
        let res_mask = emu_part_res_mask(emu_resource_count()?);

        // Drive partition lifecycle on the embedded runtime. The `let _`
        // pattern matches `fw/plat/std/lib/tests/echo_test.rs::ensure_io_part`.
        let _fence = RESET_FENCE.read();
        handle.block_on(async {
            let _ = hsm.part_alloc(EMU_PID, res_mask).await;
            let _ = hsm.part_enable(EMU_PID).await;
        });

        Ok(Self {
            hsm,
            handle,
            session: Arc::new(Mutex::new(SessionState::default())),
            device_kind: DdiDeviceKind::Physical,
        })
    }

    /// Drives `io` to completion while holding a read guard on
    /// [`RESET_FENCE`].
    fn block_on_io<F: std::future::Future>(&self, io: F) -> F::Output {
        let _fence = RESET_FENCE.read();
        self.handle.block_on(io)
    }

    /// Checks a fast-path session id against the handle's open session,
    /// as the driver does. The short app id is left to the firmware.
    fn validate_fp_session(&self, session_id: u16) -> Result<(), DdiError> {
        match self.session.lock().session_id {
            None => Err(DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession)),
            Some(id) if id != session_id => Err(DdiError::DdiStatus(
                DdiStatus::FileHandleSessionIdDoesNotMatch,
            )),
            Some(_) => Ok(()),
        }
    }

    /// Submits a bulk SQE and returns its CQE.
    ///
    /// The buffers referenced by `sqe` must stay alive until this returns.
    /// A failed CQE maps through [`DdiError::from_fp_status`], as the
    /// drivers' ioctl output does.
    fn bulk_submit(&self, sqe: &BulkSqe) -> Result<BulkCqe, DdiError> {
        let raw = self
            .block_on_io(self.hsm.bulk_io(sqe.encode(), EMU_PID, EMU_BULK_QID, 0))
            .map_err(|_| DdiError::DeviceNotReady)?;
        let cqe = BulkCqe::decode(&raw);
        if !cqe.status.is_success() {
            tracing::warn!(
                sts = cqe.status.sts,
                err = cqe.status.err,
                "DdiEmu bulk IO failed"
            );
        }
        if let Some(err) =
            DdiError::from_fp_status(u32::from(cqe.status.sts), u32::from(cqe.status.err))
        {
            Err(err)?
        }
        Ok(cqe)
    }

    /// Encodes `req` into `src` and builds the MBOR SQE that points the
    /// firmware at `src` (request) and `dst` (response).
    fn mbor_sqe<T: DdiOpReq>(
        req: &T,
        pre_encode: bool,
        session_ctrl: SessionControlKind,
        src: &mut AlignedBuf,
        dst: &mut AlignedBuf,
    ) -> DdiResult<RawSqe> {
        let req_len = {
            let mut enc = MborEncoder::new(src.as_mut_slice(), pre_encode);
            req.mbor_encode(&mut enc)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?;
            enc.position()
        };
        let req_buf = &src.as_slice()[..req_len];
        tracing::debug!(opcode = ?req.get_opcode(), len = req_len, "DdiEmu request (in hex): {:02x?}", req_buf);

        let req_session_id = req.get_session_id();
        let cmd_id = CMD_COUNTER.fetch_add(1, Ordering::Relaxed);
        Ok(SqeBuilder::new()
            .cmd(CmdDword::new().with_op(OP_MBOR).with_id(cmd_id))
            .buf_lens(req_len as u32, SCRATCH_LEN as u32)
            .src_prp1(req_buf.as_ptr() as u64)
            .dst_prp1(dst.as_mut_slice().as_mut_ptr() as u64)
            .session_flags(
                SessionFlags::new()
                    .with_ctrl(u8::from(session_ctrl))
                    .with_id_valid(req_session_id.is_some()),
            )
            .session_id(req_session_id.unwrap_or(0))
            .build())
    }

    /// Best-effort close of the device's live session, used on drop.
    ///
    /// The dropping thread may be tearing down its thread-locals (e.g.
    /// OpenSSL's `atexit` cleanup, or a Windows TLS destructor holding the
    /// loader lock). `Handle::block_on` needs Tokio's thread-locals and a
    /// helper thread can't start under the loader lock, so the request runs
    /// as a task that owns its buffers while this thread waits on a `std`
    /// condvar.
    fn close_live_session(&self) {
        let Some(sess_id) = self.session.lock().session_id else {
            return;
        };
        let req = DdiCloseSessionCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::CloseSession,
                sess_id: Some(sess_id),
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiCloseSessionReq {},
            ext: None,
        };
        let pre_encode = self.device_kind == DdiDeviceKind::Physical;
        let mut src = AlignedBuf::new(SCRATCH_LEN);
        let mut dst = AlignedBuf::new(SCRATCH_LEN);
        let Ok(sqe) = Self::mbor_sqe(
            &req,
            pre_encode,
            SessionControlKind::Close,
            &mut src,
            &mut dst,
        ) else {
            return;
        };

        let done = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = Arc::clone(&done);
        let hsm = Arc::clone(&self.hsm);
        let _fence = RESET_FENCE.read();
        self.handle.spawn(async move {
            let _bufs = (src, dst);
            let _ = hsm.io(sqe, EMU_PID, 0, 0).await;
            let (lock, cvar) = &*signal;
            *lock.lock() = true;
            cvar.notify_one();
        });
        let (lock, cvar) = &*done;
        let mut finished = lock.lock();
        let wait = cvar.wait_while_for(&mut finished, |done| !*done, CLOSE_ON_DROP_TIMEOUT);
        if wait.timed_out() {
            tracing::warn!(sess_id, "DdiEmu: timed out closing session on drop");
        }
        self.session.lock().session_id = None;
    }

    /// TBOR exec path — mirrors [`Self::exec_op_mbor`] but uses the
    /// TBOR codec, sets the SQE opcode to [`OP_TBOR`], and returns a
    /// fully-decoded owned response value via [`TborResp::decode_response`].
    ///
    /// `oob` lists each out-of-band item as `(host address, length)`; the
    /// caller keeps every item borrowed for the duration of the call.
    fn exec_tbor<T: TborOpReq>(&self, req: &T, oob: &[(u64, usize)]) -> DdiResult<T::OpResp> {
        // Match the native driver's per-file-descriptor session checks before
        // dispatching to firmware, whose session table is global to the HSM.
        let req_session_id = req.get_session_id();
        let current_session_id = self.session.lock().session_id;
        validate_tbor_session_request(req.session_ctrl(), req_session_id, current_session_id)?;

        // ── 1. Encode the TBOR request into a 4-KiB scratch buffer ─
        let mut src = AlignedBuf::new(SCRATCH_LEN);
        let mut dst = AlignedBuf::new(SCRATCH_LEN);

        let req_len = {
            let bytes = req.encode_request(src.as_mut_slice())?;
            bytes.len()
        };
        tracing::debug!(
            opcode = T::OPCODE,
            len = req_len,
            "DdiEmu TBOR request (in hex): {:02x?}",
            &src.as_slice()[..req_len]
        );

        // ── 1b. Build the out-of-band SGL Data Block descriptor page ─
        //
        // Each caller-supplied item becomes one 16-byte NVMe SGL Data
        // Block descriptor `addr(8, LE) ‖ length(4, LE) ‖ rsvd(3) ‖
        // type(1)=0` written into a page-aligned buffer the SQE points
        // at via `oob_prp`/`oob_len`. The device indexes descriptors by
        // position; the items are borrowed by the caller (no copy) and stay live
        // for the duration of the blocking `io` below.
        let mut oob_page = AlignedBuf::new(SCRATCH_LEN);
        let oob_len = if oob.is_empty() {
            0
        } else {
            let total = oob.len() * OOB_ENTRY_LEN;
            if total > SCRATCH_LEN {
                return Err(DdiError::InvalidParameter);
            }
            let page = oob_page.as_mut_slice();
            for (i, &(addr, len)) in oob.iter().enumerate() {
                let off = i * OOB_ENTRY_LEN;
                let len = u32::try_from(len).map_err(|_| DdiError::InvalidParameter)?;
                page[off..off + 8].copy_from_slice(&addr.to_le_bytes());
                page[off + 8..off + 12].copy_from_slice(&len.to_le_bytes());
                // bytes [off+12..off+16] stay zero: rsvd (3) +
                // SGL descriptor-type nibble 0 (Data Block).
            }
            total as u32
        };

        // ── 2. Build SQE with OP_TBOR ──────────────────────────────
        let cmd_id = CMD_COUNTER.fetch_add(1, Ordering::Relaxed);
        let session_ctrl = req.session_ctrl();
        let oob_prp = if oob_len != 0 {
            oob_page.as_slice().as_ptr() as u64
        } else {
            0
        };
        let sqe = SqeBuilder::new()
            .cmd(CmdDword::new().with_op(OP_TBOR).with_id(cmd_id))
            .buf_lens(req_len as u32, SCRATCH_LEN as u32)
            .src_prp1(src.as_slice().as_ptr() as u64)
            .dst_prp1(dst.as_mut_slice().as_mut_ptr() as u64)
            .oob_prp(oob_prp)
            .oob_len(oob_len)
            .session_flags(
                SessionFlags::new()
                    .with_ctrl(u8::from(session_ctrl))
                    .with_id_valid(req_session_id.is_some()),
            )
            .session_id(req_session_id.unwrap_or(0))
            .build();

        let mut raw_cqe = self
            .block_on_io(self.hsm.io(sqe, EMU_PID, 0, 0))
            .map_err(|_| DdiError::DeviceNotReady)?;
        let cqe = Cqe::from(&mut raw_cqe);

        // ── 3. Pre-decode CQE host status ──────────────────────────
        if cqe.status() != 0 {
            tracing::warn!(
                opcode = T::OPCODE,
                status = cqe.status(),
                "DdiEmu TBOR CQE pre-decode error"
            );
            return Err(DdiError::DdiError(cqe.status() as u32));
        }

        // ── 4. Decode the typed response ───────────────────────────
        let resp_len = cqe.dst_len() as usize;
        if resp_len == 0 {
            return Err(DdiError::DdiError(0));
        }
        let resp_buf = &dst.as_slice()[..resp_len];
        tracing::trace!(
            opcode = T::OPCODE,
            len = resp_len,
            "DdiEmu TBOR response (in hex): {:02x?}",
            resp_buf
        );

        // `decode_response` returns `DecodeError::FwError` on a non-`Success`
        // firmware status, so decoding first gates session tracking on
        // success: a failed command must not change the tracked session id —
        // a rejected `SessionClose` leaves the session live, so its id must
        // stay tracked for the close-on-drop retry.
        let resp = <T::OpResp>::decode_response(resp_buf).map_err(DdiError::from)?;

        // Update session tracking on Open / Close success, mirroring
        // `exec_op_mbor`.  The firmware allocates the session id and returns
        // it in the `SessionOpenInit` response — the TBOR analog of MBOR's
        // `hdr.sess_id`, carried here as a `SessionId` TOC entry — so record
        // it from the Open response and clear it on Close.  In-session ops
        // (including `SessionOpenFinish`) leave the tracked id unchanged.
        match session_ctrl {
            tsra_ddi_tbor_types::SessionControlKind::Open => {
                if let Some(id) = tsra_ddi_tbor_codec::ResponseView::parse(resp_buf)
                    .ok()
                    .and_then(|view| {
                        view.toc_iter().find_map(|entry| match entry {
                            tsra_ddi_tbor_codec::TocEntry::SessionId(id) => Some(id),
                            _ => None,
                        })
                    })
                {
                    self.session.lock().session_id = Some(id);
                }
            }
            tsra_ddi_tbor_types::SessionControlKind::Close => self.session.lock().session_id = None,
            tsra_ddi_tbor_types::SessionControlKind::InSession
            | tsra_ddi_tbor_types::SessionControlKind::NoSession => {}
        }

        Ok(resp)
    }
}

impl Drop for DdiEmuDev {
    fn drop(&mut self) {
        self.close_live_session();
    }
}

impl DdiDev for DdiEmuDev {
    /// Returns the device kind.
    ///
    /// `DdiEmuDev` always reports [`DdiDeviceKind::Physical`] since the
    /// firmware running under [`StdHsm`] reports
    /// [`DdiDeviceKind::Physical`] and the host-side MBOR codec is
    /// configured to match.
    fn device_kind(&self) -> DdiDeviceKind {
        self.device_kind
    }

    fn exec_op_mbor<T: DdiOpReq>(
        &self,
        req: &T,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        // `device_kind` selects the host-side MBOR codec mode. A few
        // request and response types (e.g., DER↔raw key conversions,
        // RSA blob layouts) carry `pre_encode_fn` / `post_decode_fn`
        // hooks that only run when the encoder/decoder is constructed
        // with the corresponding flag set. See `ddi/nix/src/dev.rs` for
        // the canonical mapping.
        let (pre_encode, post_decode) = match self.device_kind {
            DdiDeviceKind::Physical => (true, true),
            _ => (false, false),
        };

        // ── 1. Validate against current session state ──────────────
        let opcode = req.get_opcode();
        let req_session_id = req.get_session_id();
        let current_session_id = self.session.lock().session_id;
        let session_ctrl: SessionControlKind = opcode.into();
        validate_session_request(opcode, req_session_id, current_session_id)?;

        // ── 2. Encode DDI request via host MBOR (wire-compat with fw) ─
        // ── 3. Build SQE and submit on the embedded tokio runtime ─────
        let mut src = AlignedBuf::new(SCRATCH_LEN);
        let mut dst = AlignedBuf::new(SCRATCH_LEN);
        let sqe = Self::mbor_sqe(req, pre_encode, session_ctrl, &mut src, &mut dst)?;

        let mut raw_cqe = self
            .block_on_io(self.hsm.io(sqe, EMU_PID, 0, 0))
            .map_err(|_| DdiError::DeviceNotReady)?;
        let cqe = Cqe::from(&mut raw_cqe);

        // ── 4. Pre-decode CQE host status ──────────────────────────
        if cqe.status() != 0 {
            tracing::warn!(opcode = ?opcode, status = cqe.status(), "DdiEmu CQE pre-decode error");
            return Err(DdiError::DdiError(cqe.status() as u32));
        }

        // ── 5. Post-decode: read response header, then body ────────
        let resp_len = cqe.dst_len() as usize;
        if resp_len == 0 {
            return Err(DdiError::DdiError(0));
        }
        let resp_buf = &dst.as_slice()[..resp_len];
        tracing::trace!(opcode = ?opcode, len = resp_len, "DdiEmu response (in hex): {:02x?}", resp_buf);

        let mut hdr_dec = DdiDecoder::new(resp_buf, post_decode);
        let hdr: DdiRespHdr = hdr_dec
            .decode_hdr()
            .map_err(|_| DdiError::MborError(MborError::DecodeError))?;
        if hdr.status != DdiStatus::Success {
            return Err(DdiError::DdiStatus(hdr.status));
        }

        // ── 6. Update session state on Open / Close success ────────
        let kind: SessionControlKind = opcode.into();
        match kind {
            SessionControlKind::Open => self.session.lock().session_id = hdr.sess_id,
            SessionControlKind::Close => self.session.lock().session_id = None,
            SessionControlKind::NoSession | SessionControlKind::InSession => {}
        }

        // ── 7. Decode the typed response (whole-buffer decode — the
        //         response type wraps both the header and body) ─────────
        let mut body_dec = MborDecoder::new(resp_buf, post_decode);
        let resp = <T::OpResp>::mbor_decode(&mut body_dec)
            .map_err(|_| DdiError::MborError(MborError::DecodeError))?;

        if opcode == DdiOp::OpenSession {
            // Sniff the short_app_id out of the OpenSession response so
            // that future fast-path calls can be validated.
            let mut sniff_dec = MborDecoder::new(resp_buf, post_decode);
            let r = DdiOpenSessionCmdResp::mbor_decode(&mut sniff_dec)
                .map_err(|_| DdiError::MborError(MborError::DecodeError))?;
            self.session.lock().short_app_id = Some(r.data.short_app_id);
        }

        Ok(resp)
    }

    /// TBOR exec path — mirrors [`Self::exec_op_mbor`] but uses the
    /// TBOR codec, sets the SQE opcode to [`OP_TBOR`], and returns a
    /// fully-decoded owned response value via [`TborResp::decode_response`].
    fn exec_op_tbor<T: TborOpReq>(
        &self,
        req: &T,
        oob_items: Option<&[&[u8]]>,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        // Firmware may write any item the request names as an output, so
        // it only ever sees owned staging copies, never the borrowed inputs.
        let mut staged: Vec<Vec<u8>> = oob_items
            .unwrap_or(&[])
            .iter()
            .map(|item| item.to_vec())
            .collect();
        self.exec_tbor(req, &staged_oob(&mut staged))
    }

    /// TBOR exec path with device-writable out-of-band items. Items are
    /// staged in owned buffers the in-process firmware may read or write;
    /// only [`TborOobItem::Out`] buffers receive the device's writes.
    fn exec_op_tbor_oob<T: TborOpReq>(
        &self,
        req: &T,
        oob_items: &mut [TborOobItem<'_>],
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        let mut staged: Vec<Vec<u8>> = oob_items
            .iter()
            .map(|item| match item {
                TborOobItem::In(buf) => buf.to_vec(),
                TborOobItem::Out(buf) => buf.to_vec(),
            })
            .collect();
        let result = self.exec_tbor(req, &staged_oob(&mut staged));
        for (item, buf) in oob_items.iter_mut().zip(&staged) {
            if let TborOobItem::Out(out) = item {
                out.copy_from_slice(buf);
            }
        }
        result
    }

    /// Runs an AES-GCM fast-path operation through the bulk queue.
    ///
    /// Lays the buffers out as the Linux driver does: the AAD zero-padded
    /// to 32 bytes followed by the block-aligned text in one source /
    /// destination buffer pair, and the final partial block (at most 15
    /// bytes) in one tail buffer shared by input and output.
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
        self.validate_fp_session(gcm_params.session_id)?;

        let aad = gcm_params.aad.unwrap_or_default();
        let aligned_aad_len = aad.len().div_ceil(GCM_AAD_ALIGN as usize) * GCM_AAD_ALIGN as usize;
        let tail_len = src_buf.len() % BLOCK_LEN as usize;
        let body_len = src_buf.len() - tail_len;

        let mut src = vec![0u8; aligned_aad_len + body_len];
        src[..aad.len()].copy_from_slice(&aad);
        src[aligned_aad_len..].copy_from_slice(&src_buf[..body_len]);
        let mut dst = vec![0u8; src.len()];
        let mut tail_buf = [0u8; BLOCK_LEN as usize];
        tail_buf[..tail_len].copy_from_slice(&src_buf[body_len..]);
        let tail_addr = tail_buf.as_mut_ptr() as u64;

        let sgl_len = u32::try_from(src.len()).map_err(|_| DdiError::InvalidParameter)?;
        let sqe = BulkSqe {
            dir,
            cid: CMD_COUNTER.fetch_add(1, Ordering::Relaxed),
            session_id: gcm_params.session_id,
            short_app_id: gcm_params.short_app_id,
            src_len: sgl_len,
            src_addr: src.as_ptr() as u64,
            dst_len: sgl_len,
            dst_addr: dst.as_mut_ptr() as u64,
            params: BulkParams::Gcm(GcmParams {
                key_id: gcm_params.key_id,
                aad_len: aad.len() as u32,
                aligned_aad_len: aligned_aad_len as u32,
                tag: gcm_params.tag.unwrap_or_default(),
                iv: gcm_params.iv,
                tail: (tail_len > 0).then_some(GcmTail {
                    len: tail_len as u8,
                    src: tail_addr,
                    dst: tail_addr,
                }),
            }),
        };
        let cqe = self.bulk_submit(&sqe)?;
        if cqe.data_len != sgl_len || cqe.tail_len as usize != tail_len {
            Err(DdiError::DdiStatus(DdiStatus::InternalError))?;
        }

        dst_buf[..body_len].copy_from_slice(&dst[aligned_aad_len..]);
        dst_buf[body_len..src_buf.len()].copy_from_slice(&tail_buf[..tail_len]);
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

    /// Runs an AES-XTS fast-path operation through the bulk queue.
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
        self.validate_fp_session(xts_params.session_id)?;

        let sqe = BulkSqe {
            dir: bulk_dir(mode),
            cid: CMD_COUNTER.fetch_add(1, Ordering::Relaxed),
            session_id: xts_params.session_id,
            short_app_id: xts_params.short_app_id,
            src_len: len,
            src_addr: src_buf.as_ptr() as u64,
            dst_len: len,
            dst_addr: dst_buf.as_mut_ptr() as u64,
            params: BulkParams::Xts(XtsParams {
                dul,
                key_id1: xts_params.key_id1,
                key_id2: xts_params.key_id2,
                tweak: xts_params.tweak,
            }),
        };
        let cqe = self.bulk_submit(&sqe)?;
        if cqe.data_len > len {
            Err(DdiError::DdiStatus(DdiStatus::InternalError))?;
        }

        *fips_approved = cqe.fips_approved;
        Ok(cqe.data_len as usize)
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

    /// Erase the device: disable and re-enable the emulator partition,
    /// matching what real hardware does on NSSR.
    ///
    /// The host-side session state is deliberately preserved so the host
    /// can re-establish it with an in-session `ReopenSession`; clearing it
    /// would fail that reopen with `FileHandleNoExistingSession`.
    fn erase(&self) -> Result<(), DdiError> {
        // Reset partition state: disable then re-enable. This
        // matches what real hardware does on NSSR.
        let _fence = RESET_FENCE.write();
        self.handle
            .block_on(async {
                self.hsm.part_disable(EMU_PID).await.map_err(|_| ())?;
                self.hsm.part_enable(EMU_PID).await.map_err(|_| ())?;
                Ok::<_, ()>(())
            })
            .map_err(|_| DdiError::DeviceNotReady)?;

        Ok(())
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Host DMA descriptors `(address, length)` for staged OOB buffers.
fn staged_oob(staged: &mut [Vec<u8>]) -> Vec<(u64, usize)> {
    staged
        .iter_mut()
        .map(|buf| (buf.as_mut_ptr() as u64, buf.len()))
        .collect()
}

fn bulk_dir(mode: DdiAesOp) -> BulkDir {
    if mode == DdiAesOp::Encrypt {
        BulkDir::Encrypt
    } else {
        BulkDir::Decrypt
    }
}

/// Validate a request against the current session state.
///
/// Mirrors the session check the host driver performs, so mismatches
/// surface as `DdiError` before constructing an SQE.
fn validate_session_request(
    opcode: DdiOp,
    req_session_id: Option<u16>,
    current_session_id: Option<u16>,
) -> Result<(), DdiError> {
    let kind: SessionControlKind = opcode.into();
    match kind {
        SessionControlKind::NoSession => {
            if req_session_id.is_some() {
                Err(DdiError::DdiStatus(DdiStatus::InvalidArg))
            } else {
                Ok(())
            }
        }
        SessionControlKind::Open => match (current_session_id, req_session_id) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(DdiError::DdiStatus(DdiStatus::InvalidArg)),
            (Some(_), _) => Err(DdiError::DdiStatus(
                DdiStatus::FileHandleSessionLimitReached,
            )),
        },
        SessionControlKind::Close | SessionControlKind::InSession => {
            let Some(current) = current_session_id else {
                return Err(DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession));
            };
            if Some(current) == req_session_id {
                Ok(())
            } else {
                Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch,
                ))
            }
        }
    }
}

/// TBOR equivalent of [`validate_session_request`].
fn validate_tbor_session_request(
    kind: tsra_ddi_tbor_types::SessionControlKind,
    req_session_id: Option<u16>,
    current_session_id: Option<u16>,
) -> Result<(), DdiError> {
    // use local alias to avoid collision with the MBOR `SessionControlKind`.
    use tsra_ddi_tbor_types::SessionControlKind;
    match kind {
        SessionControlKind::NoSession => {
            if req_session_id.is_some() {
                Err(DdiError::TborStatus(TborStatus::InvalidArg))
            } else {
                Ok(())
            }
        }
        SessionControlKind::Open => match (current_session_id, req_session_id) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(DdiError::TborStatus(TborStatus::InvalidArg)),
            (Some(_), _) => Err(DdiError::TborStatus(
                TborStatus::FileHandleSessionLimitReached,
            )),
        },
        SessionControlKind::Close | SessionControlKind::InSession => {
            let Some(current) = current_session_id else {
                return Err(DdiError::TborStatus(TborStatus::SessionNotFound));
            };
            if Some(current) == req_session_id {
                Ok(())
            } else {
                Err(DdiError::TborStatus(
                    TborStatus::FileHandleSessionIdDoesNotMatch,
                ))
            }
        }
    }
}

/// 4-KiB-aligned heap buffer used as DMA scratch space.
///
/// `StdHsmPal` enforces page-aligned source / destination addresses, so
/// the buffers handed to the firmware via SQE PRP fields must originate
/// from a page-aligned allocation. This mirrors the `AlignedBuf` helper
/// in `fw/plat/std/lib/tests/echo_test.rs`.
struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: `AlignedBuf` exclusively owns its allocation and never aliases.
// The pointer is only dereferenced through `as_slice` / `as_mut_slice`
// while `&self` / `&mut self` is held, so standard borrow rules apply.
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        let layout =
            std::alloc::Layout::from_size_align(len, PAGE_4K).expect("AlignedBuf: invalid layout");
        // SAFETY: `layout` is non-zero and properly aligned; `alloc_zeroed`
        // returns a valid (or null) pointer for that layout.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "AlignedBuf: allocation failed");
        Self { ptr, len }
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: pointer + len describe a valid, exclusively owned
        // allocation. Borrow is tied to `&self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: see `as_slice`. Mutable borrow is tied to `&mut self`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::from_size_align(self.len, PAGE_4K)
            .expect("AlignedBuf: invalid layout on drop");
        // SAFETY: `ptr` was returned by `alloc_zeroed` with the same `layout`.
        unsafe { std::alloc::dealloc(self.ptr, layout) };
    }
}

#[cfg(test)]
mod tests {
    use tsra_ddi_interface::Ddi;
    use tsra_ddi_interface::DdiDev;
    use tsra_ddi_mbor_types::DdiApiRev;
    use tsra_ddi_mbor_types::DdiGetApiRevCmdReq;
    use tsra_ddi_mbor_types::DdiGetApiRevReq;
    use tsra_ddi_mbor_types::DdiOp;
    use tsra_ddi_mbor_types::DdiReqHdr;
    use tsra_ddi_tbor_types::TborApiRevReq;
    use tsra_ddi_tbor_types::TborApiRevResp;

    use crate::DdiEmu;
    use crate::EMU_DEVICE_PATH;

    #[test]
    fn part_res_mask_has_count_bits_from_pid() {
        use super::emu_part_res_mask;
        use super::EMU_MAX_RESOURCES;
        use super::EMU_PID;

        assert_eq!(emu_part_res_mask(1), 1u128 << EMU_PID);
        assert_eq!(emu_part_res_mask(4), 0b1111u128 << EMU_PID);
        let all = (1u128 << EMU_MAX_RESOURCES) - 1;
        assert_eq!(emu_part_res_mask(EMU_MAX_RESOURCES), all);
        let m64 = emu_part_res_mask(64);
        assert_eq!(m64.count_ones(), 64);
        assert_eq!(m64 & !all, 0);
        assert_eq!(m64 & (1u128 << (EMU_PID - 1)), 0);
    }

    #[test]
    fn fp_status_maps_firmware_invalid_key_to_key_not_found() {
        use tsra_ddi_interface::DdiError;
        use tsra_ddi_mbor_types::DdiStatus;
        use tsra_fw_hsm_bulk::BulkCipher;
        use tsra_fw_hsm_bulk::BulkStatus;
        use tsra_fw_hsm_pal_traits::HsmError;

        let map = |cipher, err| {
            let s = BulkStatus::from_error(cipher, err);
            DdiError::from_fp_status(u32::from(s.sts), u32::from(s.err))
        };
        for cipher in [BulkCipher::Gcm, BulkCipher::Xts] {
            assert!(matches!(
                map(cipher, HsmError::KeyNotFound),
                Some(DdiError::DdiStatus(DdiStatus::KeyNotFound))
            ));
            assert!(matches!(
                map(cipher, HsmError::SessionNotFound),
                Some(DdiError::FpError(_))
            ));
        }
        assert!(DdiError::from_fp_status(0, 0).is_none());
    }

    #[test]
    fn get_api_rev_round_trips_through_emulator() {
        let ddi = DdiEmu::default();
        let dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open emu device");

        let req = DdiGetApiRevCmdReq {
            hdr: DdiReqHdr {
                rev: None,
                op: DdiOp::GetApiRev,
                sess_id: None,
            },
            data: DdiGetApiRevReq {},
            ext: None,
        };

        let mut cookie = None;
        let resp = dev
            .exec_op_mbor(&req, &mut cookie)
            .expect("GetApiRev should succeed against the emulator");

        assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
        assert_eq!(
            resp.data.min,
            DdiApiRev { major: 1, minor: 0 },
            "firmware should report min api rev 1.0",
        );
        assert_eq!(
            resp.data.max,
            DdiApiRev { major: 1, minor: 1 },
            "firmware should report max api rev 1.1",
        );
    }

    #[test]
    fn get_api_rev_tbor_round_trips_through_emulator() {
        let ddi = DdiEmu::default();
        let dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open emu device");

        let req = TborApiRevReq::new();
        let mut cookie = None;
        let resp = dev
            .exec_op_tbor(&req, None, &mut cookie)
            .expect("TBOR GetApiRev should succeed against the emulator");

        assert_eq!(
            resp,
            TborApiRevResp {
                min_ver: 1,
                max_ver: 1,
            }
        );
    }

    #[test]
    fn open_waits_for_reset() {
        use std::sync::mpsc;
        use std::time::Duration;

        let ddi = DdiEmu::default();
        ddi.open_dev(EMU_DEVICE_PATH)
            .expect("initialize emu device");

        let reset_fence = super::RESET_FENCE.write();
        let (started_sender, started_receiver) = mpsc::channel();
        let (opened_sender, opened_receiver) = mpsc::channel();
        let opener = std::thread::spawn(move || {
            started_sender.send(()).expect("signal device open");
            opened_sender
                .send(ddi.open_dev(EMU_DEVICE_PATH))
                .expect("return opened device");
        });
        started_receiver.recv().expect("wait for device open");
        let before_reset = opened_receiver.recv_timeout(Duration::from_millis(100));
        drop(reset_fence);
        opener.join().expect("join device opener");

        assert!(
            matches!(before_reset, Err(mpsc::RecvTimeoutError::Timeout)),
            "opening the device must wait for the reset fence"
        );
        opened_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("device open should finish after reset")
            .expect("open emu device");
    }

    /// Dropping a device with a live session from a thread-local destructor
    /// that runs after Tokio's own thread-locals are gone (as at process
    /// exit, e.g. from OpenSSL's `atexit` cleanup) must not panic.
    #[test]
    fn drop_after_tokio_thread_locals_destroyed_does_not_panic() {
        use std::cell::RefCell;

        thread_local! {
            static DEV: RefCell<Option<super::DdiEmuDev>> = const { RefCell::new(None) };
        }

        let dev = DdiEmu::default()
            .open_dev(EMU_DEVICE_PATH)
            .expect("open emu device");
        dev.session.lock().session_id = Some(1);

        std::thread::spawn(move || {
            // Registered first, so destroyed after Tokio's thread-locals,
            // which the I/O below registers.
            DEV.with(|d| *d.borrow_mut() = Some(dev));
            DEV.with(|d| {
                let d = d.borrow();
                let dev = d.as_ref().expect("device stored");
                dev.block_on_io(async {});
            });
        })
        .join()
        .expect("device drop during thread-local teardown panicked");
    }
}
