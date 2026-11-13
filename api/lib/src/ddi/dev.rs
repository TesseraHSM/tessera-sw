// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device Discovery Interface (DDI) device management.
//!
//! This module provides functionality for discovering and opening HSM devices
//! through the DDI layer. It manages device enumeration, device handle wrapping,
//! and device access operations.

use std::cell::Cell;
use std::ops::Deref;
use std::ops::DerefMut;
use std::ptr::NonNull;
use std::sync::LazyLock;
use std::thread::LocalKey;

use parking_lot::Mutex;
use tsra_ddi_tbor_types::TborApiRevReq;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborResp;
use tsra_ddi_tbor_types::TborStatus;
use tsra_session_ex_crypto::SessionTransport;
use tsra_session_ex_crypto::SessionTransportSeal;

use super::*;
use crate::resiliency::HsmDdi;

/// Type alias for the Tsra DDI device type.
pub(in crate::ddi) type TsraDev = <HsmDdi as Ddi>::Dev;

/// Global DDI instance for device operations.
///
/// Lazily initialized singleton providing access to the DDI implementation.
static DDI: LazyLock<HsmDdi> = LazyLock::new(HsmDdi::default);

/// Retrieves the API revision range supported by the HSM device.
///
/// Queries the device for its supported API revision range, returning both
/// the minimum and maximum API revisions. This information can be used to
/// determine API compatibility and feature availability.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
///
/// # Returns
///
/// Returns a tuple containing (minimum API revision, maximum API revision).
///
/// # Errors
///
/// Returns an error if:
/// - The device communication fails
/// - The DDI operation returns an error
/// - The device is not responding
pub(crate) fn get_api_rev(dev: &HsmDev) -> HsmResult<(HsmApiRev, HsmApiRev)> {
    // TBOR first; MBOR-only firmware rejects it.
    match dev.exec_op_tbor(&TborApiRevReq, None, &mut None) {
        Ok(resp) => {
            let rev = |major: u16, minor: u16| HsmApiRev {
                major: major.into(),
                minor: minor.into(),
            };
            return Ok((
                rev(resp.min_major.get(), resp.min_minor.get()),
                rev(resp.max_major.get(), resp.max_minor.get()),
            ));
        }
        Err(
            DdiError::UnsupportedEncoding
            | DdiError::DdiStatus(DdiStatus::UnsupportedCmd)
            | DdiError::TborStatus(TborStatus::UnsupportedCmd),
        ) => {}
        Err(err) => return Err(HsmError::from(err)),
    }

    let req = DdiGetApiRevCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::GetApiRev, None, None),
        data: DdiGetApiRevReq {},
        ext: None,
    };

    let resp: DdiGetApiRevCmdResp = dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from)?;

    Ok((resp.data.min.into(), resp.data.max.into()))
}

/// Queries security-domain initialization over the out-of-session TBOR `PartInfo` command.
///
/// Returns `false` when the backend or device does not support the command.
/// Other device failures and invalid initialization values return an error.
pub(crate) fn get_sd_initialized(dev: &HsmDev) -> HsmResult<bool> {
    let resp = match dev.exec_op_tbor(&TborPartInfoReq::new(), None, &mut None) {
        Ok(resp) => resp,
        Err(
            DdiError::UnsupportedEncoding
            | DdiError::DdiStatus(DdiStatus::UnsupportedCmd)
            | DdiError::TborStatus(TborStatus::UnsupportedCmd),
        ) => {
            return Ok(false);
        }
        Err(err) => return Err(HsmError::from(err)),
    };
    match resp.sd_initialized {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(HsmError::InternalError),
    }
}

/// Converts a DDI API revision to an HSM API revision.
impl From<DdiApiRev> for HsmApiRev {
    fn from(ddi_rev: DdiApiRev) -> Self {
        HsmApiRev {
            major: ddi_rev.major,
            minor: ddi_rev.minor,
        }
    }
}

/// Converts an HSM API revision to a DDI API revision.
impl From<HsmApiRev> for DdiApiRev {
    fn from(hsm_rev: HsmApiRev) -> Self {
        DdiApiRev {
            major: hsm_rev.major,
            minor: hsm_rev.minor,
        }
    }
}

/// HSM device handle wrapper.
///
/// Wraps the underlying DDI device handle, providing a typed interface
/// for HSM device operations while maintaining deref access to the
/// underlying device.
#[derive(Debug)]
pub(crate) struct HsmDev(TsraDev);

/// Per-session DDI state owned by a session handle: the backend
/// continuity cookie and, for an encrypted (API revision 2.0) session,
/// the transport its in-session and close commands are sealed with.
///
/// The transport is fixed for the session's lifetime, so it is read
/// without locking; only the cookie, which a backend may refresh, sits
/// behind a mutex.
pub(crate) struct DdiSession {
    id: u16,
    cookie: Mutex<Option<DdiCookie>>,
    transport: Option<SessionTransport>,
}

impl DdiSession {
    pub(crate) fn new(
        id: u16,
        cookie: Option<DdiCookie>,
        transport: Option<SessionTransport>,
    ) -> Self {
        Self {
            id,
            cookie: Mutex::new(cookie),
            transport,
        }
    }

    /// The session's backend continuity cookie.
    pub(crate) fn cookie(&self) -> &Mutex<Option<DdiCookie>> {
        &self.cookie
    }

    /// Whether the session's commands are sealed with a session transport.
    pub(crate) fn is_encrypted(&self) -> bool {
        self.transport.is_some()
    }

    /// The transport to seal `req` with: this session's, if `req` is one
    /// of its in-session or close commands.
    fn transport_for<T: tsra_ddi_tbor_types::TborOpReq>(
        &self,
        req: &T,
    ) -> Option<&SessionTransport> {
        let transport = self.transport.as_ref()?;
        let in_session = matches!(
            req.session_ctrl(),
            tsra_ddi_tbor_types::SessionControlKind::InSession
                | tsra_ddi_tbor_types::SessionControlKind::Close
        );
        (in_session && req.get_session_id() == Some(self.id)).then_some(transport)
    }
}

impl std::fmt::Debug for DdiSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdiSession")
            .field("id", &self.id)
            .field("cookie", &self.cookie)
            .field("encrypted", &self.is_encrypted())
            .finish()
    }
}

/// Upper bound on an encoded TBOR request sent over the session transport.
const SECURE_REQ_CAP: usize = 8192;

// Session-bound API operations traditionally pass `&mut None` through the
// DDI layer. Scope the handle's backend cookie around those calls without
// sharing it between concurrent sessions.
//
// The pointer refers to the slot behind a live `MutexGuard` held for the
// entire duration of `with_session_cookie`'s `f()` call (see below), so the
// whole read/exchange/write-back transaction is serialized by the mutex
// itself instead of snapshot-and-release: a concurrent `with_session_cookie`
// call on the same session's cookie blocks on the mutex until this one's
// `f()` returns, rather than racing to read a possibly-stale cookie and
// later clobbering a refreshed one on write-back.
//
// `ACTIVE_SESSION_TRANSPORT` likewise scopes an encrypted session onto the
// TBOR exec paths so its commands are sealed with its own transport. It is
// per thread and per session, so sending a command takes no lock shared
// across sessions; an unencrypted session leaves it `None`.
thread_local! {
    static ACTIVE_SESSION_COOKIE: Cell<Option<NonNull<Option<DdiCookie>>>> =
        const { Cell::new(None) };
    static ACTIVE_SESSION_TRANSPORT: Cell<Option<NonNull<DdiSession>>> =
        const { Cell::new(None) };
}

/// Runs `f` with `key` set to `value`, restoring the previous value after.
fn with_scoped<T: Copy + 'static, R>(
    key: &'static LocalKey<Cell<T>>,
    value: T,
    f: impl FnOnce() -> R,
) -> R {
    struct Restore<T: Copy + 'static>(&'static LocalKey<Cell<T>>, T);
    impl<T: Copy + 'static> Drop for Restore<T> {
        fn drop(&mut self) {
            self.0.with(|active| active.set(self.1));
        }
    }
    let _restore = Restore(key, key.with(|active| active.replace(value)));
    f()
}

/// Runs `f` with `session`'s transport (if any) scoped onto the TBOR exec
/// paths, without touching its cookie.
pub(crate) fn with_session_transport<R>(session: &DdiSession, f: impl FnOnce() -> R) -> R {
    // SAFETY: `session` outlives this call, and the thread-local is only
    // read back out (as a shared reference) synchronously on this thread
    // within `f()`'s dynamic extent, before it is restored.
    let ptr = session.is_encrypted().then(|| NonNull::from(session));
    with_scoped(&ACTIVE_SESSION_TRANSPORT, ptr, f)
}

pub(crate) fn with_session_cookie<R>(session: &DdiSession, f: impl FnOnce() -> R) -> R {
    let mut guard = session.cookie.lock();
    // SAFETY: `ptr` points into `*guard`, which stays locked (and so
    // remains live and exclusively ours) for this entire function body.
    // The thread-local is only ever read back out from `exec_op_mbor`/
    // `exec_op_tbor`/`exec_op_tbor_oob` while running synchronously,
    // on this thread, within `f()`'s dynamic extent below — i.e. before
    // it is restored and before `guard` unlocks.
    let ptr = NonNull::from(&mut *guard);
    with_scoped(&ACTIVE_SESSION_COOKIE, Some(ptr), || {
        with_session_transport(session, f)
    })
}

/// The active encrypted session's transport for `req`, if any.
#[allow(unsafe_code)]
fn active_transport<'a, T: tsra_ddi_tbor_types::TborOpReq>(
    req: &'a T,
) -> Option<(u16, &'a SessionTransport)> {
    let session = ACTIVE_SESSION_TRANSPORT.with(Cell::get)?;
    // SAFETY: see `with_session_transport`; the reference is used only
    // for the current exec call (bounded by its `req` borrow), within
    // that scope.
    let session: &'a DdiSession = unsafe { session.as_ref() };
    Some((session.id, session.transport_for(req)?))
}

impl HsmDev {
    /// Encode `req`, seal it with `transport`, execute it, and open and
    /// decode the response.
    pub(crate) fn exec_op_tbor_sealed<T: tsra_ddi_tbor_types::TborOpReq>(
        &self,
        session_id: u16,
        transport: &SessionTransport,
        req: &T,
        oob_items: &mut [TborOobItem<'_>],
    ) -> DdiResult<T::OpResp> {
        let mut buf = vec![0u8; SECURE_REQ_CAP];
        let len = req.encode_request(&mut buf)?.len();
        buf.truncate(len);
        let seal = transport
            .seal_request(&mut buf)
            .map_err(|_| DdiError::TborEncodeError)?;
        let seal = DdiTransportSeal {
            iv: seal.iv,
            tag: seal.tag,
        };
        let (mut resp, seal) = self
            .0
            .exec_op_tbor_secure(session_id, &buf, seal, oob_items)?;
        let seal = SessionTransportSeal {
            iv: seal.iv,
            tag: seal.tag,
        };
        transport
            .open_response(&seal, &mut resp)
            .map_err(|_| DdiError::TborDecodeError)?;
        Ok(T::OpResp::decode_response(&resp)?)
    }

    #[allow(unsafe_code)]
    pub(crate) fn exec_op_mbor<T: DdiOpReq>(
        &self,
        req: &T,
        cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        let Some(mut active_cookie) = ACTIVE_SESSION_COOKIE.with(Cell::get) else {
            return self.0.exec_op_mbor(req, cookie);
        };
        // SAFETY: see `with_session_cookie`.
        self.0.exec_op_mbor(req, unsafe { active_cookie.as_mut() })
    }

    /// Mirrors [`exec_op_mbor`](Self::exec_op_mbor): session-bound TBOR
    /// ops traditionally pass `&mut None` through the DDI layer too, so
    /// scope them onto the active [`with_session_cookie`] handle's
    /// backend cookie the same way, keeping V2 (TBOR) sessions'
    /// generation-bound tokens threaded through transparently.
    #[allow(unsafe_code)]
    pub(crate) fn exec_op_tbor<T: tsra_ddi_tbor_types::TborOpReq>(
        &self,
        req: &T,
        oob_items: Option<&[&[u8]]>,
        cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        if let Some((id, transport)) = active_transport(req) {
            let mut items: Vec<_> = oob_items
                .unwrap_or_default()
                .iter()
                .map(|item| TborOobItem::In(item))
                .collect();
            return self.exec_op_tbor_sealed(id, transport, req, &mut items);
        }
        let Some(mut active_cookie) = ACTIVE_SESSION_COOKIE.with(Cell::get) else {
            return self.0.exec_op_tbor(req, oob_items, cookie);
        };
        // SAFETY: see `with_session_cookie`.
        self.0
            .exec_op_tbor(req, oob_items, unsafe { active_cookie.as_mut() })
    }

    /// Mirrors [`exec_op_mbor`](Self::exec_op_mbor): out-of-band TBOR ops
    /// (e.g. AES-GCM/AES-XTS) traditionally pass `&mut None` through the
    /// DDI layer too, so scope them onto the active
    /// [`with_session_cookie`] handle's backend cookie the same way.
    /// Without this wrapper, callers reaching `exec_op_tbor_oob` through
    /// `Deref` would bypass `ACTIVE_SESSION_COOKIE` entirely and always
    /// send no cookie, even inside a `with_session_cookie` scope.
    #[allow(unsafe_code)]
    pub(crate) fn exec_op_tbor_oob<T: tsra_ddi_tbor_types::TborOpReq>(
        &self,
        req: &T,
        oob_items: &mut [TborOobItem<'_>],
        cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        if let Some((id, transport)) = active_transport(req) {
            return self.exec_op_tbor_sealed(id, transport, req, oob_items);
        }
        let Some(mut active_cookie) = ACTIVE_SESSION_COOKIE.with(Cell::get) else {
            return self.0.exec_op_tbor_oob(req, oob_items, cookie);
        };
        // SAFETY: see `with_session_cookie`.
        self.0
            .exec_op_tbor_oob(req, oob_items, unsafe { active_cookie.as_mut() })
    }
}

/// Runs `f` with the explicit session cookie locked for the complete
/// read/exchange/write-back transaction.
///
/// Mirrors [`with_session_cookie`]'s serialization guarantee for call
/// sites that thread `ddi_cookie` through explicitly rather than via the
/// thread-local scope (e.g. operations that only have a `&HsmPartition`,
/// not the owning `HsmSession`): holding the mutex locked across the
/// whole exchange means a concurrent caller on the same session's cookie
/// blocks until `f` returns, instead of racing to snapshot a possibly
/// stale cookie and later overwriting a refreshed one.
pub(crate) fn with_explicit_cookie<R>(
    session: &DdiSession,
    f: impl FnOnce(&mut Option<DdiCookie>) -> R,
) -> R {
    with_session_transport(session, || f(&mut session.cookie.lock()))
}

impl Deref for HsmDev {
    type Target = TsraDev;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HsmDev {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Retrieves the paths of all available HSM devices.
///
/// Queries the DDI layer for a list of all discoverable HSM devices
/// and returns their device paths.
///
/// # Returns
///
/// A vector of device path strings.
#[tracing::instrument(skip_all)]
pub(crate) fn dev_paths() -> Vec<String> {
    DDI.dev_info_list()
        .iter()
        .map(|info| {
            tracing::debug!(path = ?info.path, "Found device");
            info.path.clone()
        })
        .collect()
}

impl HsmDev {
    /// Returns the device kind (Virtual or Physical).
    pub(crate) fn device_kind(&self) -> DdiDeviceKind {
        self.0.device_kind()
    }
}

/// Retrieves device information for a specific device path.
///
/// # Arguments
///
/// * `path` - The device path string
///
/// # Returns
///
/// Returns `DevInfo` for the specified path.
///
/// # Errors
///
/// Returns an error if the path is not found.
#[tracing::instrument(skip_all, fields(path = path))]
pub(crate) fn dev_info_by_path(path: &str) -> HsmResult<DevInfo> {
    DDI.dev_info_list()
        .into_iter()
        .find(|info| info.path == path)
        .ok_or(HsmError::InvalidArgument)
}

/// Opens an HSM device at the specified path.
///
/// Attempts to open an HSM device using the DDI layer and wraps
/// the resulting device handle in an `HsmDev` structure.
///
/// # Arguments
///
/// * `path` - The device path string identifying the HSM device to open
///
/// # Returns
///
/// Returns an `HsmDev` handle on success.
///
/// # Errors
///
/// Returns an error if:
/// - The device path is invalid or does not exist
/// - The device is already open or in use
/// - The device cannot be accessed due to permissions
/// - The underlying DDI operation fails
#[tracing::instrument(skip_all, fields(path = path))]
pub(crate) fn open_dev(path: &str) -> HsmResult<HsmDev> {
    let dev = DDI.open_dev(path).map(HsmDev).map_err(HsmError::from)?;

    // Probe the device with GetApiRev + GetDeviceInfo at open time so
    // that transient IO faults surface here (where the resiliency
    // retry machinery owns them) rather than at the first downstream
    // operation. The result is discarded — `device_kind()` is now a
    // hardcoded property of the backend, so we don't need the data;
    // the side-effect of the round-trip is what matters.
    probe_device(&dev)?;

    Ok(dev)
}

/// Round-trips two DDI ops (`GetApiRev` then `GetDeviceInfo`) against
/// the device to confirm it is reachable. Used by [`open_dev`] to
/// surface transient errors during retry-eligible operations.
fn probe_device(dev: &HsmDev) -> HsmResult<()> {
    let (_, max_rev) = get_api_rev(dev)?;
    // Revision 2.0 devices have no MBOR transport.
    if max_rev >= SESSION_TRANSPORT_API_REV {
        return Ok(());
    }

    let req = DdiGetDeviceInfoCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::GetDeviceInfo, Some(max_rev), None),
        data: DdiGetDeviceInfoReq {},
        ext: None,
    };

    dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from)?;

    Ok(())
}

/// Converts a DDI device kind to an HSM partition type.
impl From<DdiDeviceKind> for HsmPartType {
    fn from(kind: DdiDeviceKind) -> Self {
        match kind {
            DdiDeviceKind::Virtual => HsmPartType::Virtual,
            DdiDeviceKind::Physical => HsmPartType::Physical,
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::*;

    /// `with_session_cookie` must hold the cookie mutex for the complete
    /// `f()` transaction, not just to snapshot the value at the start:
    /// otherwise a concurrent scope on the same session can read a
    /// cookie before a refresh and, by writing its stale snapshot back
    /// after the refresh completes, clobber it.
    #[test]
    fn with_session_cookie_holds_the_lock_for_the_whole_transaction() {
        let session = Arc::new(DdiSession::new(1, Some(1u64), None));
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();

        let session_a = Arc::clone(&session);
        let a = thread::spawn(move || {
            with_session_cookie(&session_a, || {
                entered_tx.send(()).expect("signal entered");
                release_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("release signal");
            });
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a entered its scope");
        // `a` is inside `f()`; a concurrent attempt to lock the same
        // cookie must fail until `a`'s whole transaction completes.
        assert!(
            session.cookie().try_lock().is_none(),
            "the cookie mutex must still be held mid-transaction"
        );

        release_tx.send(()).expect("release a");
        a.join().expect("thread a");

        // Once `a` has returned, the lock must be free again.
        assert!(session.cookie().try_lock().is_some());
    }

    /// Mirrors the above for the explicit-cookie call sites (`erase`,
    /// `psk_change`, the secure-domain backup helpers, etc.), which don't
    /// go through the thread-local scope at all.
    #[test]
    fn with_explicit_cookie_holds_the_lock_for_the_whole_transaction() {
        let session = Arc::new(DdiSession::new(1, Some(1u64), None));
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();

        let session_a = Arc::clone(&session);
        let a = thread::spawn(move || {
            with_explicit_cookie(&session_a, |_active| {
                entered_tx.send(()).expect("signal entered");
                release_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("release signal");
            });
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a entered its transaction");
        assert!(
            session.cookie().try_lock().is_none(),
            "the cookie mutex must still be held mid-transaction"
        );

        release_tx.send(()).expect("release a");
        a.join().expect("thread a");

        assert!(session.cookie().try_lock().is_some());
    }

    /// Only an encrypted session's own in-session and close commands are
    /// sealed, and only while it is scoped onto the exec paths.
    #[test]
    fn active_transport_is_scoped_to_the_encrypted_session() {
        let close = |session_id| tsra_ddi_tbor_types::TborSessionCloseReq { session_id };
        let transport = SessionTransport::derive(&[7u8; 48]).expect("derive transport");
        let encrypted = DdiSession::new(5, None, Some(transport));
        let plain = DdiSession::new(5, None, None);

        assert!(active_transport(&close(5)).is_none());
        with_session_transport(&encrypted, || {
            assert_eq!(active_transport(&close(5)).map(|(id, _)| id), Some(5));
            assert!(active_transport(&close(6)).is_none());
            assert!(active_transport(&TborApiRevReq).is_none());
            with_session_transport(&plain, || {
                assert!(active_transport(&close(5)).is_none());
            });
            assert!(active_transport(&close(5)).is_some());
        });
        assert!(active_transport(&close(5)).is_none());
    }
}
