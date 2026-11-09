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

use parking_lot::Mutex;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborStatus;

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
thread_local! {
    static ACTIVE_SESSION_COOKIE: Cell<Option<NonNull<Option<DdiCookie>>>> =
        const { Cell::new(None) };
}

pub(crate) fn with_session_cookie<R>(
    cookie: &Mutex<Option<DdiCookie>>,
    f: impl FnOnce() -> R,
) -> R {
    let mut guard = cookie.lock();
    // SAFETY: `ptr` points into `*guard`, which stays locked (and so
    // remains live and exclusively ours) for this entire function body.
    // The thread-local is only ever read back out from `exec_op_mbor`/
    // `exec_op_tbor`/`exec_op_tbor_oob` while running synchronously,
    // on this thread, within `f()`'s dynamic extent below — i.e. before
    // `_restore` clears it and before `guard` unlocks.
    let ptr = NonNull::from(&mut *guard);
    let previous = ACTIVE_SESSION_COOKIE.with(|active| active.replace(Some(ptr)));
    struct RestoreScope(Option<NonNull<Option<DdiCookie>>>);
    impl Drop for RestoreScope {
        fn drop(&mut self) {
            ACTIVE_SESSION_COOKIE.with(|active| active.set(self.0));
        }
    }
    let _restore = RestoreScope(previous);
    f()
}

impl HsmDev {
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
    cookie: &Mutex<Option<DdiCookie>>,
    f: impl FnOnce(&mut Option<DdiCookie>) -> R,
) -> R {
    f(&mut cookie.lock())
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
        let cookie = Arc::new(parking_lot::Mutex::new(Some(1u64)));
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();

        let cookie_a = Arc::clone(&cookie);
        let a = thread::spawn(move || {
            with_session_cookie(&cookie_a, || {
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
            cookie.try_lock().is_none(),
            "the cookie mutex must still be held mid-transaction"
        );

        release_tx.send(()).expect("release a");
        a.join().expect("thread a");

        // Once `a` has returned, the lock must be free again.
        assert!(cookie.try_lock().is_some());
    }

    /// Mirrors the above for the explicit-cookie call sites (`erase`,
    /// `psk_change`, the secure-domain backup helpers, etc.), which don't
    /// go through the thread-local scope at all.
    #[test]
    fn with_explicit_cookie_holds_the_lock_for_the_whole_transaction() {
        let cookie = Arc::new(parking_lot::Mutex::new(Some(1u64)));
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();

        let cookie_a = Arc::clone(&cookie);
        let a = thread::spawn(move || {
            with_explicit_cookie(&cookie_a, |_active| {
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
            cookie.try_lock().is_none(),
            "the cookie mutex must still be held mid-transaction"
        );

        release_tx.send(()).expect("release a");
        a.join().expect("thread a");

        assert!(cookie.try_lock().is_some());
    }
}
