// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Device Driver Interface (DDI) library
//!
//! [`TsraDdi`] selects its transport at runtime from the `transport` key of
//! [`DDI_ARGS_ENV`]: `sock` uses the socket transport, and `ioctl` (the
//! default when unset) uses the platform device driver.

mod config;

use std::fmt;

pub use tsra_ddi_interface::*;
use tsra_ddi_mbor_types::DdiAesOp;
use tsra_ddi_mbor_types::DdiDeviceKind;
use tsra_ddi_mbor_types::DdiOpReq;
use tsra_ddi_tbor_types::TborOpReq;

pub use crate::config::DdiConfig;
pub use crate::config::DDI_ARGS_ENV;

#[cfg(target_os = "linux")]
type IoctlDdi = tsra_ddi_nix::DdiNix;
#[cfg(target_os = "linux")]
type IoctlDdiDev = tsra_ddi_nix::DdiNixDev;
#[cfg(target_os = "windows")]
type IoctlDdi = tsra_ddi_win::DdiWin;
#[cfg(target_os = "windows")]
type IoctlDdiDev = tsra_ddi_win::DdiWinDev;

/// Whether [`DDI_ARGS_ENV`] selects the socket transport.
pub fn sock_selected() -> bool {
    DdiTransport::from_env().is_some_and(DdiTransport::is_sock)
}

/// A DDI transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DdiTransport {
    /// Socket transport (`tsra_ddi_sock`).
    Sock,
    /// Platform device driver, reached through IOCTLs (`tsra_ddi_nix` on
    /// Linux, `tsra_ddi_win` on Windows).
    #[default]
    Ioctl,
}

impl DdiTransport {
    /// Whether this is the socket transport.
    pub fn is_sock(self) -> bool {
        self == Self::Sock
    }

    /// Parses a `transport` value, `sock` or `ioctl` (case-insensitive).
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("sock") {
            Some(Self::Sock)
        } else if value.eq_ignore_ascii_case("ioctl") {
            Some(Self::Ioctl)
        } else {
            None
        }
    }

    /// The transport selected by [`DDI_ARGS_ENV`], or `None` if the value
    /// is not a supported transport. Defaults to [`Self::Ioctl`] when unset.
    pub fn from_env() -> Option<Self> {
        match DdiConfig::from_env() {
            Ok(config) => Some(config.transport),
            Err(error) => {
                tracing::error!(%error, "Invalid DDI connection configuration");
                None
            }
        }
    }
}

impl fmt::Display for DdiTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sock => "sock",
            Self::Ioctl => "ioctl",
        })
    }
}

/// DDI implementation over the transport selected at construction.
pub enum TsraDdi {
    /// Socket transport.
    Sock(tsra_ddi_sock::DdiSock),
    /// Platform device driver.
    Ioctl(IoctlDdi),
    /// [`DDI_ARGS_ENV`] contained invalid configuration; no devices are
    /// reported and opening fails.
    Unsupported,
}

impl TsraDdi {
    /// Creates a DDI over `transport`.
    pub fn new(transport: DdiTransport) -> Self {
        match DdiConfig::from_env() {
            Ok(config) => Self::with_config(DdiConfig {
                transport,
                ..config
            }),
            Err(error) => {
                tracing::error!(%error, "Invalid DDI connection configuration");
                Self::Unsupported
            }
        }
    }

    /// Creates a DDI with explicit settings, without reading the environment.
    pub fn with_config(config: DdiConfig) -> Self {
        match config.transport {
            DdiTransport::Sock => Self::Sock(tsra_ddi_sock::DdiSock::new(
                config
                    .sock
                    .unwrap_or_else(|| tsra_ddi_sock::DEFAULT_SOCK_PATH.to_owned()),
            )),
            DdiTransport::Ioctl => Self::Ioctl(Default::default()),
        }
    }

    /// The transport in use, or `None` for [`Self::Unsupported`].
    pub fn transport(&self) -> Option<DdiTransport> {
        match self {
            Self::Sock(_) => Some(DdiTransport::Sock),
            Self::Ioctl(_) => Some(DdiTransport::Ioctl),
            Self::Unsupported => None,
        }
    }
}

impl Default for TsraDdi {
    /// Selects the connection from [`DDI_ARGS_ENV`].
    fn default() -> Self {
        match DdiConfig::from_env() {
            Ok(config) => Self::with_config(config),
            Err(error) => {
                tracing::error!(%error, "Invalid DDI connection configuration");
                Self::Unsupported
            }
        }
    }
}

impl Ddi for TsraDdi {
    type Dev = TsraDdiDev;

    fn dev_info_list(&self) -> Vec<DevInfo> {
        match self {
            Self::Sock(ddi) => ddi.dev_info_list(),
            Self::Ioctl(ddi) => ddi.dev_info_list(),
            Self::Unsupported => Vec::new(),
        }
    }

    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        match self {
            Self::Sock(ddi) => ddi.open_dev(path).map(TsraDdiDev::Sock),
            Self::Ioctl(ddi) => ddi.open_dev(path).map(TsraDdiDev::Ioctl),
            Self::Unsupported => Err(DdiError::InvalidParameter),
        }
    }
}

/// Device opened through [`TsraDdi`].
#[derive(Clone, Debug)]
pub enum TsraDdiDev {
    /// Socket transport device.
    Sock(tsra_ddi_sock::DdiSockDev),
    /// Platform device-driver device.
    Ioctl(IoctlDdiDev),
}

impl TsraDdiDev {
    /// The transport this device uses.
    pub fn transport(&self) -> DdiTransport {
        match self {
            Self::Sock(_) => DdiTransport::Sock,
            Self::Ioctl(_) => DdiTransport::Ioctl,
        }
    }
}

/// Forwards a call to the backend device.
macro_rules! dispatch {
    ($self:ident, $dev:ident => $call:expr) => {
        match $self {
            TsraDdiDev::Sock($dev) => $call,
            TsraDdiDev::Ioctl($dev) => $call,
        }
    };
}

impl DdiDev for TsraDdiDev {
    fn device_kind(&self) -> DdiDeviceKind {
        dispatch!(self, dev => dev.device_kind())
    }

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
        dispatch!(self, dev => dev.exec_op_fp_gcm_slice(
            mode, gcm_params, src_buf, dst_buf, tag, iv, fips_approved
        ))
    }

    fn exec_op_fp_gcm(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesGcmResult, DdiError> {
        dispatch!(self, dev => dev.exec_op_fp_gcm(mode, gcm_params, src_buf))
    }

    fn exec_op_fp_xts(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesXtsResult, DdiError> {
        dispatch!(self, dev => dev.exec_op_fp_xts(mode, xts_params, src_buf))
    }

    fn exec_op_fp_xts_slice(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        dispatch!(self, dev => dev.exec_op_fp_xts_slice(
            mode, xts_params, src_buf, dst_buf, fips_approved
        ))
    }

    fn erase(&self) -> Result<(), DdiError> {
        dispatch!(self, dev => dev.erase())
    }

    fn exec_op_mbor<T: DdiOpReq>(
        &self,
        req: &T,
        cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        dispatch!(self, dev => dev.exec_op_mbor(req, cookie))
    }

    fn exec_op_tbor<T: TborOpReq>(
        &self,
        req: &T,
        oob_items: Option<&[&[u8]]>,
        cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        dispatch!(self, dev => dev.exec_op_tbor(req, oob_items, cookie))
    }

    fn exec_op_tbor_oob<T: TborOpReq>(
        &self,
        req: &T,
        oob_items: &mut [TborOobItem<'_>],
        cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        dispatch!(self, dev => dev.exec_op_tbor_oob(req, oob_items, cookie))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_transport_names() {
        assert_eq!(DdiTransport::parse("sock"), Some(DdiTransport::Sock));
        assert_eq!(DdiTransport::parse(" SOCK "), Some(DdiTransport::Sock));
        assert_eq!(DdiTransport::parse("IOCTL"), Some(DdiTransport::Ioctl));
        for bad in ["emu", "", "native", "nix", "win"] {
            assert_eq!(DdiTransport::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn unsupported_transport_has_no_devices() {
        let ddi = TsraDdi::Unsupported;
        assert!(ddi.dev_info_list().is_empty());
        assert!(matches!(ddi.open_dev("x"), Err(DdiError::InvalidParameter)));
        assert_eq!(ddi.transport(), None);
    }

    #[test]
    fn new_reports_transport() {
        assert_eq!(
            TsraDdi::new(DdiTransport::Sock).transport(),
            Some(DdiTransport::Sock)
        );
        assert_eq!(
            TsraDdi::new(DdiTransport::Ioctl).transport(),
            Some(DdiTransport::Ioctl)
        );
    }
}
