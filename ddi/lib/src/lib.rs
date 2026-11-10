// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Device Driver Interface (DDI) library
//!
//! [`TsraDdi`] selects its transport at runtime from the `transport` key of
//! [`DDI_ARGS_ENV`]: `sock` uses
//! the socket transport, and an unset key (or `native`, `nix` on Linux,
//! `win` on Windows) uses the platform device driver.

mod config;

use std::fmt;

pub use tsra_ddi_interface::*;
use tsra_ddi_mbor_types::DdiAesOp;
use tsra_ddi_mbor_types::DdiDeviceKind;
use tsra_ddi_mbor_types::DdiOpReq;
use tsra_ddi_tbor_types::TborOpReq;

pub use crate::config::DdiConfig;
pub use crate::config::DDI_ARGS_ENV;

/// Whether [`DDI_ARGS_ENV`] selects the socket transport.
pub fn sock_selected() -> bool {
    DdiTransport::from_env().is_some_and(DdiTransport::is_sock)
}

/// A DDI transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DdiTransport {
    /// Socket transport (`tsra_ddi_sock`).
    Sock,
    /// Linux device driver (`tsra_ddi_nix`).
    #[cfg(target_os = "linux")]
    Nix,
    /// Windows device driver (`tsra_ddi_win`).
    #[cfg(target_os = "windows")]
    Win,
}

impl DdiTransport {
    /// The platform device-driver transport.
    #[cfg(target_os = "linux")]
    pub const NATIVE: Self = Self::Nix;
    /// The platform device-driver transport.
    #[cfg(target_os = "windows")]
    pub const NATIVE: Self = Self::Win;

    /// Whether this is the socket transport.
    pub fn is_sock(self) -> bool {
        self == Self::Sock
    }

    /// Parses a `transport` value (case-insensitive).
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let native = if cfg!(target_os = "windows") {
            "win"
        } else {
            "nix"
        };
        if value.eq_ignore_ascii_case("sock") {
            Some(Self::Sock)
        } else if value.eq_ignore_ascii_case("native") || value.eq_ignore_ascii_case(native) {
            Some(Self::NATIVE)
        } else {
            None
        }
    }

    /// The transport selected by [`DDI_ARGS_ENV`], or `None` if the value
    /// is not a supported transport. Defaults to [`Self::NATIVE`] when unset.
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
            #[cfg(target_os = "linux")]
            Self::Nix => "nix",
            #[cfg(target_os = "windows")]
            Self::Win => "win",
        })
    }
}

/// DDI implementation over the transport selected at construction.
pub enum TsraDdi {
    /// Socket transport.
    Sock(tsra_ddi_sock::DdiSock),
    /// Linux device driver.
    #[cfg(target_os = "linux")]
    Nix(tsra_ddi_nix::DdiNix),
    /// Windows device driver.
    #[cfg(target_os = "windows")]
    Win(tsra_ddi_win::DdiWin),
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
            #[cfg(target_os = "linux")]
            DdiTransport::Nix => Self::Nix(Default::default()),
            #[cfg(target_os = "windows")]
            DdiTransport::Win => Self::Win(Default::default()),
        }
    }

    /// The transport in use, or `None` for [`Self::Unsupported`].
    pub fn transport(&self) -> Option<DdiTransport> {
        match self {
            Self::Sock(_) => Some(DdiTransport::Sock),
            #[cfg(target_os = "linux")]
            Self::Nix(_) => Some(DdiTransport::Nix),
            #[cfg(target_os = "windows")]
            Self::Win(_) => Some(DdiTransport::Win),
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
            #[cfg(target_os = "linux")]
            Self::Nix(ddi) => ddi.dev_info_list(),
            #[cfg(target_os = "windows")]
            Self::Win(ddi) => ddi.dev_info_list(),
            Self::Unsupported => Vec::new(),
        }
    }

    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        match self {
            Self::Sock(ddi) => ddi.open_dev(path).map(TsraDdiDev::Sock),
            #[cfg(target_os = "linux")]
            Self::Nix(ddi) => ddi.open_dev(path).map(TsraDdiDev::Nix),
            #[cfg(target_os = "windows")]
            Self::Win(ddi) => ddi.open_dev(path).map(TsraDdiDev::Win),
            Self::Unsupported => Err(DdiError::InvalidParameter),
        }
    }
}

/// Device opened through [`TsraDdi`].
#[derive(Clone, Debug)]
pub enum TsraDdiDev {
    /// Socket transport device.
    Sock(tsra_ddi_sock::DdiSockDev),
    /// Linux device.
    #[cfg(target_os = "linux")]
    Nix(tsra_ddi_nix::DdiNixDev),
    /// Windows device.
    #[cfg(target_os = "windows")]
    Win(tsra_ddi_win::DdiWinDev),
}

impl TsraDdiDev {
    /// The transport this device uses.
    pub fn transport(&self) -> DdiTransport {
        match self {
            Self::Sock(_) => DdiTransport::Sock,
            #[cfg(target_os = "linux")]
            Self::Nix(_) => DdiTransport::Nix,
            #[cfg(target_os = "windows")]
            Self::Win(_) => DdiTransport::Win,
        }
    }
}

/// Forwards a call to the backend device.
macro_rules! dispatch {
    ($self:ident, $dev:ident => $call:expr) => {
        match $self {
            TsraDdiDev::Sock($dev) => $call,
            #[cfg(target_os = "linux")]
            TsraDdiDev::Nix($dev) => $call,
            #[cfg(target_os = "windows")]
            TsraDdiDev::Win($dev) => $call,
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
        assert_eq!(DdiTransport::parse("native"), Some(DdiTransport::NATIVE));
        assert_eq!(DdiTransport::parse("emu"), None);
        assert_eq!(DdiTransport::parse(""), None);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(DdiTransport::parse("nix"), Some(DdiTransport::Nix));
            assert_eq!(DdiTransport::parse("win"), None);
        }
        #[cfg(target_os = "windows")]
        {
            assert_eq!(DdiTransport::parse("win"), Some(DdiTransport::Win));
            assert_eq!(DdiTransport::parse("nix"), None);
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
            TsraDdi::new(DdiTransport::NATIVE).transport(),
            Some(DdiTransport::NATIVE)
        );
    }
}
