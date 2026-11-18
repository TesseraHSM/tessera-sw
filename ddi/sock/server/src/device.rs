// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The emulated device a server process hosts, chosen once at startup by
//! SDK API revision.

use tsra_ddi_sock_proto::DeviceInfo;
use tsra_ddi_sock_proto::DeviceModel;
use tsra_fw_hsm_std_duo::StdHsm as DuoHsm;
use tsra_fw_hsm_std_uno::StdHsm as UnoHsm;

/// The emulator served by this process: Uno (API revision 1.x, 64 B SQE /
/// 16 B CQE plus the bulk queue) or Duo (API revision 2.x, 128 B SQE /
/// 64 B CQE).
pub(crate) enum Device {
    Uno(UnoHsm),
    Duo(DuoHsm),
}

macro_rules! forward {
    ($self:ident, $hsm:ident => $body:expr) => {
        match $self {
            Device::Uno($hsm) => $body.map_err(|error| format!("{error:?}")),
            Device::Duo($hsm) => $body.map_err(|error| format!("{error:?}")),
        }
    };
}

impl Device {
    /// Starts the emulator serving API revision `major.minor` on `handle`,
    /// or Uno when no revision is requested.
    pub(crate) fn start(
        api_rev: Option<(u16, u16)>,
        handle: tokio::runtime::Handle,
    ) -> Result<Self, String> {
        match api_rev {
            None => Ok(Self::Uno(UnoHsm::with_tokio(handle))),
            Some((major, minor)) if UnoHsm::supports_api_rev(major, minor) => {
                Ok(Self::Uno(UnoHsm::with_tokio(handle)))
            }
            Some((major, minor)) if DuoHsm::supports_api_rev(major, minor) => {
                Ok(Self::Duo(DuoHsm::with_tokio(handle)))
            }
            Some((major, minor)) => Err(format!(
                "no emulated device supports API revision {major}.{minor}"
            )),
        }
    }

    /// The hosted device, as reported to a discover request.
    pub(crate) fn info(&self) -> DeviceInfo {
        let (model, (api_rev_min, api_rev_max)) = match self {
            Self::Uno(_) => (DeviceModel::Uno, UnoHsm::api_rev_range()),
            Self::Duo(_) => (DeviceModel::Duo, DuoHsm::api_rev_range()),
        };
        DeviceInfo {
            model,
            api_rev_min,
            api_rev_max,
        }
    }

    pub(crate) async fn part_alloc(&self, pid: u8, res_mask: u128) -> Result<(), String> {
        forward!(self, hsm => hsm.part_alloc(pid, res_mask).await)
    }

    pub(crate) async fn part_enable(&self, pid: u8) -> Result<(), String> {
        forward!(self, hsm => hsm.part_enable(pid).await)
    }

    pub(crate) async fn part_disable(&self, pid: u8) -> Result<(), String> {
        forward!(self, hsm => hsm.part_disable(pid).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_revisions_map_to_one_device() {
        assert!(UnoHsm::supports_api_rev(1, 0) && !DuoHsm::supports_api_rev(1, 0));
        assert!(DuoHsm::supports_api_rev(2, 0) && !UnoHsm::supports_api_rev(2, 0));
        assert!(!UnoHsm::supports_api_rev(3, 0) && !DuoHsm::supports_api_rev(3, 0));
    }
}
