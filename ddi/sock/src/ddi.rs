// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Socket DDI transport — top-level [`Ddi`] implementation.

use tsra_ddi_interface::Ddi;
use tsra_ddi_interface::DdiResult;
use tsra_ddi_interface::DevInfo;

use crate::dev::DdiSockDev;
use crate::DEFAULT_SOCK_PATH;

/// Host-side socket DDI transport.
///
/// Constructing a `DdiSock` is a no-op; the socket connection is
/// established on [`open_dev`](Ddi::open_dev).
#[derive(Debug)]
pub struct DdiSock {
    endpoint: String,
}

impl DdiSock {
    /// Creates a transport whose single device is `endpoint`.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

impl Default for DdiSock {
    /// Creates a transport whose single device is [`DEFAULT_SOCK_PATH`].
    fn default() -> Self {
        Self::new(DEFAULT_SOCK_PATH)
    }
}

impl Ddi for DdiSock {
    type Dev = DdiSockDev;

    /// Returns a single device entry whose path is the configured endpoint.
    fn dev_info_list(&self) -> Vec<DevInfo> {
        vec![DevInfo {
            path: self.endpoint.clone(),
            driver_ver: env!("CARGO_PKG_VERSION").to_owned(),
            firmware_ver: env!("CARGO_PKG_VERSION").to_owned(),
            hardware_ver: env!("CARGO_PKG_VERSION").to_owned(),
            pci_info: String::from("0.0.0"),
            entropy_data: vec![0u8; 32],
        }]
    }

    /// Connect to the server at `path` and return a device handle.
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        DdiSockDev::connect(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_info_list_reports_socket_path() {
        let devs = DdiSock::default().dev_info_list();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].path, DEFAULT_SOCK_PATH);
        assert_eq!(
            DdiSock::new("tcp://h:1").dev_info_list()[0].path,
            "tcp://h:1"
        );
    }
}
