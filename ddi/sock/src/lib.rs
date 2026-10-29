// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Socket-based DDI transport (host-side client).
//!
//! Implements the [`Ddi`](tsra_ddi_interface::Ddi) trait stack by
//! tunnelling DDI requests over TCP, a Unix domain socket, or Linux VSOCK to an emulator-side
//! server (e.g. the Uno SoC emulator's DDI server), which bridges them to
//! the real firmware. It mirrors [`tsra_ddi_emu`] but, instead of
//! running the firmware in-process, encodes each request to MBOR/TBOR
//! bytes and exchanges them with the server using
//! [`tsra_ddi_sock_proto`].
//!
//! The transport is selected by the device path passed to
//! [`Ddi::open_dev`](tsra_ddi_interface::Ddi::open_dev): the path is the
//! socket path, `tcp://HOST:PORT`, or `vsock://CID:PORT` endpoint to connect to.
//! [`Ddi::dev_info_list`] reports a single device
//! whose path comes from the `TSRA_DDI_SOCK` environment variable,
//! falling back to [`DEFAULT_SOCK_PATH`].

mod ddi;
mod dev;

pub use ddi::DdiSock;
pub use dev::DdiSockDev;
pub use dev::DEFAULT_SOCK_PATH;
pub use dev::SOCK_PATH_ENV;
