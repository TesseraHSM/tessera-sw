// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Socket-based DDI transport (host-side client).
//!
//! Implements the [`Ddi`](tsra_ddi_interface::Ddi) trait stack by
//! tunnelling DDI requests over TCP, a Unix domain socket, or Linux VSOCK to an emulator-side
//! server (e.g. the Uno SoC emulator's DDI server), which bridges them to
//! the real firmware, or to `ddi_sock_server`, which runs the std firmware.
//! It encodes each request to MBOR/TBOR
//! bytes and exchanges them with the server using
//! [`tsra_ddi_sock_proto`].
//!
//! TBOR OOB input items travel as ordered byte buffers and output items as
//! lengths returned with their bytes; the server reconstructs its own SGL
//! descriptor page. Fast-path AES-GCM/XTS requests carry a 32-dword bulk SQE
//! with the data (and any GCM tail) inline; the server substitutes its own
//! buffer addresses. Partition reset is a sideband request that disables
//! and re-enables the endpoint's existing partition. All connections to one
//! endpoint share partition state; use separate endpoints for independent
//! root/leaf application instances. Client and server must use the same updated
//! protocol.
//!
//! The transport is selected by the device path passed to
//! [`Ddi::open_dev`](tsra_ddi_interface::Ddi::open_dev): the path is the
//! socket path, `tcp://HOST:PORT`, or `vsock://CID:PORT` endpoint to connect to.
//! [`Ddi::dev_info_list`] reports a single device
//! whose path is the endpoint given to [`DdiSock::new`], or
//! [`DEFAULT_SOCK_PATH`] for [`DdiSock::default`].

mod ddi;
mod dev;

pub use ddi::DdiSock;
pub use dev::DdiSockDev;
pub use dev::DEFAULT_SOCK_PATH;
