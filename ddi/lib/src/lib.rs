// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Device Driver Interface (DDI) library

pub use tsra_ddi_interface::*;

#[cfg(all(feature = "emu", feature = "mock"))]
compile_error!("features `emu` and `mock` are mutually exclusive; enable at most one");

#[cfg(all(feature = "emu", feature = "sock"))]
compile_error!("features `emu` and `sock` are mutually exclusive; enable at most one");

#[cfg(all(feature = "mock", feature = "sock"))]
compile_error!("features `mock` and `sock` are mutually exclusive; enable at most one");

#[cfg(all(feature = "sock", not(unix)))]
compile_error!("feature `sock` requires a Unix target (tsra_ddi_sock uses Unix-domain sockets)");

cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        /// Tsra DDI emulator implementation (in-process firmware).
        pub type TsraDdi = tsra_ddi_emu::DdiEmu;
    } else if #[cfg(all(feature = "sock", unix))] {
        /// Tsra DDI socket implementation (firmware behind a socket server).
        pub type TsraDdi = tsra_ddi_sock::DdiSock;
    } else if #[cfg(feature = "mock")] {
        /// Tsra DDI mock implementation.
        pub type TsraDdi = tsra_ddi_mock::DdiMock;
    } else if #[cfg(target_os = "linux")] {
        /// Tsra DDI Linux implementation.
        pub type TsraDdi = tsra_ddi_nix::DdiNix;
    } else if #[cfg(target_os = "windows")] {
        /// Tsra DDI Windows implementation.
        pub type TsraDdi = tsra_ddi_win::DdiWin;
    }
}
