// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! DDI Implementation - Tessera Integrated HSM Emulator.
//!
//! This crate bridges the host-side TSRA SDK (`tsra_ddi_interface`) to
//! the in-process firmware running on the standard platform abstraction
//! layer (`tsra_fw_hsm_std::StdHsm`). It is intended for development and
//! testing the host SDK against the new firmware codebase without
//! requiring real hardware.

mod ddi;
mod dev;

pub use ddi::DdiEmu;
pub use dev::DdiEmuDev;
pub use dev::EMU_DEVICE_PATH;
