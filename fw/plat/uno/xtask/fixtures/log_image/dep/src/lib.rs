// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A second crate for the fixture image: its token names this crate, and the
//! fixture's `repeat_across_crates` case repeats its message.

#![no_std]
// Builds without debug-log output or a `level-*` feature compile each log
// call to nothing.
#![allow(unused_variables)]

use tsra_fw_hsm_core_tracing::info;

/// Logs one message from this crate.
pub fn report(value: u32) {
    info!("fixture", "from the dependency: {:#x}", value);
}
