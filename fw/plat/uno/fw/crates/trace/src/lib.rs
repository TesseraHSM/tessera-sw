// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM firmware tracing.
//!
//! Re-exports the level-gated tracing macros (`trace!`, `debug!`, `info!`,
//! `warn!`, `error!`) from `tsra_fw_hsm_core_tracing`.
//!
//! When the `tracing` feature is enabled, this crate also provides the
//! `__hsm_trace_emit` implementation that formats trace events with tick
//! count and task ID. The output destination is selected by the
//! mutually-exclusive `backend-uart` / `backend-semihosting` features;
//! with neither enabled the emitter compiles to a no-op (output disabled).
//!
//! `error_text!` takes the same arguments as `error!`. It prints with text
//! output, which one of this crate's `level-*` features turns on, and
//! compiles to nothing otherwise, for lines that no debug-log record can
//! hold.
//!
//! # Usage
//!
//! ```ignore
//! use tsra_fw_uno_trace::tracing::*;
//!
//! info!("iic", "initialized depth={}", depth);
//! debug!("gdma", "submit tag={} slot={}", tag, slot);
//! error!("core", err, "operation failed");
//! ```

#![no_std]

#[cfg(feature = "tracing")]
#[allow(unsafe_code)]
mod emit;

pub extern crate tsra_fw_hsm_core_tracing as tracing;

/// Prints like `error!` with text output, and compiles to nothing otherwise.
#[macro_export]
#[cfg(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info",
    feature = "level-warn",
    feature = "level-error"
))]
macro_rules! error_text {
    ($($t:tt)*) => { $crate::tracing::error!($($t)*) };
}
/// Prints like `error!` with text output, and compiles to nothing otherwise.
#[macro_export]
#[cfg(not(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info",
    feature = "level-warn",
    feature = "level-error"
)))]
macro_rules! error_text {
    ($($t:tt)*) => {};
}
