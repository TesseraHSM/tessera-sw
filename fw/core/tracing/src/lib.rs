// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM tracing facade.
//!
//! Provides level-gated tracing macros with a target string parameter.
//! The PAL provides the emit implementation via `__hsm_trace_emit`.
//!
//! With `debug-log`, no `level-*` feature, and a bare-metal target, `error!`,
//! `warn!`, and `info!` go to the Uno log crate, which records or drops them.
//!
//! ## Usage
//!
//! ```ignore
//! use tsra_fw_hsm_tracing::{debug, info, error};
//! info!("iic", "initialized depth={}", depth);
//! error!("core", HsmCoreError::POLL_IO_FAILURE, "poll_io failed");
//! ```
//!
//! ## Log level threshold
//!
//! Enable one of: `level-trace`, `level-debug`, `level-info`, `level-warn`,
//! `level-error`. Messages below the threshold compile to nothing.

#![no_std]

#[cfg(feature = "debug-log")]
#[doc(hidden)]
pub use tsra_fw_uno_debug_log as __backend;

/// Where a call goes when no `level-*` feature is on.
#[doc(hidden)]
#[macro_export]
#[cfg(all(
    feature = "debug-log",
    target_os = "none",
    not(any(
        feature = "level-trace",
        feature = "level-debug",
        feature = "level-info",
        feature = "level-warn",
        feature = "level-error"
    ))
))]
macro_rules! __off {
    ($m:ident, $($t:tt)*) => { $crate::__backend::$m!($($t)*) };
}
#[doc(hidden)]
#[macro_export]
#[cfg(not(all(
    feature = "debug-log",
    target_os = "none",
    not(any(
        feature = "level-trace",
        feature = "level-debug",
        feature = "level-info",
        feature = "level-warn",
        feature = "level-error"
    ))
)))]
macro_rules! __off {
    ($($t:tt)*) => {};
}

extern "Rust" {
    #[doc(hidden)]
    pub fn __hsm_trace_emit(level: u8, target: &str, args: core::fmt::Arguments<'_>);
}

// ── trace ───────────────────────────────────────────────────────────

#[macro_export]
#[cfg(feature = "level-trace")]
macro_rules! trace {
    ($tgt:expr, $($t:tt)*) => { unsafe { $crate::__hsm_trace_emit(b'T', $tgt, format_args!($($t)*)) } };
}
#[macro_export]
#[cfg(not(feature = "level-trace"))]
macro_rules! trace {
    ($tgt:expr, $($t:tt)*) => {};
}

// ── debug ───────────────────────────────────────────────────────────

#[macro_export]
#[cfg(any(feature = "level-trace", feature = "level-debug"))]
macro_rules! debug {
    ($tgt:expr, $($t:tt)*) => { unsafe { $crate::__hsm_trace_emit(b'D', $tgt, format_args!($($t)*)) } };
}
#[macro_export]
#[cfg(not(any(feature = "level-trace", feature = "level-debug")))]
macro_rules! debug {
    ($tgt:expr, $($t:tt)*) => {};
}

// ── info ────────────────────────────────────────────────────────────

#[macro_export]
#[cfg(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info"
))]
macro_rules! info {
    ($tgt:expr, $($t:tt)*) => { unsafe { $crate::__hsm_trace_emit(b'I', $tgt, format_args!($($t)*)) } };
}
#[macro_export]
#[cfg(not(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info"
)))]
macro_rules! info {
    ($tgt:expr, $($t:tt)*) => { $crate::__off!(info, $tgt, $($t)*) };
}

// ── warn ────────────────────────────────────────────────────────────

#[macro_export]
#[cfg(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info",
    feature = "level-warn"
))]
macro_rules! warn {
    ($tgt:expr, $($t:tt)*) => { unsafe { $crate::__hsm_trace_emit(b'W', $tgt, format_args!($($t)*)) } };
}
#[macro_export]
#[cfg(not(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info",
    feature = "level-warn"
)))]
macro_rules! warn {
    ($tgt:expr, $($t:tt)*) => { $crate::__off!(warn, $tgt, $($t)*) };
}

// ── error ───────────────────────────────────────────────────────────

#[macro_export]
#[cfg(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info",
    feature = "level-warn",
    feature = "level-error"
))]
macro_rules! error {
    ($tgt:expr, $err:expr, $($t:tt)*) => {
        unsafe {
            $crate::__hsm_trace_emit(
                b'E', $tgt,
                format_args!("{} [err:{:08x}]", format_args!($($t)*), $err.0),
            )
        }
    };
    ($tgt:expr, $($t:tt)*) => { unsafe { $crate::__hsm_trace_emit(b'E', $tgt, format_args!($($t)*)) } };
}
#[macro_export]
#[cfg(not(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info",
    feature = "level-warn",
    feature = "level-error"
)))]
macro_rules! error {
    ($($t:tt)*) => { $crate::__off!(error, $($t)*) };
}
