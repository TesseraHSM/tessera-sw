// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM tracing facade.
//!
//! Provides level-gated tracing macros with a target string parameter.
//! The PAL provides the emit implementation via `__hsm_trace_emit`.
//!
//! With `debug-log` and a bare-metal target, `error!`, `warn!`, and `info!`
//! go to the Uno log crate, which records or drops them, whatever the
//! `level-*` features. A call that text output also prints goes there with
//! the text hook, so that the call evaluates each value once.
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
//! `level-error`. Text output prints the messages at or above the threshold.
//! A message below it prints nothing, and compiles to nothing unless
//! debug-log output records it.

#![no_std]

#[cfg(feature = "debug-log")]
#[doc(hidden)]
pub use tsra_fw_uno_debug_log as __backend;

/// Where an `error!`, `warn!`, or `info!` call goes when text output doesn't
/// print its level: with debug-log output on a bare-metal target, to the Uno
/// log crate, which records or drops it; otherwise nowhere.
#[doc(hidden)]
#[macro_export]
#[cfg(all(feature = "debug-log", target_os = "none"))]
macro_rules! __off {
    ($m:ident, $($t:tt)*) => { $crate::__backend::$m!($($t)*) };
}
#[doc(hidden)]
#[macro_export]
#[cfg(not(all(feature = "debug-log", target_os = "none")))]
macro_rules! __off {
    ($($t:tt)*) => {};
}

/// Where an `error!`, `warn!`, or `info!` call goes when text output prints
/// its level: with debug-log output on a bare-metal target, to the Uno log
/// crate with the text hook and the level, which records or drops the call
/// and then prints it; otherwise to `__text!` alone.
#[doc(hidden)]
#[macro_export]
#[cfg(all(feature = "debug-log", target_os = "none"))]
macro_rules! __on {
    ($m:ident, $level:literal, $($t:tt)*) => {
        $crate::__backend::$m!(@text($crate::__hsm_trace_emit, $level); $($t)*)
    };
}
#[doc(hidden)]
#[macro_export]
#[cfg(not(all(feature = "debug-log", target_os = "none")))]
macro_rules! __on {
    ($m:ident, $level:literal, $($t:tt)*) => { $crate::__text!($m, $level, $($t)*) };
}

/// Prints a call through the text hook, and never records. For `error!`, the
/// message ends with ` [err:<code>]`, with the code as eight hex digits. The
/// Uno trace crate's `error_uart!` uses it too.
#[doc(hidden)]
#[macro_export]
macro_rules! __text {
    (error, $level:literal, $tgt:expr, $err:expr, $($t:tt)*) => {
        unsafe {
            $crate::__hsm_trace_emit(
                $level, $tgt,
                format_args!("{} [err:{:08x}]", format_args!($($t)*), $err.0),
            )
        }
    };
    ($m:ident, $level:literal, $tgt:expr, $($t:tt)*) => {
        unsafe { $crate::__hsm_trace_emit($level, $tgt, format_args!($($t)*)) }
    };
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
    ($tgt:expr, $($t:tt)*) => { $crate::__on!(info, b'I', $tgt, $($t)*) };
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
    ($tgt:expr, $($t:tt)*) => { $crate::__on!(warn, b'W', $tgt, $($t)*) };
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
    ($($t:tt)*) => { $crate::__on!(error, b'E', $($t)*) };
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
