// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A small image with debug-log output, for `cargo xtask log-fixture`. Its
//! calls cover each macro and value type, and messages with colons, leading
//! spaces, braces, and a percent sign. With `--cfg fail_case="<name>"`, it
//! adds one call that a debug-log check must reject, or, for `text_loaded`,
//! keeps a message's text, which reading the image must reject. With
//! `--cfg outside`, in a copy outside `fw/plat/uno/`, it adds calls that drop
//! from the debug log.

#![no_std]
#![no_main]
// Builds without debug-log output or a `level-*` feature compile each log
// call to nothing.
#![allow(dead_code, unused_variables)]

use core::panic::PanicInfo;

use cortex_m_rt::entry;
use tsra_fw_hsm_core_tracing::error;
use tsra_fw_hsm_core_tracing::info;
use tsra_fw_hsm_core_tracing::warn;
use tsra_fw_uno_trace::error_text;

/// A value that the optimizer can't predict, for the calls to log.
static mut INPUT: u32 = 0;

/// The last record. The hooks write it with volatile stores, as the Uno PAL
/// writes its ring, so that each call's record stays in the image.
static mut LAST: [u32; 3] = [0; 3];

/// The debug-log hook, as the Uno PAL defines it.
#[unsafe(no_mangle)]
pub fn __hsm_log_record(desc: u32, arg1: u32, arg2: u32) {
    // SAFETY: the image runs one thread, and each pointer is into `LAST`.
    unsafe {
        (&raw mut LAST[0]).write_volatile(desc);
        (&raw mut LAST[1]).write_volatile(arg1);
        (&raw mut LAST[2]).write_volatile(arg2);
    }
}

// The definition and the Uno log crate's declaration must both have this type.
const _: fn(u32, u32, u32) = __hsm_log_record;
const _: unsafe fn(u32, u32, u32) = tsra_fw_uno_debug_log::__hsm_log_record;

/// Text output: each byte goes to `LAST` with a volatile store.
struct TextSink;

impl core::fmt::Write for TextSink {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for byte in text.bytes() {
            // SAFETY: as in `__hsm_log_record`.
            unsafe { (&raw mut LAST[0]).write_volatile(u32::from(byte)) };
        }
        Ok(())
    }
}

/// The text-output hook, for builds with a `level-*` feature.
#[unsafe(no_mangle)]
pub fn __hsm_trace_emit(level: u8, target: &str, args: core::fmt::Arguments<'_>) {
    let _ = core::fmt::Write::write_fmt(&mut TextSink, format_args!("{level} {target} {args}"));
}

/// An error code, as the firmware's error types carry one.
#[derive(Clone, Copy)]
struct Code(u32);

/// An error code that no record holds.
#[derive(Clone, Copy)]
struct Code64(u64);

/// A value that the optimizer can't predict.
fn input() -> u32 {
    // SAFETY: the image runs one thread, and the pointer is to `INPUT`.
    unsafe { (&raw const INPUT).read_volatile() }
}

/// The value of the `error_text!` call. The image keeps this function only
/// when the call evaluates its value.
#[inline(never)]
fn text_only_value() -> u32 {
    input() ^ 0x5c
}

#[entry]
fn main() -> ! {
    // SAFETY: the image runs one thread, and the pointer is to `INPUT`.
    let depth = unsafe { (&raw const INPUT).read_volatile() };
    let flag = depth != 0;
    let slot = depth as u8;
    let wide = depth as u16;
    let size = depth as usize;
    info!("fixture", "started");
    info!("fixture", "depth={} flag={}", depth, flag);
    warn!("fixture", "slot {:x} at {:#010x}", slot, wide);
    warn!("fixture_io", "queue at 50% of {{capacity}} {:08x}", size);
    error!("fixture", Code(0x5a), "failed");
    error!("fixture", Code(0x5b), "  MemManage: IACCVIOL {:#x}", depth);
    // With `--cfg fail_case="text_loaded"`, the image also keeps the text of
    // the call above, which reading the image must reject.
    #[cfg(fail_case = "text_loaded")]
    core::hint::black_box("  MemManage: IACCVIOL ");
    // Text output prints this line; debug-log output compiles it to nothing,
    // and doesn't evaluate its value (TEXT_ONLY in xtask/src/log_fixture.rs).
    error_text!(
        "fixture",
        Code(0x5c),
        "a text-only line: {:?}",
        text_only_value()
    );
    tsra_log_fixture_dep::report(depth);
    variant(depth);
    fail_case(depth);
    #[cfg(outside)]
    outside::drops(depth, if flag { "fixture" } else { "other" });
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Logs a message that only the variant images have.
#[cfg(feature = "variant_a")]
fn variant(value: u32) {
    info!("fixture", "only in one variant: {}", value);
}

/// Logs variant A's message from another line.
#[cfg(feature = "variant_b")]
fn variant(value: u32) {
    let next = value + 1;
    info!("fixture", "only in one variant: {}", next);
}

#[cfg(not(any(feature = "variant_a", feature = "variant_b")))]
fn variant(value: u32) {}

#[cfg(fail_case = "message_not_literal")]
const MESSAGE: &str = "not a literal";

/// With `--cfg fail_case="<name>"`, one call that a check must reject.
fn fail_case(value: u32) {
    #[cfg(fail_case = "target_upper")]
    info!("Fixture", "bad target");
    #[cfg(fail_case = "target_dash")]
    info!("fixture-io", "bad target");
    #[cfg(fail_case = "target_empty")]
    info!("", "bad target");
    #[cfg(fail_case = "message_empty")]
    info!("fixture", "");
    #[cfg(fail_case = "message_trailing_space")]
    info!("fixture", "trailing space ");
    #[cfg(fail_case = "message_quote")]
    info!("fixture", "a \"quoted\" word");
    #[cfg(fail_case = "message_backslash")]
    info!("fixture", "a back\\slash");
    #[cfg(fail_case = "message_control")]
    info!("fixture", "a\ttab");
    #[cfg(fail_case = "message_nul")]
    info!("fixture", "a nul\0here");
    #[cfg(fail_case = "placeholder_debug")]
    info!("fixture", "value {:?}", value);
    #[cfg(fail_case = "placeholder_width")]
    info!("fixture", "value {:>8}", value);
    #[cfg(fail_case = "placeholder_named")]
    info!("fixture", "value {value}", value);
    #[cfg(fail_case = "placeholder_named_arg")]
    info!("fixture", "value {v}", v = value);
    #[cfg(fail_case = "placeholder_missing")]
    info!("fixture", "value", value);
    #[cfg(fail_case = "placeholder_extra")]
    info!("fixture", "values {} {}", value);
    #[cfg(fail_case = "brace_unpaired")]
    info!("fixture", "value }");
    #[cfg(fail_case = "three_values")]
    info!("fixture", "values {} {} {}", value, value, value);
    #[cfg(fail_case = "warn_three_values")]
    warn!("fixture", "values {} {} {}", value, value, value);
    #[cfg(fail_case = "message_not_literal")]
    info!("fixture", MESSAGE);
    #[cfg(fail_case = "error_without_code")]
    error!("fixture", "no code");
    #[cfg(fail_case = "error_two_values")]
    error!("fixture", Code(1), "values {} {}", value, value);
    #[cfg(fail_case = "code_u64")]
    error!("fixture", Code64(u64::from(value)), "wide code");
    #[cfg(fail_case = "value_u64")]
    info!("fixture", "value {}", u64::from(value));
    #[cfg(fail_case = "value_i32")]
    info!("fixture", "value {}", value as i32);
    #[cfg(fail_case = "value_literal")]
    info!("fixture", "value {}", 5);
    #[cfg(fail_case = "value_str")]
    info!("fixture", "value {}", "text");
    #[cfg(fail_case = "repeat_in_crate")]
    info!("fixture", "repeated");
    #[cfg(fail_case = "repeat_in_crate")]
    info!("fixture", "repeated");
    #[cfg(fail_case = "repeat_across_kinds")]
    warn!("fixture", "started");
    #[cfg(fail_case = "repeat_across_crates")]
    info!("fixture", "from the dependency: {:#x}", value);
}

/// Calls that don't fit a record. `cargo xtask log-fixture` builds a copy of
/// this crate outside `fw/plat/uno/` with `--cfg outside`, where each call
/// after a `drop:` comment builds and drops with that reason. Under
/// `fw/plat/uno/`, each one fails to compile.
#[cfg(outside)]
mod outside {
    use tsra_fw_hsm_core_tracing::error;
    use tsra_fw_hsm_core_tracing::info;
    use tsra_fw_hsm_core_tracing::warn;

    use crate::Code;
    use crate::Code64;

    /// The last `arg_*` function that a call evaluated.
    static mut EVALUATED: u32 = 0;

    /// Marks `id` as evaluated, and gives a value.
    fn evaluated(id: u32) -> u32 {
        // SAFETY: the image runs one thread, and the pointer is to `EVALUATED`.
        unsafe { (&raw mut EVALUATED).write_volatile(id) };
        crate::input()
    }

    // Each `arg_*` function gives the value of one dropped call. The image
    // keeps the function only if the call evaluates its value. Each one marks
    // a different id, so that the optimizer can't merge them.

    #[inline(never)]
    fn arg_placeholder() -> u32 {
        evaluated(1)
    }

    #[inline(never)]
    fn arg_named() -> u32 {
        evaluated(2)
    }

    #[inline(never)]
    fn arg_shape() -> u32 {
        evaluated(3)
    }

    #[inline(never)]
    fn arg_wide() -> u32 {
        evaluated(4)
    }

    #[inline(never)]
    fn arg_code() -> u32 {
        evaluated(5)
    }

    #[inline(never)]
    fn arg_long_code() -> u32 {
        evaluated(6)
    }

    /// Logs a value of a generic type, which always drops.
    fn generic<T: Copy>(value: T) {
        // drop: a value doesn't convert to u32
        info!("fixture", "a generic value {}", value);
    }

    /// Calls that don't fit, then calls that fit and repeat this crate's
    /// messages, which share their tokens.
    pub fn drops(value: u32, target: &str) {
        // drop: the target, the message, or a placeholder doesn't fit
        info!("fixture", "a debug value {:?}", arg_placeholder());
        // drop: a named argument isn't one of the five forms
        info!("fixture", "a named value {v}", v = arg_named());
        // drop: the call isn't a literal target, a literal message, and at most two values
        info!(
            "fixture",
            "three values {} {} {}",
            arg_shape(),
            value,
            value
        );
        // drop: the call isn't a literal target, a literal message, and at most two values
        warn!(target, "a runtime target");
        // drop: the call isn't a literal target, an error code, a literal message, and at most one value
        error!("fixture", "an error without a code");
        // drop: the target, the message, or a placeholder doesn't fit
        info!("Fixture", "an uppercase target");
        // drop: the target, the message, or a placeholder doesn't fit
        info!("fixture", "a trailing space ");
        // drop: a value doesn't convert to u32
        info!("fixture", "a wide value {}", u64::from(arg_wide()));
        // drop: a value doesn't convert to u32
        info!("fixture", "an untyped literal {}", 5);
        // drop: the error code doesn't convert to u32
        error!(
            "fixture",
            Code64(u64::from(arg_code())),
            "a wide error code"
        );
        // drop: the error code doesn't convert to u32
        error!(
            "fixture",
            Code64(u64::from(arg_long_code())),
            "a wide error code with a value {}",
            value
        );
        generic(value);
        info!("fixture", "started");
        info!("fixture", "depth={} flag={}", value, value != 0);
        error!("fixture", Code(value), "failed");
    }

    /// Exported, and called by nothing: `cargo xtask log-fixture` checks
    /// whether the drop note of its call stays in the image.
    #[unsafe(no_mangle)]
    pub extern "C" fn tsra_log_fixture_uncalled(value: u64) {
        // uncalled: a value doesn't convert to u32
        info!("fixture", "an uncalled function's value {}", value);
    }
}
