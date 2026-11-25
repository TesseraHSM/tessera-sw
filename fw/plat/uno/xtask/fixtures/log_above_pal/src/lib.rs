// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checks the records and the text of calls in code above the PAL, and that
//! the tracing facade prints text alone on the host.
//!
//! The Uno log crate builds a record's words in one branch for Uno code and
//! in another for other code, and lets only other code drop a call. `cargo
//! xtask log-fixture` copies this crate outside `fw/plat/uno/`, where its
//! calls take the other branch, and runs these tests there.

#![cfg(test)]

use std::cell::Cell;
use std::cell::RefCell;
use std::fmt;

use tsra_fw_uno_debug_log::error;
use tsra_fw_uno_debug_log::info;
use tsra_fw_uno_debug_log::warn;

/// What a call passes to the platform: one record's words, or one line of
/// text with its level and target.
#[derive(Debug, PartialEq)]
enum Event {
    Record([u32; 3]),
    Text(u8, String, String),
}

thread_local! {
    static EVENTS: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
}

/// The platform's hook: keeps each record.
#[unsafe(no_mangle)]
fn __hsm_log_record(desc: u32, arg1: u32, arg2: u32) {
    EVENTS.with(|events| events.borrow_mut().push(Event::Record([desc, arg1, arg2])));
}

/// The text hook, which the tracing facade calls, and passes in the `@text`
/// form: keeps each line.
#[unsafe(no_mangle)]
fn __hsm_trace_emit(level: u8, target: &str, args: fmt::Arguments<'_>) {
    EVENTS.with(|events| events.borrow_mut().push(line(level, target, args)));
}

/// A line of text output.
fn line(level: u8, target: &str, args: fmt::Arguments<'_>) -> Event {
    Event::Text(level, target.to_string(), args.to_string())
}

/// What this thread passed to the platform since the last call.
fn events() -> Vec<Event> {
    EVENTS.with(RefCell::take)
}

// The calls' tokens. A platform's linker script gives each token the
// descriptor as its address; here, its address is any value. In this
// unoptimized build, a call dropped for a value's or the code's type still
// refers to its token.
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:E+:test:failed")]
static FAILED: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:E+:test:failed at {:#x}")]
static FAILED_AT: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:I:test:started")]
static STARTED: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:I:test:depth={} flag={}")]
static DEPTH: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:W:test:queue at {:08x}")]
static QUEUE: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:W:test:slot {:x} at {:#010x}")]
static SLOT: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:I:test:first {} second {}")]
static SECOND: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:E+:test:value {} before a code")]
static BEFORE: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:I:test:wide {}")]
static WIDE: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:E+:test:wide code")]
static WIDE_CODE: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:I:test:owned {}")]
static OWNED: u8 = 0;

/// The descriptor that a call passes for `token`: the low 32 bits of its
/// address.
fn desc(token: &u8) -> u32 {
    (token as *const u8).addr() as u32
}

/// An error, as the firmware's error types carry a code.
struct Code(u32);

/// An error code that no record holds.
struct Code64(u64);

/// Counts one evaluation in `count`, and gives `value`.
fn counted<T>(count: &Cell<u32>, value: T) -> T {
    count.set(count.get() + 1);
    value
}

#[test]
fn error_records_above_the_pal_carry_the_code_last() {
    assert!(
        !tsra_fw_uno_debug_log::__bin::in_uno(env!("CARGO_MANIFEST_DIR")),
        "this test checks code above the PAL, so it must run outside fw/plat/uno/: \
         `cargo xtask log-fixture` copies it there and runs it"
    );
    error!("test", Code(0x5a), "failed");
    error!("test", Code(0x5b), "failed at {:#x}", 7_u32);
    assert_eq!(
        events(),
        [
            Event::Record([desc(&FAILED), 0x5a, 0]),
            Event::Record([desc(&FAILED_AT), 7, 0x5b])
        ]
    );
}

#[test]
fn a_text_call_that_fits_records_as_without_text_and_then_prints() {
    let count = Cell::new(0);
    // Each call without text output, and then in the `@text` form. The text
    // is what text output alone prints for the same call.
    info!("test", "started");
    info!(@text(__hsm_trace_emit, b'I'); "test", "started");
    info!("test", "depth={} flag={}", 3_u32, true);
    info!(@text(__hsm_trace_emit, b'I'); "test", "depth={} flag={}", counted(&count, 3_u32), counted(&count, true));
    warn!("test", "queue at {:08x}", 4_u32);
    warn!(@text(__hsm_trace_emit, b'W'); "test", "queue at {:08x}", counted(&count, 4_u32));
    warn!("test", "slot {:x} at {:#010x}", 9_u8, 0xbeef_u16);
    warn!(@text(__hsm_trace_emit, b'W'); "test", "slot {:x} at {:#010x}", counted(&count, 9_u8), counted(&count, 0xbeef_u16));
    error!("test", Code(0x5a), "failed");
    error!(@text(__hsm_trace_emit, b'E'); "test", counted(&count, Code(0x5a)), "failed");
    error!("test", Code(0x5b), "failed at {:#x}", 7_u32);
    error!(@text(__hsm_trace_emit, b'E'); "test", counted(&count, Code(0x5b)), "failed at {:#x}", counted(&count, 7_u32));
    assert_eq!(count.get(), 8);
    let started = [desc(&STARTED), 0, 0];
    let depth = [desc(&DEPTH), 3, 1];
    let queue = [desc(&QUEUE), 4, 0];
    let slot = [desc(&SLOT), 9, 0xbeef];
    let failed = [desc(&FAILED), 0x5a, 0];
    let failed_at = [desc(&FAILED_AT), 7, 0x5b];
    assert_eq!(
        events(),
        [
            Event::Record(started),
            Event::Record(started),
            line(b'I', "test", format_args!("started")),
            Event::Record(depth),
            Event::Record(depth),
            line(b'I', "test", format_args!("depth=3 flag=true")),
            Event::Record(queue),
            Event::Record(queue),
            line(b'W', "test", format_args!("queue at 00000004")),
            Event::Record(slot),
            Event::Record(slot),
            line(b'W', "test", format_args!("slot 9 at 0x0000beef")),
            Event::Record(failed),
            Event::Record(failed),
            line(b'E', "test", format_args!("failed [err:0000005a]")),
            Event::Record(failed_at),
            Event::Record(failed_at),
            line(b'E', "test", format_args!("failed at 0x7 [err:0000005b]")),
        ]
    );
}

/// Logs a value that counts in `count`, then one that leaves with `?` when
/// `second` is `None`.
fn leave_with_question_mark(count: &Cell<u32>, second: Option<u32>) -> Option<u32> {
    info!(@text(__hsm_trace_emit, b'I'); "test", "first {} second {}", counted(count, 1_u32), second?);
    Some(2)
}

/// Logs a value that counts in `count`, then an error that leaves with
/// `return` when `code` is `None`.
fn leave_with_return(count: &Cell<u32>, code: Option<u32>) -> u32 {
    error!(@text(__hsm_trace_emit, b'E'); "test", Code(match code { Some(code) => code, None => return 7 }), "value {} before a code", counted(count, 1_u32));
    8
}

#[test]
fn a_text_call_that_leaves_neither_records_nor_prints() {
    let count = Cell::new(0);
    assert_eq!(leave_with_question_mark(&count, None), None);
    assert_eq!((count.get(), events()), (1, vec![]));
    assert_eq!(leave_with_return(&count, None), 7);
    assert_eq!((count.get(), events()), (2, vec![]));
    // The same calls record and print when they don't leave.
    assert_eq!(leave_with_question_mark(&count, Some(5)), Some(2));
    assert_eq!(leave_with_return(&count, Some(0x5f)), 8);
    assert_eq!(count.get(), 4);
    assert_eq!(
        events(),
        [
            Event::Record([desc(&SECOND), 1, 5]),
            line(b'I', "test", format_args!("first 1 second 5")),
            Event::Record([desc(&BEFORE), 1, 0x5f]),
            line(
                b'E',
                "test",
                format_args!("value 1 before a code [err:0000005f]")
            ),
        ]
    );
}

#[test]
fn a_text_call_dropped_for_its_shape_prints_each_value_once() {
    let count = Cell::new(0);
    let value = 5_u32;
    let at: *const u32 = &value;
    let target = if count.get() == 0 { "runtime" } else { "other" };
    info!(@text(__hsm_trace_emit, b'I'); "test", "named {v}", v = counted(&count, 1_u32));
    warn!(@text(__hsm_trace_emit, b'W'); target, "a runtime target {}", counted(&count, 2_u32));
    info!(@text(__hsm_trace_emit, b'I'); "test", "at {:p}", counted(&count, at));
    assert_eq!(count.get(), 3);
    assert_eq!(
        events(),
        [
            line(b'I', "test", format_args!("named 1")),
            line(b'W', "runtime", format_args!("a runtime target 2")),
            line(b'I', "test", format_args!("at {at:p}")),
        ]
    );
}

#[test]
fn a_text_call_dropped_for_a_type_prints_the_value_once() {
    let count = Cell::new(0);
    info!(@text(__hsm_trace_emit, b'I'); "test", "wide {}", counted(&count, 1_u64 << 32));
    error!(@text(__hsm_trace_emit, b'E'); "test", counted(&count, Code64(1 << 32)), "wide code");
    info!(@text(__hsm_trace_emit, b'I'); "test", "owned {}", counted(&count, String::from("abc")));
    assert_eq!(count.get(), 3);
    assert_eq!(
        events(),
        [
            line(b'I', "test", format_args!("wide 4294967296")),
            line(b'E', "test", format_args!("wide code [err:100000000]")),
            line(b'I', "test", format_args!("owned abc")),
        ]
    );
}

#[test]
fn the_facade_prints_text_alone_on_the_host() {
    // This crate turns on the facade's `debug-log` and `level-info`.
    let count = Cell::new(0);
    tsra_fw_hsm_core_tracing::info!("host", "info {}", counted(&count, 1_u32));
    tsra_fw_hsm_core_tracing::warn!(
        "host",
        "warn {} {:?}",
        counted(&count, 1_u64 << 32),
        Some(2)
    );
    tsra_fw_hsm_core_tracing::error!("host", Code(0x5e), "error {}", counted(&count, 3_u32));
    tsra_fw_hsm_core_tracing::debug!("host", "debug {}", counted(&count, 4_u32));
    assert_eq!(count.get(), 3);
    assert_eq!(
        events(),
        [
            line(b'I', "host", format_args!("info 1")),
            line(b'W', "host", format_args!("warn 4294967296 Some(2)")),
            line(b'E', "host", format_args!("error 3 [err:0000005e]")),
        ]
    );
}
