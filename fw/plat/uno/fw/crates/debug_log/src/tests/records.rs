// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runs calls that fit and checks each record's words and, in the `@text`
//! form, each call's text.
//!
//! This crate is under `fw/plat/uno/`, so its own calls are Uno code: each
//! one must fit. `cargo xtask log-fixture` covers the calls that drop.

use std::cell::Cell;
use std::cell::RefCell;
use std::fmt;
use std::future::Future;
use std::pin::pin;
use std::task::Context;
use std::task::Waker;

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

/// The platform's hook: keeps each record for the test that makes it.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
fn __hsm_log_record(desc: u32, arg1: u32, arg2: u32) {
    EVENTS.with(|events| events.borrow_mut().push(Event::Record([desc, arg1, arg2])));
}

/// A text hook, which the tracing facade passes in the `@text` form: keeps
/// each line for the test that prints it.
fn emit(level: u8, target: &str, args: fmt::Arguments<'_>) {
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

/// The records that this thread made since the last call. Fails if a call
/// printed.
fn take() -> Vec<[u32; 3]> {
    events()
        .into_iter()
        .map(|event| match event {
            Event::Record(words) => words,
            Event::Text(..) => panic!("a call without text output printed {event:?}"),
        })
        .collect()
}

/// Defines a token. A platform's linker script gives it the descriptor as
/// its address; here, its address is any value.
macro_rules! token {
    ($name:ident, $symbol:literal) => {
        #[allow(unsafe_code)]
        #[unsafe(export_name = $symbol)]
        static $name: u8 = 0;
    };
}

/// The descriptor that a call passes for `token`: the low 32 bits of its
/// address.
fn desc(token: &u8) -> u32 {
    (token as *const u8).addr() as u32
}

/// An error, as the firmware's error types carry a code.
#[derive(Clone, Copy)]
struct Code(u32);

#[test]
fn an_error_record_carries_its_code_last() {
    token!(FAILED, "__tsra_log:tsra_fw_uno_debug_log:E+:test:failed");
    token!(
        FAILED_AT,
        "__tsra_log:tsra_fw_uno_debug_log:E+:test:failed at {:#x}"
    );
    crate::error!("test", Code(0x5a), "failed");
    crate::error!("test", Code(0x5b), "failed at {:#x}", 7_u32);
    assert_eq!(
        take(),
        [[desc(&FAILED), 0x5a, 0], [desc(&FAILED_AT), 7, 0x5b]]
    );
}

#[test]
fn info_and_warn_records_carry_their_values_in_order() {
    token!(STARTED, "__tsra_log:tsra_fw_uno_debug_log:I:test:started");
    token!(
        DEPTH,
        "__tsra_log:tsra_fw_uno_debug_log:I:test:depth={} flag={}"
    );
    token!(
        SLOT,
        "__tsra_log:tsra_fw_uno_debug_log:W:test:slot {:x} at {:#010x}"
    );
    let depth = 3_u32;
    let wide = 0xbeef_u16;
    crate::info!("test", "started");
    crate::info!("test", "depth={} flag={}", depth, true);
    crate::warn!("test", "slot {:x} at {:#010x}", 9_u8, &wide);
    assert_eq!(
        take(),
        [
            [desc(&STARTED), 0, 0],
            [desc(&DEPTH), 3, 1],
            [desc(&SLOT), 9, 0xbeef]
        ]
    );
}

#[test]
fn a_call_evaluates_each_value_once_in_order() {
    token!(BOTH, "__tsra_log:tsra_fw_uno_debug_log:I:test:{} then {}");
    let mut count = 0_u32;
    let mut next = || {
        count += 1;
        count
    };
    crate::info!("test", "{} then {}", next(), next());
    assert_eq!(take(), [[desc(&BOTH), 1, 2]]);
    assert_eq!(count, 2);
}

/// Takes its argument by value.
fn consume(text: String) -> u32 {
    text.len() as u32
}

/// A value that a call awaits.
async fn ready(value: u32) -> u32 {
    value
}

#[test]
fn a_value_can_be_consumed_or_awaited() {
    token!(
        CONSUMED,
        "__tsra_log:tsra_fw_uno_debug_log:I:test:consumed {}"
    );
    token!(
        AWAITED,
        "__tsra_log:tsra_fw_uno_debug_log:W:test:awaited {}"
    );
    let text = String::from("abc");
    crate::info!("test", "consumed {}", consume(text));
    let mut call = pin!(async {
        crate::warn!("test", "awaited {}", ready(5).await);
    });
    let mut context = Context::from_waker(Waker::noop());
    assert!(call.as_mut().poll(&mut context).is_ready());
    assert_eq!(take(), [[desc(&CONSUMED), 3, 0], [desc(&AWAITED), 5, 0]]);
}

#[test]
fn a_text_call_records_as_without_text_and_then_prints() {
    token!(STARTED, "__tsra_log:tsra_fw_uno_debug_log:I:text:started");
    token!(ONE, "__tsra_log:tsra_fw_uno_debug_log:I:text:one {:#x}");
    token!(
        DEPTH,
        "__tsra_log:tsra_fw_uno_debug_log:I:text:depth={} flag={}"
    );
    token!(IDLE, "__tsra_log:tsra_fw_uno_debug_log:W:text:idle");
    token!(
        QUEUE,
        "__tsra_log:tsra_fw_uno_debug_log:W:text:queue at {:08x}"
    );
    token!(
        SLOT,
        "__tsra_log:tsra_fw_uno_debug_log:W:text:slot {:x} at {:#010x}"
    );
    token!(FAILED, "__tsra_log:tsra_fw_uno_debug_log:E+:text:failed");
    token!(
        FAILED_AT,
        "__tsra_log:tsra_fw_uno_debug_log:E+:text:failed at {:#x}"
    );
    let depth = 3_u32;
    let wide = 0xbeef_u16;
    // Each call without text output, and then in the `@text` form. The text
    // is what text output alone prints for the same call.
    crate::info!("text", "started");
    crate::info!(@text(emit, b'I'); "text", "started");
    crate::info!("text", "one {:#x}", 0x1f_u8);
    crate::info!(@text(emit, b'I'); "text", "one {:#x}", 0x1f_u8);
    crate::info!("text", "depth={} flag={}", depth, true);
    crate::info!(@text(emit, b'I'); "text", "depth={} flag={}", depth, true);
    crate::warn!("text", "idle");
    crate::warn!(@text(emit, b'W'); "text", "idle");
    crate::warn!("text", "queue at {:08x}", depth);
    crate::warn!(@text(emit, b'W'); "text", "queue at {:08x}", depth);
    crate::warn!("text", "slot {:x} at {:#010x}", 9_u8, &wide);
    crate::warn!(@text(emit, b'W'); "text", "slot {:x} at {:#010x}", 9_u8, &wide);
    crate::error!("text", Code(0x5a), "failed");
    crate::error!(@text(emit, b'E'); "text", Code(0x5a), "failed");
    crate::error!("text", Code(0x5b), "failed at {:#x}", 7_u32);
    crate::error!(@text(emit, b'E'); "text", Code(0x5b), "failed at {:#x}", 7_u32);
    let started = [desc(&STARTED), 0, 0];
    let one = [desc(&ONE), 0x1f, 0];
    let depth_flag = [desc(&DEPTH), 3, 1];
    let idle = [desc(&IDLE), 0, 0];
    let queue = [desc(&QUEUE), 3, 0];
    let slot = [desc(&SLOT), 9, 0xbeef];
    let failed = [desc(&FAILED), 0x5a, 0];
    let failed_at = [desc(&FAILED_AT), 7, 0x5b];
    assert_eq!(
        events(),
        [
            Event::Record(started),
            Event::Record(started),
            line(b'I', "text", format_args!("started")),
            Event::Record(one),
            Event::Record(one),
            line(b'I', "text", format_args!("one 0x1f")),
            Event::Record(depth_flag),
            Event::Record(depth_flag),
            line(b'I', "text", format_args!("depth=3 flag=true")),
            Event::Record(idle),
            Event::Record(idle),
            line(b'W', "text", format_args!("idle")),
            Event::Record(queue),
            Event::Record(queue),
            line(b'W', "text", format_args!("queue at 00000003")),
            Event::Record(slot),
            Event::Record(slot),
            line(b'W', "text", format_args!("slot 9 at 0x0000beef")),
            Event::Record(failed),
            Event::Record(failed),
            line(b'E', "text", format_args!("failed [err:0000005a]")),
            Event::Record(failed_at),
            Event::Record(failed_at),
            line(b'E', "text", format_args!("failed at 0x7 [err:0000005b]")),
        ]
    );
}

#[test]
fn a_text_call_evaluates_each_value_and_then_the_error_once() {
    token!(THEN, "__tsra_log:tsra_fw_uno_debug_log:W:text:{} then {}");
    token!(
        CODE_AFTER,
        "__tsra_log:tsra_fw_uno_debug_log:E+:text:code after {}"
    );
    token!(
        CODE_ONLY,
        "__tsra_log:tsra_fw_uno_debug_log:E+:text:code only"
    );
    let order = RefCell::new(Vec::new());
    let next = |name: &'static str, value: u32| {
        order.borrow_mut().push(name);
        value
    };
    crate::warn!(@text(emit, b'W'); "text", "{} then {}", next("a", 1), next("b", 2));
    crate::error!(@text(emit, b'E'); "text", Code(next("error", 0x5c)), "code after {}", next("value", 4));
    crate::error!(@text(emit, b'E'); "text", Code(next("code", 0x5d)), "code only");
    assert_eq!(*order.borrow(), ["a", "b", "value", "error", "code"]);
    assert_eq!(
        events(),
        [
            Event::Record([desc(&THEN), 1, 2]),
            line(b'W', "text", format_args!("1 then 2")),
            Event::Record([desc(&CODE_AFTER), 4, 0x5c]),
            line(b'E', "text", format_args!("code after 4 [err:0000005c]")),
            Event::Record([desc(&CODE_ONLY), 0x5d, 0]),
            line(b'E', "text", format_args!("code only [err:0000005d]")),
        ]
    );
}

token!(
    SECOND,
    "__tsra_log:tsra_fw_uno_debug_log:I:text:first {} second {}"
);
token!(
    BEFORE,
    "__tsra_log:tsra_fw_uno_debug_log:E+:text:value {} before a code"
);

/// Logs a value that counts in `ran`, then one that leaves with `?` when
/// `second` is `None`.
fn leave_with_question_mark(ran: &Cell<u32>, second: Option<u32>) -> Option<u32> {
    crate::info!(@text(emit, b'I'); "text", "first {} second {}", { ran.set(ran.get() + 1); 1_u32 }, second?);
    Some(2)
}

/// Logs a value that counts in `ran`, then an error that leaves with
/// `return` when `code` is `None`.
fn leave_with_return(ran: &Cell<u32>, code: Option<u32>) -> u32 {
    crate::error!(@text(emit, b'E'); "text", Code(match code { Some(code) => code, None => return 7 }), "value {} before a code", { ran.set(ran.get() + 1); 1_u32 });
    8
}

#[test]
fn a_text_call_that_leaves_neither_records_nor_prints() {
    let ran = Cell::new(0);
    assert_eq!(leave_with_question_mark(&ran, None), None);
    assert_eq!((ran.get(), events()), (1, vec![]));
    assert_eq!(leave_with_return(&ran, None), 7);
    assert_eq!((ran.get(), events()), (2, vec![]));
    // The same calls record and print when they don't leave.
    assert_eq!(leave_with_question_mark(&ran, Some(5)), Some(2));
    assert_eq!(leave_with_return(&ran, Some(0x5f)), 8);
    assert_eq!(ran.get(), 4);
    assert_eq!(
        events(),
        [
            Event::Record([desc(&SECOND), 1, 5]),
            line(b'I', "text", format_args!("first 1 second 5")),
            Event::Record([desc(&BEFORE), 1, 0x5f]),
            line(
                b'E',
                "text",
                format_args!("value 1 before a code [err:0000005f]")
            ),
        ]
    );
}
