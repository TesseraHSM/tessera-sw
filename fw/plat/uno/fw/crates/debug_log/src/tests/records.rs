// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runs calls that fit and checks each record's words.
//!
//! This crate is under `fw/plat/uno/`, so its own calls are Uno code: each
//! one must fit. `cargo xtask log-fixture` covers the calls that drop.

use std::cell::RefCell;
use std::future::Future;
use std::pin::pin;
use std::task::Context;
use std::task::Waker;

thread_local! {
    static RECORDS: RefCell<Vec<[u32; 3]>> = const { RefCell::new(Vec::new()) };
}

/// The platform's hook: keeps each record for the test that makes it.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
fn __hsm_log_record(desc: u32, arg1: u32, arg2: u32) {
    RECORDS.with(|records| records.borrow_mut().push([desc, arg1, arg2]));
}

/// The records that this thread made since the last call.
fn take() -> Vec<[u32; 3]> {
    RECORDS.with(RefCell::take)
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
