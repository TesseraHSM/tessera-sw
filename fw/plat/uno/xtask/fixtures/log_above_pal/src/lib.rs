// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checks that an `error!` record from code above the PAL carries its error
//! code last, as one from Uno code does.
//!
//! The Uno log crate builds the record's words in one branch for Uno code
//! and in another for other code. `cargo xtask log-fixture` copies this crate
//! outside `fw/plat/uno/`, where its calls take the other branch, and runs
//! this test there.

#![cfg(test)]

use std::cell::RefCell;

use tsra_fw_uno_debug_log::error;

thread_local! {
    static RECORDS: RefCell<Vec<[u32; 3]>> = const { RefCell::new(Vec::new()) };
}

/// The platform's hook: keeps each record.
#[unsafe(no_mangle)]
fn __hsm_log_record(desc: u32, arg1: u32, arg2: u32) {
    RECORDS.with(|records| records.borrow_mut().push([desc, arg1, arg2]));
}

// The calls' tokens. A platform's linker script gives each token the
// descriptor as its address; here, its address is any value.
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:E+:test:failed")]
static FAILED: u8 = 0;
#[unsafe(export_name = "__tsra_log:tsra_log_above_pal:E+:test:failed at {:#x}")]
static FAILED_AT: u8 = 0;

/// The descriptor that a call passes for `token`: the low 32 bits of its
/// address.
fn desc(token: &u8) -> u32 {
    (token as *const u8).addr() as u32
}

/// An error, as the firmware's error types carry a code.
struct Code(u32);

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
        RECORDS.with(RefCell::take),
        [[desc(&FAILED), 0x5a, 0], [desc(&FAILED_AT), 7, 0x5b]]
    );
}
