// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Start an in-process server before `main` for test binaries.
//!
//! Linking this crate with the `autostart` feature registers a process
//! constructor that, unless `TSRA_DDI_SOCK` is already set, starts the server
//! on an ephemeral loopback port and points `TSRA_DDI_SOCK` at it. Every test
//! process therefore gets its own emulated HSM, and the unchanged socket
//! transport connects to it. Child processes inherit the endpoint.

#![allow(unsafe_code)]

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

const SOCK_ENV: &str = "TSRA_DDI_SOCK";

static STARTED: AtomicBool = AtomicBool::new(false);

/// Whether this process started its own in-process server (rather than
/// inheriting an external `TSRA_DDI_SOCK` endpoint).
pub fn autostarted() -> bool {
    STARTED.load(Ordering::Acquire)
}

fn start() {
    if std::env::var_os(SOCK_ENV).is_some() {
        return;
    }
    match crate::spawn_loopback() {
        Ok(address) => {
            // SAFETY: runs as a process constructor before `main`. The only
            // other thread is the server's, which reads the environment
            // through `std::env`, and std serialises that with `set_var`.
            unsafe { std::env::set_var(SOCK_ENV, format!("tcp://{address}")) };
            STARTED.store(true, Ordering::Release);
        }
        Err(error) => eprintln!("TSRA DDI socket server autostart failed: {error}"),
    }
}

extern "C" fn init() {
    start();
}

#[used]
#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
#[cfg_attr(windows, unsafe(link_section = ".CRT$XCU"))]
#[cfg_attr(
    target_vendor = "apple",
    unsafe(link_section = "__DATA,__mod_init_func")
)]
static INIT: extern "C" fn() = init;
