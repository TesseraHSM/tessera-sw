// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Start an in-process server before `main` for test executables.
//!
//! Linking this crate with the `autostart` feature registers a process
//! constructor that, unless `TSRA_DDI_SOCK` is already set, starts the server
//! on an ephemeral loopback port and points `TSRA_DDI_SOCK` at it. Every test
//! process therefore gets its own emulated HSM, and the unchanged socket
//! transport connects to it. Child processes inherit the endpoint.
//!
//! With `autostart-isolated`, the server is always started and the endpoint
//! is only set for this process (see [`tsra_ddi_sock::set_process_endpoint`]),
//! so processes spawned with an inherited environment (such as libFuzzer
//! `-jobs`/`-fork` workers) each get their own HSM.
//!
//! Link this only into executables, never into a library that another
//! program loads (PKCS#11 module, OpenSSL engine or provider): there the
//! constructor would run in a host that may already be multithreaded, and
//! unloading the library would pull code out from under the server thread.

#![allow(unsafe_code)]

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

const SOCK_ENV: &str = "TSRA_DDI_SOCK";

static STARTED: AtomicBool = AtomicBool::new(false);

/// Whether this process started its own in-process server (rather than
/// using an external `TSRA_DDI_SOCK` endpoint).
pub fn autostarted() -> bool {
    STARTED.load(Ordering::Acquire)
}

fn start() {
    let isolated = cfg!(feature = "autostart-isolated");
    if !isolated && std::env::var_os(SOCK_ENV).is_some() {
        return;
    }
    let result = crate::tcp::spawn_loopback_with(|address| {
        let endpoint = format!("tcp://{address}");
        if !isolated {
            // SAFETY: runs in an executable's constructor before `main`, and
            // before the server thread is spawned, so no other thread can
            // access the environment concurrently.
            unsafe { std::env::set_var(SOCK_ENV, &endpoint) };
        }
        let _ = tsra_ddi_sock::set_process_endpoint(endpoint);
    });
    match result {
        Ok(_) => STARTED.store(true, Ordering::Release),
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
