// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Start an in-process server before `main` for test executables.
//!
//! Linking this crate with the `autostart` feature registers a process
//! constructor that, when `TSRA_TEST_ARGS` selects the socket transport
//! (`transport=sock`) and names no `sock` endpoint, starts the server on an
//! ephemeral loopback port and adds `sock=tcp://ADDR` to `TSRA_TEST_ARGS`.
//! Every test process therefore gets its own emulated HSM, and the unchanged
//! socket transport connects to it. Child processes inherit the endpoint.
//!
//! With `autostart-isolated`, the server is started even if `TSRA_TEST_ARGS`
//! names a `sock` endpoint, and the endpoint is only set for this process
//! (see [`TestArgs::set_process`]), so processes spawned with an inherited
//! environment (such as libFuzzer `-jobs`/`-fork` workers) each get their own
//! HSM.
//!
//! Link this only into executables, never into a library that another
//! program loads (PKCS#11 module, OpenSSL engine or provider): there the
//! constructor would run in a host that may already be multithreaded, and
//! unloading the library would pull code out from under the server thread.

#![allow(unsafe_code)]

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use tsra_ddi::TEST_ARGS_ENV;
use tsra_ddi::TestArgs;

static STARTED: AtomicBool = AtomicBool::new(false);

/// Whether this process started its own in-process server (rather than
/// using an external `sock` endpoint from `TSRA_TEST_ARGS`).
pub fn autostarted() -> bool {
    STARTED.load(Ordering::Acquire)
}

fn start() {
    let isolated = cfg!(feature = "autostart-isolated");
    let mut args = TestArgs::from_env();
    if !tsra_ddi::sock_selected() || (!isolated && args.sock.is_some()) {
        return;
    }
    let result = crate::tcp::spawn_loopback_with(|address| {
        args.sock = Some(format!("tcp://{address}"));
        if isolated {
            let _ = TestArgs::set_process(args);
        } else {
            // SAFETY: runs in an executable's constructor before `main`, and
            // before the server thread is spawned, so no other thread can
            // access the environment concurrently.
            unsafe { std::env::set_var(TEST_ARGS_ENV, args.to_string()) };
        }
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
