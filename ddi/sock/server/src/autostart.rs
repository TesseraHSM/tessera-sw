// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Start an in-process server before `main` for test executables.
//!
//! Linking this crate with the `autostart` feature registers a process
//! constructor that, when `TSRA_TEST_ARGS` selects the socket transport
//! (`transport=sock`) and names no `sock` endpoint, starts the server on an
//! ephemeral loopback port and adds `sock=tcp://ADDR` to `TSRA_TEST_ARGS`.
//! Every test process therefore gets its own emulated HSM, and the unchanged
//! socket transport connects to it. The runner publishes the connection through
//! `TSRA_DDI_ARGS`, which child SDK processes inherit without test features.
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

use tsra_ddi::DDI_ARGS_ENV;
use tsra_ddi::DdiConfig;

use crate::TEST_ARGS_ENV;
use crate::TestArgs;

static STARTED: AtomicBool = AtomicBool::new(false);

/// Whether this process started its own in-process server (rather than
/// using an external `sock` endpoint from `TSRA_TEST_ARGS`).
pub fn autostarted() -> bool {
    STARTED.load(Ordering::Acquire)
}

fn start() {
    let isolated = cfg!(feature = "autostart-isolated");
    let mut args = TestArgs::from_env();
    let mut config = args.connection_config().unwrap_or_else(|error| {
        eprintln!("Invalid test connection configuration: {error}");
        std::process::exit(1);
    });
    let publish = |args: TestArgs, config: DdiConfig| {
        if isolated {
            TestArgs::set_process(args).expect("test configuration already set");
            DdiConfig::set_process(config).expect("connection configuration already set");
        } else {
            // SAFETY: this executable constructor runs before main and before
            // the server thread starts. Loaded product libraries never do this.
            unsafe {
                std::env::set_var(TEST_ARGS_ENV, args.to_string());
                std::env::set_var(DDI_ARGS_ENV, config.to_string());
            }
        }
    };
    if !config.transport.is_sock() || (!isolated && config.sock.is_some()) {
        publish(args, config);
        return;
    }
    let result = crate::tcp::spawn_loopback_with(|address| {
        args.sock = Some(format!("tcp://{address}"));
        config.sock = args.sock.clone();
        publish(args, config);
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
