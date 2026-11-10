// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end test: [`tsra_ddi_sock::DdiSock`] against a real
//! `ddi_sock_server` process listening on `unix://`.
//!
//! `ddi_sock_server`'s `unix://PATH` mode binds and accepts directly (no
//! `CONNECT`/`OK` dial-out handshake): `DdiSockDev` connects to it with
//! no bridge at all. `unix://` depends on
//! `std::os::unix::net::UnixListener` (see `ddi/sock/server/
//! src/unix.rs`), so this file is Linux-only.

#![cfg(target_os = "linux")]

use std::io;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use tsra_ddi_interface::Ddi;
use tsra_ddi_interface::DdiDev;
use tsra_ddi_mbor_types::DdiApiRev;
use tsra_ddi_mbor_types::DdiGetApiRevCmdReq;
use tsra_ddi_mbor_types::DdiGetApiRevReq;
use tsra_ddi_mbor_types::DdiOp;
use tsra_ddi_mbor_types::DdiReqHdr;
use tsra_ddi_sock::DdiSock;

/// Kills the `ddi_sock_server` child process when dropped, so a failing
/// assertion never leaks a background server.
struct DdiSockServerGuard(Child);

impl Drop for DdiSockServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Deletes the socket file (if any) when dropped, so a failing assertion
/// never leaves a stale socket behind for a later test run to trip over.
struct SocketPathGuard(PathBuf);

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A unique-per-test socket path under the OS temp directory.
fn unique_socket_path(tag: &str) -> PathBuf {
    static NEXT_ID: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!(
        "tsra-ddi-sock-test-ddi-sock-server-unix-{tag}-{}-{}.sock",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Locates the `ddi_sock_server` binary built alongside this test. See
/// the identical helper in `ddi_sock_server_tcp_integration.rs` for why
/// this can't just be a normal dev-dependency.
fn locate_ddi_sock_server_bin() -> PathBuf {
    if let Some(path) = ddi_sock_server::TestArgs::from_env().server_bin {
        return PathBuf::from(path);
    }

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("ddi/sock is two levels below the workspace root")
        .to_path_buf();
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("target"));
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    // Cargo builds `ddi_sock_server.exe` on Windows; without the suffix
    // this `exists()` check fails there even after a successful build.
    let bin = target_dir
        .join(profile)
        .join(format!("ddi_sock_server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        bin.exists(),
        "ddi_sock_server binary not found at {bin:?}; build it first with \
         `cargo build -p ddi_sock_server` (or set `server_bin` in TSRA_TEST_ARGS)"
    );
    bin
}

/// Starts `ddi_sock_server` listening at `unix://<socket>`.
fn spawn_ddi_sock_server_unix(socket: &std::path::Path) -> io::Result<DdiSockServerGuard> {
    let child = Command::new(locate_ddi_sock_server_bin())
        .arg(format!(
            "unix://{}",
            socket.to_str().expect("temp path is valid UTF-8")
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(DdiSockServerGuard(child))
}

/// Issues a `GetApiRev` request over `dev` and asserts it succeeds
/// against `ddi_sock_server`'s in-process `StdHsm`.
fn assert_get_api_rev_succeeds(dev: &tsra_ddi_sock::DdiSockDev) {
    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            rev: None,
            op: DdiOp::GetApiRev,
            sess_id: None,
        },
        data: DdiGetApiRevReq {},
        ext: None,
    };

    let mut cookie = None;
    let resp = dev
        .exec_op_mbor(&req, &mut cookie)
        .expect("GetApiRev should succeed against ddi_sock_server's StdHsm");

    assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
    assert_eq!(
        resp.data.min,
        DdiApiRev { major: 1, minor: 0 },
        "StdHsm should report min api rev 1.0",
    );
    assert_eq!(
        resp.data.max,
        DdiApiRev { major: 1, minor: 1 },
        "StdHsm should report max api rev 1.1",
    );
}

/// Retries `open_dev` until it succeeds or `timeout` elapses, since
/// `ddi_sock_server`'s listener may not be bound yet immediately after
/// spawn.
fn open_dev_with_retry(
    ddi: &DdiSock,
    socket: &str,
    timeout: Duration,
) -> tsra_ddi_sock::DdiSockDev {
    let deadline = Instant::now() + timeout;
    loop {
        match ddi.open_dev(socket) {
            Ok(dev) => return dev,
            Err(error) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
                let _ = error;
            }
            Err(error) => panic!("failed to connect to ddi_sock_server's unix socket: {error}"),
        }
    }
}

#[test]
fn get_api_rev_round_trips_through_ddi_sock_server_over_unix() {
    let socket = unique_socket_path("get-api-rev");
    let _socket_guard = SocketPathGuard(socket.clone());
    let _server = spawn_ddi_sock_server_unix(&socket).expect("failed to start ddi_sock_server");

    let ddi = DdiSock::default();
    let dev = open_dev_with_retry(
        &ddi,
        socket.to_str().expect("temp path is valid UTF-8"),
        Duration::from_secs(10),
    );

    assert_get_api_rev_succeeds(&dev);
}

/// Regression test for the shared-partition reset invariant over
/// `unix://`: `ddi_sock_server` must keep accepting new connections and
/// serving requests after a client disconnects (mirrors
/// `ddi_sock_server_tcp_integration.rs`'s TCP coverage of this
/// invariant).
#[test]
fn reconnect_after_disconnect_still_serves_requests_over_unix() {
    let socket = unique_socket_path("reconnect-after-disconnect");
    let _socket_guard = SocketPathGuard(socket.clone());
    let _server = spawn_ddi_sock_server_unix(&socket).expect("failed to start ddi_sock_server");
    let socket_str = socket.to_str().expect("temp path is valid UTF-8");

    let ddi = DdiSock::default();

    {
        let dev = open_dev_with_retry(&ddi, socket_str, Duration::from_secs(10));
        assert_get_api_rev_succeeds(&dev);
        // Dropping `dev` closes the connection; `ddi_sock_server` should
        // keep accepting the next client.
    }

    let dev2 = open_dev_with_retry(&ddi, socket_str, Duration::from_secs(10));
    assert_get_api_rev_succeeds(&dev2);
}
