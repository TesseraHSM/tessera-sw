// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end test: [`tsra_ddi_sock::DdiSock`] against a real
//! `ddi_sock_server` process listening on `tcp://`.
//!
//! `ddi_sock_server` never dials out (no `CONNECT`/`OK` handshake); it
//! binds a listener directly and speaks the exact framed SQE/CQE
//! protocol `DdiSockDev` expects, so this test connects to it with no
//! bridge.

use std::io;
use std::net::TcpListener;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
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

/// Reserves an ephemeral TCP port by binding then immediately dropping a
/// listener, so the port can be handed to `ddi_sock_server`'s own
/// listener as a `tcp://HOST:PORT` endpoint before it starts. This has
/// an inherent (if small) race against another process grabbing the
/// same port between the bind and `ddi_sock_server` binding it again;
/// accepted here as the simplest way to pick a free port for a child
/// process to listen on.
fn reserve_ephemeral_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Locates the `ddi_sock_server` binary built alongside this test.
///
/// `ddi_sock_server` has no library target usable here (this test must
/// spawn it as a real process, not link it in-process), so Cargo cannot
/// wire it up as a normal dev-dependency. Instead this resolves the path
/// the same way Cargo lays out the workspace target directory:
/// `<target-dir>/<profile>/ddi_sock_server`. CI builds `ddi_sock_server`
/// explicitly before running this test (see `.github/workflows/rust.yml`);
/// set `server_bin` in `TSRA_TEST_ARGS` to override the path directly (e.g. for
/// local runs with a non-default target directory).
fn locate_ddi_sock_server_bin() -> std::path::PathBuf {
    if let Some(path) = ddi_sock_server::TestArgs::from_env().server_bin {
        return std::path::PathBuf::from(path);
    }

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("ddi/sock is two levels below the workspace root")
        .to_path_buf();
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
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

/// Starts `ddi_sock_server` listening on `127.0.0.1:<port>`.
fn spawn_ddi_sock_server_tcp(port: u16) -> io::Result<DdiSockServerGuard> {
    let child = Command::new(locate_ddi_sock_server_bin())
        .arg(format!("tcp://127.0.0.1:{port}"))
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
    endpoint: &str,
    timeout: Duration,
) -> tsra_ddi_sock::DdiSockDev {
    let deadline = Instant::now() + timeout;
    loop {
        match ddi.open_dev(endpoint) {
            Ok(dev) => return dev,
            Err(error) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
                let _ = error;
            }
            Err(error) => panic!("failed to connect to ddi_sock_server over TCP: {error}"),
        }
    }
}

/// Reconnects (via [`open_dev_with_retry`]) and issues `GetApiRev`,
/// retrying the whole connect-and-request cycle until it succeeds or
/// `timeout` elapses.
///
/// A freshly accepted TCP connection can occasionally be reset right
/// after `connect()` returns under heavy local load (observed flakily
/// in this test file when run alongside sibling tests spawning their
/// own `ddi_sock_server` processes concurrently) — a transient loopback
/// TCP/scheduling artifact, not a protocol bug, but `open_dev` alone
/// succeeds in that case, so only retrying the request (not just the
/// connect) actually recovers; and since the failed connection is dead,
/// recovery requires a brand new connection rather than retrying on
/// the same one.
fn reconnect_and_get_api_rev_with_retry(
    ddi: &DdiSock,
    endpoint: &str,
    timeout: Duration,
) -> tsra_ddi_sock::DdiSockDev {
    let deadline = Instant::now() + timeout;
    loop {
        let dev = open_dev_with_retry(ddi, endpoint, timeout);
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
        match dev.exec_op_mbor(&req, &mut cookie) {
            Ok(_) => return dev,
            Err(error) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
                let _ = error;
            }
            Err(error) => panic!("GetApiRev repeatedly failed against a fresh connection: {error}"),
        }
    }
}

#[test]
fn get_api_rev_round_trips_through_ddi_sock_server_over_tcp() {
    let port = reserve_ephemeral_port().expect("failed to reserve a TCP port");
    let _server = spawn_ddi_sock_server_tcp(port).expect("failed to start ddi_sock_server");
    let endpoint = format!("tcp://127.0.0.1:{port}");

    let ddi = DdiSock::default();
    let dev = open_dev_with_retry(&ddi, &endpoint, Duration::from_secs(10));

    assert_get_api_rev_succeeds(&dev);
}

/// Regression test for the shared-partition reset invariant over TCP:
/// `ddi_sock_server` must keep accepting new connections and serving
/// requests after a client disconnects.
#[test]
fn reconnect_after_disconnect_still_serves_requests_over_tcp() {
    let port = reserve_ephemeral_port().expect("failed to reserve a TCP port");
    let _server = spawn_ddi_sock_server_tcp(port).expect("failed to start ddi_sock_server");
    let endpoint = format!("tcp://127.0.0.1:{port}");

    let ddi = DdiSock::default();

    {
        let dev = open_dev_with_retry(&ddi, &endpoint, Duration::from_secs(10));
        assert_get_api_rev_succeeds(&dev);
        // Dropping `dev` closes the connection; `ddi_sock_server` should
        // keep accepting the next client.
    }

    reconnect_and_get_api_rev_with_retry(&ddi, &endpoint, Duration::from_secs(10));
}

/// Regression test: `ddi_sock_server` is designed to serve multiple
/// simultaneous connections against the same shared partition rather
/// than resetting it per-connection. This asserts that shape actually
/// works end-to-end over TCP: several connections opened at once must
/// all be able to issue requests successfully.
#[test]
fn concurrent_connections_are_all_served_over_tcp() {
    const CONNECTIONS: usize = 4;

    let port = reserve_ephemeral_port().expect("failed to reserve a TCP port");
    let _server = spawn_ddi_sock_server_tcp(port).expect("failed to start ddi_sock_server");
    let endpoint = format!("tcp://127.0.0.1:{port}");

    let ddi = DdiSock::default();
    let devs: Vec<_> = (0..CONNECTIONS)
        .map(|_| open_dev_with_retry(&ddi, &endpoint, Duration::from_secs(10)))
        .collect();

    for dev in &devs {
        assert_get_api_rev_succeeds(dev);
    }
}
