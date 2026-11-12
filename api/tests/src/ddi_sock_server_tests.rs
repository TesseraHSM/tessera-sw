// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test: `tsra_api`'s high-level partition/session API
//! against a real `ddi_sock_server` process.
//!
//! `ddi/sock/tests/ddi_sock_server_*_integration.rs` already cover the
//! raw DDI wire protocol (`GetApiRev` round trips, reconnect-after-
//! disconnect) directly against `tsra_ddi_sock`, and `ddi_sock_server`'s
//! own crate tests (`ddi/sock/server/src/tcp.rs`) cover
//! session ownership, reset, and cleanup at the DDI/connection level in
//! depth. What neither covers is the high-level `tsra_api` layer
//! (`HsmPartitionManager`, `HsmPartition`, `HsmSession`) actually
//! working end-to-end over this transport.
//!
//! `ddi_sock_server` initializes its partition once at server startup
//! and keeps it enabled for the life of the process, shared across
//! arbitrarily many concurrent connections (see
//! `ddi/sock/server/README.md`) rather than resetting
//! (and requiring re-`init`) on every disconnect. So this test `init`s
//! the partition once, then drives many real session open/close cycles
//! (including concurrently) against the one initialized partition.
//!
//! Each test spawns its own `ddi_sock_server`, so it runs regardless of the
//! transport `TSRA_TEST_ARGS` selects.

use std::io;
use std::net::TcpListener;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use tsra_api::*;

use crate::utils::partition::APP_ID;
use crate::utils::partition::APP_PIN;
use crate::utils::partition::TEST_OBK;
use crate::utils::partition::generate_pota_endorsement;
use crate::utils::partition::test_api_rev;

/// Number of sequential open/close cycles to drive, comfortably past
/// `MAX_SESSIONS` (8, see `fw/plat/std/pal/src/drivers/session.rs`) so a
/// session leak (closed sessions not actually freeing their table slot)
/// would exhaust the partition's session table well before this test
/// completes.
const RECONNECTS: usize = 16;

/// Set on the re-executed child process (see [`reexec_with_ddi_sock_env`])
/// so it knows to run the test body directly instead of re-executing
/// itself again.
const REEXEC_CHILD_MARKER: &str = "TSRA_DDI_SOCK_SERVER_TEST_REEXEC_CHILD";

/// Kills the `ddi_sock_server` child process when dropped, so a failing
/// assertion never leaks a background server.
struct DdiSockServerGuard(Child);

impl Drop for DdiSockServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Reserves an ephemeral TCP port the same way
/// `ddi/sock/tests/ddi_sock_server_tcp_integration.rs` does.
fn reserve_ephemeral_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Re-executes the current test binary, filtered down to `test_name`,
/// with the `sock` key of `TSRA_TEST_ARGS` set (via [`Command::env`]) to a freshly
/// reserved `tcp://127.0.0.1:<port>` endpoint - the only endpoint
/// `HsmPartitionManager::open_partition` will accept, since its
/// internal `dev_info_by_path` lookup matches against
/// `tsra_ddi_sock::DdiSock::dev_info_list()`'s reported path, not
/// whatever path a caller passes to `open_partition` directly.
///
/// Setting an environment variable on an about-to-be-spawned child
/// process is always safe (unlike mutating this process's own
/// environment with `std::env::set_var`, which is unsound if any other
/// thread might concurrently read or write it), so this lets the test
/// body observe the endpoint without this crate ever needing
/// `unsafe_code`.
fn reexec_with_ddi_sock_env(test_name: &str) {
    let port = reserve_ephemeral_port().expect("failed to reserve a TCP port");
    let mut args = ddi_sock_server::TestArgs::from_env();
    args.sock = Some(format!("tcp://127.0.0.1:{port}"));

    let exe = std::env::current_exe().expect("failed to resolve current test executable");
    let status = Command::new(exe)
        .arg(test_name)
        .arg("--nocapture")
        .env(ddi_sock_server::TEST_ARGS_ENV, args.to_string())
        .env(REEXEC_CHILD_MARKER, "1")
        .status()
        .expect("failed to spawn re-executed test process");
    assert!(
        status.success(),
        "re-executed test process for `{test_name}` failed: {status}"
    );
}

/// Locates the `ddi_sock_server` binary built alongside this test. See
/// the identical helper in `ddi/sock/tests/ddi_sock_server_tcp_integration
/// .rs` for why this can't just be a normal dev-dependency.
fn locate_ddi_sock_server_bin() -> std::path::PathBuf {
    if let Some(path) = ddi_sock_server::TestArgs::from_env().server_bin {
        return std::path::PathBuf::from(path);
    }

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("api/tests is two levels below the workspace root")
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

/// Starts `ddi_sock_server` listening at the `tcp://HOST:PORT` endpoint
/// named by the `sock` key of `TSRA_TEST_ARGS` (set by
/// [`reexec_with_ddi_sock_env`]).
fn spawn_ddi_sock_server(endpoint: &str) -> io::Result<DdiSockServerGuard> {
    let child = Command::new(locate_ddi_sock_server_bin())
        .arg(endpoint)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(DdiSockServerGuard(child))
}

/// Retries [`HsmPartitionManager::open_partition`] until it succeeds or
/// `timeout` elapses, since `ddi_sock_server`'s listener may not be
/// bound yet immediately after spawn.
fn open_partition_with_retry(path: &str, api_rev: HsmApiRev, timeout: Duration) -> HsmPartition {
    let deadline = Instant::now() + timeout;
    loop {
        match HsmPartitionManager::open_partition(path, api_rev) {
            Ok(part) => return part,
            Err(error) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
                let _ = error;
            }
            Err(error) => panic!("failed to connect to ddi_sock_server: {error}"),
        }
    }
}

/// Regression test: `ddi_sock_server` must fully free a closed (or
/// dropped) session's table slot, not just its connection, across many
/// sequential open/close cycles against the one partition it
/// initializes at startup.
#[test]
fn many_sequential_sessions_do_not_exhaust_partition() {
    // Re-execute this test in a child process with the `sock` endpoint set
    // via `Command::env` instead of mutating this process's own
    // environment: see `reexec_with_ddi_sock_env`.
    if std::env::var_os(REEXEC_CHILD_MARKER).is_none() {
        return reexec_with_ddi_sock_env("many_sequential_sessions_do_not_exhaust_partition");
    }

    let endpoint = ddi_sock_server::TestArgs::from_env()
        .sock
        .expect("sock must be set by re-exec");
    let _server = spawn_ddi_sock_server(&endpoint).expect("failed to start ddi_sock_server");
    let api_rev = test_api_rev();

    let part = open_partition_with_retry(&endpoint, api_rev, Duration::from_secs(10));
    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (sig, pubkey) = generate_pota_endorsement(&part);
    let obk_config = HsmOwnerBackupKeyConfig::new(
        HsmOwnerBackupKeySource::Caller,
        HsmOwnerBackupKey::from_obk(&TEST_OBK),
    );
    let pota_endorsement = HsmPotaEndorsement::new(
        HsmPotaEndorsementSource::Caller,
        Some(HsmPotaEndorsementData::new(&sig, &pubkey)),
    );
    part.init(creds, None, None, obk_config, pota_endorsement, None)
        .expect("partition init failed");

    for i in 0..RECONNECTS {
        let session = part
            .open_session(api_rev, &creds, None)
            .unwrap_or_else(|error| panic!("failed to open session on iteration {i}: {error}"));
        // Dropping `session` here sends a graceful `CloseSession`
        // before the next iteration opens a new one; a session-table
        // leak would exhaust `MAX_SESSIONS` well before `RECONNECTS`.
        drop(session);
    }
}

/// Regression test: `ddi_sock_server` must support many
/// *simultaneously open* sessions against the same partition, since
/// each session owns its own connection and slot independently of the
/// others.
#[test]
fn many_concurrent_sessions_are_all_usable() {
    if std::env::var_os(REEXEC_CHILD_MARKER).is_none() {
        return reexec_with_ddi_sock_env("many_concurrent_sessions_are_all_usable");
    }

    const CONCURRENT_SESSIONS: usize = 4;

    let endpoint = ddi_sock_server::TestArgs::from_env()
        .sock
        .expect("sock must be set by re-exec");
    let _server = spawn_ddi_sock_server(&endpoint).expect("failed to start ddi_sock_server");
    let api_rev = test_api_rev();

    let part = open_partition_with_retry(&endpoint, api_rev, Duration::from_secs(10));
    let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
    let (sig, pubkey) = generate_pota_endorsement(&part);
    let obk_config = HsmOwnerBackupKeyConfig::new(
        HsmOwnerBackupKeySource::Caller,
        HsmOwnerBackupKey::from_obk(&TEST_OBK),
    );
    let pota_endorsement = HsmPotaEndorsement::new(
        HsmPotaEndorsementSource::Caller,
        Some(HsmPotaEndorsementData::new(&sig, &pubkey)),
    );
    part.init(creds, None, None, obk_config, pota_endorsement, None)
        .expect("partition init failed");

    // Each connection dials the same already-initialized partition
    // independently (`HsmPartitionManager::open_partition` opens a
    // fresh socket each time), so opening several sessions from
    // independent partition handles concurrently genuinely exercises
    // `ddi_sock_server`'s concurrent-connection design.
    let sessions: Vec<_> = (0..CONCURRENT_SESSIONS)
        .map(|i| {
            let conn_part = open_partition_with_retry(&endpoint, api_rev, Duration::from_secs(10));
            conn_part
                .open_session(api_rev, &creds, None)
                .unwrap_or_else(|error| panic!("failed to open concurrent session {i}: {error}"))
        })
        .collect();

    assert_eq!(sessions.len(), CONCURRENT_SESSIONS);
    // All sessions are dropped together here, each sending its own
    // graceful `CloseSession` over its own connection.
}
