// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Gives every service process its own simulated HSM.
//!
//! The service binaries only reach an HSM through the `sock` endpoint in
//! `TSRA_TEST_ARGS`, so each
//! run or spawn below first starts a dedicated `ddi_sock_server` process and
//! points the service at it. The server lives as long as the command output
//! is being collected, or as long as the spawned child. The test process
//! itself gets a separate in-process HSM from the autostart hook below.

#![allow(dead_code)]

// Starts an in-process DDI sock server before `main` for the test's own
// HSM use. Spawned services are pointed at their own servers instead.
use std::ffi::OsStr;
use std::io;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use ddi_sock_server as _;
use tsra_ddi::TestArgs;
use tsra_ddi::TEST_ARGS_ENV;

/// Path of a binary built next to `root_svc`.
pub fn sibling_binary(name: &str) -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_root_svc"))
        .with_file_name(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

/// The standalone `ddi_sock_server` binary: `server_bin` in `TSRA_TEST_ARGS`
/// when set, otherwise the one built next to `root_svc`.
fn ddi_sock_server_binary() -> PathBuf {
    TestArgs::from_env()
        .server_bin
        .map(PathBuf::from)
        .unwrap_or_else(|| sibling_binary("ddi_sock_server"))
}

/// `TSRA_TEST_ARGS` for a child process using the HSM at `endpoint`.
pub fn test_args_for(endpoint: &str) -> String {
    let mut args = TestArgs::from_env();
    args.sock = Some(endpoint.to_owned());
    args.to_string()
}

/// A running `ddi_sock_server` process, killed on drop.
pub struct Hsm {
    child: Child,
    endpoint: String,
}

impl Hsm {
    pub fn start() -> io::Result<Self> {
        let address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        let endpoint = format!("tcp://{address}");
        let child = Command::new(ddi_sock_server_binary())
            .arg(&endpoint)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("build ddi_sock_server before running this test: {error}"),
                )
            })?;
        let mut hsm = Self { child, endpoint };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = hsm.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "ddi_sock_server exited before readiness: {status}"
                )));
            }
            if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
                return Ok(hsm);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("ddi_sock_server readiness timeout"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Drop for Hsm {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            eprintln!("ddi_sock_server shutdown failed: {error}");
        }
        if let Err(error) = self.child.wait() {
            eprintln!("ddi_sock_server reap failed: {error}");
        }
    }
}

/// A service command that runs against its own fresh HSM.
pub struct SimCommand(Command);

impl SimCommand {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self(Command::new(program))
    }

    pub fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.0.arg(arg);
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.0.args(args);
        self
    }

    pub fn stdout(&mut self, cfg: impl Into<Stdio>) -> &mut Self {
        self.0.stdout(cfg);
        self
    }

    pub fn stderr(&mut self, cfg: impl Into<Stdio>) -> &mut Self {
        self.0.stderr(cfg);
        self
    }

    pub fn output(&mut self) -> io::Result<Output> {
        let hsm = Hsm::start()?;
        self.0
            .env(TEST_ARGS_ENV, test_args_for(hsm.endpoint()))
            .output()
    }

    pub fn spawn(&mut self) -> io::Result<SimChild> {
        let hsm = Hsm::start()?;
        let child = self
            .0
            .env(TEST_ARGS_ENV, test_args_for(hsm.endpoint()))
            .spawn()?;
        Ok(SimChild { child, _hsm: hsm })
    }
}

/// A spawned service and the HSM it uses. The HSM is dropped after the
/// service.
pub struct SimChild {
    child: Child,
    _hsm: Hsm,
}

impl std::ops::Deref for SimChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl std::ops::DerefMut for SimChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}
