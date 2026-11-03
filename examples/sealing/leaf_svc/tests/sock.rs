// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "sock")]

use std::fs;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use jzon::JsonValue;
use tsra_sealing_common::http::Client;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("sealing-sock-{}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("socket sealing test cleanup failed: {error}");
        }
    }
}

struct Process(Child);

impl Process {
    fn spawn(command: &mut Command, log: &Path) -> Result<Self> {
        let stdout = fs::File::create(log)?;
        Ok(Self(
            command.stdout(stdout).stderr(Stdio::inherit()).spawn()?,
        ))
    }

    fn alive(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.0.try_wait()?.is_none(),
            "child exited before readiness"
        );
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Err(error) = self.0.kill() {
            eprintln!("socket sealing child shutdown failed: {error}");
        }
        if let Err(error) = self.0.wait() {
            eprintln!("socket sealing child reap failed: {error}");
        }
    }
}

fn binary(name: &str) -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_leaf_svc"))
        .with_file_name(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

fn address() -> Result<SocketAddr> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?)
}

fn socket_server(dir: &Path, name: &str) -> Result<(Process, String)> {
    let address = address()?;
    let endpoint = format!("tcp://{address}");
    let mut process = Process::spawn(
        Command::new(binary("ddi_sock_server")).arg(&endpoint),
        &dir.join(format!("{name}-ddi.log")),
    )
    .context("build ddi_sock_server before running the socket integration test")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        process.alive()?;
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok((process, endpoint));
        }
        anyhow::ensure!(Instant::now() < deadline, "DDI listener readiness timeout");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn app(name: &str, endpoint: &str) -> Command {
    let mut command = Command::new(binary(name));
    command.env("TSRA_DDI_SOCK", endpoint);
    command
}

fn worker(command: &mut Command, url: &str, log: &Path) -> Result<Process> {
    let address = url.strip_prefix("http://").context("worker URL")?;
    let mut process = Process::spawn(command.args(["--listen", address]), log)?;
    let client = Client::new(url)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        process.alive()?;
        if let Ok(health) = client.get("/v1/health") {
            anyhow::ensure!(
                health["status"] == "ok" && health["backend"] == "sock",
                "worker must use the socket backend"
            );
            return Ok(process);
        }
        anyhow::ensure!(Instant::now() < deadline, "worker readiness timeout");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn run(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    anyhow::ensure!(
        output.status.success(),
        "sealing command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn record(path: &Path) -> Result<JsonValue> {
    Ok(jzon::parse(&fs::read_to_string(path)?)?)
}

fn sign(client: &Client, identity: &JsonValue) -> Result<()> {
    let signed = client.post(
        "/v1/sign",
        &jzon::object! { challenge: "socket sealing integration" },
    )?;
    anyhow::ensure!(signed["verified"] == true, "signature must verify");
    anyhow::ensure!(signed["identity"] == *identity, "domain identity changed");
    Ok(())
}

#[test]
fn socket_leaf_create_restore_and_authorized_join() -> Result<()> {
    let dir = TestDir::new()?;
    let root_state = dir.0.join("root");
    let leaf_state = dir.0.join("primary");
    let joined_state = dir.0.join("secondary");
    let (_root_ddi, root_endpoint) = socket_server(&dir.0, "root")?;
    let (_leaf_ddi, leaf_endpoint) = socket_server(&dir.0, "primary")?;
    let root_url = format!("http://{}", address()?);
    let leaf_url = format!("http://{}", address()?);
    let root = Client::new(&root_url)?;
    let leaf = Client::new(&leaf_url)?;
    let root_log = dir.0.join("root.log");
    let primary_log = dir.0.join("primary.log");

    let root_process = worker(
        app("root_svc", &root_endpoint)
            .args(["create", "--name", "root", "--state-dir"])
            .arg(&root_state),
        &root_url,
        &root_log,
    )
    .context("root creation over sock")?;
    let primary = worker(
        app("leaf_svc", &leaf_endpoint)
            .args([
                "create",
                "--name",
                "orders",
                "--root",
                &root_url,
                "--state-dir",
            ])
            .arg(&leaf_state),
        &leaf_url,
        &primary_log,
    )
    .context("leaf creation over sock")?;
    let identity = leaf.get("/v1/health")?["identity"].clone();
    for _ in 0..3 {
        sign(&leaf, &identity)?;
    }
    let keys = fs::read(leaf_state.join("keys.json"))?;
    let root_backup = fs::read(root_state.join("leaf-remote-orders.json"))?;
    assert_eq!(
        root.get("/v1/leaves/orders/recovery")?["status"],
        "available"
    );
    assert_eq!(
        root.get("/v1/leaves/orders/catalog")?["scope"],
        "security-domain"
    );
    assert!(leaf_state.join("leaf-backup.json").exists());

    let duplicate = app("leaf_svc", &leaf_endpoint)
        .args([
            "create",
            "--name",
            "orders",
            "--root",
            &root_url,
            "--state-dir",
        ])
        .arg(&leaf_state)
        .output()?;
    assert!(!duplicate.status.success());
    sign(&leaf, &identity)?;
    drop(primary);

    let output = run(app("leaf_svc", &leaf_endpoint)
        .args(["restore-local", "--reset", "--state-dir"])
        .arg(&leaf_state))?;
    for expected in [
        "local: sign + verify passed",
        "security-domain: sign + verify passed",
        "ephemeral: rejected as expected",
        "session: rejected as expected",
    ] {
        assert!(
            output.contains(expected),
            "missing recovery scope proof: {expected}"
        );
    }
    assert_eq!(fs::read(leaf_state.join("keys.json"))?, keys);

    // Application restarts retain the remote emulator. Reset explicitly,
    // rather than restarting a server and losing its device-lifetime state.
    drop(root_process);
    let _root_process = worker(
        app("root_svc", &root_endpoint)
            .args(["restore-local", "--reset", "--state-dir"])
            .arg(&root_state),
        &root_url,
        &root_log,
    )?;
    let recovery_path = leaf_state.join("recovery-state.json");
    let mut recovery = record(&recovery_path)?;
    recovery["security_domain"] = JsonValue::Null;
    fs::write(&recovery_path, recovery.dump())?;
    fs::remove_file(leaf_state.join("leaf-backup.json"))?;
    let retained_recovery = fs::read(&recovery_path)?;
    let backup_path = root_state.join("leaf-remote-orders.json");
    fs::remove_file(&backup_path)?;
    let missing = app("leaf_svc", &leaf_endpoint)
        .args(["restore-remote", "--reset", "--state-dir"])
        .arg(&leaf_state)
        .output()?;
    assert!(!missing.status.success());
    assert!(!String::from_utf8_lossy(&missing.stdout).contains("Opening"));
    assert_eq!(fs::read(&recovery_path)?, retained_recovery);
    let mut corrupt = jzon::parse(std::str::from_utf8(&root_backup)?)?;
    let mut seal = hex::decode(corrupt["pok_remote_backup"].as_str().context("seal")?)?;
    *seal.last_mut().context("seal tag")? ^= 1;
    corrupt["pok_remote_backup"] = hex::encode(seal).into();
    fs::write(&backup_path, corrupt.dump())?;
    let rejected = app("leaf_svc", &leaf_endpoint)
        .args(["restore-remote", "--reset", "--state-dir"])
        .arg(&leaf_state)
        .output()?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("root reseal failed"));
    assert_eq!(fs::read(&recovery_path)?, retained_recovery);
    assert!(leaf_state.join("leaf-remote-prepared.json").exists());
    assert!(!leaf_state.join("leaf-resealed.json").exists());
    fs::write(&backup_path, &root_backup)?;

    let _primary = worker(
        app("leaf_svc", &leaf_endpoint)
            .args(["restore-remote", "--reset", "--state-dir"])
            .arg(&leaf_state),
        &leaf_url,
        &primary_log,
    )
    .context("root-resealed leaf recovery over sock without local SD backup")?;
    sign(&leaf, &identity)?;
    assert_eq!(fs::read(leaf_state.join("keys.json"))?, keys);
    assert_eq!(
        fs::read(root_state.join("leaf-remote-orders.json"))?,
        root_backup
    );
    assert!(leaf_state.join("leaf-remote-prepared.json").exists());
    assert!(leaf_state.join("leaf-resealed.json").exists());

    let (_joined_ddi, joined_endpoint) = socket_server(&dir.0, "secondary")?;
    let mut join = app("leaf_svc", &joined_endpoint);
    join.args([
        "join",
        "--name",
        "orders",
        "--instance",
        "secondary",
        "--root",
        &root_url,
        "--state-dir",
    ])
    .arg(&joined_state);
    let rejected = join.output()?;
    assert!(!rejected.status.success());
    assert!(!joined_state.join("leaf.json").exists());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("not authorized"));
    root.post(
        "/v1/leaves/orders/instances",
        &jzon::object! { instance: "secondary" },
    )?;
    let joined_url = format!("http://{}", address()?);
    let _joined = worker(&mut join, &joined_url, &dir.0.join("secondary.log"))?;
    let joined = Client::new(&joined_url)?;
    for _ in 0..3 {
        sign(&leaf, &identity)?;
        sign(&joined, &identity)?;
    }
    let primary_keys = record(&leaf_state.join("keys.json"))?;
    let joined_keys = record(&joined_state.join("keys.json"))?;
    assert_eq!(
        primary_keys["ecc_keys"]["security-domain"],
        joined_keys["ecc_keys"]["security-domain"]
    );
    for scope in ["local", "ephemeral", "session"] {
        assert_ne!(
            primary_keys["ecc_keys"][scope],
            joined_keys["ecc_keys"][scope]
        );
    }
    assert_ne!(
        record(&leaf_state.join("leaf.json"))?["seed"],
        record(&joined_state.join("leaf.json"))?["seed"]
    );
    Ok(())
}
