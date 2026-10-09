// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "emu")]

use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "sealing-peer-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("peer test cleanup failed: {error}");
        }
    }
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        if let Err(error) = self.0.kill() {
            eprintln!("peer server shutdown failed: {error}");
        }
        if let Err(error) = self.0.wait() {
            eprintln!("peer server reap failed: {error}");
        }
    }
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_root_svc"))
}

fn success(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    anyhow::ensure!(
        output.status.success(),
        "command failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn record(path: &Path) -> Result<jzon::JsonValue> {
    Ok(jzon::parse(&fs::read_to_string(path)?)?)
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(2)))
        .build()
        .into()
}

fn reject_invalid_enrollment(url: &str, policy_bytes: &[u8]) -> Result<()> {
    use tsra_api::PartPolicy;
    use tsra_crypto::HashAlgo;
    use tsra_crypto::HashOp;
    use tsra_sealing_api::device_cert_chain;
    use tsra_sealing_api::SealingSession;

    let mut response = agent().get(format!("{url}/v1/authorities")).call()?;
    let authorities = jzon::parse(&response.body_mut().read_to_string()?)?;
    let thumbprint = |name: &str| -> Result<[u8; 48]> {
        let cert = hex::decode(
            authorities[name]
                .as_str()
                .context("authority certificate")?,
        )?;
        let mut digest = [0u8; 48];
        HashAlgo::sha384().hash(&cert, Some(&mut digest))?;
        Ok(digest)
    };
    let session = SealingSession::open_reset()?;
    let policy = PartPolicy::ref_from_wire(policy_bytes).context("decode policy")?;
    let initialized = session.session.part_init_ex(
        policy,
        &[0x42; 32],
        &thumbprint("pota")?,
        &thumbprint("sata")?,
        None,
    )?;
    let manufacturer = device_cert_chain(&session.partition, 0)?;
    let request = jzon::object! {
        csr: hex::encode(&initialized.pta_csr),
        report: hex::encode(&initialized.pta_report),
        manufacturer: jzon::JsonValue::Array(manufacturer.iter().map(|cert| hex::encode(cert).into()).collect()),
    };
    let mut malformed_csr = request.clone();
    malformed_csr["csr"] = "00".into();
    let mut bad_csr_signature = request.clone();
    let mut csr = initialized.pta_csr;
    *csr.last_mut().context("CSR signature")? ^= 1;
    bad_csr_signature["csr"] = hex::encode(csr).into();
    let mut bad_report = request.clone();
    let mut report = initialized.pta_report;
    *report.last_mut().context("report signature")? ^= 1;
    bad_report["report"] = hex::encode(report).into();
    for invalid in [malformed_csr, bad_csr_signature, bad_report] {
        assert!(agent()
            .post(format!("{url}/v1/pta-cert"))
            .header("Content-Type", "application/json")
            .send(invalid.dump())
            .is_err());
        assert!(agent().get(format!("{url}/v1/health")).call().is_ok());
    }
    // The unchanged valid request succeeds; failures above are not merely
    // rejecting every request or failing due to unavailable device state.
    assert!(agent()
        .post(format!("{url}/v1/pta-cert"))
        .header("Content-Type", "application/json")
        .send(request.dump())
        .is_ok());
    Ok(())
}

fn run_clone(source: &str) -> Result<()> {
    let dir = TestDir::new()?;
    let primary = dir.0.join("primary");
    if source != "create" {
        success(
            command()
                .args([
                    "create",
                    "--name",
                    "primary",
                    "--remote-restorable",
                    "--state-dir",
                ])
                .arg(&primary),
        )?;
    }
    let reservation = TcpListener::bind("127.0.0.1:0")?;
    let address = reservation.local_addr()?;
    drop(reservation);
    let url = format!("http://{address}");
    let mut cmd = command();
    cmd.args([source, "--state-dir"])
        .arg(&primary)
        .args(["--listen", &address.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if source == "create" {
        cmd.args(["--name", "primary"]);
    }
    let mut server = Server(cmd.spawn()?);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        anyhow::ensure!(
            server.0.try_wait()?.is_none(),
            "primary exited before readiness"
        );
        if agent().get(format!("{url}/v1/health")).call().is_ok() {
            break;
        }
        anyhow::ensure!(Instant::now() < deadline, "primary readiness timeout");
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut response = agent().get(format!("{url}/v1/policy")).call()?;
    let served_policy = jzon::parse(&response.body_mut().read_to_string()?)?;
    let primary_record = record(&primary.join("recovery-state.json"))?;
    assert_eq!(
        served_policy["policy"],
        primary_record["partition"]["policy"]
    );
    assert_eq!(
        served_policy.len(),
        1,
        "policy endpoint returns only the full policy"
    );
    if source == "create" {
        reject_invalid_enrollment(
            &url,
            &hex::decode(served_policy["policy"].as_str().context("served policy")?)?,
        )?;
    }

    // Invalid network CSR must fail without terminating the service.
    assert!(agent()
        .post(format!("{url}/v1/pta-cert"))
        .header("Content-Type", "application/json")
        .send(r#"{"csr":"00","report":"00","manufacturer":[]}"#)
        .is_err());
    assert!(agent()
        .get(format!("{url}/v1/service-config"))
        .call()
        .is_err());
    assert!(agent().get(format!("{url}/v1/health")).call().is_ok());

    let secondary = dir.0.join("secondary");
    let output = success(
        command()
            .args([
                "clone",
                "--primary",
                &url,
                "--name",
                "secondary",
                "--state-dir",
            ])
            .arg(&secondary),
    )?;
    assert!(output.contains("Security domain cloned"));
    let stages = [
        "Peer cloning: authority certificates received from primary",
        "Peer cloning: PTA enrollment request to primary",
        "Peer cloning: issued certificate chains received from primary",
        "Peer cloning: Receiver sealing-key evidence",
        "Peer cloning: Sender sealing-key evidence",
        "Security domain cloned",
    ];
    let mut previous = 0;
    for stage in stages {
        let position = output
            .find(stage)
            .with_context(|| format!("missing {stage}"))?;
        assert!(
            position >= previous,
            "clone exchange output is out of order"
        );
        previous = position;
    }
    for chain in [
        "Primary POTA",
        "Primary SATA",
        "Joining peer POTA/PTA",
        "Joining peer SATA/PID",
    ] {
        assert!(output.contains(&format!("{chain} certificate chain (root-first;")));
    }
    for role in ["Receiver", "Sender"] {
        for chain in ["manufacturer", "partition-owner"] {
            assert!(output.contains(&format!("{role} {chain} certificate chain (root-first;")));
        }
        assert!(output.contains(&format!("{role} device-owner evidence: omitted (optional)")));
        assert!(output.contains(&format!("{role} attestation report:")));
    }
    assert!(output.contains("Joining PTA attestation report:"));
    assert_eq!(
        output
            .matches("Verification:        valid ES384 signature")
            .count(),
        3
    );
    assert_eq!(output.matches("Policy digest:       SHA-384").count(), 3);
    assert!(output.contains("Trust: supplied root only"));
    assert!(!output.contains("-----BEGIN"));
    let secondary_record = record(&secondary.join("recovery-state.json"))?;
    assert_eq!(
        secondary_record["partition"]["policy"],
        primary_record["partition"]["policy"]
    );
    assert_ne!(
        secondary_record["partition"]["local_mk_backup"],
        primary_record["partition"]["local_mk_backup"]
    );
    assert!(
        !secondary.join("pota.json").exists(),
        "never copy private software authority keys"
    );
    assert!(!secondary.join("sata.json").exists());
    for field in ["pok_local_backup", "sd_mk_backup"] {
        let blob = secondary_record["security_domain"][field]
            .as_str()
            .context("backup field")?;
        assert!(!blob.is_empty());
        assert!(!output.contains(blob), "backup bytes must not be displayed");
    }
    let prepared = record(&secondary.join("peer-prepared.json"))?;
    for field in ["local_mk_backup", "masked_receiver", "report"] {
        assert!(
            !output.contains(prepared[field].as_str().context("prepared field")?),
            "raw recovery material or report must not be displayed"
        );
    }
    // Prove the source's original domain key works on the distinct peer;
    // merely generating a new key on the destination would not prove cloning.
    let source_keys = record(&primary.join("keys.json"))?;
    let mut destination_keys = record(&secondary.join("keys.json"))?;
    destination_keys["ecc_keys"]["security-domain"] =
        source_keys["ecc_keys"]["security-domain"].clone();
    fs::write(secondary.join("keys.json"), destination_keys.dump())?;
    let output = success(
        command()
            .args(["restore-local", "--state-dir"])
            .arg(&secondary),
    )?;
    assert!(output.contains("Security domain restored from local backups."));
    assert!(output.contains("security-domain: sign + verify passed"));
    assert!(output.contains("local: sign + verify passed"));
    assert!(output.contains("ephemeral: rejected as expected"));
    assert!(output.contains("session: rejected as expected"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in ["peer.json", "peer-prepared.json", "recovery-state.json"] {
            assert_eq!(
                fs::metadata(secondary.join(file))?.permissions().mode() & 0o777,
                0o600
            );
        }
    }

    let duplicate = command()
        .args([
            "clone",
            "--primary",
            &url,
            "--name",
            "secondary",
            "--state-dir",
        ])
        .arg(&secondary)
        .output()?;
    assert!(!duplicate.status.success());
    assert!(!String::from_utf8(duplicate.stdout)?.contains("Opening"));
    let mut peer_metadata = record(&secondary.join("peer.json"))?;
    peer_metadata["policy"] = "00".into();
    fs::write(secondary.join("peer.json"), peer_metadata.dump())?;
    let invalid_restore = command()
        .args(["restore-local", "--reset", "--state-dir"])
        .arg(&secondary)
        .output()?;
    assert!(!invalid_restore.status.success());
    assert!(!String::from_utf8(invalid_restore.stdout)?.contains("Opening"));
    Ok(())
}

#[test]
fn clone_from_created_primary() -> Result<()> {
    run_clone("create")
}

#[test]
fn clone_from_locally_restored_primary() -> Result<()> {
    run_clone("restore-local")
}

#[test]
fn clone_from_remotely_restored_primary() -> Result<()> {
    run_clone("restore-remote")
}

#[test]
fn non_loopback_listen_is_rejected_before_device_access() -> Result<()> {
    let dir = TestDir::new()?;
    let output = command()
        .args([
            "create",
            "--name",
            "primary",
            "--listen",
            "0.0.0.0:8000",
            "--state-dir",
        ])
        .arg(dir.0.join("state"))
        .output()?;
    assert!(!output.status.success());
    assert!(!String::from_utf8(output.stdout)?.contains("Opening"));
    assert!(!dir.0.join("state").exists());
    Ok(())
}
