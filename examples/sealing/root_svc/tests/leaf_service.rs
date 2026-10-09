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
use jzon::JsonValue;
use tsra_api::PartPolicy;
use tsra_sealing_common::http::Client;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "sealing-leaf-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("leaf test cleanup failed: {error}");
        }
    }
}

struct Server {
    child: Child,
    url: String,
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            eprintln!("root shutdown failed: {error}");
        }
        if let Err(error) = self.child.wait() {
            eprintln!("root reap failed: {error}");
        }
    }
}

fn root() -> Command {
    Command::new(env!("CARGO_BIN_EXE_root_svc"))
}
fn leaf() -> Command {
    // Cross-application suite: build both apps before running this target.
    let binary = Path::new(env!("CARGO_BIN_EXE_root_svc"))
        .with_file_name(format!("leaf_svc{}", std::env::consts::EXE_SUFFIX));
    Command::new(binary)
}

fn success(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    anyhow::ensure!(
        output.status.success(),
        "command failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn record(path: &Path) -> Result<JsonValue> {
    Ok(jzon::parse(&fs::read_to_string(path)?)?)
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(2)))
        .build()
        .into()
}

fn get(url: &str) -> Result<JsonValue> {
    Ok(jzon::parse(
        &agent().get(url).call()?.body_mut().read_to_string()?,
    )?)
}

fn start(state: &Path, previous_url: Option<&str>) -> Result<Server> {
    start_with_log(state, previous_url, None)
}

fn start_with_log(state: &Path, previous_url: Option<&str>, log: Option<&Path>) -> Result<Server> {
    let address = if let Some(url) = previous_url {
        url.strip_prefix("http://").context("root URL")?.to_owned()
    } else {
        let reservation = TcpListener::bind("127.0.0.1:0")?;
        reservation.local_addr()?.to_string()
    };
    let mut cmd = root();
    if previous_url.is_some() {
        cmd.arg("restore-local");
    } else {
        cmd.args(["create", "--name", "root"]);
    }
    let mut server = Server {
        child: cmd
            .arg("--state-dir")
            .arg(state)
            .args(["--listen", &address])
            .stdout(Stdio::null())
            .stderr(match log {
                Some(path) => Stdio::from(fs::File::create(path)?),
                None => Stdio::inherit(),
            })
            .spawn()?,
        url: format!("http://{address}"),
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        anyhow::ensure!(
            server.child.try_wait()?.is_none(),
            "root exited before readiness"
        );
        if get(&format!("{}/v1/health", server.url)).is_ok() {
            break;
        }
        anyhow::ensure!(Instant::now() < deadline, "root readiness timeout");
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(server)
}

fn start_worker(command: &mut Command) -> Result<Server> {
    let reservation = TcpListener::bind("127.0.0.1:0")?;
    let address = reservation.local_addr()?.to_string();
    drop(reservation);
    let mut server = Server {
        child: command
            .args(["--listen", &address, "--require-emu"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?,
        url: format!("http://{address}"),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        anyhow::ensure!(
            server.child.try_wait()?.is_none(),
            "leaf exited before readiness"
        );
        if get(&format!("{}/v1/health", server.url)).is_ok() {
            return Ok(server);
        }
        anyhow::ensure!(Instant::now() < deadline, "leaf readiness timeout");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn concurrent_instances_share_only_domain_key_and_require_explicit_enrollment() -> Result<()> {
    let dir = TestDir::new()?;
    let root_state = dir.0.join("root");
    let primary_state = dir.0.join("primary");
    let joined_state = dir.0.join("secondary");
    let root = start(&root_state, None)?;
    let base = format!("{}/v1/leaves/orders", root.url);
    let primary = start_worker(
        leaf()
            .args([
                "create",
                "--name",
                "orders",
                "--root",
                &root.url,
                "--state-dir",
            ])
            .arg(&primary_state),
    )?;
    let original_binding = fs::read(root_state.join("leaf-binding-orders.json"))?;
    let original_backup = fs::read(root_state.join("leaf-remote-orders.json"))?;
    let mut rejected = leaf();
    rejected
        .args([
            "join",
            "--name",
            "orders",
            "--instance",
            "secondary",
            "--root",
            &root.url,
            "--state-dir",
        ])
        .arg(&joined_state);
    let output = rejected.output()?;
    assert!(!output.status.success());
    assert!(!joined_state.join("leaf.json").exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not authorized"));
    let authorization = jzon::object! { instance: "secondary" };
    assert!(post(
        &format!("{}/v1/leaves/missing/instances", root.url),
        &authorization
    )
    .is_err());
    let authorized = post(&format!("{base}/instances"), &authorization)?;
    assert_eq!(authorized["status"], "authorized");
    assert_eq!(
        post(&format!("{base}/instances"), &authorization)?,
        authorized
    );
    let secondary = start_worker(
        leaf()
            .args([
                "join",
                "--name",
                "orders",
                "--instance",
                "secondary",
                "--root",
                &root.url,
                "--events",
                "--state-dir",
            ])
            .arg(&joined_state),
    )?;
    assert_eq!(
        get(&format!("{base}/instances/secondary"))?["status"],
        "enrolled"
    );
    let first = record(&primary_state.join("leaf.json"))?;
    let second = record(&joined_state.join("leaf.json"))?;
    assert_eq!(first["instance"], "primary");
    assert_eq!(second["instance"], "secondary");
    assert_ne!(first["seed"], second["seed"]);
    assert_eq!(first["policy"], second["policy"]);
    let policy_bytes = blob(&first, "policy")?;
    let policy = PartPolicy::ref_from_wire(&policy_bytes).context("policy")?;
    assert!(!policy.flags.allow_peer_cloning());
    let primary_recovery = record(&primary_state.join("recovery-state.json"))?;
    let secondary_recovery = record(&joined_state.join("recovery-state.json"))?;
    assert_ne!(
        primary_recovery["partition"]["local_mk_backup"],
        secondary_recovery["partition"]["local_mk_backup"]
    );
    let target_binding = record(&root_state.join("leaf-instance-binding-6-orders-secondary.json"))?;
    assert_ne!(
        target_binding["pta_public"],
        jzon::parse(std::str::from_utf8(&original_binding)?)?["pta_public"]
    );
    let primary_keys = record(&primary_state.join("keys.json"))?;
    let secondary_keys = record(&joined_state.join("keys.json"))?;
    assert_eq!(
        primary_keys["ecc_keys"]["security-domain"],
        secondary_keys["ecc_keys"]["security-domain"]
    );
    for scope in ["local", "ephemeral", "session"] {
        assert_ne!(
            primary_keys["ecc_keys"][scope],
            secondary_keys["ecc_keys"][scope]
        );
    }
    let identity = get(&format!("{}/v1/health", primary.url))?["identity"].clone();
    assert_eq!(
        identity,
        get(&format!("{}/v1/health", secondary.url))?["identity"]
    );
    for round in 0..3 {
        for server in [&primary, &secondary] {
            let signed = post(
                &format!("{}/v1/sign", server.url),
                &jzon::object! {
                    challenge: format!("concurrent instance challenge {round}"),
                },
            )?;
            assert_eq!(signed["verified"], true);
            assert_eq!(signed["identity"], identity);
        }
    }
    let catalog = get(&format!("{base}/catalog"))?;
    assert_eq!(
        post(&format!("{base}/catalog"), &catalog)?["status"],
        "stored"
    );
    for field in [
        "service",
        "policy",
        "scope",
        "algorithm",
        "fingerprint",
        "public_key",
        "masked_key",
    ] {
        let mut changed = catalog.clone();
        changed[field] = "invalid".into();
        assert!(
            post(&format!("{base}/catalog"), &changed).is_err(),
            "{field}"
        );
    }
    let mut changed = catalog.clone();
    changed["unexpected"] = true.into();
    assert!(post(&format!("{base}/catalog"), &changed).is_err());
    // Even another well-formed public identity cannot replace the catalog.
    let mut replacement = catalog.clone();
    replacement["public_key"] = primary_keys["ecc_keys"]["local"]["public_key"].clone();
    let mut fingerprint = [0u8; 48];
    use tsra_crypto::HashOp;
    tsra_crypto::HashAlgo::sha384()
        .hash(&blob(&replacement, "public_key")?, Some(&mut fingerprint))?;
    replacement["fingerprint"] = hex::encode(fingerprint).into();
    tsra_sealing_common::key_check::validate_domain_catalog(&replacement, "orders", &policy_bytes)?;
    assert!(post(&format!("{base}/catalog"), &replacement).is_err());
    let prepared = record(&joined_state.join("leaf-remote-prepared.json"))?;
    let receiver = prepared["receiver"].clone();
    let reseal = jzon::object! {
        instance: "secondary", policy: first["policy"].clone(), receiver: receiver,
    };
    assert!(post(&format!("{base}/reseal"), &reseal).is_ok());
    for instance in ["primary", "unapproved"] {
        let mut wrong = reseal.clone();
        wrong["instance"] = instance.into();
        assert!(post(&format!("{base}/reseal"), &wrong).is_err());
    }
    // A newly authorized target must never become an accepted creation source.
    let backup_path = root_state.join("leaf-remote-orders.json");
    let mut wrong_source = jzon::parse(std::str::from_utf8(&original_backup)?)?;
    wrong_source["sender"] = prepared["receiver"].clone();
    fs::write(&backup_path, wrong_source.dump())?;
    assert!(post(&format!("{base}/reseal"), &reseal).is_err());
    fs::write(&backup_path, &original_backup)?;
    assert_eq!(
        fs::read(root_state.join("leaf-binding-orders.json"))?,
        original_binding
    );
    assert_eq!(fs::read(&backup_path)?, original_backup);
    drop(secondary);
    let mut wrong_local = secondary_keys.clone();
    wrong_local["ecc_keys"]["local"] = primary_keys["ecc_keys"]["local"].clone();
    fs::write(joined_state.join("keys.json"), wrong_local.dump())?;
    let rejected = leaf()
        .args(["restore-local", "--state-dir"])
        .arg(&joined_state)
        .output()?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("sign with original local key"));
    fs::write(joined_state.join("keys.json"), secondary_keys.dump())?;
    success(
        leaf()
            .args(["restore-local", "--state-dir"])
            .arg(&joined_state),
    )?;
    let restored = start_worker(
        leaf()
            .args(["restore-remote", "--state-dir"])
            .arg(&joined_state),
    )?;
    assert_eq!(
        get(&format!("{}/v1/health", restored.url))?["identity"],
        identity
    );
    assert_eq!(
        get(&format!("{}/v1/health", primary.url))?["identity"],
        identity
    );
    assert_eq!(
        post(
            &format!("{}/v1/sign", primary.url),
            &jzon::object! { challenge: "still alive" }
        )?["verified"],
        true
    );
    let root_url = root.url.clone();
    drop(root);
    let _restarted = start(&root_state, Some(&root_url))?;
    assert_eq!(
        get(&format!("{base}/instances/secondary"))?["status"],
        "enrolled"
    );
    assert_eq!(get(&format!("{base}/catalog"))?, catalog);
    assert_eq!(
        post(
            &format!("{}/v1/sign", restored.url),
            &jzon::object! {challenge: "root restarted"}
        )?["verified"],
        true
    );
    Ok(())
}

#[test]
fn named_leaf_creation_recovery_and_root_restart() -> Result<()> {
    let dir = TestDir::new()?;
    let root_state = dir.0.join("root");
    let server = start(&root_state, None)?;
    let url = server.url.clone();
    for name in ["orders", "payments"] {
        Client::new(&url)?.register_leaf(name)?;
        let registration_path = root_state.join(format!("leaf-registration-{name}.json"));
        let registration_bytes = fs::read(&registration_path)?;
        Client::new(&url)?.register_leaf(name)?;
        assert_eq!(fs::read(&registration_path)?, registration_bytes);
        let config = get(&format!("{url}/v1/leaves/{name}"))?;
        assert!(config["policy"].is_null());
        for secret in ["pota_private", "sata_private", "masked_receiver"] {
            assert!(!config.has_key(secret));
        }
        let state = dir.0.join(name);
        let output = success(
            leaf()
                .args(["create", "--name", name, "--root", &url, "--state-dir"])
                .arg(&state),
        )?;
        assert!(output.contains("security domain created"));
        assert!(output.contains("root-HSM receiver endorsed by leaf SATA"));
        assert!(output.contains("Trusted-SA evidence anchored to root POTA"));
        let saved = record(&state.join("leaf.json"))?;
        let bytes = hex::decode(saved["policy"].as_str().context("policy")?)?;
        let policy = PartPolicy::ref_from_wire(&bytes).context("decode leaf policy")?;
        assert!(policy.flags.require_trusted_sa_key());
        assert!(!policy.flags.allow_peer_cloning());
        assert!(!policy.sapota_pub_key.is_empty());
        let registration = record(&registration_path)?;
        for field in ["pota", "sata", "sapota"] {
            assert_eq!(registration[field], saved[field]);
        }
        assert_eq!(
            record(&root_state.join(format!("leaf-remote-{name}.json")))?,
            record(&state.join("leaf-backup.json"))?
        );
        assert!(!state.join("pota.json").exists());
        assert!(!state.join("sata.json").exists());
        upload_saved_backup(&url, name, &state)?;
        // Legacy leaf metadata without an instance must retain primary behavior.
        let mut legacy = saved.clone();
        legacy.remove("instance");
        fs::write(state.join("leaf.json"), legacy.dump())?;
        let output = success(leaf().args(["restore-local", "--state-dir"]).arg(&state))?;
        assert!(output.contains("restored from local backups"));
        assert!(output.contains("security-domain: sign + verify passed"));
        let duplicate = leaf()
            .args(["create", "--name", name, "--root", &url, "--state-dir"])
            .arg(dir.0.join(format!("{name}-duplicate")))
            .output()?;
        assert!(!duplicate.status.success());
        assert!(!String::from_utf8_lossy(&duplicate.stdout).contains("Opening"));
    }
    let orders = record(&root_state.join("leaf-registration-orders.json"))?;
    let payments = record(&root_state.join("leaf-registration-payments.json"))?;
    for field in ["pota", "sata", "masked_receiver"] {
        assert_ne!(orders[field], payments[field]);
    }
    let root_pota = record(&root_state.join("pota.json"))?;
    assert_eq!(orders["sapota"], root_pota["certificate"]);
    let registration_before = fs::read(root_state.join("leaf-registration-orders.json"))?;
    let receiver_before = get(&format!("{url}/v1/leaves/orders/receiver"))?;
    drop(server);
    let _restarted = start(&root_state, Some(&url))?;
    assert_eq!(
        fs::read(root_state.join("leaf-registration-orders.json"))?,
        registration_before
    );
    let receiver_after = get(&format!("{url}/v1/leaves/orders/receiver"))?;
    assert_eq!(receiver_after["chain"], receiver_before["chain"]);
    assert_ne!(
        receiver_after["evidence"]["report"],
        receiver_before["evidence"]["report"]
    );
    success(
        leaf()
            .args(["restore-local", "--state-dir"])
            .arg(dir.0.join("orders")),
    )?;
    upload_saved_backup(&url, "orders", &dir.0.join("orders"))?;
    // A leaf is an independent domain, not a clone of its root or sibling.
    let order_keys = record(&dir.0.join("orders/keys.json"))?;
    let payments_path = dir.0.join("payments/keys.json");
    let payments_keys = record(&payments_path)?;
    let mut foreign = payments_keys.clone();
    foreign["ecc_keys"]["security-domain"] = order_keys["ecc_keys"]["security-domain"].clone();
    fs::write(&payments_path, foreign.dump())?;
    let rejected = leaf()
        .args(["restore-local", "--state-dir"])
        .arg(dir.0.join("payments"))
        .output()?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr)
        .contains("sign with original security-domain key"));
    fs::write(&payments_path, payments_keys.dump())?;
    success(
        leaf()
            .args(["restore-local", "--state-dir"])
            .arg(dir.0.join("payments")),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in [&root_state, &dir.0.join("orders"), &dir.0.join("payments")] {
            for entry in fs::read_dir(directory)? {
                assert_eq!(entry?.metadata()?.permissions().mode() & 0o777, 0o600);
            }
        }
    }
    drop(_restarted);
    let root_keys_path = root_state.join("keys.json");
    let mut root_keys = record(&root_keys_path)?;
    root_keys["ecc_keys"]["security-domain"] = order_keys["ecc_keys"]["security-domain"].clone();
    fs::write(root_keys_path, root_keys.dump())?;
    let rejected = root()
        .args(["restore-local", "--state-dir"])
        .arg(&root_state)
        .output()?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr)
        .contains("sign with original security-domain key"));
    Ok(())
}

fn blob(record: &JsonValue, field: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        record[field]
            .as_str()
            .with_context(|| format!("missing {field}"))?,
    )?)
}

fn chain(record: &JsonValue, field: &str) -> Result<Vec<Vec<u8>>> {
    record[field]
        .members()
        .map(|item| Ok(hex::decode(item.as_str().context("certificate")?)?))
        .collect()
}

fn encode_chain(certs: &[Vec<u8>]) -> JsonValue {
    JsonValue::Array(certs.iter().map(|cert| hex::encode(cert).into()).collect())
}

fn evidence(record: &JsonValue) -> Result<tsra_sealing_api::Evidence> {
    Ok(tsra_sealing_api::Evidence {
        mfgr_cert_chain: chain(record, "manufacturer")?,
        owner_cert_chain: chain(record, "owner")?,
        part_owner_cert_chain: chain(record, "partition_owner")?,
        report: blob(record, "report")?,
    })
}

fn post(url: &str, body: &JsonValue) -> Result<JsonValue> {
    let mut response = agent().post(url).send(body.dump())?;
    Ok(jzon::parse(&response.body_mut().read_to_string()?)?)
}

fn upload_saved_backup(root: &str, name: &str, state: &Path) -> Result<()> {
    let response = post(
        &format!("{root}/v1/leaves/{name}/backup"),
        &record(&state.join("leaf-backup.json"))?,
    )?;
    anyhow::ensure!(
        response["status"] == "stored",
        "backup was not acknowledged"
    );
    Ok(())
}

#[test]
fn enrollment_and_firmware_enforce_leaf_trust_and_disable_cloning() -> Result<()> {
    use tsra_api::HsmCert;
    use tsra_crypto::HashAlgo;
    use tsra_crypto::HashOp;
    use tsra_sealing_api::device_cert_chain;
    use tsra_sealing_api::mint_sealing_key;
    use tsra_sealing_api::SealingSession;
    use zerocopy::IntoBytes;

    let dir = TestDir::new()?;
    let server = start(&dir.0.join("root"), None)?;
    for name in ["orders", "other"] {
        Client::new(&server.url)?.register_leaf(name)?;
    }
    let base = format!("{}/v1/leaves/orders", server.url);
    let config = get(&base)?;
    let session = SealingSession::open_reset()?;
    let full_policy = post(
        &format!("{base}/policy"),
        &jzon::object! {
            pid: hex::encode(session.partition.pid()?),
            public: hex::encode(session.partition.ex_pub_key()?),
        },
    )?;
    let bytes = blob(&full_policy, "policy")?;
    let policy = PartPolicy::ref_from_wire(&bytes).context("leaf policy")?;
    let thumbprint = |field: &str| -> Result<[u8; 48]> {
        let mut digest = [0; 48];
        HashAlgo::sha384().hash(&blob(&config, field)?, Some(&mut digest))?;
        Ok(digest)
    };
    let initialized = session.session.part_init_ex(
        policy,
        &[0x57; 32],
        &thumbprint("pota")?,
        &thumbprint("sata")?,
        Some(&thumbprint("sapota")?),
    )?;
    let request = jzon::object! {
        policy: hex::encode(policy.as_bytes()), csr: hex::encode(&initialized.pta_csr),
        report: hex::encode(&initialized.pta_report),
        manufacturer: encode_chain(&device_cert_chain(&session.partition, 0)?),
    };
    let mut invalid_csr = request.clone();
    invalid_csr["csr"] = "00".into();
    let mut invalid_report = request.clone();
    let mut report = initialized.pta_report.clone();
    *report.last_mut().context("signature")? ^= 1;
    invalid_report["report"] = hex::encode(report).into();
    let mut invalid_policy = request.clone();
    let mut changed = policy.clone();
    changed.flags.set_allow_peer_cloning(true);
    invalid_policy["policy"] = hex::encode(changed.as_bytes()).into();
    for invalid in [invalid_csr, invalid_report, invalid_policy] {
        assert!(post(&format!("{base}/pta-cert"), &invalid).is_err());
        assert!(
            get(&base)?["policy"].is_null(),
            "failed enrollment must not claim the name"
        );
    }
    let pta = post(&format!("{base}/pta-cert"), &request)?;
    let pta_chain = chain(&pta, "pta")?;
    let pta_certs: Vec<_> = pta_chain.iter().map(|cert| HsmCert { cert }).collect();
    session.session.part_final_ex(policy, &pta_certs, None)?;
    let sender = mint_sealing_key(&session.session)?;
    let receiver = get(&format!("{base}/receiver"))?;
    let receiver_chain = chain(&receiver, "chain")?;
    let receiver_certs: Vec<_> = receiver_chain.iter().map(|cert| HsmCert { cert }).collect();
    let receiver_evidence = evidence(&receiver["evidence"])?;
    assert!(receiver_evidence.owner_cert_chain.is_empty());
    let mut bad_owner = receiver_evidence.clone();
    bad_owner.owner_cert_chain = vec![vec![0x30, 0]];
    let mut wrong_sapota = receiver_evidence.clone();
    wrong_sapota.part_owner_cert_chain = wrong_sapota.mfgr_cert_chain.clone();
    let other = get(&format!("{}/v1/leaves/other/receiver", server.url))?;
    let other_evidence = evidence(&other["evidence"])?;
    // Same root PID and valid root POTA chain, but another attested sealing key.
    for invalid in [bad_owner, wrong_sapota, other_evidence] {
        assert!(invalid
            .with_hsm_evidence(|ev| session.session.sd_create_remote_backup(
                policy,
                &sender.masked,
                &receiver_certs,
                ev
            ))
            .is_err());
    }
    let other_chain = chain(&other, "chain")?;
    let other_certs: Vec<_> = other_chain.iter().map(|cert| HsmCert { cert }).collect();
    assert!(receiver_evidence
        .with_hsm_evidence(|ev| session.session.sd_create_remote_backup(
            policy,
            &sender.masked,
            &other_certs,
            ev
        ))
        .is_err());
    let created = receiver_evidence.with_hsm_evidence(|ev| {
        session
            .session
            .sd_create_remote_backup(policy, &sender.masked, &receiver_certs, ev)
    })?;
    assert!(receiver_evidence
        .with_hsm_evidence(|ev| session.session.sd_create_peer_backup(
            policy,
            &sender.masked,
            ev,
            &created.pok_local_backup
        ))
        .is_err());
    let binding_before = fs::read(dir.0.join("root/leaf-binding-orders.json"))?;
    drop(session);

    // A different seed cannot get a new PTA endorsed under a bound name,
    // even when it presents a valid report for the exact same leaf policy.
    let impostor = SealingSession::open_reset()?;
    let initialized = impostor.session.part_init_ex(
        policy,
        &[0x58; 32],
        &thumbprint("pota")?,
        &thumbprint("sata")?,
        Some(&thumbprint("sapota")?),
    )?;
    let claim = jzon::object! {
        policy: hex::encode(policy.as_bytes()),
        csr: hex::encode(initialized.pta_csr), report: hex::encode(initialized.pta_report),
        manufacturer: encode_chain(&device_cert_chain(&impostor.partition, 0)?),
    };
    assert!(post(&format!("{base}/pta-cert"), &claim).is_err());
    assert_eq!(
        fs::read(dir.0.join("root/leaf-binding-orders.json"))?,
        binding_before
    );
    assert!(post(
        &format!("{}/v1/leaves/other/pta-cert", server.url),
        &request
    )
    .is_err());
    post(
        &format!("{base}/instances"),
        &jzon::object! {instance: "secondary"},
    )?;
    let mut instance_claim = claim.clone();
    instance_claim["instance"] = "secondary".into();
    assert!(post(&format!("{base}/pta-cert"), &instance_claim).is_ok());
    let pin_path = dir
        .0
        .join("root/leaf-instance-binding-6-orders-secondary.json");
    let instance_pin = fs::read(&pin_path)?;
    assert!(post(&format!("{base}/pta-cert"), &instance_claim).is_ok());
    instance_claim["instance"] = "not-approved".into();
    assert!(post(&format!("{base}/pta-cert"), &instance_claim).is_err());
    drop(impostor);
    let changed_instance = SealingSession::open_reset()?;
    let changed_init = changed_instance.session.part_init_ex(
        policy,
        &[0x59; 32],
        &thumbprint("pota")?,
        &thumbprint("sata")?,
        Some(&thumbprint("sapota")?),
    )?;
    let changed_claim = jzon::object! {
        instance: "secondary", policy: hex::encode(policy.as_bytes()),
        csr: hex::encode(changed_init.pta_csr), report: hex::encode(changed_init.pta_report),
        manufacturer: encode_chain(&device_cert_chain(&changed_instance.partition, 0)?),
    };
    assert!(post(&format!("{base}/pta-cert"), &changed_claim).is_err());
    assert!(post(
        &format!("{}/v1/leaves/other/pta-cert", server.url),
        &changed_claim
    )
    .is_err());
    assert_eq!(fs::read(&pin_path)?, instance_pin);
    assert_eq!(
        fs::read(dir.0.join("root/leaf-binding-orders.json"))?,
        binding_before
    );
    assert!(get(&format!("{}/v1/leaves/missing", server.url)).is_err());
    assert!(post(
        &format!("{}/v1/leaves", server.url),
        &jzon::object! {name: "../escape"}
    )
    .is_err());
    Ok(())
}

#[test]
fn failed_root_backup_publication_retains_retryable_outbox() -> Result<()> {
    let dir = TestDir::new()?;
    let root_state = dir.0.join("root");
    let leaf_state = dir.0.join("orders");
    let server = start(&root_state, None)?;
    Client::new(&server.url)?.register_leaf("orders")?;
    let blocked = root_state.join("leaf-remote-orders.json");
    fs::create_dir(&blocked)?;
    let failed = leaf()
        .args([
            "create",
            "--name",
            "orders",
            "--root",
            &server.url,
            "--state-dir",
        ])
        .arg(&leaf_state)
        .output()?;
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr)
        .contains("local recovery and leaf-backup.json retained"));
    let outbox = fs::read(leaf_state.join("leaf-backup.json"))?;
    assert!(leaf_state.join("recovery-state.json").exists());
    fs::remove_dir(&blocked)?;
    upload_saved_backup(&server.url, "orders", &leaf_state)?;
    assert_eq!(
        record(&blocked)?,
        record(&leaf_state.join("leaf-backup.json"))?
    );
    assert_eq!(fs::read(leaf_state.join("leaf-backup.json"))?, outbox);
    success(
        leaf()
            .args(["restore-local", "--state-dir"])
            .arg(&leaf_state),
    )?;
    let metadata_path = leaf_state.join("leaf.json");
    let metadata = record(&metadata_path)?;
    let mut changed_cert = metadata.clone();
    changed_cert["sapota"] = metadata["sata"].clone();
    let mut changed_seed = metadata.clone();
    changed_seed["seed"] = "00".into();
    let mut changed_trust = metadata.clone();
    let mut policy = PartPolicy::ref_from_wire(&blob(&metadata, "policy")?)
        .context("saved policy")?
        .clone();
    policy.flags.set_require_trusted_sa_key(false);
    use zerocopy::IntoBytes;
    changed_trust["policy"] = hex::encode(policy.as_bytes()).into();
    let mut changed_peering = metadata.clone();
    policy.flags.set_require_trusted_sa_key(true);
    policy.flags.set_allow_peer_cloning(true);
    changed_peering["policy"] = hex::encode(policy.as_bytes()).into();
    for invalid in [changed_cert, changed_seed, changed_trust, changed_peering] {
        fs::write(&metadata_path, invalid.dump())?;
        let failed = leaf()
            .args(["restore-local", "--reset", "--state-dir"])
            .arg(&leaf_state)
            .output()?;
        assert!(!failed.status.success());
        assert!(!String::from_utf8_lossy(&failed.stdout).contains("Opening"));
    }

    fs::write(metadata_path, metadata.dump())?;
    Ok(())
}

#[test]
fn trusted_remote_restore_rejects_bad_evidence_and_seals() -> Result<()> {
    use tsra_api::HsmCert;
    use tsra_sealing_api::device_cert_chain;
    use tsra_sealing_api::mint_sealing_key;
    use tsra_sealing_api::SealingSession;
    use tsra_sealing_common::key_check;
    use tsra_sealing_common::pki::thumbprint;
    use tsra_sealing_common::wire;
    use zerocopy::IntoBytes;

    let dir = TestDir::new()?;
    let state = dir.0.join("leaf");
    let server = start(&dir.0.join("root"), None)?;
    success(
        leaf()
            .args([
                "create",
                "--name",
                "guarded",
                "--root",
                &server.url,
                "--state-dir",
            ])
            .arg(&state),
    )?;
    let metadata = record(&state.join("leaf.json"))?;
    let recovery = record(&state.join("recovery-state.json"))?;
    let bytes = blob(&metadata, "policy")?;
    let policy = PartPolicy::ref_from_wire(&bytes).context("leaf policy")?;
    let session = SealingSession::open_reset()?;
    let init = session.session.part_init_ex(
        policy,
        &blob(&metadata, "seed")?,
        &thumbprint(&blob(&metadata, "pota")?),
        &thumbprint(&blob(&metadata, "sata")?),
        Some(&thumbprint(&blob(&metadata, "sapota")?)),
    )?;
    let manufacturer = device_cert_chain(&session.partition, 0)?;
    let base = format!("{}/v1/leaves/guarded", server.url);
    let certified = post(
        &format!("{base}/pta-cert"),
        &jzon::object! {
            policy: hex::encode(policy.as_bytes()), csr: hex::encode(init.pta_csr),
            report: hex::encode(init.pta_report), manufacturer: encode_chain(&manufacturer),
        },
    )?;
    let pta = chain(&certified, "pta")?;
    let certs: Vec<_> = pta.iter().map(|cert| HsmCert { cert }).collect();
    session.session.part_final_ex(
        policy,
        &certs,
        Some(&blob(&recovery["partition"], "local_mk_backup")?),
    )?;
    let receiver = mint_sealing_key(&session.session)?;
    let mut part_owner = pta;
    part_owner.extend(device_cert_chain(&session.partition, 2)?);
    let destination = tsra_sealing_api::Evidence {
        mfgr_cert_chain: manufacturer.clone(),
        owner_cert_chain: manufacturer,
        part_owner_cert_chain: part_owner,
        report: receiver.report,
    };
    let request = jzon::object! {
        policy: hex::encode(policy.as_bytes()), receiver: wire::encode_evidence(&destination),
    };
    let mut bad_report = request.clone();
    let mut corrupted = destination.report.clone();
    *corrupted.last_mut().context("report signature")? ^= 1;
    bad_report["receiver"]["report"] = hex::encode(corrupted).into();
    let mut wrong_policy = request.clone();
    let mut changed = policy.clone();
    changed.flags.set_allow_peer_cloning(true);
    wrong_policy["policy"] = hex::encode(changed.as_bytes()).into();
    for invalid in [bad_report, wrong_policy] {
        assert!(post(&format!("{base}/reseal"), &invalid).is_err());
    }
    let response = post(&format!("{base}/reseal"), &request)?;
    let backup = wire::resealed_backup(&response)?;
    let sender_certs: Vec<_> = backup
        .sender_cert_chain
        .iter()
        .map(|cert| HsmCert { cert })
        .collect();
    let restore = |ev: &tsra_sealing_api::Evidence, ciphertext: &[u8], sd_mk: &[u8]| {
        ev.with_hsm_evidence(|evidence| {
            session.session.sd_restore_remote_backup(
                policy,
                &receiver.masked,
                &sender_certs,
                evidence,
                ciphertext,
                sd_mk,
            )
        })
    };
    assert!(backup.sender_evidence.owner_cert_chain.is_empty());
    let mut bad_owner = backup.sender_evidence.clone();
    bad_owner.owner_cert_chain = vec![vec![0x30, 0]];
    let mut wrong_sapota = backup.sender_evidence.clone();
    wrong_sapota.part_owner_cert_chain = wrong_sapota.mfgr_cert_chain.clone();
    let mut tampered_report = backup.sender_evidence.clone();
    *tampered_report.report.last_mut().context("signature")? ^= 1;
    Client::new(&server.url)?.register_leaf("different-key")?;
    let other = get(&format!("{}/v1/leaves/different-key/receiver", server.url))?;
    let wrong_key = wire::evidence(&other["evidence"])?;
    for invalid in [bad_owner, wrong_sapota, tampered_report, wrong_key] {
        assert!(restore(&invalid, &backup.pok_remote_backup, &backup.sd_mk_backup).is_err());
    }
    let wrong_certs = chain(&other, "chain")?;
    let wrong_certs: Vec<_> = wrong_certs.iter().map(|cert| HsmCert { cert }).collect();
    assert!(backup
        .sender_evidence
        .with_hsm_evidence(|evidence| session.session.sd_restore_remote_backup(
            policy,
            &receiver.masked,
            &wrong_certs,
            evidence,
            &backup.pok_remote_backup,
            &backup.sd_mk_backup,
        ))
        .is_err());
    let mut ciphertext = backup.pok_remote_backup.clone();
    *ciphertext.last_mut().context("seal tag")? ^= 1;
    assert!(restore(&backup.sender_evidence, &ciphertext, &backup.sd_mk_backup).is_err());
    let mut sd_mk = backup.sd_mk_backup.clone();
    *sd_mk.last_mut().context("SDMK tag")? ^= 1;
    assert!(restore(&backup.sender_evidence, &backup.pok_remote_backup, &sd_mk).is_err());
    assert!(backup
        .sender_evidence
        .with_hsm_evidence(|evidence| session.session.sd_restore_remote_backup(
            &changed,
            &receiver.masked,
            &sender_certs,
            evidence,
            &backup.pok_remote_backup,
            &backup.sd_mk_backup,
        ))
        .is_err());
    restore(
        &backup.sender_evidence,
        &backup.pok_remote_backup,
        &backup.sd_mk_backup,
    )?;
    let keys = key_check::decode(&record(&state.join("keys.json"))?["ecc_keys"])?;
    key_check::check_after_restore(&session.session, &keys, &mut Vec::new())?;
    Ok(())
}

#[test]
fn remote_restore_does_not_fall_back_when_root_backup_is_missing_or_corrupt() -> Result<()> {
    let dir = TestDir::new()?;
    let root_state = dir.0.join("root");
    let state = dir.0.join("leaf");
    let server = start(&root_state, None)?;
    success(
        leaf()
            .args([
                "create",
                "--name",
                "failure",
                "--root",
                &server.url,
                "--state-dir",
            ])
            .arg(&state),
    )?;
    let root_backup = root_state.join("leaf-remote-failure.json");
    let original_backup = record(&root_backup)?;
    let recovery = fs::read(state.join("recovery-state.json"))?;
    fs::remove_file(&root_backup)?;
    let failed = leaf()
        .args(["restore-remote", "--state-dir"])
        .arg(&state)
        .output()?;
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stdout).contains("Opening"));
    assert_eq!(fs::read(state.join("recovery-state.json"))?, recovery);
    let mut corrupt = original_backup.clone();
    let mut seal = blob(&corrupt, "pok_remote_backup")?;
    *seal.last_mut().context("seal tag")? ^= 1;
    corrupt["pok_remote_backup"] = hex::encode(seal).into();
    fs::write(&root_backup, corrupt.dump())?;
    let failed = leaf()
        .args(["restore-remote", "--state-dir"])
        .arg(&state)
        .output()?;
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("root reseal failed"));
    assert_eq!(fs::read(state.join("recovery-state.json"))?, recovery);
    assert!(state.join("leaf-remote-prepared.json").exists());
    assert!(!state.join("leaf-resealed.json").exists());
    fs::write(root_backup, original_backup.dump())?;
    for name in ["leaf-remote-prepared.json", "leaf-resealed.json"] {
        let blocked = state.join(name);
        if blocked.exists() {
            fs::remove_file(&blocked)?;
        }
        fs::create_dir(&blocked)?;
        let failed = leaf()
            .args(["restore-remote", "--state-dir"])
            .arg(&state)
            .output()?;
        assert!(!failed.status.success());
        assert_eq!(fs::read(state.join("recovery-state.json"))?, recovery);
        fs::remove_dir(&blocked)?;
    }
    success(leaf().args(["restore-remote", "--state-dir"]).arg(&state))?;
    Ok(())
}

#[test]
fn remote_restore_reseals_without_local_sd_or_local_remote_backup() -> Result<()> {
    let dir = TestDir::new()?;
    let root_state = dir.0.join("root");
    let state = dir.0.join("leaf");
    let server = start(&root_state, None)?;
    let url = server.url.clone();
    success(
        leaf()
            .args(["create", "--name", "remote", "--root", &url, "--state-dir"])
            .arg(&state),
    )?;
    let original_keys = fs::read(state.join("keys.json"))?;
    let original_remote = fs::read(root_state.join("leaf-remote-remote.json"))?;
    let original_receiver = fs::read(root_state.join("leaf-registration-remote.json"))?;
    let recovery_path = state.join("recovery-state.json");
    let mut recovery = record(&recovery_path)?;
    recovery["security_domain"] = JsonValue::Null;
    fs::write(&recovery_path, recovery.dump())?;
    fs::remove_file(state.join("leaf-backup.json"))?;
    drop(server);
    let _restarted = start(&root_state, Some(&url))?;

    let output = success(leaf().args(["restore-remote", "--state-dir"]).arg(&state))?;
    assert!(output.contains("restored from root-resealed remote backup"));
    assert!(output.contains("security-domain: sign + verify passed"));
    assert!(output.contains("local: sign + verify passed"));
    assert!(output.contains("ephemeral: rejected as expected"));
    assert!(output.contains("session: rejected as expected"));
    assert_eq!(fs::read(state.join("keys.json"))?, original_keys);
    assert_eq!(
        fs::read(root_state.join("leaf-remote-remote.json"))?,
        original_remote
    );
    assert_eq!(
        fs::read(root_state.join("leaf-registration-remote.json"))?,
        original_receiver
    );
    let prepared = record(&state.join("leaf-remote-prepared.json"))?;
    let resealed = record(&state.join("leaf-resealed.json"))?;
    let original = record(&root_state.join("leaf-remote-remote.json"))?;
    assert_ne!(resealed["pok_remote_backup"], original["pok_remote_backup"]);
    assert_eq!(resealed["sd_mk_backup"], original["sd_mk_backup"]);
    let source_report = blob(&original["sender"], "report")?;
    let destination_report = blob(&prepared["receiver"], "report")?;
    let root_report = blob(&resealed["sender"]["evidence"], "report")?;
    for evidence in [
        &original["sender"],
        &prepared["receiver"],
        &resealed["sender"]["evidence"],
    ] {
        assert!(evidence["owner"].is_array());
        assert!(evidence["owner"].is_empty());
        assert!(!evidence["manufacturer"].is_empty());
        assert!(!evidence["partition_owner"].is_empty());
    }
    assert!(!output.contains("Root receiver owner certificate chain"));
    use tsra_sealing_report::parse_key_report_bytes;
    assert_eq!(
        parse_key_report_bytes(&source_report)?.policy_hash,
        parse_key_report_bytes(&destination_report)?.policy_hash
    );
    assert_ne!(
        parse_key_report_bytes(&root_report)?.policy_hash,
        parse_key_report_bytes(&destination_report)?.policy_hash
    );
    assert!(!output.contains(
        prepared["masked_receiver"]
            .as_str()
            .context("masked receiver")?
    ));
    assert!(!output.contains(
        resealed["pok_remote_backup"]
            .as_str()
            .context("ciphertext")?
    ));
    success(leaf().args(["restore-local", "--state-dir"]).arg(&state))?;
    success(leaf().args(["restore-remote", "--state-dir"]).arg(&state))?;
    Ok(())
}

#[test]
fn leaf_registers_itself_over_http_before_creation() -> Result<()> {
    let dir = TestDir::new()?;
    let root_state = dir.0.join("root");
    let state = dir.0.join("leaf");
    let log = dir.0.join("root.log");
    let server = start_with_log(&root_state, None, Some(&log))?;
    assert!(!root_state.join("leaf-registration-self.json").exists());
    let output = success(
        leaf()
            .args([
                "create",
                "--name",
                "self",
                "--root",
                &server.url,
                "--state-dir",
            ])
            .arg(&state),
    )?;
    assert!(output.contains("Leaf 'self' registered with root."));
    assert!(output.contains("Root receiver device-owner evidence: omitted (optional)"));
    assert!(!output.contains("Root receiver owner certificate chain"));
    assert!(output.contains("security domain created"));
    assert!(root_state.join("leaf-registration-self.json").exists());
    assert!(root_state.join("leaf-binding-self.json").exists());
    assert!(root_state.join("leaf-remote-self.json").exists());
    success(leaf().args(["restore-local", "--state-dir"]).arg(&state))?;
    success(leaf().args(["restore-remote", "--state-dir"]).arg(&state))?;
    assert!(post(
        &format!("{}/v1/leaves/self/reseal", server.url),
        &jzon::object! { report: "do-not-log-this-payload" }
    )
    .is_err());
    let trace = fs::read_to_string(log)?;
    for operation in ["register", "pta-enrollment", "store-backup", "reseal"] {
        assert!(trace.contains(&format!("operation={operation} phase=start")));
        assert!(trace.contains(&format!("operation={operation} phase=complete status=200")));
    }
    assert!(trace.contains("leaf=self instance=primary operation=reseal"));
    assert!(trace.contains("operation=reseal phase=complete status=400 elapsed_ms="));
    assert!(!trace.contains("do-not-log-this-payload"));
    let registration = record(&root_state.join("leaf-registration-self.json"))?;
    for field in ["pota_private", "sata_private", "masked_receiver"] {
        assert!(!trace.contains(registration[field].as_str().context("private field")?));
    }
    Ok(())
}
