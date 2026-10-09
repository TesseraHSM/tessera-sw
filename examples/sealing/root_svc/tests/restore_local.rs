// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "emu")]

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use anyhow::Context;
use anyhow::Result;
use jzon::JsonValue;
use tsra_crypto::EccCurve;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::ExportableKey;
use tsra_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use tsra_ddi_tbor_types::MASKED_SD_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;
use zerocopy::IntoBytes;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct StateDir(PathBuf);

impl StateDir {
    fn new() -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "tsra-sealing-restore-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    fn record(&self) -> PathBuf {
        self.file("recovery-state.json")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join("state").join(name)
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to clean local restore test directory: {error}");
        }
    }
}

fn run(dir: &Path, operation: &str, reset: bool) -> Result<Output> {
    let remote_create = operation == "create-remote";
    let operation = if remote_create { "create" } else { operation };
    let mut command = Command::new(env!("CARGO_BIN_EXE_root_svc"));
    command
        .args([operation, "--state-dir"])
        .arg(dir.join("state"));
    if operation == "create" {
        command.args(["--name", "local-restore-test"]);
        if remote_create {
            command.arg("--remote-restorable");
        }
    } else if reset {
        command.arg("--reset");
    }
    command.output().context("run root service")
}

#[test]
fn remote_restore_without_local_sd_backups_and_then_local_restore() -> Result<()> {
    let dir = StateDir::new()?;
    let output = success(run(&dir.0, "create-remote", false)?)?;
    assert!(output.contains("creation receiver:    external software sealing authority"));
    assert_evidence_output(&output);
    let original = record(&dir.record())?;
    assert_eq!(original["remote_file"].as_str(), Some("remote-backup.json"));
    let remote = record(&dir.file("remote-backup.json"))?;
    assert_eq!(remote["version"].as_u32(), Some(2));
    assert!(remote["creation_sender"]["owner_cert_chain"].is_empty());
    assert!(!remote.has_key("sender"));
    assert_eq!(remote["sender_cert_chain"].len(), 2);
    assert_eq!(remote["receiver_cert_chain"].len(), 2);
    assert_ne!(
        remote["sender_cert_chain"][1],
        remote["receiver_cert_chain"][1]
    );
    assert!(!output.contains("Sender owner certificate chain (root-first; 2"));
    for field in ["masked_receiver_key", "pok_remote_backup", "sd_mk_backup"] {
        assert!(remote[field].as_str().is_some());
    }
    let snapshots = ["pota.json", "sata.json", "keys.json", "remote-backup.json"]
        .into_iter()
        .map(|name| Ok((name, fs::read(dir.file(name))?)))
        .collect::<Result<Vec<_>>>()?;
    for reset in [false, true, false] {
        let mut saved = record(&dir.record())?;
        // Prove that no local SD backup or local-restore fallback is used.
        saved["security_domain"] = jzon::JsonValue::Null;
        fs::write(dir.record(), saved.dump())?;
        let output = success(run(&dir.0, "restore-remote", reset)?)?;
        assert!(output.contains("External-SA sender and HSM receiver HPKE chains verified"));
        assert_evidence_output(&output);
        assert!(output.contains("saved certificates, not fresh attestation"));
        assert!(!output.contains("attestation report:"));
        assert!(!output.contains("owner certificate chain"));
        assert!(
            output
                .find("Receiver SATA-authorized HPKE certificate chain")
                .context("receiver output")?
                < output.find("Opening").context("partition opening output")?,
            "print saved evidence before opening/resetting the partition"
        );
        assert!(output.contains("Security domain restored from remote backup."));
        assert!(output.contains("local: sign + verify passed"));
        assert!(output.contains("security-domain: sign + verify passed"));
        assert!(output.contains("ephemeral: rejected as expected"));
        assert!(output.contains("session: rejected as expected"));
        let restored = record(&dir.record())?;
        assert!(restored["security_domain"]["pok_local_backup"]
            .as_str()
            .is_some());
        assert!(restored["security_domain"]["sd_mk_backup"]
            .as_str()
            .is_some());
        for (name, bytes) in &snapshots {
            assert!(fs::read(dir.file(name))? == *bytes);
        }
    }
    let output = success(run(&dir.0, "restore-local", false)?)?;
    assert!(output.contains("Security domain restored from local backups."));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(dir.file("remote-backup.json"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    Ok(())
}

#[test]
fn missing_or_unprepared_remote_backup_fails_before_reset() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create", false)?)?;
    let output = run(&dir.0, "restore-remote", true)?;
    assert!(!output.status.success());
    assert!(!String::from_utf8(output.stdout)?.contains("Opening"));
    assert!(String::from_utf8(output.stderr)?.contains("create with --remote-restorable"));
    Ok(())
}

#[test]
fn invalid_remote_metadata_and_evidence_fail_before_reset() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create-remote", false)?)?;
    let path = dir.file("remote-backup.json");
    let original = record(&path)?;
    let recovery = fs::read(dir.record())?;
    let mut cases = vec![jzon::object! { version: 99 }];
    for field in ["masked_receiver_key", "pok_remote_backup", "sd_mk_backup"] {
        let mut invalid = original.clone();
        invalid[field] = "00".into();
        cases.push(invalid);
    }
    for field in ["mfgr_cert_chain", "part_owner_cert_chain"] {
        let mut invalid = original.clone();
        invalid["creation_sender"][field] = jzon::array![];
        cases.push(invalid);
    }
    for field in ["sender_cert_chain", "receiver_cert_chain"] {
        let mut invalid = original.clone();
        invalid[field] = jzon::array![];
        cases.push(invalid);
        let mut invalid = original.clone();
        invalid[field][1] = "00".into();
        cases.push(invalid);
    }
    let mut invalid_report = original.clone();
    let mut report = hex::decode(
        original["creation_sender"]["report"]
            .as_str()
            .context("report")?,
    )?;
    *report.last_mut().context("report signature")? ^= 1;
    invalid_report["creation_sender"]["report"] = hex::encode(report).into();
    cases.push(invalid_report);
    fs::remove_file(&path)?;
    let missing = run(&dir.0, "restore-remote", true)?;
    assert!(!missing.status.success());
    assert!(!String::from_utf8(missing.stdout)?.contains("Opening"));
    for invalid in cases {
        let text = invalid.dump();
        fs::write(&path, &text)?;
        let output = run(&dir.0, "restore-remote", true)?;
        assert!(!output.status.success());
        assert!(!String::from_utf8(output.stdout)?.contains("Opening"));
        assert_eq!(fs::read(dir.record())?, recovery);
        assert_eq!(fs::read_to_string(&path)?, text);
    }
    fs::write(&path, original.dump())?;
    let mut changed = record(&dir.record())?;
    let policy = hex::decode(changed["partition"]["policy"].as_str().context("policy")?)?;
    let mut policy = tsra_api::PartPolicy::ref_from_wire(&policy)
        .context("decode policy")?
        .clone();
    policy.info[0] ^= 1;
    changed["partition"]["policy"] = hex::encode(policy.as_bytes()).into();
    fs::write(dir.record(), changed.dump())?;
    let output = run(&dir.0, "restore-remote", true)?;
    assert!(!output.status.success());
    assert!(!String::from_utf8(output.stdout)?.contains("Opening"));
    assert!(String::from_utf8(output.stderr)?.contains("policy binding mismatch"));
    Ok(())
}

#[test]
fn tampered_remote_ciphertexts_fail_without_publishing_recovery() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create-remote", false)?)?;
    let path = dir.file("remote-backup.json");
    let original = record(&path)?;
    let recovery = fs::read(dir.record())?;
    let mut cases = Vec::new();
    for field in ["masked_receiver_key", "pok_remote_backup", "sd_mk_backup"] {
        let mut invalid = original.clone();
        let mut blob = hex::decode(invalid[field].as_str().context("remote blob")?)?;
        *blob.last_mut().context("remote tag")? ^= 1;
        invalid[field] = hex::encode(blob).into();
        cases.push(invalid);
    }
    // Both keys are authorized by SATA, but only the real SA key authenticates this seal.
    let mut wrong_sender = original.clone();
    wrong_sender["sender_cert_chain"] = original["receiver_cert_chain"].clone();
    cases.push(wrong_sender);
    for invalid in cases {
        fs::write(&path, invalid.dump())?;
        let output = run(&dir.0, "restore-remote", false)?;
        assert!(!output.status.success());
        assert!(!String::from_utf8(output.stdout)?.contains("Security domain restored"));
        assert!(String::from_utf8(output.stderr)?.contains("sd_restore_remote_backup"));
        assert_eq!(fs::read(dir.record())?, recovery);
    }
    fs::write(&path, original.dump())?;
    success(run(&dir.0, "restore-remote", false)?)?;
    Ok(())
}

fn success(output: Output) -> Result<String> {
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    anyhow::ensure!(
        output.status.success(),
        "root service failed:\n{stdout}\n{stderr}"
    );
    Ok(stdout)
}

fn assert_evidence_output(output: &str) {
    for role in ["Sender", "Receiver"] {
        assert!(output.contains(&format!(
            "{role} SATA-authorized HPKE certificate chain (root-first; 2 certificates):"
        )));
    }
    assert!(output.contains("SA attestation: omitted; require_trusted_sa_key = false"));
    assert!(output.contains("Verification: valid path to supplied root"));
}

fn record(path: &Path) -> Result<JsonValue> {
    Ok(jzon::parse(&fs::read_to_string(path)?)?)
}

fn legacy_record(dir: &StateDir) -> Result<JsonValue> {
    let mut saved = record(&dir.record())?;
    let pota = record(&dir.file("pota.json"))?;
    let keys = record(&dir.file("keys.json"))?;
    saved["version"] = 1.into();
    saved["authority"] = jzon::object! {
        pota_private_key: pota["private_key"].clone(),
        pota_certificate: pota["certificate"].clone(),
        machine_seed: saved["machine_seed"].clone(),
        sata_thumbprint: saved["sata_thumbprint"].clone(),
    };
    saved["ecc_keys"] = keys["ecc_keys"].clone();
    for field in [
        "pota_file",
        "sata_file",
        "keys_file",
        "machine_seed",
        "pota_thumbprint",
        "sata_thumbprint",
    ] {
        saved.remove(field);
    }
    for name in ["pota.json", "sata.json", "keys.json"] {
        fs::remove_file(dir.file(name))?;
    }
    Ok(saved)
}

#[test]
fn create_and_restore_local_in_separate_processes() -> Result<()> {
    let dir = StateDir::new()?;
    let output = success(run(&dir.0, "create", false)?)?;
    assert!(output.contains("Security domain created."));
    assert!(output.contains("Receiver attestation omitted: temporary host receiver"));
    assert!(output.contains("Receiver SATA-authorized HPKE certificate chain"));
    for scope in ["local", "security-domain", "ephemeral", "session"] {
        assert!(output.contains(&format!(
            "{scope}: sign + verify passed; original masked key saved"
        )));
    }
    let original = record(&dir.record())?;
    let pota = record(&dir.file("pota.json"))?;
    let sata = record(&dir.file("sata.json"))?;
    let keys = record(&dir.file("keys.json"))?;
    assert_eq!(original["version"].as_u32(), Some(2));
    assert!(!original.has_key("authority"));
    assert!(!original.has_key("ecc_keys"));
    assert_eq!(original["pota_file"].as_str(), Some("pota.json"));
    assert_eq!(original["sata_file"].as_str(), Some("sata.json"));
    assert_eq!(original["keys_file"].as_str(), Some("keys.json"));
    assert_eq!(keys["ecc_keys"].len(), 4);
    assert!(pota["private_key"].as_str().is_some());
    assert!(sata["private_key"].as_str().is_some());
    let snapshots = ["pota.json", "sata.json", "keys.json"]
        .into_iter()
        .map(|name| {
            Ok((
                name,
                fs::read(dir.file(name))?,
                fs::metadata(dir.file(name))?.modified()?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut previous = original.clone();
    for reset in [false, true, false] {
        let output = success(run(&dir.0, "restore-local", reset)?)?;
        assert!(output.contains("Security domain restored from local backups."));
        assert!(output.contains("refreshed local recovery state:"));
        assert!(output.contains("local: sign + verify passed"));
        assert!(output.contains("security-domain: sign + verify passed"));
        assert!(
            output.contains("ephemeral: rejected as expected (masked-key authentication failed)")
        );
        assert!(output.contains("session: rejected as expected (masked-key authentication failed)"));
        let restored = record(&dir.record())?;
        for (name, bytes, modified) in &snapshots {
            assert!(fs::read(dir.file(name))? == *bytes);
            assert_eq!(&fs::metadata(dir.file(name))?.modified()?, modified);
        }
        for field in [
            "machine_seed",
            "pota_thumbprint",
            "sata_thumbprint",
            "pota_file",
            "sata_file",
            "keys_file",
        ] {
            assert!(restored[field] == original[field]);
        }
        assert!(restored["partition"]["policy"] == original["partition"]["policy"]);
        assert!(restored["partition"]["pta_cert_chain"][0] == pota["certificate"]);
        for (section, field, length) in [
            ("partition", "local_mk_backup", LOCAL_MK_BACKUP_LEN),
            ("security_domain", "pok_local_backup", MASKED_SD_LEN),
            ("security_domain", "sd_mk_backup", SD_MK_BACKUP_LEN),
        ] {
            let bytes = hex::decode(restored[section][field].as_str().context("saved backup")?)?;
            assert_eq!(bytes.len(), length);
            assert!(bytes.iter().any(|&byte| byte != 0));
            assert!(restored[section][field] != previous[section][field]);
        }
        previous = restored;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["recovery-state.json", "pota.json", "sata.json", "keys.json"] {
            assert_eq!(
                fs::metadata(dir.file(name))?.permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::metadata(dir.0.join("state"))?.permissions().mode() & 0o777,
            0o700
        );
    }
    let state_files = fs::read_dir(dir.0.join("state"))?.count();
    assert_eq!(
        state_files, 4,
        "authorities and keys must be separate from the recovery backups"
    );
    Ok(())
}

#[test]
fn invalid_recovery_is_rejected_before_open_or_reset() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create", false)?)?;
    let original = record(&dir.record())?;
    let mut legacy = original.clone();
    legacy.remove("pota_file");
    let mut missing_domain = original.clone();
    missing_domain.remove("security_domain");
    let mut bad_policy = original.clone();
    bad_policy["partition"]["policy"] = "00".into();
    let mut bad_backup = original.clone();
    bad_backup["security_domain"]["sd_mk_backup"] = "00".into();
    let mut bad_seed = original.clone();
    bad_seed["machine_seed"] = "00".into();
    let mut wrong_reference = original.clone();
    wrong_reference["pota_file"] = "../pota.json".into();
    let mut bad_thumbprint = original.clone();
    bad_thumbprint["sata_thumbprint"] = hex::encode([0u8; 48]).into();
    for invalid in [
        legacy,
        missing_domain,
        bad_policy,
        bad_backup,
        bad_seed,
        wrong_reference,
        bad_thumbprint,
    ] {
        let text = invalid.dump();
        fs::write(dir.record(), &text)?;
        let output = run(&dir.0, "restore-local", true)?;
        assert!(!output.status.success());
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            stderr.contains("load local recovery state and POTA signer")
                || stderr.contains("load saved ECC scope check keys")
        );
        assert!(!stdout.contains("Opening"));
        assert!(!stdout.contains("Security domain restored"));
        assert!(fs::read_to_string(dir.record())? == text);
    }
    fs::write(dir.record(), original.dump())?;
    success(run(&dir.0, "restore-local", false)?)?;
    Ok(())
}

#[test]
fn missing_recovery_is_an_error_without_reset() -> Result<()> {
    let dir = StateDir::new()?;
    let output = run(&dir.0, "restore-local", true)?;
    assert!(!output.status.success());
    assert!(!String::from_utf8(output.stdout)?.contains("Opening"));
    assert!(String::from_utf8(output.stderr)?.contains("partition recovery state is missing"));
    assert!(!dir.record().exists());
    Ok(())
}

#[test]
fn invalid_or_missing_sidecars_fail_before_reset() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create", false)?)?;
    let recovery = fs::read(dir.record())?;
    let other = EccPrivateKey::from_curve(EccCurve::P384)?.to_vec()?;
    for name in ["pota.json", "sata.json", "keys.json"] {
        let path = dir.file(name);
        let original = fs::read_to_string(&path)?;
        fs::remove_file(&path)?;
        let output = run(&dir.0, "restore-local", true)?;
        assert!(!output.status.success());
        assert!(!String::from_utf8(output.stdout)?.contains("Opening"));
        assert_eq!(fs::read(dir.record())?, recovery);
        fs::write(&path, &original)?;
        let parsed = jzon::parse(&original)?;
        let mut invalid_records = vec![jzon::object! { version: 99 }];
        if name != "keys.json" {
            let mut bad_private = parsed.clone();
            bad_private["private_key"] = "00".into();
            invalid_records.push(bad_private);
            let mut wrong_private = parsed.clone();
            wrong_private["private_key"] = hex::encode(&other).into();
            invalid_records.push(wrong_private);
            let mut bad_certificate = parsed.clone();
            bad_certificate["certificate"] = "00".into();
            invalid_records.push(bad_certificate);
        }
        for invalid in invalid_records {
            let text = invalid.dump();
            fs::write(&path, &text)?;
            let output = run(&dir.0, "restore-local", true)?;
            assert!(!output.status.success());
            assert!(!String::from_utf8(output.stdout)?.contains("Opening"));
            assert_eq!(fs::read(dir.record())?, recovery);
            assert_eq!(fs::read_to_string(&path)?, text);
        }
        fs::write(&path, original)?;
    }
    success(run(&dir.0, "restore-local", false)?)?;
    Ok(())
}

#[test]
fn combined_authority_and_keys_migrate_without_regeneration() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create", false)?)?;
    let saved = legacy_record(&dir)?;
    let original_keys = saved["ecc_keys"].clone();
    let original_pota = saved["authority"].clone();
    fs::write(dir.record(), saved.dump())?;
    let output = success(run(&dir.0, "restore-local", false)?)?;
    assert!(output.contains("local: sign + verify passed"));
    assert!(output.contains("security-domain: sign + verify passed"));
    assert!(output.contains("ephemeral: rejected as expected"));
    assert!(output.contains("session: rejected as expected"));
    let restored = record(&dir.record())?;
    assert_eq!(restored["version"].as_u32(), Some(2));
    assert!(restored["sata_file"].is_null());
    assert!(!dir.file("sata.json").exists());
    let pota = record(&dir.file("pota.json"))?;
    assert!(pota["private_key"] == original_pota["pota_private_key"]);
    assert!(pota["certificate"] == original_pota["pota_certificate"]);
    assert!(restored["machine_seed"] == original_pota["machine_seed"]);
    assert!(restored["sata_thumbprint"] == original_pota["sata_thumbprint"]);
    assert!(record(&dir.file("keys.json"))?["ecc_keys"] == original_keys);
    success(run(&dir.0, "restore-local", false)?)?;
    Ok(())
}

#[test]
fn valid_signer_file_encodings_are_preserved_byte_for_byte() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create", false)?)?;
    let mut snapshots = Vec::new();
    for name in ["pota.json", "sata.json"] {
        let mut signer = record(&dir.file(name))?;
        for field in ["private_key", "certificate"] {
            signer[field] = signer[field]
                .as_str()
                .context("signer field")?
                .to_ascii_uppercase()
                .into();
        }
        signer["description"] = "retained authority".into();
        let text = signer.dump();
        fs::write(dir.file(name), &text)?;
        snapshots.push((name, text));
    }
    success(run(&dir.0, "restore-local", false)?)?;
    for (name, text) in snapshots {
        assert_eq!(fs::read_to_string(dir.file(name))?, text);
    }
    Ok(())
}

#[test]
fn orphaned_sidecar_blocks_create_before_reset() -> Result<()> {
    for name in ["pota.json", "sata.json", "keys.json", "remote-backup.json"] {
        let dir = StateDir::new()?;
        fs::create_dir(dir.0.join("state"))?;
        fs::write(dir.file(name), "partial state")?;
        let output = run(&dir.0, "create", false)?;
        assert!(!output.status.success());
        assert!(!String::from_utf8(output.stdout)?.contains("Opening"));
        assert!(String::from_utf8(output.stderr)?.contains("refusing to reset"));
        assert!(!dir.record().exists());
        assert_eq!(fs::read_to_string(dir.file(name))?, "partial state");
    }
    Ok(())
}

#[test]
fn older_recovery_without_ecc_keys_explicitly_skips_checks() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create", false)?)?;
    let mut saved = legacy_record(&dir)?;
    saved.remove("ecc_keys");
    fs::write(dir.record(), saved.dump())?;
    let output = success(run(&dir.0, "restore-local", false)?)?;
    assert!(output.contains("Security domain restored from local backups."));
    assert!(output.contains("ECC scope checks skipped: no keys saved"));
    assert!(!output.contains("sign + verify passed"));
    Ok(())
}

#[test]
fn older_three_scope_recovery_explicitly_skips_session_check() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create", false)?)?;
    let mut saved = legacy_record(&dir)?;
    saved["ecc_keys"].remove("session");
    let original_keys = saved["ecc_keys"].clone();
    fs::write(dir.record(), saved.dump())?;
    let output = success(run(&dir.0, "restore-local", false)?)?;
    assert!(output.contains("local: sign + verify passed"));
    assert!(output.contains("security-domain: sign + verify passed"));
    assert!(output.contains("ephemeral: rejected as expected (masked-key authentication failed)"));
    assert!(output.contains("session: skipped (no session key saved"));
    assert!(!output.contains("session: rejected"));
    assert!(record(&dir.file("keys.json"))?["ecc_keys"] == original_keys);
    assert_eq!(record(&dir.record())?["version"].as_u32(), Some(2));
    Ok(())
}

#[test]
fn malformed_or_mislabelled_ecc_keys_fail_before_reset() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create", false)?)?;
    let original = record(&dir.file("keys.json"))?;
    let mut bad_blob = original.clone();
    bad_blob["ecc_keys"]["ephemeral"]["masked_key"] = "00".into();
    let mut wrong_scope = original.clone();
    wrong_scope["ecc_keys"]["ephemeral"] = original["ecc_keys"]["local"].clone();
    let mut bad_public_key = original.clone();
    bad_public_key["ecc_keys"]["local"]["public_key"] = "00".into();
    let mut missing_key = original.clone();
    missing_key["ecc_keys"].remove("security-domain");
    let mut wrong_session_scope = original.clone();
    wrong_session_scope["ecc_keys"]["session"] = original["ecc_keys"]["ephemeral"].clone();
    let mut missing_session_blob = original.clone();
    missing_session_blob["ecc_keys"]["session"].remove("masked_key");
    for invalid in [
        bad_blob,
        wrong_scope,
        bad_public_key,
        missing_key,
        wrong_session_scope,
        missing_session_blob,
    ] {
        let text = invalid.dump();
        fs::write(dir.file("keys.json"), &text)?;
        let output = run(&dir.0, "restore-local", true)?;
        assert!(!output.status.success());
        assert!(!String::from_utf8(output.stdout)?.contains("Opening"));
        assert!(String::from_utf8(output.stderr)?.contains("load saved ECC scope check keys"));
        assert_eq!(fs::read_to_string(dir.file("keys.json"))?, text);
    }
    Ok(())
}

#[test]
fn tampered_durable_keys_are_not_expected_ephemeral_failures() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create", false)?)?;
    let original = record(&dir.file("keys.json"))?;
    for scope in ["local", "security-domain"] {
        let mut saved = original.clone();
        let mut blob = hex::decode(
            saved["ecc_keys"][scope]["masked_key"]
                .as_str()
                .context("masked key")?,
        )?;
        let tag = blob.last_mut().context("masked key tag")?;
        *tag ^= 1;
        saved["ecc_keys"][scope]["masked_key"] = hex::encode(blob).into();
        fs::write(dir.file("keys.json"), saved.dump())?;
        let output = run(&dir.0, "restore-local", false)?;
        assert!(!output.status.success());
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stdout.contains("Security domain restored from local backups."));
        assert!(!stdout.contains("ephemeral: rejected as expected"));
        assert!(stderr.contains("ECC scope checks failed"));
        assert!(stderr.contains(&format!("sign with original {scope} key")));
        assert!(stderr.contains("MaskedKeyAuthenticationFailed"));
    }
    Ok(())
}

#[test]
fn signatures_must_match_original_public_keys() -> Result<()> {
    let dir = StateDir::new()?;
    success(run(&dir.0, "create", false)?)?;
    let mut saved = record(&dir.file("keys.json"))?;
    saved["ecc_keys"]["local"]["public_key"] =
        saved["ecc_keys"]["security-domain"]["public_key"].clone();
    fs::write(dir.file("keys.json"), saved.dump())?;
    let output = run(&dir.0, "restore-local", false)?;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("verify signature from original local key"));
    assert!(stderr.contains("signature does not match the original public key"));
    Ok(())
}
