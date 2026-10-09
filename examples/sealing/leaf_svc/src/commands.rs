// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Leaf orchestration delegates all partition and SD operations to the common
//! API. The local backup outbox is retained even when HTTP delivery fails.
//!
//! Join requires `--name`, `--instance`, `--root`, `--state-dir`, and prior
//! controller authorization at the root. `--listen` retains the worker without
//! changing its health/signing protocol. `--events` emits redacted
//! `SEALING_EVENT {"stage":...,"title":...}` lines: registered, authority,
//! preflight, receiver, resealed, restored, keys. The new `keys` stage means the
//! catalog SD key signed successfully and independent scope-check keys were
//! saved. Poll worker health for final readiness, not a progress event.

use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use tsra_api::HsmCert;
use tsra_crypto::Rng;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_sealing_api::device_cert_chain;
use tsra_sealing_api::load_local_recovery;
use tsra_sealing_api::load_partition_recovery;
use tsra_sealing_api::SealingSession;
use tsra_sealing_api::SecurityDomain;
use tsra_sealing_common::http::Client;
use tsra_sealing_common::runtime::finish_restore;
use tsra_sealing_common::runtime::open_restore_session;
use tsra_sealing_common::wire;
use zerocopy::IntoBytes;

use super::env::LeafEnv;
use super::validate_name;
use crate::display;
use crate::key_check;
use crate::store::FileStore;

#[derive(Parser)]
#[command(
    name = "leaf_svc",
    version,
    about = "Named leaf security domains using a loopback root issuer"
)]
struct Cli {
    /// Refuse device access unless built with the emulator backend.
    #[arg(long, global = true)]
    require_emu: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register this name over HTTP, then enroll and create an independent SD.
    Create(CreateArgs),
    /// Join an existing SD after the controller explicitly authorizes this instance.
    Join(JoinArgs),
    /// Restore local backups. The saved root must be online to sign a new PTA.
    RestoreLocal(RestoreArgs),
    /// Restore the SD using the root's saved backup, resealed to this partition.
    RestoreRemote(RestoreArgs),
}

#[derive(Args)]
struct StateArgs {
    #[arg(long, value_name = "DIR")]
    state_dir: PathBuf,
    /// Keep the leaf instance alive; signing opens a fresh session per request.
    #[arg(long, value_parser = tsra_sealing_common::http::listen_addr)]
    listen: Option<std::net::SocketAddr>,
    /// Emit redacted JSON progress events for the demo controller.
    #[arg(long)]
    events: bool,
}

#[derive(Args)]
struct CreateArgs {
    #[arg(long, value_parser = validate_name)]
    name: String,
    /// Loopback root URL, e.g. http://127.0.0.1:8080.
    #[arg(long)]
    root: String,
    #[command(flatten)]
    state: StateArgs,
}

#[derive(Args)]
struct RestoreArgs {
    #[command(flatten)]
    state: StateArgs,
    /// Explicitly reset an initialized hardware partition before recovery.
    #[arg(long)]
    reset: bool,
}

#[derive(Args)]
struct JoinArgs {
    #[arg(long, value_parser = validate_name)]
    name: String,
    #[arg(long, value_parser = validate_name)]
    instance: String,
    #[arg(long)]
    root: String,
    #[command(flatten)]
    state: StateArgs,
}

pub(crate) fn run() -> Result<()> {
    let args = Cli::parse();
    anyhow::ensure!(
        !args.require_emu || cfg!(feature = "emu"),
        "this operation requires an emulator build"
    );
    match args.command {
        Command::Create(args) => create(&args),
        Command::Join(args) => join(&args),
        Command::RestoreLocal(args) => restore(&args),
        Command::RestoreRemote(args) => restore_remote(&args),
    }
}

fn create(args: &CreateArgs) -> Result<()> {
    let listener = crate::worker::bind(args.state.listen)?;
    let client = Client::new(&args.root)?;
    let store = FileStore::new(&args.state.state_dir)?;
    store.ensure_new_creation()?;
    let base = format!("/v1/leaves/{}", args.name);
    client
        .register_leaf(&args.name)
        .context("register leaf with root")?;
    println!("Leaf '{}' registered with root.", args.name);
    progress(&args.state, "registered", "Name registered with root");
    let mut record = client.get(&base)?;
    anyhow::ensure!(
        record["name"].as_str() == Some(args.name.as_str()),
        "root returned another leaf"
    );
    anyhow::ensure!(
        record["policy"].is_null(),
        "leaf name is already enrolled; use saved local recovery state"
    );
    let receiver = client.get(&format!("{base}/receiver"))?;
    let mut seed = [0u8; MACH_SEED_LEN];
    Rng::rand_bytes(&mut seed)?;
    eprintln!("Demo only: HTTP name-based enrollment; the first verified partition claims the name. Supplied roots are not trusted hardware admission.");
    println!("Opening and resetting leaf partition...");
    let session = SealingSession::open_reset()?;
    let pid = session.partition.pid()?;
    let public = session.partition.ex_pub_key()?;
    let response = client.post(
        &format!("{base}/policy"),
        &jzon::object! { pid: hex::encode(&pid), public: hex::encode(&public) },
    )?;
    record["policy"] = response["policy"].clone();
    record["root"] = args.root.as_str().into();
    record["seed"] = hex::encode(seed).into();
    record["instance"] = "primary".into();
    let mut env = LeafEnv::from_record(store, &record)?;
    anyhow::ensure!(
        env.policy.backup_part_id.as_slice() == pid
            && env.policy.backup_part_pub_key.data.as_slice() == public,
        "leaf policy is bound to another partition"
    );
    let (chain, evidence) = env.validate_receiver(&receiver)?;
    progress(
        &args.state,
        "authority",
        "Root receiver evidence and leaf SATA verified",
    );
    env.manufacturer = device_cert_chain(&session.partition, 0)?;
    env.store.write_immutable("leaf.json", &record)?;
    display::write_leaf_receiver(&mut std::io::stdout().lock(), &chain, &evidence)?;
    let domain = SecurityDomain::new(env);
    let env = domain.env();
    let certs: Vec<_> = chain.iter().map(|cert| HsmCert { cert }).collect();
    let backup = domain.create(&session, &seed, &certs, &evidence, |csr, report| {
        env.certify(csr, report)
    })?;
    progress(
        &args.state,
        "created",
        "Leaf enrolled and security domain created",
    );
    let (_, state) = load_local_recovery(&env.store)?;
    let outbox = jzon::object! {
        version: 1, policy: hex::encode(env.policy.as_bytes()),
        pok_remote_backup: hex::encode(backup.pok_remote_backup),
        sd_mk_backup: hex::encode(state.sd_mk_backup),
        sender: wire::encode_evidence(&backup.evidence),
        receiver: receiver,
    };
    env.store
        .write_immutable("leaf-backup.json", &outbox)
        .context(
            "leaf created and local recovery saved, but creation backup outbox persistence failed",
        )?;
    let keys = key_check::generate(&session.session)?;
    env.store.save_ecc_keys(&keys)?;
    upload(env)?;
    let catalog = key_check::domain_catalog(&keys, &env.name, env.policy.as_bytes())?;
    let response = client
        .post(&env.route("catalog"), &catalog)
        .context("catalog upload failed; local masked keys and recovery remain saved")?;
    anyhow::ensure!(
        response["status"] == "stored",
        "root did not store domain catalog"
    );
    progress(
        &args.state,
        "backed-up",
        "Root acknowledged durable sealed backup",
    );
    println!(
        "Leaf '{}' security domain created; local recovery saved in {}.",
        args.name,
        args.state.state_dir.display()
    );
    key_check::print_created(&mut std::io::stdout().lock())?;
    crate::worker::serve(listener, session, &keys, &args.name)
}

fn join(args: &JoinArgs) -> Result<()> {
    anyhow::ensure!(
        args.instance != "primary",
        "primary is reserved for create and restore"
    );
    let listener = crate::worker::bind(args.state.listen)?;
    let client = Client::new(&args.root)?;
    let store = FileStore::new(&args.state.state_dir)?;
    store.ensure_new_creation()?;
    let base = format!("/v1/leaves/{}", args.name);
    // This is deliberately GET only. Authorization belongs to the controller,
    // never to the joining process.
    let authorized = client
        .get(&format!("{base}/instances/{}", args.instance))
        .context(
            "instance is not authorized; controller must POST to the root instances endpoint",
        )?;
    anyhow::ensure!(
        authorized["name"].as_str() == Some(args.name.as_str())
            && authorized["instance"].as_str() == Some(args.instance.as_str())
            && authorized["status"] == "authorized",
        "instance is already enrolled or authorization does not match"
    );
    progress(
        &args.state,
        "registered",
        "Controller-authorized instance confirmed",
    );
    let mut record = client.get(&base)?;
    anyhow::ensure!(
        record["name"].as_str() == Some(args.name.as_str()),
        "root returned another service"
    );
    record["root"] = args.root.as_str().into();
    record["instance"] = args.instance.as_str().into();
    let mut seed = [0u8; MACH_SEED_LEN];
    Rng::rand_bytes(&mut seed)?;
    record["seed"] = hex::encode(seed).into();
    let mut env = LeafEnv::from_record(store, &record)?;
    let available = client.get(&env.route("recovery"))?;
    anyhow::ensure!(
        available["status"] == "available"
            && wire::blob(&available, "policy")? == env.policy.as_bytes(),
        "root has no matching original backup"
    );
    let catalog = client.get(&env.route("catalog"))?;
    key_check::validate_domain_catalog(&catalog, &env.name, env.policy.as_bytes())?;
    env.validate_receiver(&client.get(&env.route("receiver"))?)?;
    progress(
        &args.state,
        "authority",
        "Original policy, root receiver and domain catalog verified",
    );
    progress(
        &args.state,
        "preflight",
        "Fresh instance authorized; original service remains live",
    );
    let session = SealingSession::open_reset()?;
    env.manufacturer = device_cert_chain(&session.partition, 0)?;
    env.store.write_immutable("leaf.json", &record)?;
    let domain = SecurityDomain::new(env);
    let env = domain.env();
    let prepared = domain
        .prepare_remote_instance(&session, &env.seed, |csr, report| env.certify(csr, report))?;
    save_prepared(env, &prepared)?;
    progress(
        &args.state,
        "receiver",
        "Independent seed, PTA, local MK and attested receiver prepared",
    );
    let response = client
        .post(
            &env.route("reseal"),
            &jzon::object! {
                instance: env.instance.as_str(),
                policy: hex::encode(env.policy.as_bytes()),
                receiver: wire::encode_evidence(&prepared.evidence),
            },
        )
        .context("root reseal failed; instance identity and prepared receiver retained")?;
    anyhow::ensure!(
        wire::blob(&response, "policy")? == env.policy.as_bytes(),
        "resealed policy mismatch"
    );
    env.validate_receiver(&response["sender"])?;
    let backup = wire::resealed_backup(&response)?;
    progress(
        &args.state,
        "resealed",
        "Root resealed original SD only to this authorized receiver",
    );
    env.store
        .write_record("leaf-resealed.json", &response, false)?;
    domain.restore_resealed(&session, &prepared, &backup)?;
    progress(
        &args.state,
        "restored",
        "Same security domain restored on independent instance",
    );
    let keys = key_check::generate_from_domain_catalog(
        &session.session,
        &catalog,
        &env.name,
        env.policy.as_bytes(),
    )?;
    env.store.save_ecc_keys(&keys)?;
    progress(
        &args.state,
        "keys",
        "Shared SD signing key verified; private instance test keys generated",
    );
    println!(
        "Leaf '{}' instance '{}' joined the existing security domain.",
        env.name, env.instance
    );
    crate::worker::serve(listener, session, &keys, &env.name)
}

fn load(args: &StateArgs) -> Result<LeafEnv> {
    let store = FileStore::new(&args.state_dir)?;
    let record = store
        .load("leaf.json")?
        .context("missing leaf enrollment state")?;
    let env = LeafEnv::from_record(store, &record)?;
    let partition = load_partition_recovery(&env.store)?;
    anyhow::ensure!(
        partition.policy == env.policy.as_bytes()
            && partition.pta_cert_chain.first() == Some(&env.pota),
        "saved leaf recovery identity mismatch"
    );
    Ok(env)
}

fn restore(args: &RestoreArgs) -> Result<()> {
    let listener = crate::worker::bind(args.state.listen)?;
    let mut env = load(&args.state)?;
    load_local_recovery(&env.store)?;
    let keys = env.store.load_ecc_keys()?;
    env.check_root()
        .context("verify saved root issuer before opening partition")?;
    let session = open_restore_session(args.reset, "leaf local")?;
    env.manufacturer = device_cert_chain(&session.partition, 0)?;
    let domain = SecurityDomain::new(env);
    domain.restore_local(&session, &domain.env().seed, |csr, report| {
        domain.env().certify(csr, report)
    })?;
    println!(
        "Leaf '{}' security domain restored from local backups.",
        domain.env().name
    );
    finish_restore(&session, keys.as_deref(), &args.state.state_dir)?;
    crate::worker::serve(
        listener,
        session,
        keys.as_deref().unwrap_or(&[]),
        &domain.env().name,
    )
}

fn restore_remote(args: &RestoreArgs) -> Result<()> {
    let listener = crate::worker::bind(args.state.listen)?;
    let mut env = load(&args.state)?;
    let keys = env.store.load_ecc_keys()?;
    env.check_root()
        .context("verify root issuer before remote recovery")?;
    let client = Client::new(&env.root)?;
    let available = client.get(&env.route("recovery"))?;
    anyhow::ensure!(
        available["status"] == "available"
            && wire::blob(&available, "policy")? == env.policy.as_bytes(),
        "root has no matching remote recovery backup"
    );
    progress(
        &args.state,
        "preflight",
        "Root identity and original backup availability verified",
    );
    let session = open_restore_session(args.reset, "leaf remote")?;
    env.manufacturer = device_cert_chain(&session.partition, 0)?;
    let domain = SecurityDomain::new(env);
    let env = domain.env();
    let prepared = domain
        .prepare_remote_restore(&session, &env.seed, |csr, report| env.certify(csr, report))?;
    save_prepared(env, &prepared)?;
    progress(
        &args.state,
        "receiver",
        "Partition recovered; fresh attested receiver persisted",
    );
    let request = jzon::object! {
        instance: env.instance.as_str(),
        policy: hex::encode(env.policy.as_bytes()),
        receiver: wire::encode_evidence(&prepared.evidence),
    };
    let response = client
        .post(&env.route("reseal"), &request)
        .context("root reseal failed; original recovery and prepared receiver retained")?;
    anyhow::ensure!(
        wire::blob(&response, "policy")? == env.policy.as_bytes(),
        "resealed policy mismatch"
    );
    let backup = wire::resealed_backup(&response)?;
    env.validate_receiver(&response["sender"])
        .context("verify reseal sender against saved root policy and leaf SATA/SAPOTA")?;
    progress(
        &args.state,
        "resealed",
        "HSM reseal returned; root sender evidence verified",
    );
    env.store
        .write_record("leaf-resealed.json", &response, false)?;
    domain.restore_resealed(&session, &prepared, &backup)?;
    progress(
        &args.state,
        "restored",
        "Original security domain restored; local recovery saved",
    );
    println!(
        "Leaf '{}' security domain restored from root-resealed remote backup.",
        env.name
    );
    finish_restore(&session, keys.as_deref(), &args.state.state_dir)?;
    crate::worker::serve(listener, session, keys.as_deref().unwrap_or(&[]), &env.name)
}

fn save_prepared(env: &LeafEnv, prepared: &tsra_sealing_api::PreparedRemoteRestore) -> Result<()> {
    env.store
        .write_record(
            "leaf-remote-prepared.json",
            &jzon::object! {
                version: 1,
                policy: hex::encode(&prepared.partition.policy),
                pta: wire::encode_chain(&prepared.partition.pta_cert_chain),
                local_mk_backup: hex::encode(&prepared.partition.local_mk_backup),
                masked_receiver: hex::encode(&prepared.receiver.masked),
                receiver: wire::encode_evidence(&prepared.evidence),
            },
            false,
        )
        .context("partition finalized, but remote preparation persistence failed")
}

fn progress(args: &StateArgs, stage: &str, title: &str) {
    if args.events {
        println!(
            "SEALING_EVENT {}",
            jzon::object! {stage: stage, title: title}.dump()
        );
    }
}

fn upload(env: &LeafEnv) -> Result<()> {
    let record = env
        .store
        .load("leaf-backup.json")?
        .context("missing leaf backup outbox")?;
    anyhow::ensure!(
        wire::blob(&record, "policy")? == env.policy.as_bytes(),
        "outbox policy mismatch"
    );
    let response = Client::new(&env.root)?.post(&env.route("backup"), &record)
        .context("backup upload failed; local recovery and leaf-backup.json retained; do not recreate the SD")?;
    anyhow::ensure!(
        response["status"] == "stored",
        "root did not acknowledge durable backup storage"
    );
    println!("Leaf creation backup persisted in the root store.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_supports_only_leaf_operations() {
        let mut cli = Cli::command();
        cli.debug_assert();
        cli = Cli::command();
        for supported in ["create", "join", "restore-local", "restore-remote"] {
            assert!(cli.find_subcommand(supported).is_some());
        }
        for unsupported in ["clone", "child", "upload-backup"] {
            assert!(cli.find_subcommand(unsupported).is_none());
            assert!(
                Cli::try_parse_from(["leaf_svc", unsupported, "--state-dir", "state"]).is_err()
            );
        }
        assert!(Cli::try_parse_from([
            "leaf_svc",
            "create",
            "--name",
            "../bad",
            "--root",
            "http://127.0.0.1:8080",
            "--state-dir",
            "state"
        ])
        .is_err());
    }
}
