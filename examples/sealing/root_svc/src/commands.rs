// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Service command orchestration.
//!
//! Creation refuses existing state before resetting the partition. Recovery
//! loads saved material (and validates remote evidence) before device access.
//! After recovery, local/domain keys must still sign, while ephemeral/session
//! keys must fail authentication. Backups and saved key checks remain separate.

use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::SealingSession;
use tsra_sealing_api::SecurityDomain;
use tsra_sealing_api::SecurityDomainEnv;

use crate::cli::CreateArgs;
use crate::cli::RestoreArgs;
use crate::display;
use crate::env::SelfContainedEnv;
use crate::key_check;
use crate::key_check::SavedKey;
use crate::peer;
use crate::pki::CaKey;
use crate::remote;
use crate::store::FileStore;

pub(crate) fn create(args: &CreateArgs) -> Result<()> {
    let listener = peer::http::bind(args.listen.map(|addr| addr.to_string()).as_deref())?;
    warn_ignored_device(args.device.as_deref());
    let store = FileStore::new(&args.state_dir)?;
    store.ensure_new_creation()?;
    println!("Opening and resetting partition...");
    let session = SealingSession::open_reset().context("bring up partition and CO session")?;
    let tee_seed = tee_seed_from_name(&args.name)?;
    let env = SelfContainedEnv::generate(&session, store, tee_seed)?;
    let domain = SecurityDomain::new(env);

    println!("Creating security domain...");
    if args.remote_restorable {
        create_remote_backup(&domain, &session, &args.state_dir)?;
    } else {
        create_temporary_backup(&domain, &session, &args.state_dir)?;
    }

    let keys = key_check::generate(&session.session)
        .context("security domain created and recovery saved, but ECC scope checks failed")?;
    domain
        .env()
        .store()
        .save_ecc_keys(&keys)
        .context("security domain created and recovery saved, but ECC key persistence failed")?;
    key_check::print_created(&mut std::io::stdout().lock())?;
    peer::serve(listener, domain, session)
}

fn create_remote_backup(
    domain: &SecurityDomain<SelfContainedEnv>,
    session: &SealingSession,
    state_dir: &Path,
) -> Result<()> {
    let recovery = remote::create(domain, session, domain.env().machine_seed())?;
    if let Err(source) = domain.env().store().save_remote(&recovery) {
        return Err(tsra_sealing_api::Error::RemoteBackupPersistence {
            result: recovery,
            source,
        }
        .into());
    }

    let mut output = std::io::stdout().lock();
    display::write_remote_creation(&mut output, &recovery, state_dir)?;
    Ok(())
}

fn create_temporary_backup(
    domain: &SecurityDomain<SelfContainedEnv>,
    session: &SealingSession,
    state_dir: &Path,
) -> Result<()> {
    let receiver_key = CaKey::generate();
    let receiver_pub = receiver_key.raw_pub();
    let receiver_chain = domain.env().receiver_chain(&receiver_pub)?;
    // This demo receiver does not require trusted-SA attestation.
    let receiver_evidence = Evidence {
        mfgr_cert_chain: Vec::new(),
        owner_cert_chain: Vec::new(),
        part_owner_cert_chain: Vec::new(),
        report: Vec::new(),
    };
    let created = domain.create(
        session,
        domain.env().machine_seed(),
        &receiver_chain.certs(),
        &receiver_evidence,
        |csr, report| domain.env().sign_pta(csr, report),
    )?;
    display::write_temporary_creation(
        &mut std::io::stdout().lock(),
        &created,
        &receiver_pub,
        &[receiver_chain.root_der, receiver_chain.leaf_der],
        state_dir,
    )?;
    Ok(())
}

pub(crate) fn restore_local(args: &RestoreArgs) -> Result<()> {
    let store = FileStore::new(&args.state_dir)?;
    if let Some(record) = store.load_peer()? {
        return peer::restore_local(args, store, &record);
    }
    let listener = peer::http::bind(args.listen.map(|addr| addr.to_string()).as_deref())?;
    let keys = load_saved_keys(&store)?;
    let env = SelfContainedEnv::load(store).context("load local recovery state and POTA signer")?;
    if listener.is_some() {
        env.peer_authorities()?;
    }
    warn_ignored_device(args.device.as_deref());
    let session = open_restore_session(args.reset, "local")?;
    let domain = SecurityDomain::new(env);
    domain.restore_local(&session, domain.env().machine_seed(), |csr, report| {
        domain.env().sign_pta(csr, report)
    })?;
    println!("Security domain restored from local backups.");
    finish_restore(&session, keys.as_deref(), &args.state_dir)
        .context("security domain restored and recovery saved, but ECC scope checks failed")?;
    peer::serve(listener, domain, session)
}

pub(crate) fn restore_remote(args: &RestoreArgs) -> Result<()> {
    let listener = peer::http::bind(args.listen.map(|addr| addr.to_string()).as_deref())?;
    let store = FileStore::new(&args.state_dir)?;
    let recovery = store
        .load_remote()
        .context("load saved remote backup before opening partition")?;
    let keys = load_saved_keys(&store)?;
    let env = SelfContainedEnv::load_remote(store)
        .context("load partition recovery state and authority signers")?;
    if listener.is_some() {
        env.peer_authorities()?;
    }
    remote::validate(&recovery, env.policy())
        .context("verify remote sender evidence and policy before opening partition")?;
    warn_ignored_device(args.device.as_deref());
    display::write_validated_remote(&mut std::io::stdout().lock(), &recovery)?;

    let session = open_restore_session(args.reset, "remote")?;
    let domain = SecurityDomain::new(env);
    domain.restore_remote(
        &session,
        domain.env().machine_seed(),
        &recovery,
        |csr, report| domain.env().sign_pta(csr, report),
    )?;
    println!("Security domain restored from remote backup.");
    finish_restore(&session, keys.as_deref(), &args.state_dir).context(
        "security domain restored remotely and local recovery saved, but ECC scope checks failed",
    )?;
    peer::serve(listener, domain, session)
}

fn load_saved_keys(store: &FileStore) -> Result<Option<Vec<SavedKey>>> {
    store
        .load_ecc_keys()
        .context("load saved ECC scope check keys before opening partition")
}

fn warn_ignored_device(device: Option<&str>) {
    if let Some(device) = device {
        eprintln!("note: --device {device} ignored; using the first advertised partition");
    }
}

pub(crate) use tsra_sealing_common::runtime::finish_restore;
pub(crate) use tsra_sealing_common::runtime::open_restore_session;

/// Demo-only deterministic seed: equal names reproduce the same identity.
pub(crate) fn tee_seed_from_name(name: &str) -> Result<[u8; MACH_SEED_LEN]> {
    let mut seed = [0u8; MACH_SEED_LEN];
    HashAlgo::sha256()
        .hash(name.as_bytes(), Some(&mut seed))
        .context("derive demo machine seed from partition name")?;
    Ok(seed)
}
