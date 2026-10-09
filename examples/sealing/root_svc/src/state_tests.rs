// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Application-specific authority and recovery tests, separate from the store.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use anyhow::Context;
use anyhow::Result;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_sealing_api::Error;
use tsra_sealing_api::SealingSession;
use tsra_sealing_api::SecurityDomain;
use tsra_sealing_api::SecurityDomainEnv;
use tsra_sealing_api::SecurityDomainStore;

use crate::store::FileStore;

const RECOVERY_FILE: &str = "recovery-state.json";
const REMOTE_FILE: &str = "remote-backup.json";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "sealing-root-state-{}-{}",
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
            eprintln!("root state test cleanup failed: {error}");
        }
    }
}

#[test]
fn reopened_sata_signer_uses_the_exact_saved_root_certificate() -> Result<()> {
    let dir = TestDir::new()?;
    crate::commands::create(&crate::cli::CreateArgs {
        device: None,
        name: "saved-sata-signer-test".into(),
        state_dir: dir.0.clone(),
        remote_restorable: false,
        listen: None,
    })?;
    let store = FileStore::new(&dir.0)?;
    let saved = store
        .load_authority()?
        .context("saved authority")?
        .sata
        .context("saved SATA")?;
    let env = crate::env::SelfContainedEnv::load(store)?;
    let receiver = crate::pki::CaKey::generate();
    let chain = env.receiver_chain(&receiver.raw_pub())?;
    assert_eq!(chain.root_der, saved.certificate);
    tsra_sealing_report::verify_certificate_chain(&[chain.root_der, chain.leaf_der])?;
    Ok(())
}

#[test]
fn remote_create_and_restore_persistence_failures_retain_retryable_material() -> Result<()> {
    let dir = TestDir::new()?;
    let session = SealingSession::open_reset()?;
    let seed = [0x42; MACH_SEED_LEN];
    let env = crate::env::SelfContainedEnv::generate(&session, FileStore::new(&dir.0)?, seed)?;
    let domain = SecurityDomain::new(env);
    let remote = crate::remote::create(&domain, &session, &seed)?;
    let original = fs::read(dir.0.join(RECOVERY_FILE))?;
    fs::create_dir(dir.0.join(REMOTE_FILE))?;
    assert!(domain.env().store().save_remote(&remote).is_err());
    assert_eq!(fs::read(dir.0.join(RECOVERY_FILE))?, original);
    crate::remote::validate(&remote, domain.env().policy())?;
    fs::remove_dir(dir.0.join(REMOTE_FILE))?;
    domain.env().store().save_remote(&remote)?;
    drop(session);

    let session = SealingSession::open_reset()?;
    let old = dir.0.join("original-recovery.json");
    let error = domain
        .restore_remote(&session, &seed, &remote, |csr, report| {
            let chain = domain.env().sign_pta(csr, report)?;
            fs::rename(dir.0.join(RECOVERY_FILE), &old)?;
            fs::create_dir(dir.0.join(RECOVERY_FILE))?;
            Ok(chain)
        })
        .expect_err("remote restore persistence must fail");
    let Some(Error::RemoteRestorePersistence {
        partition, state, ..
    }) = error.downcast_ref::<Error>()
    else {
        anyhow::bail!("remote restore did not retain refreshed recovery material");
    };
    fs::remove_dir(dir.0.join(RECOVERY_FILE))?;
    fs::rename(&old, dir.0.join(RECOVERY_FILE))?;
    // Retry storage, not the successful device restore.
    domain.env().store().save_creation(partition, state)?;
    assert!(domain.env().store().load_partition()?.as_ref() == Some(partition));
    assert!(domain.env().store().load_security_domain()?.as_ref() == Some(state));
    drop(session);
    let session = SealingSession::open_reset()?;
    domain.restore_local(&session, &seed, |csr, report| {
        domain.env().sign_pta(csr, report)
    })?;
    Ok(())
}
