// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Loopback-only peer-cloning demo. Software authority private keys never
//! leave the primary. A clone's local recovery therefore needs its issuer
//! online to sign a new PTA; it is not an independent authority replica.
//!
//! Routes: `GET /v1/policy` returns only the complete bound policy as hex;
//! `GET /v1/authorities` returns the public POTA/SATA certificates needed to
//! derive DER thumbprints, not private signers. `POST /v1/pta-cert` validates
//! the CSR, PID-signed report and policy before issuing POTA/PTA and SATA/PID
//! chains. `POST /v1/sd/clone` exchanges receiver evidence for a peer backup.
//! `GET /v1/health` becomes available only after successful provisioning.
//!
//! The destination saves `peer.json` (public authority certificates, issuer URL,
//! machine seed and policy) and `peer-prepared.json` (local MK and receiver
//! material) with the store's 0600/atomic-write rules. Interrupted joins retain
//! those files and refuse implicit reset/overwrite; automatic resume of an
//! interrupted join is not implemented.

mod env;
use anyhow::Context;
use anyhow::Result;
use env::PeerEnv;
use http::Client;
use jzon::JsonValue;
use tiny_http::Server;
use tsra_api::PartPolicy;
use tsra_sealing_api::device_cert_chain;
use tsra_sealing_api::load_local_recovery;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::SealingSession;
use tsra_sealing_api::SecurityDomain;
use tsra_sealing_api::SecurityDomainEnv;
pub(crate) use tsra_sealing_common::evidence;
pub(crate) use tsra_sealing_common::http;
pub(crate) use tsra_sealing_common::wire;
use zerocopy::IntoBytes;

use crate::cli::CloneArgs;
use crate::cli::RestoreArgs;
use crate::display;
use crate::env::SelfContainedEnv;
use crate::key_check;
use crate::pki;
use crate::store::FileStore;

pub fn serve(
    server: Option<Server>,
    domain: SecurityDomain<SelfContainedEnv>,
    session: SealingSession,
) -> Result<()> {
    let Some(server) = server else {
        return Ok(());
    };
    let env = domain.env();
    anyhow::ensure!(
        env.policy().flags.allow_peer_cloning(),
        "peer cloning is disabled"
    );
    let (pota, sata) = env.peer_authorities()?;
    let manufacturer = device_cert_chain(&session.partition, 0)?;
    let pid: [u8; 96] = session
        .partition
        .ex_pub_key()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid partition PID public key"))?;
    let endorsement = env.receiver_chain(&pid)?;
    let pid_chain = vec![endorsement.root_der, endorsement.leaf_der];

    http::serve(server, |method, path, request| {
        if path == "/v1/leaves" || path.starts_with("/v1/leaves/") {
            return crate::leaf::handle(&domain, &session, method, path, request);
        }
        match (method, path) {
            ("GET", "/v1/health") => Ok(jzon::object! { status: "ok" }),
            // The full bound policy, never reconstructed from partial config.
            ("GET", "/v1/policy") => {
                Ok(jzon::object! { policy: hex::encode(env.policy().as_bytes()) })
            }
            ("GET", "/v1/authorities") => Ok(jzon::object! {
                pota: hex::encode(pota), sata: hex::encode(sata),
            }),
            ("POST", "/v1/pta-cert") => {
                let csr = wire::blob(request, "csr")?;
                let report = wire::blob(request, "report")?;
                let mfgr = wire::chain(request, "manufacturer")?;
                let (pid, attested) = evidence::verify_report(&mfgr, &report, env.policy())?;
                anyhow::ensure!(
                    pki::pta_pub_from_csr(&csr)?[1..] == attested,
                    "CSR does not match attested PTA key"
                );
                let pta = env.sign_pta(&csr, &report)?;
                let endorsed = env.receiver_chain(&pid)?;
                Ok(jzon::object! {
                    pta: wire::encode_chain(&pta),
                    pid: wire::encode_chain(&[endorsed.root_der, endorsed.leaf_der]),
                })
            }
            ("POST", "/v1/sd/clone") => {
                let receiver = wire::evidence(request)?;
                evidence::verify_peer(&receiver, env.policy())?;
                let backup = domain.create_peer_backup(&session, &receiver, |key| {
                    Ok(Evidence {
                        mfgr_cert_chain: manufacturer.clone(),
                        owner_cert_chain: Vec::new(),
                        part_owner_cert_chain: pid_chain.clone(),
                        report: key.report.clone(),
                    })
                })?;
                Ok(wire::encode_backup(&backup))
            }
            _ => anyhow::bail!("unsupported peer route"),
        }
    })
}

pub fn clone(args: &CloneArgs) -> Result<()> {
    let client = Client::new(&args.primary)?;
    let store = FileStore::new(&args.state_dir)?;
    store.ensure_new_creation()?;
    let policy = wire::blob(&client.get("/v1/policy")?, "policy")?;
    PartPolicy::ref_from_wire(&policy).context("invalid primary policy")?;
    let authorities = client.get("/v1/authorities")?;
    let seed = crate::commands::tee_seed_from_name(&args.name)?;
    let record = jzon::object! {
        version: 1, primary: args.primary.as_str(),
        policy: hex::encode(&policy), seed: hex::encode(seed),
        pota: authorities["pota"].clone(), sata: authorities["sata"].clone(),
    };
    let mut env = PeerEnv::from_record(store, &record)?;
    display::write_peer_authorities(&mut std::io::stdout().lock(), &env.pota, &env.sata)?;
    println!("Opening and resetting destination partition...");
    let session = SealingSession::open_reset()?;
    env.manufacturer = device_cert_chain(&session.partition, 0)?;
    env.store.save_peer(&env.record())?;
    let domain = SecurityDomain::new(env);
    let env = domain.env();
    let mut pid_chain = Vec::new();
    let prepared = domain.prepare_peer(&session, &seed, |csr, report| {
        display::write_peer_enrollment(
            &mut std::io::stdout().lock(),
            &env.manufacturer,
            csr,
            report,
        )?;
        let response = env.certify(csr, report)?;
        pid_chain = wire::chain(&response, "pid")?;
        let pta_chain = wire::chain(&response, "pta")?;
        evidence::verify_peer(
            &Evidence {
                mfgr_cert_chain: env.manufacturer.clone(),
                owner_cert_chain: Vec::new(),
                part_owner_cert_chain: pid_chain.clone(),
                report: report.to_vec(),
            },
            env.policy(),
        )?;
        display::write_peer_enrollment_response(
            &mut std::io::stdout().lock(),
            &pta_chain,
            &pid_chain,
        )?;
        Ok(pta_chain)
    })?;
    env.store
        .save_prepared_peer(&prepared)
        .context("destination finalized; failed to persist prepared peer recovery material")?;
    let receiver = Evidence {
        mfgr_cert_chain: env.manufacturer.clone(),
        owner_cert_chain: Vec::new(),
        part_owner_cert_chain: pid_chain,
        report: prepared.receiver.report.clone(),
    };
    evidence::verify_peer(&receiver, env.policy())?;
    display::write_peer_evidence(&mut std::io::stdout().lock(), &receiver, "Receiver")?;
    let backup = wire::backup(&client.post("/v1/sd/clone", &wire::encode_evidence(&receiver))?)?;
    evidence::verify_peer(&backup.sender_evidence, env.policy())?;
    display::write_peer_evidence(
        &mut std::io::stdout().lock(),
        &backup.sender_evidence,
        "Sender",
    )?;
    domain.restore_peer(&session, &prepared, &backup)?;
    let keys = key_check::generate(&session.session)?;
    env.store.save_ecc_keys(&keys)?;
    println!(
        "Security domain cloned; local recovery saved in {}.",
        args.state_dir.display()
    );
    println!(
        "Local recovery requires the primary POTA issuer at {}.",
        args.primary
    );
    key_check::print_created(&mut std::io::stdout().lock())?;
    Ok(())
}

pub fn restore_local(args: &RestoreArgs, store: FileStore, record: &JsonValue) -> Result<()> {
    anyhow::ensure!(
        args.listen.is_none(),
        "a software-signer peer has no authority private keys to serve PTA requests"
    );
    let (partition, _) = load_local_recovery(&store)?;
    let keys = store.load_ecc_keys()?;
    let mut env = PeerEnv::from_record(store, record)?;
    anyhow::ensure!(
        partition.policy == env.policy.as_bytes(),
        "saved peer policy mismatch"
    );
    anyhow::ensure!(
        partition.pta_cert_chain.first() == Some(&env.pota),
        "saved peer POTA mismatch"
    );
    // Fail before reset if the issuer is offline or now serves another policy.
    let client = Client::new(&env.primary)?;
    anyhow::ensure!(
        wire::blob(&client.get("/v1/policy")?, "policy")? == partition.policy,
        "issuer policy changed"
    );
    if let Some(device) = &args.device {
        eprintln!("note: --device {device} ignored; using the first advertised partition");
    }
    let session = crate::commands::open_restore_session(args.reset, "local")?;
    env.manufacturer = device_cert_chain(&session.partition, 0)?;
    let domain = SecurityDomain::new(env);
    domain.restore_local(&session, &domain.env().seed, |csr, report| {
        wire::chain(&domain.env().certify(csr, report)?, "pta")
    })?;
    println!("Security domain restored from local backups.");
    crate::commands::finish_restore(&session, keys.as_deref(), &args.state_dir)
}
