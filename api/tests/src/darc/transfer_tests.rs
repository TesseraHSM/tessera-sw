// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end DARC key-transfer flow over the public api surface.
//!
//! Drives source-to-target transfers, including independent simulator
//! instances, through [`HsmSession`]'s DARC methods: mint a Transfer
//! Masking Key (TMK), mint a recipient key, seal and PID-sign the
//! TMK to the target (`export`), and re-open it (`import`) — proving the
//! TMK survives the export→import round-trip. The key wrap/unwrap surface
//! is exercised as a full happy path — mint an ECC signing key, wrap it
//! under the TMK ([`HsmEccKeyDarcKeyWrapAlgo`]), unwrap it back
//! ([`HsmEccKeyDarcKeyUnwrapAlgo`]), then sign with the recovered key and
//! verify against the original public key.

use std::io::BufRead;
use std::io::Write;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

use tsra_api::*;
use tsra_crypto::EccPrivateKey;
use tsra_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use tsra_ddi_tbor_types::KEY_SCOPE_LOCAL;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::DarcReady;
use crate::utils::sd_provision::RAW_PUB_LEN;
use crate::utils::sd_provision::darc_sd_initialized_partition;
use crate::utils::sd_provision::darc_sd_initialized_session;
use crate::utils::sd_provision::hsm_certs;
use crate::utils::sd_provision::make_chain;
use crate::utils::sd_provision::masked_key_and_report;
use crate::utils::sd_provision::pid_chain_under;

/// Every supported DARC recipient KEM.
const ALL_KEMS: [HsmTransferKem; 3] = [
    HsmTransferKem::P384,
    HsmTransferKem::MlKem1024,
    HsmTransferKem::MlKem1024P384,
];

/// Pinned `(masked KEX key, KEX public key, sealed TMK)` lengths for `kem`.
fn kem_lens(kem: HsmTransferKem) -> (usize, usize, usize) {
    match kem {
        HsmTransferKem::P384 => (MASKED_KEX_KEY_LEN, KEX_PUB_KEY_LEN, SEALED_TMK_LEN),
        HsmTransferKem::MlKem1024 => (296, 1568, 1729),
        HsmTransferKem::MlKem1024P384 => (264, KEX_PUB_KEY_MAX_LEN, SEALED_TMK_MAX_LEN),
    }
}

/// A minted DARC key-exchange key: its masked blob (the HPKE identity the
/// device unmasks on import), its public key, and the partition PID's key
/// report attesting it (the exporter's recipient authentication).
struct KexKey {
    masked: Vec<u8>,
    public: Vec<u8>,
    report: Vec<u8>,
}

struct PeerServer {
    child: Child,
    messages: std::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl PeerServer {
    fn start() -> Self {
        let mut args = ddi_sock_server::TestArgs::from_env();
        args.sock = None;
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "darc::transfer_tests::darc_transfer_between_distinct_partitions",
                "--nocapture",
            ])
            .env("TSRA_DARC_PEER_SERVER", "1")
            .env(ddi_sock_server::TEST_ARGS_ENV, args.to_string())
            .env_remove(tsra_ddi::DDI_ARGS_ENV)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start independent simulator process");
        let stdout = child.stdout.take().expect("peer stdout");
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if let Some(message) = line.strip_prefix("TSRA_DARC_PEER=") {
                            let message = hex::decode(message)
                                .map_err(|error| format!("invalid peer message: {error}"));
                            if sender.send(message).is_err() {
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        if let Err(error) = sender.send(Err(format!("peer output: {error}"))) {
                            tracing::debug!(%error, "peer receiver closed");
                        }
                        return;
                    }
                }
            }
            if let Err(error) = sender.send(Err("peer output closed".into())) {
                tracing::debug!(%error, "peer receiver closed");
            }
        });
        Self {
            child,
            messages: receiver,
            reader: Some(reader),
        }
    }

    fn receive(&self) -> Vec<u8> {
        self.messages
            .recv_timeout(Duration::from_secs(30))
            .expect("peer response timed out")
            .expect("peer response failed")
    }

    fn send(&mut self, bytes: &[u8]) {
        writeln!(
            self.child.stdin.as_mut().expect("peer stdin"),
            "{}",
            hex::encode(bytes)
        )
        .expect("send peer message");
    }
}

impl Drop for PeerServer {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = self.child.kill() {
                    tracing::warn!(%error, "failed to stop peer simulator");
                }
            }
            Err(error) => tracing::warn!(%error, "failed to inspect peer simulator"),
        }
        if let Err(error) = self.child.wait() {
            tracing::warn!(%error, "failed to reap peer simulator");
        }
        if let Some(reader) = self.reader.take()
            && reader.join().is_err()
        {
            tracing::warn!("peer output reader panicked");
        }
    }
}

fn multiprocess_darc_session() -> DarcReady {
    // Public test-only CA scalars let isolated SDK processes share trust roots.
    let pota = std::sync::Arc::new(CaKey::from_private_key(
        EccPrivateKey::from_hsm_bytes(&[0x11; 48]).expect("test POTA"),
    ));
    let data = std::sync::Arc::new(CaKey::from_private_key(
        EccPrivateKey::from_hsm_bytes(&[0x22; 48]).expect("test DATA"),
    ));
    let (part, rev) = crate::utils::partition_ex_helpers::new_partition();
    darc_sd_initialized_partition(part, rev, pota, data)
}

fn publish_peer(bytes: &[u8]) {
    println!("\nTSRA_DARC_PEER={}", hex::encode(bytes));
    std::io::stdout().flush().expect("publish peer message");
}

fn read_peer(reader: &mut impl BufRead) -> Vec<u8> {
    let mut line = String::new();
    assert!(
        reader.read_line(&mut line).expect("read peer message") > 0,
        "peer input closed"
    );
    hex::decode(line.trim()).expect("peer message")
}

/// Target side of [`darc_transfer_between_distinct_partitions`]: for each
/// KEM, publish its DATA-anchored PID chain and a fresh KEX key report,
/// import the sealed TMK, unwrap the transferred key and sign with it.
fn run_darc_peer() {
    let target = multiprocess_darc_session();
    publish_peer(&target.partition.pid().expect("target PID"));
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    for kem in ALL_KEMS {
        let recipient = mint_kex(&target, kem);
        for cert in &target.target_chain {
            publish_peer(cert);
        }
        publish_peer(&recipient.report);
        let sealed = read_peer(&mut input);
        let report = read_peer(&mut input);
        let chain: Vec<Vec<u8>> = (0..3).map(|_| read_peer(&mut input)).collect();
        let wrapped = read_peer(&mut input);
        let imported = target
            .session
            .darc_tmk_import(
                &recipient.masked,
                &target.policy,
                &sealed,
                &report,
                &hsm_certs(&chain),
            )
            .expect("import on independent target");
        let tmk = HsmDarcTmk::new(target.session.clone(), imported);
        let (recovered, _) = HsmKeyManager::unwrap_key_pair(
            &mut HsmEccKeyDarcKeyUnwrapAlgo::new(),
            &tmk,
            &wrapped,
            p256_sign_priv_props(),
            p256_verify_pub_props(),
        )
        .expect("unwrap on independent target");
        let signature =
            HsmSigner::sign_vec(&mut HsmEccSignAlgo::default(), &recovered, &[0x55; 32])
                .expect("target signature");
        publish_peer(&signature);
    }
}

/// Mint a `DarcKexKeyGen` key of `kem` and attest it with the partition
/// PID's key report.
fn mint_kex(ready: &DarcReady, kem: HsmTransferKem) -> KexKey {
    let (masked, public) = ready
        .session
        .darc_kex_key_gen(KEY_SCOPE_LOCAL, kem)
        .expect("darc_kex_key_gen");
    let report = kex_report(&ready.session, &masked);
    KexKey {
        masked,
        public,
        report,
    }
}

/// `darc_kex_key_report` over `masked` (probe for the size, then fill).
fn kex_report(session: &HsmSession, masked: &[u8]) -> Vec<u8> {
    let report_data = vec![0xA5u8; KEY_REPORT_DATA_LEN];
    let max = session
        .darc_kex_key_report(masked, &report_data, None)
        .expect("key report size");
    let mut report = vec![0u8; max];
    let len = session
        .darc_kex_key_report(masked, &report_data, Some(&mut report))
        .expect("darc_kex_key_report");
    report.truncate(len);
    report
}

/// Seal `masked_tmk` to `kex` on `ready` using its DATA-anchored PID chain.
fn export_to(ready: &DarcReady, masked_tmk: &[u8], kex: &KexKey) -> HsmDarcTmkExportResult {
    ready
        .session
        .darc_tmk_export(
            masked_tmk,
            &ready.policy,
            &hsm_certs(&ready.target_chain),
            &kex.report,
        )
        .expect("darc_tmk_export")
}

/// Import `export` with `masked_kex` and the POTA-anchored source chain.
fn import_with(
    ready: &DarcReady,
    masked_kex: &[u8],
    export: &HsmDarcTmkExportResult,
) -> HsmResult<Vec<u8>> {
    ready.session.darc_tmk_import(
        masked_kex,
        &ready.policy,
        &export.sealed_tmk,
        &export.report,
        &hsm_certs(&ready.pid_chain),
    )
}

/// Prove two masked TMKs hold the same key: a signing key wrapped under
/// `source` unwraps under `imported` and its signature verifies.
fn assert_same_tmk(session: &HsmSession, source: Vec<u8>, imported: Vec<u8>) {
    let source = HsmDarcTmk::new(session.clone(), source);
    let imported = HsmDarcTmk::new(session.clone(), imported);
    let (key, public) = HsmKeyManager::generate_key_pair(
        session,
        &mut HsmEccKeyGenAlgo {},
        p256_sign_priv_props(),
        p256_verify_pub_props(),
    )
    .expect("generate ECC signing key");
    let wrapped = HsmKeyManager::wrap_key(&mut HsmEccKeyDarcKeyWrapAlgo::new(), &source, &key)
        .expect("wrap under source TMK");
    let (recovered, _) = HsmKeyManager::unwrap_key_pair(
        &mut HsmEccKeyDarcKeyUnwrapAlgo::new(),
        &imported,
        &wrapped,
        p256_sign_priv_props(),
        p256_verify_pub_props(),
    )
    .expect("unwrap under imported TMK");
    let digest = [0x33u8; 32];
    let signature = HsmSigner::sign_vec(&mut HsmEccSignAlgo::default(), &recovered, &digest)
        .expect("sign with recovered key");
    assert!(
        HsmVerifier::verify(&mut HsmEccSignAlgo::default(), &public, &digest, &signature)
            .expect("verify"),
        "imported TMK must equal the exported TMK",
    );
}

/// Full DARC TMK transfer for every KEM: create a TMK, mint and attest the
/// target recipient key, seal the TMK to it (DATA-anchored target PID
/// chain + KEX key report), then re-open it (POTA-anchored source PID
/// chain) and prove the recovered TMK is the original.
#[test]
fn darc_transfer_tmk_export_import_roundtrip() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    for kem in ALL_KEMS {
        let (_, _, sealed_len) = kem_lens(kem);
        let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
        assert_eq!(masked_tmk.len(), MASKED_TMK_LEN);
        let target_kex = mint_kex(&ready, kem);

        let export = export_to(&ready, &masked_tmk, &target_kex);
        assert_eq!(export.sealed_tmk.len(), sealed_len, "{kem:?} sealed TMK");
        assert!(!export.report.is_empty(), "{kem:?} report");
        assert!(export.report.len() <= DARC_REPORT_MAX_LEN);

        let imported = import_with(&ready, &target_kex.masked, &export)
            .unwrap_or_else(|error| panic!("{kem:?} darc_tmk_import: {error:?}"));
        assert_eq!(imported.len(), MASKED_TMK_LEN);
        assert_same_tmk(session, masked_tmk, imported);
    }
}

/// Each export draws fresh HPKE randomness: sealing the same TMK to the
/// same recipient twice yields distinct envelopes and reports, both of
/// which import.
#[test]
fn darc_tmk_export_is_freshly_sealed() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();

    for kem in ALL_KEMS {
        let masked_tmk = ready.session.darc_tmk_gen().expect("darc_tmk_gen");
        let kex = mint_kex(&ready, kem);
        let first = export_to(&ready, &masked_tmk, &kex);
        let second = export_to(&ready, &masked_tmk, &kex);
        assert_ne!(first.sealed_tmk, second.sealed_tmk, "{kem:?} sealed TMK");
        assert_ne!(first.report, second.report, "{kem:?} report");
        import_with(&ready, &kex.masked, &first).expect("import first export");
        import_with(&ready, &kex.masked, &second).expect("import second export");
    }
}

/// Proves the recovered TMK is identical across genuinely distinct partitions
/// by unwrapping a transferred signing key and verifying its signature, for
/// every KEM.
#[test]
fn darc_transfer_between_distinct_partitions() {
    if std::env::var_os("TSRA_DARC_PEER_SERVER").is_some() {
        run_darc_peer();
        return;
    }
    if !tsra_ddi::sock_selected() || !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let source = multiprocess_darc_session();
    let mut peer = PeerServer::start();
    assert_ne!(source.partition.pid().expect("source PID"), peer.receive());

    for kem in ALL_KEMS {
        let target_chain: Vec<Vec<u8>> = (0..3).map(|_| peer.receive()).collect();
        let target_report = peer.receive();
        let masked_tmk = source.session.darc_tmk_gen().expect("TMK");
        let transfer = source
            .session
            .darc_tmk_export(
                &masked_tmk,
                &source.policy,
                &hsm_certs(&target_chain),
                &target_report,
            )
            .unwrap_or_else(|error| panic!("{kem:?} export: {error:?}"));
        assert_eq!(transfer.sealed_tmk.len(), kem_lens(kem).2);
        peer.send(&transfer.sealed_tmk);
        peer.send(&transfer.report);
        for cert in &source.pid_chain {
            peer.send(cert);
        }

        let source_tmk = HsmDarcTmk::new(source.session.clone(), masked_tmk);
        let (key, public) = HsmKeyManager::generate_key_pair(
            &source.session,
            &mut HsmEccKeyGenAlgo {},
            p256_sign_priv_props(),
            p256_verify_pub_props(),
        )
        .expect("source signing key");
        let wrapped =
            HsmKeyManager::wrap_key(&mut HsmEccKeyDarcKeyWrapAlgo::new(), &source_tmk, &key)
                .expect("wrap");
        peer.send(&wrapped);
        let digest = [0x55; 32];
        let signature = peer.receive();
        assert!(
            HsmVerifier::verify(&mut HsmEccSignAlgo::default(), &public, &digest, &signature)
                .expect("verify source public key"),
            "{kem:?} transferred key must verify",
        );
    }
}

/// The key-exchange and TMK generation primitives return well-formed,
/// non-zero envelopes of the pinned wire lengths for every KEM, and each
/// mint is fresh.
#[test]
fn darc_kex_and_tmk_gen_smoke() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    for kem in ALL_KEMS {
        let (masked_len, pub_len, _) = kem_lens(kem);
        let (masked_kex, pub_kex) = session
            .darc_kex_key_gen(KEY_SCOPE_LOCAL, kem)
            .expect("darc_kex_key_gen");
        assert_eq!(masked_kex.len(), masked_len, "{kem:?} masked KEX key");
        assert_eq!(pub_kex.len(), pub_len, "{kem:?} KEX public key");
        assert!(masked_kex.len() <= MASKED_KEX_KEY_MAX_LEN);
        assert!(masked_kex.iter().any(|&b| b != 0));
        assert!(pub_kex.iter().any(|&b| b != 0));

        // Each mint draws a fresh key.
        let (masked_kex2, pub_kex2) = session
            .darc_kex_key_gen(KEY_SCOPE_LOCAL, kem)
            .expect("second darc_kex_key_gen");
        assert_ne!(masked_kex, masked_kex2, "{kem:?} masked KEX key reuse");
        assert_ne!(pub_kex, pub_kex2, "{kem:?} KEX public key reuse");
    }

    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    assert_eq!(masked_tmk.len(), MASKED_TMK_LEN);
    assert!(masked_tmk.iter().any(|&b| b != 0));
}

/// `darc_kex_key_report` follows the probe/fill convention and rejects
/// malformed inputs host-side.
#[test]
fn darc_kex_key_report_shape() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;
    let (masked, _) = session
        .darc_kex_key_gen(KEY_SCOPE_LOCAL, HsmTransferKem::MlKem1024P384)
        .expect("darc_kex_key_gen");
    let report_data = vec![0u8; KEY_REPORT_DATA_LEN];

    let max = session
        .darc_kex_key_report(&masked, &report_data, None)
        .expect("probe");
    let report = kex_report(session, &masked);
    assert!(!report.is_empty() && report.len() <= max);

    let mut short = vec![0u8; 1];
    assert!(matches!(
        session.darc_kex_key_report(&masked, &report_data, Some(&mut short)),
        Err(HsmError::BufferTooSmall)
    ));
    let mut out = vec![0u8; max];
    assert!(matches!(
        session.darc_kex_key_report(&masked, &report_data[1..], Some(&mut out)),
        Err(HsmError::InvalidArgument)
    ));
    assert!(matches!(
        session.darc_kex_key_report(&[], &report_data, Some(&mut out)),
        Err(HsmError::InvalidArgument)
    ));
}

/// The public wrap/unwrap surface performs a full DARC key transfer: an
/// ECC signing key wrapped under a TMK unwraps to a usable key on the same
/// partition (acting as both endpoints), and a signature from the recovered
/// key verifies against the original public key.
#[test]
fn darc_key_wrap_unwrap_sign_round_trip() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    assert_same_tmk(session, masked_tmk.clone(), masked_tmk);
}

/// A bogus wrapped envelope fails the AES-KWP integrity check under a
/// (valid) TMK, proving the api marshals the payload through to the
/// on-device crypto rather than accepting it blindly.
#[test]
fn darc_key_unwrap_rejects_bogus_envelope() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    let tmk = HsmDarcTmk::new(session.clone(), masked_tmk);

    let bogus_wrapped = vec![0u8; 40];
    let unwrap = HsmKeyManager::unwrap_key_pair(
        &mut HsmEccKeyDarcKeyUnwrapAlgo::new(),
        &tmk,
        &bogus_wrapped,
        p256_sign_priv_props(),
        p256_verify_pub_props(),
    );
    assert!(
        unwrap.is_err(),
        "unwrapping a bogus envelope must be rejected",
    );
}

/// P-256 signing private-key properties.
fn p256_sign_priv_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("build P-256 signing private props")
}

/// P-256 verifying public-key properties.
fn p256_verify_pub_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("build P-256 verifying public props")
}

/// Target chains that do not authenticate the report signer under the
/// policy DATA anchor are rejected: a foreign-CA anchor, the
/// POTA-anchored PID chain, and the retired DATA -> KEX-key leaf model.
#[test]
fn darc_tmk_export_rejects_unanchored_target_chain() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    let kex = mint_kex(&ready, HsmTransferKem::P384);
    let pid_cert = ready.target_chain.last().expect("PID cert");

    let rogue_ca = CaKey::generate();
    let rogue_chain = pid_chain_under(&rogue_ca, &ready.pta_pub, pid_cert);
    let kex_pub: [u8; RAW_PUB_LEN] = kex.public.as_slice().try_into().expect("P-384 KEX pub");
    let kex_leaf_chain = make_chain(&ready.data, &kex_pub);
    let kex_leaf_chain: Vec<Vec<u8>> = kex_leaf_chain
        .certs()
        .iter()
        .map(|cert| cert.cert.to_vec())
        .collect();

    for (name, chain) in [
        ("foreign CA", &rogue_chain),
        ("POTA-anchored", &ready.pid_chain),
        ("KEX-key leaf", &kex_leaf_chain),
    ] {
        let result =
            session.darc_tmk_export(&masked_tmk, &ready.policy, &hsm_certs(chain), &kex.report);
        assert!(
            matches!(result, Err(HsmError::InvalidArgument)),
            "{name} target chain must be rejected with InvalidArgument, got {result:?}",
        );
    }
}

/// Only a PID-signed report over a generated DARC KEX key authenticates the
/// recipient: reports over an SD sealing key (from either report entry
/// point), a tampered report, and a missing report are rejected.
#[test]
fn darc_tmk_export_rejects_non_darc_key_report() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;
    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");

    let (sealing_masked, _, sealing_report) = masked_key_and_report(session);
    let sealing_via_darc = kex_report(session, &sealing_masked);
    let mut tampered = mint_kex(&ready, HsmTransferKem::MlKem1024).report;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    for (name, report) in [
        ("SD sealing key report", sealing_report.as_slice()),
        ("darc_kex_key_report over SD sealing key", &sealing_via_darc),
        ("tampered report", &tampered),
        ("empty report", &[]),
    ] {
        let result = session.darc_tmk_export(
            &masked_tmk,
            &ready.policy,
            &hsm_certs(&ready.target_chain),
            report,
        );
        assert!(result.is_err(), "{name} must be rejected, got {result:?}");
    }
}

/// Import rejects a tampered envelope or report, the wrong recipient key
/// (same or different KEM), and a source chain not anchored at POTA.
#[test]
fn darc_tmk_import_rejects_tampering_and_wrong_key() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    for kem in ALL_KEMS {
        let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
        let kex = mint_kex(&ready, kem);
        let export = export_to(&ready, &masked_tmk, &kex);

        let mut bad_sealed = export.clone();
        let mid = bad_sealed.sealed_tmk.len() / 2;
        bad_sealed.sealed_tmk[mid] ^= 0x01;
        let mut bad_tag = export.clone();
        let last = bad_tag.sealed_tmk.len() - 1;
        bad_tag.sealed_tmk[last] ^= 0x80;
        let mut bad_report = export.clone();
        let last = bad_report.report.len() - 1;
        bad_report.report[last] ^= 0x01;

        for (name, candidate) in [
            ("tampered sealed TMK", &bad_sealed),
            ("tampered sealed TMK tag", &bad_tag),
            ("tampered report", &bad_report),
        ] {
            let result = import_with(&ready, &kex.masked, candidate);
            assert!(result.is_err(), "{kem:?} {name} must fail, got {result:?}");
        }

        let other = mint_kex(&ready, kem);
        let result = import_with(&ready, &other.masked, &export);
        assert!(result.is_err(), "{kem:?} wrong KEX key must fail");

        for other_kem in ALL_KEMS.into_iter().filter(|&k| k != kem) {
            let other = mint_kex(&ready, other_kem);
            let result = import_with(&ready, &other.masked, &export);
            assert!(
                result.is_err(),
                "{kem:?} export opened with a {other_kem:?} key must fail",
            );
        }

        let result = session.darc_tmk_import(
            &kex.masked,
            &ready.policy,
            &export.sealed_tmk,
            &export.report,
            &hsm_certs(&ready.target_chain),
        );
        assert!(
            result.is_err(),
            "{kem:?} DATA-anchored source chain must fail"
        );

        import_with(&ready, &kex.masked, &export).expect("untampered import still succeeds");
    }
}

/// Malformed lengths are rejected host-side with `InvalidArgument`.
#[test]
fn darc_tmk_export_import_reject_invalid_lengths() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;
    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    let kex = mint_kex(&ready, HsmTransferKem::P384);
    let export = export_to(&ready, &masked_tmk, &kex);
    let target = hsm_certs(&ready.target_chain);
    let source = hsm_certs(&ready.pid_chain);
    let oversized_report = vec![0u8; DARC_REPORT_MAX_LEN + 1];
    let mut four_certs = target.clone();
    four_certs.push(target[2]);

    let export_cases: [(&str, HsmResult<HsmDarcTmkExportResult>); 5] = [
        (
            "short masked TMK",
            session.darc_tmk_export(&masked_tmk[1..], &ready.policy, &target, &kex.report),
        ),
        (
            "oversized key report",
            session.darc_tmk_export(&masked_tmk, &ready.policy, &target, &oversized_report),
        ),
        (
            "empty chain",
            session.darc_tmk_export(&masked_tmk, &ready.policy, &[], &kex.report),
        ),
        (
            "four-cert chain",
            session.darc_tmk_export(&masked_tmk, &ready.policy, &four_certs, &kex.report),
        ),
        (
            "empty policy",
            session.darc_tmk_export(&masked_tmk, &[], &target, &kex.report),
        ),
    ];
    for (name, result) in export_cases {
        assert!(
            matches!(result, Err(HsmError::InvalidArgument)),
            "export {name}: {result:?}",
        );
    }

    let mut long_sealed = export.sealed_tmk.clone();
    long_sealed.push(0);
    let import_cases: [(&str, HsmResult<Vec<u8>>); 5] = [
        (
            "short masked KEX key",
            session.darc_tmk_import(
                &kex.masked[1..],
                &ready.policy,
                &export.sealed_tmk,
                &export.report,
                &source,
            ),
        ),
        (
            "short sealed TMK",
            session.darc_tmk_import(
                &kex.masked,
                &ready.policy,
                &export.sealed_tmk[1..],
                &export.report,
                &source,
            ),
        ),
        (
            "long sealed TMK",
            session.darc_tmk_import(
                &kex.masked,
                &ready.policy,
                &long_sealed,
                &export.report,
                &source,
            ),
        ),
        (
            "oversized report",
            session.darc_tmk_import(
                &kex.masked,
                &ready.policy,
                &export.sealed_tmk,
                &oversized_report,
                &source,
            ),
        ),
        (
            "four-cert chain",
            session.darc_tmk_import(
                &kex.masked,
                &ready.policy,
                &export.sealed_tmk,
                &export.report,
                &four_certs,
            ),
        ),
    ];
    for (name, result) in import_cases {
        assert!(
            matches!(result, Err(HsmError::InvalidArgument)),
            "import {name}: {result:?}",
        );
    }
}
