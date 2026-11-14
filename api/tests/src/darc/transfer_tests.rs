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
use tsra_ddi_tbor_types::KEY_SCOPE_LOCAL;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::DarcReady;
use crate::utils::sd_provision::RAW_PUB_LEN;
use crate::utils::sd_provision::darc_sd_initialized_partition;
use crate::utils::sd_provision::darc_sd_initialized_session;
use crate::utils::sd_provision::make_chain;

/// A minted DARC key-exchange key: its masked blob (the HPKE identity the
/// device unmasks on import) and its public key as raw big-endian
/// `X ‖ Y` — the certificate-leaf format the cert chains carry.
struct KexKey {
    masked: [u8; MASKED_KEX_KEY_LEN],
    pub_raw: [u8; RAW_PUB_LEN],
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

fn run_darc_peer() {
    let target = multiprocess_darc_session();
    let recipient = mint_kex(&target);
    publish_peer(&target.partition.pid().expect("target PID"));
    publish_peer(&recipient.pub_raw);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let sealed = read_peer(&mut input);
    let report = read_peer(&mut input);
    let chain: Vec<Vec<u8>> = (0..3).map(|_| read_peer(&mut input)).collect();
    let chain: Vec<HsmCert<'_>> = chain.iter().map(|cert| HsmCert { cert }).collect();
    let wrapped = read_peer(&mut input);
    let imported = target
        .session
        .darc_tmk_import(&recipient.masked, &target.policy, &sealed, &report, &chain)
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
    let signature = HsmSigner::sign_vec(&mut HsmEccSignAlgo::default(), &recovered, &[0x55; 32])
        .expect("target signature");
    publish_peer(&signature);
}

/// Mint a `DarcKexKeyGen` key; its public key is already the raw
/// big-endian `X ‖ Y` a certificate leaf carries.
fn mint_kex(ready: &DarcReady) -> KexKey {
    let (masked, pub_raw) = ready
        .session
        .darc_kex_key_gen(KEY_SCOPE_LOCAL)
        .expect("darc_kex_key_gen");
    KexKey { masked, pub_raw }
}

/// Full DARC TMK transfer: create a TMK on the source, mint the
/// target recipient key, seal the TMK to the target
/// (DATA-anchored target chain), then re-open it on the target
/// (POTA-anchored PID chain) — the export→import hand-off that ships a
/// TMK from one endpoint to another.
#[test]
fn darc_transfer_tmk_export_import_roundtrip() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    // (1) Originate a TMK (masked under the SDMK).
    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    assert_eq!(masked_tmk.len(), MASKED_TMK_LEN);

    // (2) Mint the target recipient key.
    let target_kex = mint_kex(&ready);

    // (3) Seal the TMK to the target, anchoring the target chain to the
    // policy DATA CA.
    let target_chain = make_chain(&ready.data, &target_kex.pub_raw);
    let sealed_tmk = session
        .darc_tmk_export(&masked_tmk, &ready.policy, &target_chain.certs())
        .expect("darc_tmk_export");
    assert_eq!(sealed_tmk.sealed_tmk.len(), SEALED_TMK_LEN);
    assert!(
        sealed_tmk.sealed_tmk.iter().any(|&b| b != 0),
        "sealed TMK must not be all-zero",
    );

    // (4) Re-open the sealed TMK on the target: the target key is the
    // receiver, and the source PID signs the report (POTA-authorized).
    let source_chain: Vec<HsmCert<'_>> = ready
        .pid_chain
        .iter()
        .map(|cert| HsmCert { cert })
        .collect();
    let imported_tmk = session
        .darc_tmk_import(
            &target_kex.masked,
            &ready.policy,
            &sealed_tmk.sealed_tmk,
            &sealed_tmk.report,
            &source_chain,
        )
        .expect("darc_tmk_import");
    assert_eq!(imported_tmk.len(), MASKED_TMK_LEN);
    assert!(
        imported_tmk.iter().any(|&b| b != 0),
        "re-imported masked TMK must not be all-zero",
    );
}

/// Proves the recovered TMK is identical across genuinely distinct partitions
/// by unwrapping a transferred signing key and verifying its signature.
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
    let recipient: [u8; RAW_PUB_LEN] = peer.receive().try_into().expect("recipient public key");
    let chain = make_chain(&source.data, &recipient);
    let masked_tmk = source.session.darc_tmk_gen().expect("TMK");
    let transfer = source
        .session
        .darc_tmk_export(&masked_tmk, &source.policy, &chain.certs())
        .expect("export");
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
    let wrapped = HsmKeyManager::wrap_key(&mut HsmEccKeyDarcKeyWrapAlgo::new(), &source_tmk, &key)
        .expect("wrap");
    peer.send(&wrapped);
    let digest = [0x55; 32];
    let signature = peer.receive();
    assert!(
        HsmVerifier::verify(&mut HsmEccSignAlgo::default(), &public, &digest, &signature)
            .expect("verify source public key")
    );
}

/// The key-exchange and TMK generation primitives return well-formed,
/// non-zero envelopes of the pinned wire lengths, and each mint is fresh.
#[test]
fn darc_kex_and_tmk_gen_smoke() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    let (masked_kex, pub_kex) = session
        .darc_kex_key_gen(KEY_SCOPE_LOCAL)
        .expect("darc_kex_key_gen");
    assert_eq!(masked_kex.len(), MASKED_KEX_KEY_LEN);
    assert_eq!(pub_kex.len(), KEX_PUB_KEY_LEN);
    assert!(
        masked_kex.iter().any(|&b| b != 0),
        "masked KEX key must not be all-zero",
    );
    assert!(
        pub_kex.iter().any(|&b| b != 0),
        "KEX public key must not be all-zero",
    );

    // Each mint draws a fresh key, so two masked envelopes differ.
    let (masked_kex2, _) = session
        .darc_kex_key_gen(KEY_SCOPE_LOCAL)
        .expect("second darc_kex_key_gen");
    assert_ne!(
        masked_kex, masked_kex2,
        "each DarcKexKeyGen must mint a fresh key",
    );

    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    assert_eq!(masked_tmk.len(), MASKED_TMK_LEN);
    assert!(
        masked_tmk.iter().any(|&b| b != 0),
        "masked TMK must not be all-zero",
    );
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
    let tmk = HsmDarcTmk::new(session.clone(), masked_tmk);

    // Mint a P-256 signing key on the source to transfer under the TMK.
    let (source_key, source_pub) = HsmKeyManager::generate_key_pair(
        session,
        &mut HsmEccKeyGenAlgo {},
        p256_sign_priv_props(),
        p256_verify_pub_props(),
    )
    .expect("generate ECC signing key");

    // Wrap it under the TMK, then unwrap it back under the same TMK.
    let wrapped = HsmKeyManager::wrap_key(&mut HsmEccKeyDarcKeyWrapAlgo::new(), &tmk, &source_key)
        .expect("darc wrap_key");
    assert!(!wrapped.is_empty(), "wrapped key must not be empty");

    let (recovered_key, _recovered_pub) = HsmKeyManager::unwrap_key_pair(
        &mut HsmEccKeyDarcKeyUnwrapAlgo::new(),
        &tmk,
        &wrapped,
        p256_sign_priv_props(),
        p256_verify_pub_props(),
    )
    .expect("darc unwrap_key_pair");

    // Sign with the recovered key and verify against the original public key.
    let digest = [0x11u8; 32];
    let signature = HsmSigner::sign_vec(&mut HsmEccSignAlgo::default(), &recovered_key, &digest)
        .expect("sign with recovered key");
    let verified = HsmVerifier::verify(
        &mut HsmEccSignAlgo::default(),
        &source_pub,
        &digest,
        &signature,
    )
    .expect("verify signature");
    assert!(
        verified,
        "signature from the recovered key must verify against the original public key",
    );
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

/// A target certificate chain that does not chain up to the policy DATA
/// anchor is rejected: the on-device anchor check fails after the policy
/// hash verifies, surfacing as `InvalidArgument`.
#[test]
fn darc_tmk_export_rejects_unanchored_target_chain() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    let target_kex = mint_kex(&ready);

    // Anchor the target chain to an unrelated CA while the bound policy's
    // DATA anchor is unchanged, so the anchor check fails.
    let rogue_ca = CaKey::generate();
    let rogue_chain = make_chain(&rogue_ca, &target_kex.pub_raw);

    let result = session.darc_tmk_export(&masked_tmk, &ready.policy, &rogue_chain.certs());
    assert!(
        matches!(result, Err(HsmError::InvalidArgument)),
        "an unanchored target chain must be rejected with InvalidArgument, got {result:?}",
    );
}
