// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `DarcTmkImport` command.
//!
//! `DarcTmkImport` imports a DARC Transfer Masking Key (TMK) that was
//! HPKE Base sealed to a `DarcKexKeyGen` recipient and re-masks it under
//! the SDMK. A POTA-endorsed PID operation report authenticates the exact
//! encrypted envelope and recipient before HPKE opening.
//!
//! The **round-trip** test mirrors the real flow end to end: it finalizes
//! a partition and initializes its security domain (`SdCreateRemoteBackup`,
//! which provisions the SDMK), mints a DARC key-exchange key
//! (`DarcKexKeyGen`), then — entirely on the host with `tsra_crypto` —
//! seals a TMK and independently builds a directly signed envelope
//! fixture under a synthetic POTA-authorized PID, then imports it.
//!
//! Coverage:
//! * Round-trip — the imported TMK comes back as a non-zero 264-byte
//!   masked envelope.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).
//! * Wrong masked-key kind (an `SdSealing` key) → `UnsupportedKeyType`.
//! * Tampered envelope/report or substituted recipient -> `InvalidArg`.
//! * A generic public-key report cannot replace an operation report.
//! * `policy` hash mismatch → `InvalidArg`.
//! * Sender chain not anchored to the policy POTA → `InvalidArg`.

use tsra_crypto::seal_vec;
use tsra_crypto::EccCurve;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EccPublicKey;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_crypto::HpkeSealConfig;
use tsra_crypto::HpkeSuite;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::dev_rev_in_place;
use tsra_ddi_tbor_test_harness::x509_fixture::make_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::GeneratedChain;
use tsra_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::SessionSuite;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::CertDescriptor;
use tsra_ddi_tbor_types::TborDarcKexKeyGenReq;
use tsra_ddi_tbor_types::TborDarcTmkImportReq;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborSdSealingKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MASKED_KEX_KEY_LEN;
use tsra_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_ddi_tbor_types::SEALED_TMK_LEN;
use tsra_ddi_tbor_types::TMK_LEN;

use crate::commands::common::assert_masked_key_layout_rejected;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::perturb_policy_info;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_report_and_pub;

/// `KeyScope::Local` discriminant (wire mirror of the firmware
/// `HsmKeyScope`).
const SCOPE_LOCAL: u8 = 0b011;

/// P-384 coordinate length.
const COORD_LEN: usize = 48;

/// A partition whose security domain has been initialized, plus the exact
/// policy image the handler will re-verify.
pub(crate) struct SdReady {
    pub(crate) ctx: TestCtx,
    pub(crate) session: SessionHandshake,
    pub(crate) policy: Vec<u8>,
    /// Policy POTA CA (anchors the sender certificate chain).
    pub(crate) pota: CaKey,
}

/// Finalize a partition and initialize its security domain (via
/// `SdCreateRemoteBackup`, which provisions the SDMK) so `DarcTmkImport`
/// can mask its output under the SDMK.
pub(crate) fn sd_initialized_session() -> SdReady {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);
    let policy = backing_part_policy(
        &info.pid,
        &info.pid_pub_key,
        &sata.raw_pub(),
        &pota.raw_pub(),
    );

    let init = ctx.part_init(&session, &seed, &policy).expect("PartInit");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    // CreateSD provisions the SDMK and marks the partition SD-initialized.
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata, &report);
    let create_req = backup_request(session.session_id, &evidence, &policy);
    ctx.tbor_oob(&create_req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    SdReady {
        ctx,
        session,
        policy,
        pota,
    }
}

/// Import the device's `x ‖ y` key-exchange public key (device byte order)
/// as a host [`EccPublicKey`] (`from_hsm_bytes` parses big-endian
/// coordinates).
fn kex_pub_to_host(pub_le: &[u8]) -> EccPublicKey {
    let mut be = pub_le.to_vec();
    dev_rev_in_place(&mut be[..COORD_LEN]);
    dev_rev_in_place(&mut be[COORD_LEN..]);
    EccPublicKey::from_hsm_bytes(&be).expect("import kex public key")
}

fn sha384(bytes: &[u8]) -> [u8; 48] {
    let mut digest = [0; 48];
    HashAlgo::sha384()
        .hash(bytes, Some(&mut digest))
        .expect("SHA384");
    digest
}

fn key_id(key: &impl EccKeyOp) -> [u8; 48] {
    let (x, y) = key.coord_vec().expect("coordinates");
    let public = EccPublicKey::from_coordinates(EccCurve::P384, &x, &y).expect("public key");
    sha384(&public.to_vec().expect("canonical DER SPKI"))
}

/// Independent host-side HPKE Base and directly signed envelope fixture.
fn seal_tmk(pk_r: &EccPublicKey, sk_s: &EccPrivateKey, tmk: &[u8]) -> [u8; SEALED_TMK_LEN] {
    let source_id = key_id(sk_s);
    let recipient_id = key_id(pk_r);
    let mut header = b"TSRA-XFER".to_vec();
    header.extend_from_slice(&[1, 1, 0, 0x11, 0, 2, 0, 2]);
    header.extend_from_slice(&source_id);
    header.extend_from_slice(&recipient_id);
    let cfg = HpkeSealConfig::base(HpkeSuite::DHKemP384Sha384AesGcm256, pk_r, &header, &[]);
    let sealed = seal_vec(&cfg, tmk).expect("HPKE Base seal");
    let (ex, ey) = sealed.enc.coord_vec().expect("enc coordinates");
    let mut payload = header;
    payload.push(4);
    payload.extend_from_slice(&ex);
    payload.extend_from_slice(&ey);
    payload.extend_from_slice(&sealed.ct);
    crate::commands::common::sign_transfer_envelope(&payload, sk_s)
        .try_into()
        .expect("signed TMK length")
}

/// A valid authenticated TMK import succeeds and produces fresh masked envelopes.
#[test]
fn darc_tmk_import_roundtrip() {
    let ready = sd_initialized_session();
    let ctx = &ready.ctx;

    // A fully valid import anchored to the policy POTA.
    let (req, chain) = build_valid_import(&ready, &ready.pota, &[0x5Au8; TMK_LEN]);
    let der = chain.der_items();
    let resp = ctx.tbor_oob(&req, &der).expect("DarcTmkImport roundtrip");

    // The imported TMK comes back as a full, non-zero masked envelope.
    assert_eq!(resp.masked_tmk.len(), MASKED_TMK_LEN);
    assert!(
        resp.masked_tmk.iter().any(|&b| b != 0),
        "masked_tmk must not be all-zero",
    );

    // A second import of the same inputs yields a distinct envelope (fresh
    // masking IV) — the command is deterministic in effect but not output.
    let resp2 = ctx.tbor_oob(&req, &der).expect("second DarcTmkImport");
    assert_ne!(
        resp.masked_tmk, resp2.masked_tmk,
        "each import must yield a fresh masked envelope",
    );
}

/// Build a fully valid `DarcTmkImport` request against `ready`, anchoring
/// the sender certificate chain to `anchor_ca`.  Mints a receiver DARC
/// key-exchange key (`DarcKexKeyGen`) and — entirely on the host — mints a
/// synthetic PID key, certifies it under `anchor_ca`, HPKE Base seals
/// `tmk`, and signs an operation-report fixture over that envelope.
///
/// Returns the request together with the owning [`GeneratedChain`] (its
/// DER must outlive the request and be passed out of band via
/// [`GeneratedChain::der_items`]).  Pass `&ready.pota` for the happy path;
/// pass a foreign CA to exercise the unanchored-chain rejection.
pub(crate) fn build_valid_import(
    ready: &SdReady,
    anchor_ca: &CaKey,
    tmk: &[u8; TMK_LEN],
) -> (TborDarcTmkImportReq, GeneratedChain) {
    let ctx = &ready.ctx;

    // Receiver: mint a DARC key-exchange key; keep its masked blob (the
    // handler unmasks it to `RcvrPriv`) and public key (the HPKE recipient).
    let kex = ctx
        .tbor(&TborDarcKexKeyGenReq {
            session_id: ready.session.session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("DarcKexKeyGen");
    let pk_r = kex_pub_to_host(&kex.pub_key);

    // Sender: a fresh P-384 key whose leaf certificate is anchored to
    // `anchor_ca`.  `make_chain(ca, leaf_raw)` builds root(ca) → leaf, so
    // the (non-leaf) root's public key equals the anchor and the leaf
    // carries the synthetic PID report-signing key the handler authorizes.
    let sk_s = EccPrivateKey::from_curve(EccCurve::P384).expect("sender key");
    let (sx, sy) = sk_s.coord_vec().expect("sender coords");
    let mut sender_raw = [0u8; RAW_PUB_LEN];
    sender_raw[..COORD_LEN].copy_from_slice(&sx);
    sender_raw[COORD_LEN..].copy_from_slice(&sy);
    let chain = make_chain(anchor_ca, &sender_raw);
    let der = chain.der_items();

    let sealed_tmk = seal_tmk(&pk_r, &sk_s, tmk);
    let masked_kex_key: [u8; MASKED_KEX_KEY_LEN] = kex
        .masked_key
        .as_slice()
        .try_into()
        .expect("masked kex key length");
    let remote_cert_chain = vec![
        CertDescriptor {
            index: 0,
            length: (der[0].len() as u16).into(),
        },
        CertDescriptor {
            index: 1,
            length: (der[1].len() as u16).into(),
        },
    ];

    let req = TborDarcTmkImportReq {
        session_id: ready.session.session_id,
        masked_kex_key,
        policy: ready.policy.clone(),
        sealed_tmk,
        remote_cert_chain,
    };
    (req, chain)
}

/// A masked key of the wrong kind is rejected with `UnsupportedKeyType`.
///
/// The substitute is an `SdSealing` key minted at the same `Local` scope,
/// so it routes to — and unmasks successfully under — the same masking
/// key: the handler's `key_kind == DarcKex` gate is what rejects it, not
/// an unmask (AEAD) failure.
#[test]
fn darc_tmk_import_rejects_wrong_key_kind() {
    let ready = sd_initialized_session();
    let ctx = &ready.ctx;
    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5Au8; TMK_LEN]);

    let seal = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id: ready.session.session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("SdSealingKeyGen");
    req.masked_kex_key = seal
        .masked_key
        .as_slice()
        .try_into()
        .expect("masked sealing key length");

    ctx.expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::UnsupportedKeyType);
}

/// A flipped ciphertext byte fails the signed envelope digest before opening.
#[test]
fn darc_tmk_import_rejects_tampered_sealed_tmk() {
    let ready = sd_initialized_session();
    let ctx = &ready.ctx;
    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5Au8; TMK_LEN]);

    // Flip a byte in the ciphertext region (past the 97-byte `enc`).
    req.sealed_tmk[SEALED_TMK_LEN - 1] ^= 0xFF;

    ctx.expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_import_rejects_report_and_recipient_substitution() {
    let ready = sd_initialized_session();
    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);
    let last = req.sealed_tmk.len() - 1;
    req.sealed_tmk[last] ^= 1;
    ready
        .ctx
        .expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
    req.sealed_tmk[last] ^= 1;
    let other = ready
        .ctx
        .tbor(&TborDarcKexKeyGenReq {
            session_id: ready.session.session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("other recipient");
    req.masked_kex_key = other
        .masked_key
        .as_slice()
        .try_into()
        .expect("recipient key");
    ready
        .ctx
        .expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_import_rejects_public_key_report_bytes_and_zero_envelope() {
    let ready = sd_initialized_session();
    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);
    let (_, public_key_report, _) = masked_key_report_and_pub(&ready.ctx, ready.session.session_id);
    let prefix = public_key_report
        .get(..SEALED_TMK_LEN)
        .expect("public-key reports cannot fit the fixed transfer field");
    req.sealed_tmk.copy_from_slice(prefix);
    ready
        .ctx
        .expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
    req.sealed_tmk.fill(0);
    ready
        .ctx
        .expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
}

/// A `policy` whose SHA-384 digest does not match the partition's bound
/// `policy_hash` is rejected with `InvalidArg`, before the POTA anchor it
/// carries is ever trusted.
#[test]
fn darc_tmk_import_rejects_policy_hash_mismatch() {
    let ready = sd_initialized_session();
    let ctx = &ready.ctx;
    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5Au8; TMK_LEN]);

    // Perturb an opaque, POTA-independent field so only the hash changes
    // (the anchor stays valid, isolating the hash gate).
    req.policy = perturb_policy_info(&req.policy);

    ctx.expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
}

/// A sender certificate chain that does not chain up to the policy POTA is
/// rejected with `InvalidArg`.  The chain here is anchored to an unrelated
/// CA while the policy (and thus the on-device anchor) is unchanged, so
/// `verify_policy_hash` passes and validation fails at the anchor check.
#[test]
fn darc_tmk_import_rejects_unanchored_cert_chain() {
    let ready = sd_initialized_session();
    let ctx = &ready.ctx;

    let rogue_ca = CaKey::generate();
    let (req, chain) = build_valid_import(&ready, &rogue_ca, &[0x5Au8; TMK_LEN]);

    ctx.expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
}

/// A dummy well-formed request whose crypto inputs never get exercised —
/// used by gating tests that must fail at the session/lifecycle gate
/// before any evidence or crypto work.
fn dummy_req(session_id: u16) -> TborDarcTmkImportReq {
    TborDarcTmkImportReq {
        session_id,
        masked_kex_key: [0u8; MASKED_KEX_KEY_LEN],
        policy: Vec::new(),
        sealed_tmk: [0u8; SEALED_TMK_LEN],
        // A single (unused) descriptor so the request decodes past the FW
        // fixed-length check — these tests fail at the session/lifecycle
        // gate, which runs after decode but before any chain/crypto work.
        remote_cert_chain: vec![CertDescriptor {
            index: 0,
            length: 1u16.into(),
        }],
    }
}

/// Import is rejected before the partition is finalized.
#[test]
fn darc_tmk_import_rejects_before_finalize() {
    // A rotated CO session but no PartInit/PartFinal → the partition is
    // not Initialized, so the command is rejected at the lifecycle gate
    // before any crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

/// Crypto-User sessions cannot import a DARC TMK.
#[test]
fn darc_tmk_import_rejected_on_cu_session() {
    // DarcTmkImport is Crypto-Officer-only: the handler's role gate
    // (checked before the state/crypto gates) rejects a CU session.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    ctx.expect_fw_reject(
        &dummy_req(session.session_id),
        TborStatus::InvalidPermissions,
    );
}

/// A default-PSK CO session cannot import a DARC TMK.
#[test]
fn darc_tmk_import_rejected_on_default_psk() {
    // A CO session on the still-default PSK is rejected by the
    // dispatcher's default-PSK gate before the handler runs.
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("open_session must succeed");
    let mut req = dummy_req(session.session_id());
    req.session_id = session.session_id();
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}

/// Rejects a misaligned masked key-exchange key and one without its
/// padding entry; the decoder rejects before the OOB chain is read.
#[test]
fn darc_tmk_import_rejects_bad_masked_key_layout() {
    let ready = sd_initialized_session();
    let (req, _chain) = build_valid_import(&ready, &ready.pota, &[0x5Au8; TMK_LEN]);
    assert_masked_key_layout_rejected(&ready.ctx, &req);
}

/// A finalized partition without an initialized security domain cannot
/// import a TMK because the SDMK required for output masking is absent.
#[test]
fn darc_tmk_import_rejects_before_sd_init() {
    let ctx = TestCtx::new();
    let session = crate::commands::sd_sealing_key_gen::finalized_co_session(&ctx);

    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

/// An unallocated session identifier must not authorize the import.
/// Do not treat session ID zero as invalid: valid CO sessions may use zero.
#[test]
fn darc_tmk_import_rejects_max_session_id() {
    let ready = sd_initialized_session();

    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);

    req.session_id = u16::MAX;

    assert!(
        ready.ctx.tbor_oob(&req, &chain.der_items()).is_err(),
        "unallocated session ID must be rejected",
    );
}

/// Altering the authenticated masked KEX envelope must prevent the
/// receiver private key from being recovered.
#[test]
fn darc_tmk_import_rejects_corrupted_masked_kex_key() {
    let ready = sd_initialized_session();

    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);

    let last = req.masked_kex_key.len() - 1;
    req.masked_kex_key[last] ^= 0x80;

    assert!(
        ready.ctx.tbor_oob(&req, &chain.der_items()).is_err(),
        "corrupted masked KEX key must be rejected",
    );
}

/// A zero-filled buffer is not a valid masked DARC KEX key.
#[test]
fn darc_tmk_import_rejects_zeroed_masked_kex_key() {
    let ready = sd_initialized_session();

    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);

    req.masked_kex_key.fill(0);

    assert!(
        ready.ctx.tbor_oob(&req, &chain.der_items()).is_err(),
        "zeroed masked KEX key must be rejected",
    );
}

/// Tampering with the encapsulated HPKE public key must not allow an
/// unauthenticated TMK to be imported.
#[test]
fn darc_tmk_import_rejects_tampered_hpke_encapsulation() {
    let ready = sd_initialized_session();

    let (req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);

    for offset in [0usize, 1, COORD_LEN, 2 * COORD_LEN] {
        let mut bad = req.clone();
        bad.sealed_tmk[offset] ^= 0x01;

        assert!(
            ready.ctx.tbor_oob(&bad, &chain.der_items()).is_err(),
            "tampered encapsulation at offset {offset} must fail",
        );
    }
}

/// A sealed TMK is cryptographically bound to the receiver key.
/// Replacing the masked receiver key with another valid DARC KEX key
/// must make HPKE opening fail.
#[test]
fn darc_tmk_import_rejects_different_receiver_key() {
    let ready = sd_initialized_session();

    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);

    let other = ready
        .ctx
        .tbor(&TborDarcKexKeyGenReq {
            session_id: ready.session.session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("generate another receiver KEX key");

    req.masked_kex_key = other
        .masked_key
        .as_slice()
        .try_into()
        .expect("masked KEX key length");

    assert!(
        ready.ctx.tbor_oob(&req, &chain.der_items()).is_err(),
        "TMK sealed to one receiver must fail with another receiver",
    );
}

/// Both sender chains are trusted by the same POTA, but only the
/// original sender's private key authenticated the HPKE seal.
/// A different trusted sender must not be able to import it.
#[test]
fn darc_tmk_import_rejects_sender_key_mismatch() {
    let ready = sd_initialized_session();

    let (req, _original_chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);

    let (_other_req, other_chain) = build_valid_import(&ready, &ready.pota, &[0xA5; TMK_LEN]);

    let other_der = other_chain.der_items();

    let mut bad = req.clone();
    for (descriptor, cert) in bad.remote_cert_chain.iter_mut().zip(other_der.iter()) {
        descriptor.length = (cert.len() as u16).into();
    }

    assert!(
        ready.ctx.tbor_oob(&bad, &other_der).is_err(),
        "a different trusted sender must not authenticate the seal",
    );
}

/// The import requires a sender certificate chain.
#[test]
fn darc_tmk_import_rejects_empty_cert_chain() {
    let ready = sd_initialized_session();

    let (mut req, _chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);

    req.remote_cert_chain.clear();

    assert!(
        ready.ctx.tbor_oob(&req, &[]).is_err(),
        "empty certificate chain must be rejected",
    );
}

/// A certificate descriptor must reference an actual OOB data block.
#[test]
fn darc_tmk_import_rejects_invalid_cert_index() {
    let ready = sd_initialized_session();

    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);

    req.remote_cert_chain[0].index = u8::MAX;

    assert!(
        ready.ctx.tbor_oob(&req, &chain.der_items()).is_err(),
        "out-of-range certificate index must be rejected",
    );
}

/// The claimed DER certificate length must agree with the actual OOB
/// certificate bytes.
#[test]
fn darc_tmk_import_rejects_cert_length_mismatch() {
    let ready = sd_initialized_session();

    let (req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);

    for cert_index in 0..req.remote_cert_chain.len() {
        let mut bad = req.clone();

        let original: u16 = bad.remote_cert_chain[cert_index].length.into();

        bad.remote_cert_chain[cert_index].length = original.saturating_sub(1).into();

        assert!(
            ready.ctx.tbor_oob(&bad, &chain.der_items()).is_err(),
            "certificate {cert_index} length mismatch must fail",
        );
    }
}

/// A failed authenticated import must not corrupt the session or
/// prevent a subsequent valid import.
#[test]
fn darc_tmk_import_recovers_after_failed_import() {
    let ready = sd_initialized_session();

    let (req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);

    let der = chain.der_items();

    let mut bad = req.clone();
    bad.sealed_tmk[SEALED_TMK_LEN - 1] ^= 0xFF;

    assert!(
        ready.ctx.tbor_oob(&bad, &der).is_err(),
        "tampered import must fail",
    );

    let recovered = ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("valid import must succeed after failed import");

    assert_eq!(recovered.masked_tmk.len(), MASKED_TMK_LEN);
    assert!(recovered.masked_tmk.iter().any(|&b| b != 0));
}

/// Verify that the import command accepts varied valid TMK values,
/// not just a single repeated-byte fixture.
#[test]
fn darc_tmk_import_accepts_multiple_tmk_patterns() {
    let ready = sd_initialized_session();

    let mut ascending = [0u8; TMK_LEN];
    for (index, byte) in ascending.iter_mut().enumerate() {
        *byte = index as u8;
    }

    let mut descending = [0u8; TMK_LEN];
    for (index, byte) in descending.iter_mut().enumerate() {
        *byte = (TMK_LEN - 1 - index) as u8;
    }

    let patterns = [
        [0x00u8; TMK_LEN],
        [0xFFu8; TMK_LEN],
        [0xAAu8; TMK_LEN],
        [0x55u8; TMK_LEN],
        ascending,
        descending,
    ];

    for (index, pattern) in patterns.iter().enumerate() {
        let (req, chain) = build_valid_import(&ready, &ready.pota, pattern);

        let resp = ready
            .ctx
            .tbor_oob(&req, &chain.der_items())
            .unwrap_or_else(|e| panic!("TMK pattern {index} import failed: {e:?}"));

        assert_eq!(resp.masked_tmk.len(), MASKED_TMK_LEN, "pattern {index}",);

        assert!(
            resp.masked_tmk.iter().any(|&b| b != 0),
            "pattern {index}: masked output must not be zero",
        );
    }
}

/// Missing OOB certificate material must reject an otherwise valid import.
#[test]
fn darc_tmk_import_rejects_missing_oob_certificate() {
    let ready = sd_initialized_session();
    let (req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);
    let der = chain.der_items();

    for missing_index in 0..der.len() {
        let mut incomplete = chain.der_items().to_vec();
        incomplete.remove(missing_index);
        assert!(
            ready.ctx.tbor_oob(&req, &incomplete).is_err(),
            "missing OOB certificate {missing_index} must be rejected",
        );
    }
}

/// Zero-length certificate descriptors must not authenticate a sender chain.
#[test]
fn darc_tmk_import_rejects_zero_length_cert_descriptors() {
    let ready = sd_initialized_session();
    let (req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);
    let der = chain.der_items();

    for index in 0..req.remote_cert_chain.len() {
        let mut bad = req.clone();
        bad.remote_cert_chain[index].length = 0u16.into();
        assert!(
            ready.ctx.tbor_oob(&bad, &der).is_err(),
            "zero-length certificate descriptor {index} must be rejected",
        );
    }
}

/// Oversized certificate descriptors must not read beyond their OOB payloads.
#[test]
fn darc_tmk_import_rejects_oversized_cert_descriptors() {
    let ready = sd_initialized_session();
    let (req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);
    let der = chain.der_items();

    for index in 0..req.remote_cert_chain.len() {
        let mut bad = req.clone();
        let original: u16 = bad.remote_cert_chain[index].length.into();
        bad.remote_cert_chain[index].length = original.checked_add(1).expect("DER size").into();
        assert!(
            ready.ctx.tbor_oob(&bad, &der).is_err(),
            "oversized certificate descriptor {index} must be rejected",
        );
    }
}

/// Corrupting either sender certificate must prevent authenticated import.
#[test]
fn darc_tmk_import_rejects_corrupted_certificate_der() {
    let ready = sd_initialized_session();
    let (req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);
    let der = chain.der_items();

    for index in 0..der.len() {
        let mut damaged: Vec<Vec<u8>> = der.iter().map(|cert| cert.to_vec()).collect();
        damaged[index][0] = 0; // Invalidate the outer DER SEQUENCE tag.
        let damaged_refs: Vec<&[u8]> = damaged.iter().map(Vec::as_slice).collect();
        assert!(
            ready.ctx.tbor_oob(&req, &damaged_refs).is_err(),
            "corrupted DER certificate {index} must be rejected",
        );
    }
}

/// Any mutated HPKE ciphertext or authentication tag must fail import.
#[test]
fn darc_tmk_import_rejects_ciphertext_and_tag_mutations() {
    let ready = sd_initialized_session();
    let (req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);
    let der = chain.der_items();
    let ciphertext_start = 1 + 2 * COORD_LEN;

    for offset in [
        ciphertext_start,
        ciphertext_start + TMK_LEN / 2,
        ciphertext_start + TMK_LEN - 1,
        SEALED_TMK_LEN - 16,
        SEALED_TMK_LEN - 1,
    ] {
        let mut bad = req.clone();
        bad.sealed_tmk[offset] ^= 0x01;
        assert!(
            ready.ctx.tbor_oob(&bad, &der).is_err(),
            "HPKE ciphertext/tag mutation at offset {offset} must be rejected",
        );
    }
}

/// A malformed certificate attempt must not prevent a later valid import.
#[test]
fn darc_tmk_import_recovers_after_bad_certificate() {
    let ready = sd_initialized_session();
    let (req, chain) = build_valid_import(&ready, &ready.pota, &[0x5A; TMK_LEN]);
    let der = chain.der_items();
    let mut bad = req.clone();
    bad.remote_cert_chain[0].index = u8::MAX;

    assert!(ready.ctx.tbor_oob(&bad, &der).is_err());
    let response = ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("valid import must succeed after bad certificate descriptor");
    assert_eq!(response.masked_tmk.len(), MASKED_TMK_LEN);
    assert!(response.masked_tmk.iter().any(|&b| b != 0));
}
