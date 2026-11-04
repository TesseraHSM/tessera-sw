// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `DarcTmkImport` command.
//!
//! `DarcTmkImport` imports a DARC Transfer Masking Key (TMK) that was
//! HPKE-Auth-sealed off-device to a `DarcKexKeyGen` key-exchange key and
//! re-masks it locally under the partition security-domain masking key
//! (SDMK).  The 32-byte TMK is recovered by HPKE-Auth-opening `sealed_tmk`
//! with the receiver's masked DARC key-exchange private key, authenticated
//! by the sender public key recovered from a POTA-anchored certificate
//! chain.
//!
//! The **round-trip** test mirrors the real flow end to end: it finalizes
//! a partition and initializes its security domain (`SdCreateRemoteBackup`,
//! which provisions the SDMK), mints a DARC key-exchange key
//! (`DarcKexKeyGen`), then — entirely on the host with `tsra_crypto` —
//! seals a TMK to that key under a fresh sender key whose certificate chain
//! is anchored to the policy POTA, and imports it.
//!
//! Coverage:
//! * Round-trip — the imported TMK comes back as a non-zero 264-byte
//!   masked envelope.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).
//! * Wrong masked-key kind (an `SdSealing` key) → `UnsupportedKeyType`.
//! * Tampered `sealed_tmk` (HPKE-Auth open fails the GCM tag) →
//!   `AesGcmDecryptTagDoesNotMatch`.
//! * `policy` hash mismatch → `InvalidArg`.
//! * Sender chain not anchored to the policy POTA → `InvalidArg`.

use tsra_crypto::seal_vec;
use tsra_crypto::EccCurve;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EccPublicKey;
use tsra_crypto::HpkeSealConfig;
use tsra_crypto::HpkeSuite;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::x509_fixture::make_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::GeneratedChain;
use tsra_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::CertDescriptor;
use tsra_ddi_tbor_types::PartPolicy;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborDarcKexKeyGenReq;
use tsra_ddi_tbor_types::TborDarcTmkImportReq;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborSdSealingKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MASKED_KEX_KEY_LEN;
use tsra_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_ddi_tbor_types::PART_POLICY_LEN;
use tsra_ddi_tbor_types::SEALED_TMK_LEN;
use tsra_ddi_tbor_types::TMK_LEN;
use zerocopy::TryFromBytes;

use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
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
    pub(crate) policy: [u8; PART_POLICY_LEN],
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

    let init = ctx
        .part_init(&session, &seed, &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    // CreateSD provisions the SDMK and marks the partition SD-initialized.
    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata, &report);
    let create_req = backup_request(session.session_id, masked, &evidence, &policy);
    ctx.tbor_oob(&create_req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    SdReady {
        ctx,
        session,
        policy,
        pota,
    }
}

/// Import the device's little-endian `x ‖ y` key-exchange public key as a
/// host [`EccPublicKey`] (`from_hsm_bytes` parses big-endian coordinates,
/// so each coordinate is reversed).
fn kex_pub_to_host(pub_le: &[u8]) -> EccPublicKey {
    let mut be = pub_le.to_vec();
    be[..COORD_LEN].reverse();
    be[COORD_LEN..].reverse();
    EccPublicKey::from_hsm_bytes(&be).expect("import kex public key")
}

/// HPKE-Auth-seal `tmk` to `pk_r` under `sk_s`, returning the on-wire
/// `sealed_tmk` = `enc(SEC1 97) ‖ ct(48)`.
fn seal_tmk(pk_r: &EccPublicKey, sk_s: &EccPrivateKey, tmk: &[u8]) -> [u8; SEALED_TMK_LEN] {
    let cfg = HpkeSealConfig::auth(HpkeSuite::DHKemP384Sha384AesGcm256, pk_r, &[], &[], sk_s);
    let sealed = seal_vec(&cfg, tmk).expect("HPKE-Auth seal");

    // Serialize `enc` as SEC1 uncompressed (`0x04 ‖ X ‖ Y`, big-endian).
    let (ex, ey) = sealed.enc.coord_vec().expect("enc coords");
    let mut out = [0u8; SEALED_TMK_LEN];
    out[0] = 0x04;
    out[1..1 + COORD_LEN].copy_from_slice(&ex);
    out[1 + COORD_LEN..1 + 2 * COORD_LEN].copy_from_slice(&ey);
    out[1 + 2 * COORD_LEN..].copy_from_slice(&sealed.ct);
    out
}

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
/// fresh sender key, certifies it under `anchor_ca`, and HPKE-Auth-seals
/// `tmk` to the receiver key under the sender key.
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
    // carries the sender key the handler recovers.
    let sk_s = EccPrivateKey::from_curve(EccCurve::P384).expect("sender key");
    let (sx, sy) = sk_s.coord_vec().expect("sender coords");
    let mut sender_raw = [0u8; RAW_PUB_LEN];
    sender_raw[..COORD_LEN].copy_from_slice(&sx);
    sender_raw[COORD_LEN..].copy_from_slice(&sy);
    let chain = make_chain(anchor_ca, &sender_raw);
    let der = chain.der_items();

    // Seal the TMK to the receiver key, authenticated by the sender key.
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
        policy: PartPolicy::try_read_from_bytes(&ready.policy).expect("policy image is canonical"),
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

/// A tampered `sealed_tmk` (a flipped ciphertext byte) fails HPKE-Auth
/// open's GCM tag check → `AesGcmDecryptTagDoesNotMatch`.
#[test]
fn darc_tmk_import_rejects_tampered_sealed_tmk() {
    let ready = sd_initialized_session();
    let ctx = &ready.ctx;
    let (mut req, chain) = build_valid_import(&ready, &ready.pota, &[0x5Au8; TMK_LEN]);

    // Flip a byte in the ciphertext region (past the 97-byte `enc`).
    req.sealed_tmk[SEALED_TMK_LEN - 1] ^= 0xFF;

    ctx.expect_fw_reject_oob(
        &req,
        &chain.der_items(),
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
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
    req.policy.info[0] ^= 0xFF;

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
        policy: PartPolicy::zeroed(),
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

#[test]
fn darc_tmk_import_rejects_before_finalize() {
    // A rotated CO session but no PartInit/PartFinal → the partition is
    // not Initialized, so the command is rejected at the lifecycle gate
    // before any crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

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

#[test]
fn darc_tmk_import_rejected_on_default_psk() {
    // A CO session on the still-default PSK is rejected by the
    // dispatcher's default-PSK gate before the handler runs.
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");
    let mut req = dummy_req(session.session_id());
    req.session_id = session.session_id();
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}
