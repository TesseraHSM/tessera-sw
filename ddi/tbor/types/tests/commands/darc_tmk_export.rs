// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `DarcTmkExport` command.
//!
//! `DarcTmkExport` is the **source-side** mirror of `DarcTmkImport`: it
//! unmasks a locally-masked DARC Transfer Masking Key (TMK, from
//! `DarcTmkGen`/`DarcTmkImport`), recovers the HPKE sender private key
//! from the source's own masked `DarcKexKeyGen` key, verifies the
//! **target's** certificate chain anchored to the policy `DATAPubKey`
//! (recovering the target's public key), and HPKE-Auth-seals the 32-byte
//! TMK to it — producing a 145-byte `sealed_tmk` byte-compatible with what
//! `DarcTmkImport` consumes.
//!
//! The **lifecycle** test exercises the full source→target hand-off on a
//! single device: it mints a TMK (`DarcTmkGen`), a source key-exchange key
//! and a target key-exchange key (`DarcKexKeyGen`), exports the TMK to the
//! target (chain anchored to the policy DATA anchor), then feeds the
//! resulting `sealed_tmk` straight back into `DarcTmkImport` (chain
//! anchored to the policy POTA), proving the exported envelope re-imports
//! and re-masks to a valid TMK.
//!
//! Coverage:
//! * Lifecycle — `DarcTmkGen` → `DarcTmkExport` → `DarcTmkImport`
//!   round-trips: the exported `sealed_tmk` is a non-zero 145-byte
//!   envelope that imports back to a non-zero 164-byte masked TMK.
//! * Fresh `enc` — two exports of the same inputs yield distinct
//!   `sealed_tmk` (fresh HPKE ephemeral).
//! * Wrong masked sender-key kind (an `SdSealing` key) →
//!   `UnsupportedKeyType`.
//! * `policy` hash mismatch → `InvalidArg`.
//! * Target chain not anchored to the policy DATA anchor → `InvalidArg`.
//! * Before SD init (partition `Initialized`, no security domain) →
//!   `InvalidArg`.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).

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
use tsra_ddi_tbor_types::PolicyKeyKind;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborDarcKexKeyGenReq;
use tsra_ddi_tbor_types::TborDarcTmkExportReq;
use tsra_ddi_tbor_types::TborDarcTmkGenReq;
use tsra_ddi_tbor_types::TborDarcTmkImportReq;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborSdSealingKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MASKED_KEX_KEY_LEN;
use tsra_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_ddi_tbor_types::PART_POLICY_LEN;
use tsra_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use tsra_ddi_tbor_types::SEALED_TMK_LEN;
use zerocopy::TryFromBytes;

use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_report_and_pub;
use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant (wire mirror of the firmware
/// `HsmKeyScope`).
const SCOPE_LOCAL: u8 = 0b011;

/// P-384 coordinate length.
const COORD_LEN: usize = 48;

/// Offset of the appended optional `data_pub_key` slot in the 584-byte
/// `PartPolicy` image (`kind(2) ‖ len(2) ‖ data(96)`).
const OFF_DATA_PUB_KEY: usize = 484;

/// A partition whose security domain is initialized and whose policy
/// carries **both** a DATA anchor (for `DarcTmkExport` target chains) and
/// a POTA anchor (for the `DarcTmkImport` sender chain the lifecycle test
/// feeds the exported `sealed_tmk` into).
pub(crate) struct ExportReady {
    pub(crate) ctx: TestCtx,
    pub(crate) session: SessionHandshake,
    pub(crate) policy: [u8; PART_POLICY_LEN],
    /// Policy DATA CA — anchors the target certificate chain.
    pub(crate) data: CaKey,
    /// Policy POTA CA — anchors the sender chain on re-import.
    pub(crate) pota: CaKey,
}

/// Overwrite the policy `data_pub_key` slot with `data_pub` (raw P-384
/// `X ‖ Y`, big-endian), marking the DATA anchor present (`Ecc384` / 96).
fn set_data_anchor(bytes: &mut [u8; PART_POLICY_LEN], data_pub: &[u8; RAW_PUB_LEN]) {
    let off = OFF_DATA_PUB_KEY;
    bytes[off..off + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
    bytes[off + 2..off + 4].copy_from_slice(&(POLICY_MAX_KEY_LEN as u16).to_le_bytes());
    bytes[off + 4..off + 4 + RAW_PUB_LEN].copy_from_slice(data_pub);
}

/// Finalize a partition and initialize its security domain, binding a
/// policy that anchors both a DATA CA and a POTA CA.  Mirrors
/// [`crate::commands::darc_tmk_import::sd_initialized_session`] but injects
/// the DATA anchor before `PartInit` so it is covered by the bound
/// `policy_hash`.
pub(crate) fn sd_initialized_session_with_data() -> ExportReady {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let data = CaKey::generate();

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);
    let mut policy = backing_part_policy(
        &info.pid,
        &info.pid_pub_key,
        &sata.raw_pub(),
        &pota.raw_pub(),
    );
    set_data_anchor(&mut policy, &data.raw_pub());

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

    ExportReady {
        ctx,
        session,
        policy,
        data,
        pota,
    }
}

/// Mint a TMK via `DarcTmkGen`, returning its 164-byte masked envelope.
pub(crate) fn gen_masked_tmk(ready: &ExportReady) -> [u8; MASKED_TMK_LEN] {
    let resp = ready
        .ctx
        .tbor(&TborDarcTmkGenReq {
            session_id: ready.session.session_id,
        })
        .expect("DarcTmkGen");
    resp.masked_tmk
        .as_slice()
        .try_into()
        .expect("masked TMK length")
}

/// A minted DARC key-exchange key: its masked blob (unmasked on-device to
/// the private key) and its public key as raw big-endian `X ‖ Y` (the
/// certificate-chain leaf format).
pub(crate) struct KexKey {
    pub(crate) masked: [u8; MASKED_KEX_KEY_LEN],
    pub(crate) pub_raw: [u8; RAW_PUB_LEN],
}

/// Mint a `DarcKexKeyGen` key and return its masked blob plus its public
/// key converted from the device's little-endian `x ‖ y` to the raw
/// big-endian `X ‖ Y` a certificate leaf carries.
pub(crate) fn mint_kex(ready: &ExportReady) -> KexKey {
    let kex = ready
        .ctx
        .tbor(&TborDarcKexKeyGenReq {
            session_id: ready.session.session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("DarcKexKeyGen");
    let masked = kex
        .masked_key
        .as_slice()
        .try_into()
        .expect("masked kex key length");
    let mut pub_raw = [0u8; RAW_PUB_LEN];
    pub_raw.copy_from_slice(&kex.pub_key);
    pub_raw[..COORD_LEN].reverse();
    pub_raw[COORD_LEN..].reverse();
    KexKey { masked, pub_raw }
}

/// Build a fully valid `DarcTmkExport` request whose target chain is
/// anchored to `anchor_ca` and whose leaf carries `target_pub_raw`.
///
/// Returns the request together with the owning [`GeneratedChain`] (its
/// DER must outlive the request and be passed out of band via
/// [`GeneratedChain::der_items`]).  Pass `&ready.data` for the happy path;
/// pass a foreign CA to exercise the unanchored-chain rejection.
pub(crate) fn build_valid_export(
    ready: &ExportReady,
    anchor_ca: &CaKey,
    target_pub_raw: &[u8; RAW_PUB_LEN],
    masked_sender_key: [u8; MASKED_KEX_KEY_LEN],
    masked_tmk: [u8; MASKED_TMK_LEN],
) -> (TborDarcTmkExportReq, GeneratedChain) {
    let chain = make_chain(anchor_ca, target_pub_raw);
    let der = chain.der_items();
    let target_cert_chain = vec![
        CertDescriptor {
            index: 0,
            length: (der[0].len() as u16).into(),
        },
        CertDescriptor {
            index: 1,
            length: (der[1].len() as u16).into(),
        },
    ];

    let req = TborDarcTmkExportReq {
        session_id: ready.session.session_id,
        masked_sender_key,
        masked_tmk,
        policy: PartPolicy::try_read_from_bytes(&ready.policy).expect("policy image is canonical"),
        target_cert_chain,
    };
    (req, chain)
}

/// Import an exported `sealed_tmk` back on the same device, using the
/// target key-exchange key as the receiver and a POTA-anchored chain over
/// the source public key as the sender attestation.
pub(crate) fn reimport(
    ready: &ExportReady,
    receiver_masked: [u8; MASKED_KEX_KEY_LEN],
    sender_pub_raw: &[u8; RAW_PUB_LEN],
    sealed_tmk: [u8; SEALED_TMK_LEN],
) -> Vec<u8> {
    let chain = make_chain(&ready.pota, sender_pub_raw);
    let der = chain.der_items();
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
        masked_kex_key: receiver_masked,
        policy: PartPolicy::try_read_from_bytes(&ready.policy).expect("policy image is canonical"),
        sealed_tmk,
        remote_cert_chain,
    };
    let resp = ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("DarcTmkImport of exported TMK");
    resp.masked_tmk
}

#[test]
fn darc_tmk_export_lifecycle() {
    let ready = sd_initialized_session_with_data();

    // Source: a locally-minted TMK and key-exchange key.  Target: a
    // separate key-exchange key standing in for the remote receiver.
    let masked_tmk = gen_masked_tmk(&ready);
    let source_kex = mint_kex(&ready);
    let target_kex = mint_kex(&ready);

    // Export the TMK to the target (chain anchored to the policy DATA).
    let (export_req, export_chain) = build_valid_export(
        &ready,
        &ready.data,
        &target_kex.pub_raw,
        source_kex.masked,
        masked_tmk,
    );
    let export = ready
        .ctx
        .tbor_oob(&export_req, &export_chain.der_items())
        .expect("DarcTmkExport lifecycle");
    assert_eq!(
        export.sealed_tmk.len(),
        SEALED_TMK_LEN,
        "sealed_tmk must be the fixed 145-byte envelope",
    );
    assert!(
        export.sealed_tmk.iter().any(|&b| b != 0),
        "sealed_tmk must not be all-zero",
    );

    // Re-import the exported envelope: the target key is the receiver, the
    // source key the sender (attested by a POTA-anchored chain).  A
    // successful, non-zero masked TMK proves the export→import hand-off.
    let reimported = reimport(
        &ready,
        target_kex.masked,
        &source_kex.pub_raw,
        export.sealed_tmk,
    );
    assert_eq!(
        reimported.len(),
        MASKED_TMK_LEN,
        "re-imported TMK must be the fixed 164-byte envelope",
    );
    assert!(
        reimported.iter().any(|&b| b != 0),
        "re-imported masked TMK must not be all-zero",
    );
}

#[test]
fn darc_tmk_export_yields_fresh_seal() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let source_kex = mint_kex(&ready);
    let target_kex = mint_kex(&ready);

    let (req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target_kex.pub_raw,
        source_kex.masked,
        masked_tmk,
    );
    let der = chain.der_items();
    let first = ready.ctx.tbor_oob(&req, &der).expect("first DarcTmkExport");
    let second = ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("second DarcTmkExport");

    // Each seal draws a fresh HPKE ephemeral, so the envelopes differ.
    assert_ne!(
        first.sealed_tmk, second.sealed_tmk,
        "each DarcTmkExport must yield a fresh sealed envelope",
    );
}

/// A masked sender key of the wrong kind is rejected with
/// `UnsupportedKeyType`.
///
/// The substitute is an `SdSealing` key minted at the same `Local` scope,
/// so it routes to — and unmasks successfully under — the same masking
/// key: the handler's `key_kind == DarcKex` gate is what rejects it, not
/// an unmask (AEAD) failure.
#[test]
fn darc_tmk_export_rejects_wrong_sender_key_kind() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let target_kex = mint_kex(&ready);

    let seal = ready
        .ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id: ready.session.session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("SdSealingKeyGen");
    let wrong_sender: [u8; MASKED_KEX_KEY_LEN] = seal
        .masked_key
        .as_slice()
        .try_into()
        .expect("masked sealing key length");

    let (req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target_kex.pub_raw,
        wrong_sender,
        masked_tmk,
    );
    ready
        .ctx
        .expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::UnsupportedKeyType);
}

/// A `policy` whose SHA-384 digest does not match the partition's bound
/// `policy_hash` is rejected with `InvalidArg`, before the DATA anchor it
/// carries is ever trusted.
#[test]
fn darc_tmk_export_rejects_policy_hash_mismatch() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let source_kex = mint_kex(&ready);
    let target_kex = mint_kex(&ready);

    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target_kex.pub_raw,
        source_kex.masked,
        masked_tmk,
    );

    // Perturb an opaque, anchor-independent field so only the hash changes.
    req.policy.info[0] ^= 0xFF;

    ready
        .ctx
        .expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
}

/// A target certificate chain that does not chain up to the policy DATA
/// anchor is rejected with `InvalidArg`.  The chain here is anchored to an
/// unrelated CA while the policy (and thus the on-device anchor) is
/// unchanged, so `verify_policy_hash` passes and validation fails at the
/// anchor check.
#[test]
fn darc_tmk_export_rejects_unanchored_cert_chain() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let source_kex = mint_kex(&ready);
    let target_kex = mint_kex(&ready);

    let rogue_ca = CaKey::generate();
    let (req, chain) = build_valid_export(
        &ready,
        &rogue_ca,
        &target_kex.pub_raw,
        source_kex.masked,
        masked_tmk,
    );
    ready
        .ctx
        .expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
}

/// A well-formed request whose crypto inputs never get exercised — used by
/// gating tests that must fail at the session/lifecycle gate before any
/// evidence or crypto work.
fn dummy_req(session_id: u16) -> TborDarcTmkExportReq {
    TborDarcTmkExportReq {
        session_id,
        masked_sender_key: [0u8; MASKED_KEX_KEY_LEN],
        masked_tmk: [0u8; MASKED_TMK_LEN],
        policy: PartPolicy::zeroed(),
        // A single (unused) descriptor so the request decodes past the FW
        // fixed-length check — these tests fail at the session/lifecycle
        // gate, which runs after decode but before any chain/crypto work.
        target_cert_chain: vec![CertDescriptor {
            index: 0,
            length: 1u16.into(),
        }],
    }
}

#[test]
fn darc_tmk_export_rejects_before_sd_init() {
    // The partition is finalized (`Initialized`) but its security domain
    // is not set up, so the SDMK the input TMK is masked under does not
    // exist → rejected before any crypto work.
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_export_rejects_before_finalize() {
    // A rotated CO session but no PartInit/PartFinal → the partition is
    // not `Initialized`, so the command is rejected at the lifecycle gate
    // before any crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_export_rejected_on_cu_session() {
    // DarcTmkExport is Crypto-Officer-only: the handler's role gate
    // (checked before the state/crypto gates) rejects a CU session.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    ctx.expect_fw_reject(
        &dummy_req(session.session_id),
        TborStatus::InvalidPermissions,
    );
}

#[test]
fn darc_tmk_export_rejected_on_default_psk() {
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
