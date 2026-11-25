// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DARC Base-mode export (P-384, ML-KEM-1024, MLKEM1024-P384), DATA-anchored
//! recipient authentication, PID authorization, and unchanged command gates.
//!
//! The target is this device itself: its DATA -> PTA -> PID chain and a
//! PID-signed `KeyReport` over a `DarcKexKeyGen` key. The PID-signed Darc
//! report is returned at out-of-band item [`DARC_REPORT_OOB_INDEX`].

use tsra_ddi_tbor_test_harness::x509_fixture::make_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use tsra_ddi_tbor_test_harness::x509_fixture::SEC1_PUB_LEN;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::tbor_int::U16;
use tsra_ddi_tbor_types::*;

use crate::commands::common::assert_masked_key_layout_rejected;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::perturb_policy_info;
use crate::commands::sd_create_remote_backup::backing_test_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::kem_sealing_key_and_report;
use crate::commands::sd_create_remote_backup::masked_key_report_and_pub;
use crate::commands::sd_create_remote_backup::sd_oob_items;
use crate::commands::sd_create_remote_backup::SdOob;
use crate::commands::sd_create_remote_backup::SdOut;
use crate::commands::sd_sealing_key_gen::finalized_co_session;

const SCOPE_LOCAL: u8 = 3;

/// Every DARC KEM with its ES384-signed encrypted artifact length.
const KEMS: [(u8, usize); 3] = [
    (TRANSFER_KEM_P384, SEALED_TMK_LEN),
    (TRANSFER_KEM_MLKEM1024, 1838),
    (TRANSFER_KEM_MLKEM1024_P384, 1935),
];

pub(crate) struct ExportReady {
    pub(crate) ctx: TestCtx,
    pub(crate) session: SessionHandshake,
    pub(crate) policy: Vec<u8>,
    pub(crate) pota: CaKey,
    /// Partition PTA public key (SEC1), for re-issuing PTA chains.
    pub(crate) pta_pub: [u8; SEC1_PUB_LEN],
    /// Device PID leaf certificate (DER), issued by the PTA.
    pub(crate) pid_leaf: Vec<u8>,
    /// POTA -> PTA -> PID chain (source chain for import).
    pub(crate) pid_chain: Vec<Vec<u8>>,
    /// DATA -> PTA -> PID chain (target chain for export).
    pub(crate) target_chain: Vec<Vec<u8>>,
}

/// Descriptors for `items`, which sit at consecutive OOB indexes from
/// `first`.
fn descriptors_from(first: usize, items: &[Vec<u8>]) -> Vec<CertDescriptor> {
    items
        .iter()
        .enumerate()
        .map(|(i, der)| CertDescriptor {
            index: u8::try_from(first + i).expect("OOB index"),
            length: u16::try_from(der.len()).expect("certificate length").into(),
        })
        .collect()
}

fn report_descriptor(index: usize, report: &[u8]) -> ReportDescriptor {
    ReportDescriptor {
        index: u8::try_from(index).expect("OOB index"),
        length: U16::new(u16::try_from(report.len()).expect("report length")),
    }
}

pub(crate) fn sd_initialized_session_with_data() -> ExportReady {
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let data = CaKey::generate();
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);
    let policy = backing_test_policy(
        &info.pid,
        &info.pid_pub_key,
        &sata.raw_pub(),
        &pota.raw_pub(),
    )
    .with_data(data.spki_thumbprint())
    .encode();

    let init = ctx
        .part_init(&session, &mach_seed(), &policy)
        .expect("PartInit");
    let pta_pub = pta_pub_from_csr(&init.pta_csr);
    let chain = make_pta_chain(&pota, &pta_pub);
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");
    let pid_leaf = ctx.get_cert(2, CERT_BANK_ECC, 0).expect("PID certificate");
    let pid_chain = vec![chain.root_der, chain.pta_der, pid_leaf.clone()];
    let data_chain = make_pta_chain(&data, &pta_pub);
    let target_chain = vec![data_chain.root_der, data_chain.pta_der, pid_leaf.clone()];
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata, &report);
    ctx.sd_oob(
        &backup_request(session.session_id, &evidence, &policy),
        &evidence.oob(),
    )
    .expect("SdCreateRemoteBackup");
    ExportReady {
        ctx,
        session,
        policy,
        pota,
        pta_pub,
        pid_leaf,
        pid_chain,
        target_chain,
    }
}

pub(crate) fn gen_masked_tmk(ready: &ExportReady) -> [u8; MASKED_TMK_LEN] {
    ready
        .ctx
        .tbor(&TborDarcTmkGenReq {
            session_id: ready.session.session_id,
        })
        .expect("DarcTmkGen")
        .masked_tmk
        .as_slice()
        .try_into()
        .expect("TMK length")
}

/// A DARC key-exchange key plus its PID-signed key report.
pub(crate) struct KexKey {
    pub(crate) masked: Vec<u8>,
    pub(crate) pub_key: Vec<u8>,
    pub(crate) report: Vec<u8>,
}

/// Mint a `kem` DARC key-exchange key and attest it with `KeyReport`.
pub(crate) fn mint_kex(ready: &ExportReady, kem: u8) -> KexKey {
    let sid = ready.session.session_id;
    let kex = ready
        .ctx
        .tbor(&TborDarcKexKeyGenReq {
            session_id: sid,
            scope: SCOPE_LOCAL,
            kem,
        })
        .expect("DarcKexKeyGen");
    let report = ready
        .ctx
        .key_report(&TborKeyReportReq {
            session_id: sid,
            auth_envelope: Vec::new(),
            masked_key: kex.masked_key.clone(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
        })
        .expect("KeyReport over DARC KEX key");
    KexKey {
        masked: kex.masked_key,
        pub_key: kex.pub_key,
        report,
    }
}

/// An export request plus its OOB items (`items[0]` is the report output
/// slot, then the target chain, then the target key report).
pub(crate) struct ExportReq {
    pub(crate) req: TborDarcTmkExportReq,
    items: Vec<Vec<u8>>,
}

impl ExportReq {
    pub(crate) fn oob(&self) -> Vec<&[u8]> {
        self.items.iter().map(Vec::as_slice).collect()
    }
}

/// Export request targeting `chain` and the key attested by `report`.
pub(crate) fn export_request(
    ready: &ExportReady,
    chain: &[Vec<u8>],
    report: &[u8],
    masked_tmk: [u8; MASKED_TMK_LEN],
) -> ExportReq {
    let mut items = sd_oob_items();
    let target_cert_chain = descriptors_from(items.len(), chain);
    items.extend(chain.iter().cloned());
    let target_key_report = report_descriptor(items.len(), report);
    items.push(report.to_vec());
    ExportReq {
        req: TborDarcTmkExportReq {
            session_id: ready.session.session_id,
            masked_tmk,
            policy: ready.policy.clone(),
            target_cert_chain,
            target_key_report,
        },
        items,
    }
}

/// Valid export of `masked_tmk` to `target` (DATA -> PTA -> PID chain).
pub(crate) fn build_valid_export(
    ready: &ExportReady,
    target: &KexKey,
    masked_tmk: [u8; MASKED_TMK_LEN],
) -> ExportReq {
    export_request(ready, &ready.target_chain, &target.report, masked_tmk)
}

pub(crate) fn export(ready: &ExportReady, req: &ExportReq) -> SdOut<TborDarcTmkExportResp> {
    ready
        .ctx
        .sd_oob(&req.req, &req.oob())
        .expect("DarcTmkExport")
}

/// Import request sourced from `chain`, followed by the full signed artifact.
pub(crate) fn import_request(
    ready: &ExportReady,
    chain: &[Vec<u8>],
    receiver_masked: &[u8],
    artifact: &[u8],
) -> (TborDarcTmkImportReq, Vec<Vec<u8>>) {
    let mut items = chain.to_vec();
    let artifact_desc = report_descriptor(items.len(), artifact);
    items.push(artifact.to_vec());
    let req = TborDarcTmkImportReq {
        session_id: ready.session.session_id,
        masked_kex_key: receiver_masked.to_vec(),
        policy: ready.policy.clone(),
        sealed_tmk: artifact_desc,
        remote_cert_chain: descriptors_from(0, chain),
    };
    (req, items)
}

fn as_slices(items: &[Vec<u8>]) -> Vec<&[u8]> {
    items.iter().map(Vec::as_slice).collect()
}

/// Import an export on the same device (POTA -> PTA -> PID source chain).
pub(crate) fn reimport(ready: &ExportReady, receiver_masked: &[u8], artifact: &[u8]) -> Vec<u8> {
    let (req, items) = import_request(ready, &ready.pid_chain, receiver_masked, artifact);
    ready
        .ctx
        .tbor_oob(&req, &as_slices(&items))
        .expect("PID-authorized import")
        .masked_tmk
}

#[test]
fn darc_tmk_export_lifecycle() {
    let ready = sd_initialized_session_with_data();
    for (kem, sealed_len) in KEMS {
        let receiver = mint_kex(&ready, kem);
        let out = export(
            &ready,
            &build_valid_export(&ready, &receiver, gen_masked_tmk(&ready)),
        );
        assert_eq!(out.report.len(), sealed_len);
        let imported = reimport(&ready, &receiver.masked, &out.report);
        assert_eq!(imported.len(), MASKED_TMK_LEN);
        assert!(imported.iter().any(|b| *b != 0));
    }
}

#[test]
fn darc_tmk_export_yields_fresh_seal() {
    let ready = sd_initialized_session_with_data();
    let receiver = mint_kex(&ready, TRANSFER_KEM_P384);
    let req = build_valid_export(&ready, &receiver, gen_masked_tmk(&ready));
    let first = export(&ready, &req);
    let second = export(&ready, &req);
    assert_ne!(first.report, second.report);
}

#[test]
fn darc_tmk_export_report_does_not_authenticate_a_sender_kex_identity() {
    let ready = sd_initialized_session_with_data();
    let receiver = mint_kex(&ready, TRANSFER_KEM_P384);
    let former_sender = mint_kex(&ready, TRANSFER_KEM_P384);
    let out = export(
        &ready,
        &build_valid_export(&ready, &receiver, gen_masked_tmk(&ready)),
    );
    // A POTA-anchored chain whose leaf is a KEX key rather than the PID.
    let mut sender_raw: [u8; RAW_PUB_LEN] = former_sender
        .pub_key
        .as_slice()
        .try_into()
        .expect("P-384 KEX public key");
    dev_rev_in_place(&mut sender_raw[..RAW_PUB_LEN / 2]);
    dev_rev_in_place(&mut sender_raw[RAW_PUB_LEN / 2..]);
    let wrong_chain = make_chain(&ready.pota, &sender_raw);
    let wrong_chain = vec![wrong_chain.root_der, wrong_chain.leaf_der];
    let (import, items) = import_request(&ready, &wrong_chain, &receiver.masked, &out.report);
    ready
        .ctx
        .expect_fw_reject_oob(&import, &as_slices(&items), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_export_rejects_policy_hash_mismatch() {
    let ready = sd_initialized_session_with_data();
    let receiver = mint_kex(&ready, TRANSFER_KEM_P384);
    let mut req = build_valid_export(&ready, &receiver, gen_masked_tmk(&ready));

    // Perturb an opaque, anchor-independent field so only the hash changes.
    req.req.policy = perturb_policy_info(&req.req.policy);

    ready
        .ctx
        .expect_sd_reject(&req.req, &req.oob(), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_export_rejects_unanchored_cert_chain() {
    let ready = sd_initialized_session_with_data();
    let receiver = mint_kex(&ready, TRANSFER_KEM_P384);
    // A well-formed PTA -> PID chain anchored to a foreign CA, not DATA.
    let foreign = make_pta_chain(&CaKey::generate(), &ready.pta_pub);
    let chain = vec![foreign.root_der, foreign.pta_der, ready.pid_leaf.clone()];
    let req = export_request(&ready, &chain, &receiver.report, gen_masked_tmk(&ready));
    ready
        .ctx
        .expect_sd_reject(&req.req, &req.oob(), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_export_rejects_non_darc_key_report() {
    let ready = sd_initialized_session_with_data();
    // A PID-signed report over an SD sealing key: correctly signed and
    // device-generated, but not a DARC key-exchange key.
    let (_, report) =
        kem_sealing_key_and_report(&ready.ctx, ready.session.session_id, TRANSFER_KEM_P384);
    let req = export_request(&ready, &ready.target_chain, &report, gen_masked_tmk(&ready));
    ready
        .ctx
        .expect_sd_reject(&req.req, &req.oob(), TborStatus::InvalidArg);
}

fn dummy_req(session_id: u16) -> TborDarcTmkExportReq {
    TborDarcTmkExportReq {
        session_id,
        masked_tmk: [0; MASKED_TMK_LEN],
        policy: Vec::new(),
        target_cert_chain: vec![CertDescriptor {
            index: 1,
            length: 1u16.into(),
        }],
        target_key_report: ReportDescriptor {
            index: 2,
            length: 1u16.into(),
        },
    }
}

#[test]
fn darc_tmk_export_rejects_before_sd_init() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_export_rejects_before_finalize() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_export_rejected_on_cu_session() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    ctx.expect_fw_reject(
        &dummy_req(session.session_id),
        TborStatus::InvalidPermissions,
    );
}

#[test]
fn darc_tmk_export_rejected_on_default_psk() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("open_session must succeed");
    let mut req = dummy_req(session.session_id());
    req.session_id = session.session_id();
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}

#[test]
fn darc_tmk_export_rejects_bad_masked_key_layout() {
    let ready = sd_initialized_session_with_data();
    let receiver = mint_kex(&ready, TRANSFER_KEM_P384);
    let req = build_valid_export(&ready, &receiver, gen_masked_tmk(&ready));
    assert_masked_key_layout_rejected(&ready.ctx, &req.req);
}
