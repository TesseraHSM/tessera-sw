// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DARC Base-mode export, PID authorization, and unchanged command gates.

use tsra_ddi_tbor_test_harness::x509_fixture::make_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::GeneratedChain;
use tsra_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

use crate::commands::common::assert_masked_key_layout_rejected;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::perturb_policy_info;
use crate::commands::sd_create_remote_backup::backing_test_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_report_and_pub;
use crate::commands::sd_sealing_key_gen::finalized_co_session;

const SCOPE_LOCAL: u8 = 3;

pub(crate) struct ExportReady {
    pub(crate) ctx: TestCtx,
    pub(crate) session: SessionHandshake,
    pub(crate) policy: Vec<u8>,
    pub(crate) data: CaKey,
    pub(crate) pota: CaKey,
    pub(crate) pid_chain: Vec<Vec<u8>>,
}

fn descriptors(items: &[&[u8]]) -> Vec<CertDescriptor> {
    items
        .iter()
        .enumerate()
        .map(|(i, der)| CertDescriptor {
            index: i as u8,
            length: u16::try_from(der.len()).expect("certificate length").into(),
        })
        .collect()
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
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");
    let leaf = ctx
        .tbor(&TborGetCertReq {
            slot_id: 2,
            cert_id: 0,
        })
        .expect("PID certificate");
    let pid_chain = vec![chain.root_der, chain.pta_der, leaf.certificate];
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata, &report);
    ctx.tbor_oob(
        &backup_request(session.session_id, &evidence, &policy),
        &evidence.oob(),
    )
    .expect("SdCreateRemoteBackup");
    ExportReady {
        ctx,
        session,
        policy,
        data,
        pota,
        pid_chain,
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

pub(crate) struct KexKey {
    pub(crate) masked: [u8; MASKED_KEX_KEY_LEN],
    pub(crate) pub_raw: [u8; RAW_PUB_LEN],
}

pub(crate) fn mint_kex(ready: &ExportReady) -> KexKey {
    let kex = ready
        .ctx
        .tbor(&TborDarcKexKeyGenReq {
            session_id: ready.session.session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("DarcKexKeyGen");
    let masked = kex.masked_key.as_slice().try_into().expect("KEX length");
    let mut pub_raw = [0; RAW_PUB_LEN];
    pub_raw.copy_from_slice(&kex.pub_key);
    dev_rev_in_place(&mut pub_raw[..48]);
    dev_rev_in_place(&mut pub_raw[48..]);
    KexKey { masked, pub_raw }
}

pub(crate) fn build_valid_export(
    ready: &ExportReady,
    anchor_ca: &CaKey,
    target_pub_raw: &[u8; RAW_PUB_LEN],
    masked_tmk: [u8; MASKED_TMK_LEN],
) -> (TborDarcTmkExportReq, GeneratedChain) {
    let chain = make_chain(anchor_ca, target_pub_raw);
    let req = TborDarcTmkExportReq {
        session_id: ready.session.session_id,
        masked_tmk,
        policy: ready.policy.clone(),
        target_cert_chain: descriptors(&chain.der_items()),
    };
    (req, chain)
}

pub(crate) fn reimport(
    ready: &ExportReady,
    receiver_masked: [u8; MASKED_KEX_KEY_LEN],
    sealed_tmk: [u8; SEALED_TMK_LEN],
    report: Vec<u8>,
) -> Vec<u8> {
    let der: Vec<&[u8]> = ready.pid_chain.iter().map(Vec::as_slice).collect();
    let req = TborDarcTmkImportReq {
        session_id: ready.session.session_id,
        masked_kex_key: receiver_masked,
        policy: ready.policy.clone(),
        sealed_tmk,
        report,
        remote_cert_chain: descriptors(&der),
    };
    ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("PID-authorized import")
        .masked_tmk
}

#[test]
fn darc_tmk_export_lifecycle() {
    let ready = sd_initialized_session_with_data();
    let receiver = mint_kex(&ready);
    let (req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &receiver.pub_raw,
        gen_masked_tmk(&ready),
    );
    let export = ready
        .ctx
        .tbor_oob(&req, &chain.der_items())
        .expect("DarcTmkExport");
    let pid_der: Vec<&[u8]> = ready.pid_chain.iter().map(Vec::as_slice).collect();
    let import = TborDarcTmkImportReq {
        session_id: ready.session.session_id,
        masked_kex_key: receiver.masked,
        policy: req.policy,
        sealed_tmk: export.sealed_tmk,
        report: export.report,
        remote_cert_chain: descriptors(&pid_der),
    };
    let imported = ready
        .ctx
        .tbor_oob(&import, &pid_der)
        .expect("POTA -> PTA -> PID import");
    assert_eq!(imported.masked_tmk.len(), MASKED_TMK_LEN);
    assert!(imported.masked_tmk.iter().any(|b| *b != 0));
}

#[test]
fn darc_tmk_export_yields_fresh_seal() {
    let ready = sd_initialized_session_with_data();
    let receiver = mint_kex(&ready);
    let (req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &receiver.pub_raw,
        gen_masked_tmk(&ready),
    );
    let first = ready
        .ctx
        .tbor_oob(&req, &chain.der_items())
        .expect("first export");
    let second = ready
        .ctx
        .tbor_oob(&req, &chain.der_items())
        .expect("second export");
    assert_ne!(first.sealed_tmk, second.sealed_tmk);
    assert_ne!(first.report, second.report);
}

#[test]
fn darc_tmk_export_report_does_not_authenticate_a_sender_kex_identity() {
    let ready = sd_initialized_session_with_data();
    let receiver = mint_kex(&ready);
    let former_sender = mint_kex(&ready);
    let (req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &receiver.pub_raw,
        gen_masked_tmk(&ready),
    );
    let export = ready
        .ctx
        .tbor_oob(&req, &chain.der_items())
        .expect("export");
    let wrong_chain = make_chain(&ready.pota, &former_sender.pub_raw);
    let import = TborDarcTmkImportReq {
        session_id: ready.session.session_id,
        masked_kex_key: receiver.masked,
        policy: req.policy,
        sealed_tmk: export.sealed_tmk,
        report: export.report,
        remote_cert_chain: descriptors(&wrong_chain.der_items()),
    };
    ready
        .ctx
        .expect_fw_reject_oob(&import, &wrong_chain.der_items(), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_export_rejects_policy_hash_mismatch() {
    let ready = sd_initialized_session_with_data();
    let receiver = mint_kex(&ready);
    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &receiver.pub_raw,
        gen_masked_tmk(&ready),
    );

    // Perturb an opaque, anchor-independent field so only the hash changes.
    req.policy = perturb_policy_info(&req.policy);

    ready
        .ctx
        .expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_export_rejects_unanchored_cert_chain() {
    let ready = sd_initialized_session_with_data();
    let receiver = mint_kex(&ready);
    let (req, chain) = build_valid_export(
        &ready,
        &CaKey::generate(),
        &receiver.pub_raw,
        gen_masked_tmk(&ready),
    );
    ready
        .ctx
        .expect_fw_reject_oob(&req, &chain.der_items(), TborStatus::InvalidArg);
}

fn dummy_req(session_id: u16) -> TborDarcTmkExportReq {
    TborDarcTmkExportReq {
        session_id,
        masked_tmk: [0; MASKED_TMK_LEN],
        policy: Vec::new(),
        target_cert_chain: vec![CertDescriptor {
            index: 0,
            length: 1u16.into(),
        }],
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
    let receiver = mint_kex(&ready);
    let (req, _) = build_valid_export(
        &ready,
        &ready.data,
        &receiver.pub_raw,
        gen_masked_tmk(&ready),
    );
    assert_masked_key_layout_rejected(&ready.ctx, &req);
}
