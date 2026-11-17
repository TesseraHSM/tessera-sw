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
) -> Vec<u8> {
    let der: Vec<&[u8]> = ready.pid_chain.iter().map(Vec::as_slice).collect();
    let req = TborDarcTmkImportReq {
        session_id: ready.session.session_id,
        masked_kex_key: receiver_masked,
        policy: ready.policy.clone(),
        sealed_tmk,
        remote_cert_chain: descriptors(&der),
    };
    ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("PID-authorized import")
        .masked_tmk
}

/// Exports a TMK and re-imports it with the intended target key.
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
        remote_cert_chain: descriptors(&pid_der),
    };
    let imported = ready
        .ctx
        .tbor_oob(&import, &pid_der)
        .expect("POTA -> PTA -> PID import");
    assert_eq!(imported.masked_tmk.len(), MASKED_TMK_LEN);
    assert!(imported.masked_tmk.iter().any(|b| *b != 0));
}

/// Repeated exports of identical inputs produce distinct HPKE envelopes.
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

/// Rejects export when the partition is finalized but the SD is not initialized.
#[test]
fn darc_tmk_export_rejects_before_sd_init() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

/// Rejects export before partition finalization.
#[test]
fn darc_tmk_export_rejects_before_finalize() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

/// Rejects a Crypto-User session for the CO-only export command.
#[test]
fn darc_tmk_export_rejected_on_cu_session() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    ctx.expect_fw_reject(
        &dummy_req(session.session_id),
        TborStatus::InvalidPermissions,
    );
}

/// Rejects export while the CO session still uses the default PSK.
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

/// Rejects an authenticated sender-key blob with corrupted ciphertext.
#[test]
fn darc_tmk_export_rejects_corrupted_masked_sender_key() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);

    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        masked_tmk,
    );
    let der = chain.der_items();

    // Modify authenticated ciphertext without changing its length.
    req.masked_sender_key[MASKED_KEX_KEY_LEN / 2] ^= 0x80;
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "tampered masked sender key must not be accepted"
    );

    // A failed request must not prevent a subsequent valid export.
    req.masked_sender_key = source.masked;
    ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("valid export after sender-key rejection");
}

/// Rejects a tampered masked TMK without breaking subsequent exports.
#[test]
fn darc_tmk_export_rejects_corrupted_masked_tmk() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);

    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        masked_tmk,
    );
    let der = chain.der_items();

    req.masked_tmk[MASKED_TMK_LEN / 2] ^= 0x80;
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "tampered masked TMK must not be exported"
    );

    req.masked_tmk = masked_tmk;
    ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("valid export after TMK rejection");
}

/// Rejects zero-filled masked sender keys and TMKs.
#[test]
fn darc_tmk_export_rejects_zeroed_masked_inputs() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);

    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        masked_tmk,
    );
    let der = chain.der_items();

    req.masked_sender_key = [0u8; MASKED_KEX_KEY_LEN];
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "all-zero masked sender key must fail"
    );

    req.masked_sender_key = source.masked;
    req.masked_tmk = [0u8; MASKED_TMK_LEN];
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "all-zero masked TMK must fail"
    );

    req.masked_tmk = masked_tmk;
    ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("valid export after zero-input rejections");
}

/// Rejects a certificate descriptor referring to an absent OOB item.
#[test]
fn darc_tmk_export_rejects_out_of_range_cert_index() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);

    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        masked_tmk,
    );
    let der = chain.der_items();

    // Only two OOB certificates are supplied: indices 0 and 1.
    req.target_cert_chain[0].index = 99;
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "out-of-range OOB certificate index must fail"
    );
}

/// Rejects a certificate descriptor that misstates the DER length.
#[test]
fn darc_tmk_export_rejects_incorrect_cert_length() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);

    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        masked_tmk,
    );
    let der = chain.der_items();

    // The actual DER bytes are unchanged, but their advertised size is wrong.
    req.target_cert_chain[0].length = 1u16.into();
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "certificate length mismatch must fail"
    );
}

/// Rejects a target chain missing a required certificate descriptor.
#[test]
fn darc_tmk_export_rejects_incomplete_target_cert_chain() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);

    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        masked_tmk,
    );
    let der = chain.der_items();

    // The request now describes only one of the two provided certificates.
    req.target_cert_chain.pop();
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "incomplete target chain must fail"
    );
}

/// Exports one TMK to two independent targets and re-imports both envelopes.
#[test]
fn darc_tmk_export_multiple_targets_roundtrip() {
    let ready = sd_initialized_session_with_data();
    let masked_tmk = gen_masked_tmk(&ready);
    let source = mint_kex(&ready);
    let target_a = mint_kex(&ready);
    let target_b = mint_kex(&ready);

    let (req_a, chain_a) = build_valid_export(
        &ready,
        &ready.data,
        &target_a.pub_raw,
        source.masked,
        masked_tmk,
    );
    let (req_b, chain_b) = build_valid_export(
        &ready,
        &ready.data,
        &target_b.pub_raw,
        source.masked,
        masked_tmk,
    );

    let exported_a = ready
        .ctx
        .tbor_oob(&req_a, &chain_a.der_items())
        .expect("export for target A");
    let exported_b = ready
        .ctx
        .tbor_oob(&req_b, &chain_b.der_items())
        .expect("export for target B");

    assert_ne!(
        exported_a.sealed_tmk, exported_b.sealed_tmk,
        "separate target exports must not produce identical envelopes"
    );

    let imported_a = reimport(
        &ready,
        target_a.masked,
        &source.pub_raw,
        exported_a.sealed_tmk,
    );
    let imported_b = reimport(
        &ready,
        target_b.masked,
        &source.pub_raw,
        exported_b.sealed_tmk,
    );

    assert_eq!(imported_a.len(), MASKED_TMK_LEN);
    assert_eq!(imported_b.len(), MASKED_TMK_LEN);
    assert!(imported_a.iter().any(|&b| b != 0));
    assert!(imported_b.iter().any(|&b| b != 0));
}

/// Rejects duplicate OOB certificate indexes in the target chain.
#[test]
fn darc_tmk_export_rejects_duplicate_cert_descriptors() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );
    let der = chain.der_items();

    // Both descriptors now point at the same OOB certificate.
    req.target_cert_chain[1].index = req.target_cert_chain[0].index;
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "duplicate certificate indexes should not form a valid target chain"
    );
}

/// Rejects a target chain with reversed certificate order.
#[test]
fn darc_tmk_export_rejects_swapped_cert_descriptors() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );
    let der = chain.der_items();

    // Preserve OOB bytes but reverse the logical certificate-chain order.
    req.target_cert_chain.swap(0, 1);
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "reversing the certificate chain must not validate"
    );
}

/// Rejects an export request with no target certificate descriptors.
#[test]
fn darc_tmk_export_rejects_empty_target_cert_chain() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );

    req.target_cert_chain.clear();
    assert!(
        ready.ctx.tbor_oob(&req, &chain.der_items()).is_err(),
        "empty target certificate chain must be rejected"
    );
}

/// Rejects an otherwise valid target chain containing corrupted DER.
#[test]
fn darc_tmk_export_rejects_tampered_target_der() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let (req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );
    let mut der = chain.der_items();

    // Keep the declared length unchanged but corrupt the DER encoding itself.
    let mut corrupted = der[0].to_vec();
    corrupted[0] ^= 0xFF;
    der[0] = &corrupted;
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "tampered target certificate DER must not be accepted"
    );
}

/// Exports distinct TMKs to the same target and re-imports both.
#[test]
fn darc_tmk_export_distinct_tmks_roundtrip_to_same_target() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let tmk_a = gen_masked_tmk(&ready);
    let tmk_b = gen_masked_tmk(&ready);

    let (req_a, chain_a) =
        build_valid_export(&ready, &ready.data, &target.pub_raw, source.masked, tmk_a);
    let (req_b, chain_b) =
        build_valid_export(&ready, &ready.data, &target.pub_raw, source.masked, tmk_b);
    let sealed_a = ready
        .ctx
        .tbor_oob(&req_a, &chain_a.der_items())
        .expect("export TMK A")
        .sealed_tmk;
    let sealed_b = ready
        .ctx
        .tbor_oob(&req_b, &chain_b.der_items())
        .expect("export TMK B")
        .sealed_tmk;
    assert_ne!(sealed_a, sealed_b);

    let imported_a = reimport(&ready, target.masked, &source.pub_raw, sealed_a);
    let imported_b = reimport(&ready, target.masked, &source.pub_raw, sealed_b);
    assert_eq!(imported_a.len(), MASKED_TMK_LEN);
    assert_eq!(imported_b.len(), MASKED_TMK_LEN);
    assert!(imported_a.iter().any(|&b| b != 0));
    assert!(imported_b.iter().any(|&b| b != 0));
    // Masking may be randomized: do not compare imported masked ciphertexts.
}

/// Prevents a different target private key from importing the sealed TMK.
#[test]
fn darc_tmk_export_sealed_tmk_is_bound_to_target_receiver() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target_a = mint_kex(&ready);
    let target_b = mint_kex(&ready);
    let (req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target_a.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );
    let sealed = ready
        .ctx
        .tbor_oob(&req, &chain.der_items())
        .expect("export for target A")
        .sealed_tmk;

    // The import-side sender chain must be valid, so only the receiver
    // private key differs from the positive round-trip case.
    let sender_chain = make_chain(&ready.pota, &source.pub_raw);
    let sender_der = sender_chain.der_items();
    let sender_descriptors = vec![
        CertDescriptor {
            index: 0,
            length: (sender_der[0].len() as u16).into(),
        },
        CertDescriptor {
            index: 1,
            length: (sender_der[1].len() as u16).into(),
        },
    ];
    let import_req = TborDarcTmkImportReq {
        session_id: ready.session.session_id,
        masked_kex_key: target_b.masked,
        policy: ready.policy.clone(),
        sealed_tmk: sealed,
        remote_cert_chain: sender_descriptors,
    };
    assert!(
        ready.ctx.tbor_oob(&import_req, &sender_der).is_err(),
        "target B must not be able to decrypt an envelope sealed for A"
    );
    // Also prove the same envelope is valid for the intended recipient.
    let imported = reimport(&ready, target_a.masked, &source.pub_raw, sealed);
    assert_eq!(imported.len(), MASKED_TMK_LEN);
}

/// Rejects the maximum session ID without disrupting the active CO session.
#[test]
fn darc_tmk_export_rejects_max_session_id_and_recovers() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );
    let der = chain.der_items();
    let session_id = req.session_id;

    req.session_id = u16::MAX;
    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "an unallocated maximum session ID must be rejected"
    );

    req.session_id = session_id;
    ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("valid export after invalid session");
}

/// Rejects missing out-of-band target certificates even with valid descriptors.
#[test]
fn darc_tmk_export_rejects_missing_oob_certificates() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let (req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );

    let empty: [&[u8]; 0] = [];
    assert!(
        ready.ctx.tbor_oob(&req, &empty).is_err(),
        "target chain cannot reference omitted OOB certificates"
    );
    ready
        .ctx
        .tbor_oob(&req, &chain.der_items())
        .expect("valid export after missing OOB");
}

/// Rejects a corrupted second target-chain certificate and accepts the original.
#[test]
fn darc_tmk_export_rejects_tampered_second_target_der() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let (req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );
    let original = chain.der_items();
    let mut tampered = original.clone();
    let mut second = original[1].to_vec();
    second[0] ^= 0xFF;
    tampered[1] = &second;

    assert!(
        ready.ctx.tbor_oob(&req, &tampered).is_err(),
        "corrupt second certificate must not validate"
    );
    ready
        .ctx
        .tbor_oob(&req, &original)
        .expect("valid export after bad second certificate");
}

/// Rejects a bad length for the second certificate without poisoning the session.
#[test]
fn darc_tmk_export_rejects_second_cert_length_mismatch() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );
    let der = chain.der_items();
    let original = req.target_cert_chain[1].length;
    req.target_cert_chain[1].length = 1u16.into();

    assert!(
        ready.ctx.tbor_oob(&req, &der).is_err(),
        "second certificate length mismatch must fail"
    );
    req.target_cert_chain[1].length = original;
    ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("valid export after restoring length");
}

/// Detects tampering at both ends of the authenticated masked sender key.
#[test]
fn darc_tmk_export_rejects_sender_key_boundary_tampering() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );
    let der = chain.der_items();
    let original = req.masked_sender_key;

    for offset in [0, MASKED_KEX_KEY_LEN - 1] {
        req.masked_sender_key = original;
        req.masked_sender_key[offset] ^= 0x01;
        assert!(
            ready.ctx.tbor_oob(&req, &der).is_err(),
            "sender key tampering at offset {offset} must fail"
        );
    }
    req.masked_sender_key = original;
    ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("valid export after boundary tampering");
}

/// Detects tampering at both ends of the authenticated masked TMK.
#[test]
fn darc_tmk_export_rejects_tmk_boundary_tampering() {
    let ready = sd_initialized_session_with_data();
    let source = mint_kex(&ready);
    let target = mint_kex(&ready);
    let (mut req, chain) = build_valid_export(
        &ready,
        &ready.data,
        &target.pub_raw,
        source.masked,
        gen_masked_tmk(&ready),
    );
    let der = chain.der_items();
    let original = req.masked_tmk;

    for offset in [0, MASKED_TMK_LEN - 1] {
        req.masked_tmk = original;
        req.masked_tmk[offset] ^= 0x01;
        assert!(
            ready.ctx.tbor_oob(&req, &der).is_err(),
            "masked TMK tampering at offset {offset} must fail"
        );
    }
    req.masked_tmk = original;
    ready
        .ctx
        .tbor_oob(&req, &der)
        .expect("valid export after boundary tampering");
}
