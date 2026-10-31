// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdResealRemoteBackup` command.
//!
//! `SdResealRemoteBackup` reseals a remote backup from a source recipient
//! to a destination recipient: it HPKE-Auth-opens the caller-supplied
//! `src_remote_backup` with the masked **receiver** key (recovering the
//! BKS3, authenticated by the source **sender** public key from
//! `src_evidence`) and HPKE-Auth-seals that BKS3 to the destination
//! **receiver** public key (from `dest_evidence`), returning
//! `dst_remote_backup`.  Nothing is persisted.
//!
//! These tests run a **self-reseal** on one partition: it mints receiver /
//! sender / destination SD sealing keys, uses `SdCreateRemoteBackup` to
//! produce a real source backup (BKS3 sealed to the receiver by the
//! sender), then reseals it.  A successful reseal is itself the correctness
//! check: the HPKE-Auth **open** only succeeds if the receiver key and the
//! attested sender key match those that sealed the source, so a non-error
//! result proves the BKS3 was recovered and resealed.
//!
//! Coverage:
//! * Happy path — a 161-byte, non-zero `dst_remote_backup`.
//! * Re-randomization — two reseals of the same source differ (fresh HPKE
//!   ephemeral each call).
//! * Tampered `src_remote_backup` → the open's AEAD auth fails → reject.
//! * Missing OOB evidence → `InvalidArg`.

use tsra_ddi_tbor_test_harness::x509_fixture::make_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::GeneratedChain;
use tsra_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::tbor_int::U16;
use tsra_ddi_tbor_types::CertDescriptor;
use tsra_ddi_tbor_types::PartPolicy;
use tsra_ddi_tbor_types::ReportDescriptor;
use tsra_ddi_tbor_types::TborSdResealRemoteBackupReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::PART_POLICY_LEN;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use zerocopy::TryFromBytes;

use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::finalized_backing_session;
use crate::commands::sd_create_remote_backup::masked_key_and_report;
use crate::commands::sd_create_remote_backup::masked_key_report_and_pub;

/// Both attestation evidences (source sender, destination receiver) laid
/// out in a single OOB page, with descriptors indexing into it.
struct ResealEvidence {
    /// OOB items in index order: the source evidence's `[mfgr root, mfgr
    /// leaf, owner root, owner leaf, part-owner root, part-owner leaf,
    /// report]` (indices 0..=6) followed by the destination evidence's
    /// (indices 7..=13).
    oob_items: Vec<Vec<u8>>,
    src_mfgr: Vec<CertDescriptor>,
    src_owner: Vec<CertDescriptor>,
    src_part_owner: Vec<CertDescriptor>,
    src_report: ReportDescriptor,
    dest_mfgr: Vec<CertDescriptor>,
    dest_owner: Vec<CertDescriptor>,
    dest_part_owner: Vec<CertDescriptor>,
    dest_report: ReportDescriptor,
}

impl ResealEvidence {
    fn oob(&self) -> Vec<&[u8]> {
        self.oob_items.iter().map(Vec::as_slice).collect()
    }
}

/// Append `der` as the next OOB item and return a descriptor for it.
fn push_item(items: &mut Vec<Vec<u8>>, der: &[u8]) -> CertDescriptor {
    let index = items.len() as u8;
    items.push(der.to_vec());
    CertDescriptor {
        index,
        length: U16::new(der.len() as u16),
    }
}

/// Push one evidence's three chains and report into `items`, returning
/// their descriptors.
fn push_evidence(
    items: &mut Vec<Vec<u8>>,
    mfgr: &GeneratedChain,
    owner: &GeneratedChain,
    part_owner: &GeneratedChain,
    report: &[u8],
) -> (
    Vec<CertDescriptor>,
    Vec<CertDescriptor>,
    Vec<CertDescriptor>,
    ReportDescriptor,
) {
    let m = vec![
        push_item(items, &mfgr.root_der),
        push_item(items, &mfgr.leaf_der),
    ];
    let o = vec![
        push_item(items, &owner.root_der),
        push_item(items, &owner.leaf_der),
    ];
    let p = vec![
        push_item(items, &part_owner.root_der),
        push_item(items, &part_owner.leaf_der),
    ];
    let r = push_item(items, report);
    (
        m,
        o,
        p,
        ReportDescriptor {
            index: r.index,
            length: r.length,
        },
    )
}

/// Build the combined source + destination evidence.  Each side's three
/// chains all certify `pid_pub` (the report signer), with the
/// partition-owner chain rooted at the policy `sata_key`.
fn build_reseal_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    src_report: &[u8],
    dest_report: &[u8],
) -> ResealEvidence {
    let mut items = Vec::new();
    let (src_mfgr, src_owner, src_part_owner, src_report_desc) = push_evidence(
        &mut items,
        &make_chain(&CaKey::generate(), pid_pub),
        &make_chain(&CaKey::generate(), pid_pub),
        &make_chain(sata_key, pid_pub),
        src_report,
    );
    let (dest_mfgr, dest_owner, dest_part_owner, dest_report_desc) = push_evidence(
        &mut items,
        &make_chain(&CaKey::generate(), pid_pub),
        &make_chain(&CaKey::generate(), pid_pub),
        &make_chain(sata_key, pid_pub),
        dest_report,
    );
    ResealEvidence {
        oob_items: items,
        src_mfgr,
        src_owner,
        src_part_owner,
        src_report: src_report_desc,
        dest_mfgr,
        dest_owner,
        dest_part_owner,
        dest_report: dest_report_desc,
    }
}

/// Assemble a `SdResealRemoteBackup` request.
fn reseal_request(
    session_id: u16,
    masked_receiver_key: Vec<u8>,
    evidence: &ResealEvidence,
    policy: &[u8; PART_POLICY_LEN],
    src_remote_backup: &[u8; POK_REMOTE_BACKUP_LEN],
) -> TborSdResealRemoteBackupReq {
    TborSdResealRemoteBackupReq {
        session_id,
        masked_sealing_key: masked_receiver_key
            .as_slice()
            .try_into()
            .expect("masked receiver key is exactly MASKED_SEALING_KEY_LEN bytes"),
        policy: PartPolicy::try_read_from_bytes(policy).expect("policy image is canonical"),
        src_mfgr_cert_chain: evidence.src_mfgr.clone(),
        src_owner_cert_chain: evidence.src_owner.clone(),
        src_part_owner_cert_chain: evidence.src_part_owner.clone(),
        src_report: evidence.src_report,
        dest_mfgr_cert_chain: evidence.dest_mfgr.clone(),
        dest_owner_cert_chain: evidence.dest_owner.clone(),
        dest_part_owner_cert_chain: evidence.dest_part_owner.clone(),
        dest_report: evidence.dest_report,
        src_remote_backup: *src_remote_backup,
    }
}

/// Create a real source backup: a fresh BKS3 sealed to the receiver's
/// attested public key (`receiver_pub`, certified by the receiver key
/// chain and attested by `receiver_report`) by the sender's masked key.
fn create_source_backup(
    ctx: &TestCtx,
    session_id: u16,
    pid_pub: &[u8; RAW_PUB_LEN],
    receiver_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    masked_sender_key: Vec<u8>,
    receiver_report: &[u8],
    policy: &[u8; PART_POLICY_LEN],
) -> [u8; POK_REMOTE_BACKUP_LEN] {
    let rcvr_ev = build_receiver_evidence(pid_pub, receiver_pub, sata_key, receiver_report);
    let req = backup_request(session_id, masked_sender_key, &rcvr_ev, policy);
    ctx.tbor_oob(&req, &rcvr_ev.oob())
        .expect("SdCreateRemoteBackup source backup")
        .pok_remote_backup
}

/// Build a valid reseal request with source and destination evidence.
fn valid_reseal_fixture() -> (TestCtx, TborSdResealRemoteBackupReq, ResealEvidence) {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let sid = session.session_id;

    let (masked_rcvr, report_rcvr, rcvr_pub) = masked_key_report_and_pub(&ctx, sid);

    let (masked_sndr, report_sndr) = masked_key_and_report(&ctx, sid);

    let (_masked_dst, report_dst) = masked_key_and_report(&ctx, sid);

    let src_backup = create_source_backup(
        &ctx,
        sid,
        &pid_pub,
        &rcvr_pub,
        &sata_key,
        masked_sndr,
        &report_rcvr,
        &policy,
    );

    let evidence = build_reseal_evidence(&pid_pub, &sata_key, &report_sndr, &report_dst);

    let req = reseal_request(sid, masked_rcvr, &evidence, &policy, &src_backup);

    (ctx, req, evidence)
}

/// Verify that a valid source backup can be successfully resealed.
#[test]
fn sd_reseal_remote_backup_roundtrip() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let sid = session.session_id;

    // Receiver (unseals the source), sender (sealed the source), and
    // destination (the reseal target) SD sealing keys, each attested.
    let (masked_rcvr, report_rcvr, rcvr_pub) = masked_key_report_and_pub(&ctx, sid);
    let (masked_sndr, report_sndr) = masked_key_and_report(&ctx, sid);
    let (_masked_dst, report_dst) = masked_key_and_report(&ctx, sid);

    // Source backup: BKS3 sealed to the receiver by the sender.
    let src_backup = create_source_backup(
        &ctx,
        sid,
        &pid_pub,
        &rcvr_pub,
        &sata_key,
        masked_sndr,
        &report_rcvr,
        &policy,
    );

    // Reseal: open with the receiver key (auth = sender), reseal to the
    // destination receiver.
    let evidence = build_reseal_evidence(&pid_pub, &sata_key, &report_sndr, &report_dst);
    let req = reseal_request(sid, masked_rcvr, &evidence, &policy, &src_backup);
    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdResealRemoteBackup roundtrip");

    // A successful HPKE open→seal yields a 161-byte, non-zero backup.
    assert_eq!(resp.dst_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        resp.dst_remote_backup.iter().any(|&b| b != 0),
        "dst_remote_backup must not be all-zero",
    );
    // The resealed backup is a fresh HPKE encapsulation, distinct from the
    // source ciphertext.
    assert_ne!(
        resp.dst_remote_backup, src_backup,
        "reseal must produce a fresh encapsulation, not echo the source",
    );
}

/// Verify that repeated reseals produce different HPKE ciphertexts.
#[test]
fn sd_reseal_remote_backup_rerandomizes() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let sid = session.session_id;

    let (masked_rcvr, report_rcvr, rcvr_pub) = masked_key_report_and_pub(&ctx, sid);
    let (masked_sndr, report_sndr) = masked_key_and_report(&ctx, sid);
    let (_masked_dst, report_dst) = masked_key_and_report(&ctx, sid);

    let src_backup = create_source_backup(
        &ctx,
        sid,
        &pid_pub,
        &rcvr_pub,
        &sata_key,
        masked_sndr,
        &report_rcvr,
        &policy,
    );

    let evidence = build_reseal_evidence(&pid_pub, &sata_key, &report_sndr, &report_dst);
    let req = reseal_request(sid, masked_rcvr, &evidence, &policy, &src_backup);

    let first = ctx.tbor_oob(&req, &evidence.oob()).expect("first reseal");
    let second = ctx.tbor_oob(&req, &evidence.oob()).expect("second reseal");

    // Each reseal uses a fresh HPKE ephemeral → distinct ciphertexts.
    assert_ne!(
        first.dst_remote_backup, second.dst_remote_backup,
        "each reseal must re-randomize the HPKE encapsulation",
    );
}

/// Reject a source backup with corrupted ciphertext.
#[test]
fn sd_reseal_remote_backup_rejects_tampered_src() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let sid = session.session_id;

    let (masked_rcvr, report_rcvr, rcvr_pub) = masked_key_report_and_pub(&ctx, sid);
    let (masked_sndr, report_sndr) = masked_key_and_report(&ctx, sid);
    let (_masked_dst, report_dst) = masked_key_and_report(&ctx, sid);

    let mut src_backup = create_source_backup(
        &ctx,
        sid,
        &pid_pub,
        &rcvr_pub,
        &sata_key,
        masked_sndr,
        &report_rcvr,
        &policy,
    );
    // Flip a byte in the ciphertext region so the HPKE-Auth open fails.
    src_backup[POK_REMOTE_BACKUP_LEN - 1] ^= 0xFF;

    let evidence = build_reseal_evidence(&pid_pub, &sata_key, &report_sndr, &report_dst);
    let req = reseal_request(sid, masked_rcvr, &evidence, &policy, &src_backup);

    // The evidence still validates, but the unseal's AEAD tag check fails.
    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("tampered source backup must fail the HPKE open");
}

/// Reject a reseal request when the required OOB evidence is missing.
#[test]
fn sd_reseal_remote_backup_rejects_missing_oob() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let sid = session.session_id;

    let (masked_rcvr, report_rcvr, rcvr_pub) = masked_key_report_and_pub(&ctx, sid);
    let (masked_sndr, report_sndr) = masked_key_and_report(&ctx, sid);
    let (_masked_dst, report_dst) = masked_key_and_report(&ctx, sid);

    let src_backup = create_source_backup(
        &ctx,
        sid,
        &pid_pub,
        &rcvr_pub,
        &sata_key,
        masked_sndr,
        &report_rcvr,
        &policy,
    );

    // The evidence descriptors reference OOB items, but no OOB page is
    // supplied → the handler rejects before any crypto.
    let evidence = build_reseal_evidence(&pid_pub, &sata_key, &report_sndr, &report_dst);
    let req = reseal_request(sid, masked_rcvr, &evidence, &policy, &src_backup);
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Reject a reseal request referencing an unknown session.
#[test]
fn sd_reseal_remote_backup_invalid_session_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.session_id = u16::MAX;

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("unknown session must be rejected");
}

/// Reject a masked receiver key that does not match the source backup.
#[test]
fn sd_reseal_remote_backup_wrong_receiver_key_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    let (wrong_masked_key, _) = masked_key_and_report(&ctx, req.session_id);

    req.masked_sealing_key = wrong_masked_key
        .as_slice()
        .try_into()
        .expect("masked key has the required length");

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("wrong receiver key must be rejected");
}

/// Reject a source remote backup containing only zeros.
#[test]
fn sd_reseal_remote_backup_empty_source_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.src_remote_backup = [0u8; POK_REMOTE_BACKUP_LEN];

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("empty source backup must be rejected");
}

/// Reject a source backup with a corrupted HPKE encapsulation.
#[test]
fn sd_reseal_remote_backup_tampered_encapsulation_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.src_remote_backup[0] ^= 0xFF;

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("tampered encapsulation must be rejected");
}

/// Reject source evidence without its manufacturer certificate chain.
#[test]
fn sd_reseal_remote_backup_missing_src_mfgr_chain_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.src_mfgr_cert_chain.clear();

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("missing source manufacturer chain must be rejected");
}

/// Reject destination evidence without its manufacturer certificate chain.
#[test]
fn sd_reseal_remote_backup_missing_dest_mfgr_chain_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.dest_mfgr_cert_chain.clear();

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("missing destination manufacturer chain must be rejected");
}

/// Reject a source attestation report referencing a nonexistent OOB item.
#[test]
fn sd_reseal_remote_backup_invalid_src_report_index_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.src_report.index = u8::MAX;

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("invalid source report index must be rejected");
}

/// Reject source evidence that authenticates a different sender.
#[test]
fn sd_reseal_remote_backup_wrong_sender_evidence_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    // Generate another sender key and use its attestation report.
    let (_masked_other_sender, other_sender_report) = masked_key_and_report(&ctx, req.session_id);

    // Replace the source sender report in the OOB evidence.
    let mut evidence = evidence;
    evidence.oob_items[req.src_report.index as usize] = other_sender_report;

    req.src_report.length =
        U16::new(evidence.oob_items[req.src_report.index as usize].len() as u16);

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("wrong source sender evidence must be rejected");
}

/// Reject a masked receiver key that has been corrupted.
#[test]
fn sd_reseal_remote_backup_tampered_masked_key_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    let mut masked_key = req.masked_sealing_key.to_vec();
    masked_key[0] ^= 0xFF;

    req.masked_sealing_key = masked_key
        .as_slice()
        .try_into()
        .expect("masked key has the required length");

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("tampered masked receiver key must be rejected");
}

/// Reject an attestation report that references a nonexistent OOB item.
#[test]
fn sd_reseal_remote_backup_invalid_dest_report_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.dest_report.index = u8::MAX;

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("invalid destination report must be rejected");
}

/// Reject a source report whose attestation bytes have been corrupted.
#[test]
fn sd_reseal_remote_backup_corrupted_src_report_rejected() {
    let (ctx, req, mut evidence) = valid_reseal_fixture();

    let report = &mut evidence.oob_items[req.src_report.index as usize];

    assert!(!report.is_empty(), "source report must not be empty");
    let last = report.len() - 1;
    report[last] ^= 0xFF;

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("corrupted source report must be rejected");
}

/// Reject a destination report whose attestation bytes have been corrupted.
#[test]
fn sd_reseal_remote_backup_corrupted_dest_report_rejected() {
    let (ctx, req, mut evidence) = valid_reseal_fixture();

    let report = &mut evidence.oob_items[req.dest_report.index as usize];

    assert!(!report.is_empty(), "destination report must not be empty");
    let last = report.len() - 1;
    report[last] ^= 0xFF;

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("corrupted destination report must be rejected");
}

/// Reject source evidence without its partition-owner certificate chain.
#[test]
fn sd_reseal_remote_backup_missing_src_part_owner_chain_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.src_part_owner_cert_chain.clear();

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("missing source partition-owner chain must be rejected");
}

/// Reject destination evidence without its partition-owner certificate chain.
#[test]
fn sd_reseal_remote_backup_missing_dest_part_owner_chain_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.dest_part_owner_cert_chain.clear();

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("missing destination partition-owner chain must be rejected");
}

/// Reject source evidence with an invalid attestation report length.
#[test]
fn sd_reseal_remote_backup_invalid_src_report_length_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.src_report.length = U16::new(0);

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("invalid source report length must be rejected");
}

/// Reject destination evidence with an invalid attestation report length.
#[test]
fn sd_reseal_remote_backup_invalid_dest_report_length_rejected() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.dest_report.length = U16::new(0);

    ctx.tbor_oob(&req, &evidence.oob())
        .expect_err("invalid destination report length must be rejected");
}

/// Verify that resealing succeeds without a source owner certificate chain.
#[test]
fn sd_reseal_remote_backup_empty_src_owner_chain_succeeds() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.src_owner_cert_chain.clear();

    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("reseal should succeed without source owner chain");

    assert_eq!(resp.dst_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(resp.dst_remote_backup.iter().any(|&b| b != 0));
}

/// Verify that resealing succeeds without a destination owner certificate chain.
#[test]
fn sd_reseal_remote_backup_empty_dest_owner_chain_succeeds() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.dest_owner_cert_chain.clear();

    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("reseal should succeed without destination owner chain");

    assert_eq!(resp.dst_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(resp.dst_remote_backup.iter().any(|&b| b != 0));
}

/// Verify that resealing succeeds with session ID zero.
#[test]
fn sd_reseal_remote_backup_zero_session_succeeds() {
    let (ctx, mut req, evidence) = valid_reseal_fixture();

    req.session_id = 0;

    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("reseal should succeed with session ID zero");

    assert_eq!(resp.dst_remote_backup.len(), POK_REMOTE_BACKUP_LEN);

    assert!(
        resp.dst_remote_backup.iter().any(|&b| b != 0),
        "resealed backup must not be all-zero"
    );
}
