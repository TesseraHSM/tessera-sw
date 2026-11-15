// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdRestoreRemoteBackup` command.
//!
//! `SdRestoreRemoteBackup` restores a security domain from a **remote**
//! backup: it HPKE Base-opens `src_remote_backup` (an HPKE seal of BKS3)
//! with the receiver's masked SD-sealing key after verifying the mandatory
//! PID-signed operation report and policy. It recovers `SDMK` from `prev_sd_mk_backup`, and
//! returns the device-local backups.
//!
//! The **round-trip** test uses a self-backup (sender == receiver): a first
//! device finalizes and `CreateSD`s (producing the `pok_remote_backup` /
//! `sd_mk_backup` this command consumes, plus the `local_mk_backup`), then a
//! second device (factory-reset, same machine seed) restores `PartLocalMK`
//! via `PartFinal` — so it can unmask the captured sealing key — and
//! restores the security domain from the remote backup.
//!
//! Coverage:
//! * Round-trip — create → reboot → PartFinal(restore PartLocalMK) →
//!   restore-remote returns non-zero refreshed local backups.
//! * One-shot — restore onto an already-initialized SD → `SdAlreadyInitialized`.
//! * Restore before finalize → `InvalidArg`.

use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::x509_fixture::make_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use tsra_ddi_tbor_types::TborSdRestoreRemoteBackupReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MASKED_SD_LEN;
use tsra_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;
use tsra_ddi_tbor_types::SD_SEALING_KEM_MLKEM1024;
use tsra_ddi_tbor_types::SD_SEALING_KEM_MLKEM1024_P384;

use crate::commands::common::assert_masked_key_layout_rejected;
use crate::commands::part_info::assert_part_state;
use crate::commands::part_info::PART_STATE_INITIALIZED;
use crate::commands::part_init::mach_seed;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backing_part_policy_trusted;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::evidence_from_chains;
use crate::commands::sd_create_remote_backup::kem_sealing_key_and_report;
use crate::commands::sd_create_remote_backup::masked_key_report_and_pub;
use crate::commands::sd_create_remote_backup::resign_key_report;
use crate::commands::sd_create_remote_backup::ReceiverEvidence;
use crate::commands::sd_create_remote_backup::SdOob;

/// A remote backup produced by the first device's `CreateSD`, replayed on
/// the second (rebooted) device to restore the security domain.
struct RemoteBackup {
    pid_pub: [u8; RAW_PUB_LEN],
    /// The receiver's masked SD-sealing key (used to open the backup).
    masked_sealing_key: Vec<u8>,
    /// Source PID identity chains and the create command's operation report.
    evidence: ReceiverEvidence,
    /// The 584-byte `PartPolicy` image.
    policy: Vec<u8>,
    /// `pok_remote_backup` from `CreateSD` — the HPKE seal to restore.
    src_remote_backup: Vec<u8>,
    /// `sd_mk_backup` from `CreateSD` — the previous SDMK backup.
    prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
    /// `PartFinal`'s `local_mk_backup`, replayed to restore `PartLocalMK`.
    local_mk_backup: Vec<u8>,
}

/// Drive device 1: finalize a backing partition, `CreateSD`, and capture
/// everything device 2 needs to restore the domain remotely.
fn create_remote_backup(seed: &[u8], sata: &CaKey, pota: &CaKey) -> RemoteBackup {
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

    let init = ctx.part_init(&session, seed, &policy).expect("PartInit");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal")
        .local_mk_backup;

    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, sata, &report);
    let req = backup_request(session.session_id, &evidence, &policy);
    let resp = ctx
        .sd_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    RemoteBackup {
        pid_pub,
        masked_sealing_key: masked,
        evidence: evidence.with_report(&resp.report),
        policy,
        src_remote_backup: resp.resp.pok_remote_backup,
        prev_sd_mk_backup: resp.resp.sd_mk_backup,
        local_mk_backup,
    }
}

/// Device 1 finalized under a trusted-SA-key policy, before `CreateSD`.
struct TrustedSource {
    ctx: TestCtx,
    session: SessionHandshake,
    pid_pub: [u8; RAW_PUB_LEN],
    policy: Vec<u8>,
    local_mk_backup: Vec<u8>,
}

/// Finalize device 1 under a trusted-SA-key policy anchored at `sata`
/// (receiver chain), `sapota` (evidence) and `pota` (PTA).
fn trusted_source(sata: &CaKey, sapota: &CaKey, pota: &CaKey) -> TrustedSource {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);
    let policy = backing_part_policy_trusted(
        &info.pid,
        &info.pid_pub_key,
        &sata.raw_pub(),
        &sapota.raw_pub(),
        &pota.raw_pub(),
    );

    let init = ctx
        .part_init(&session, &mach_seed(), &policy)
        .expect("PartInit");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal")
        .local_mk_backup;

    TrustedSource {
        ctx,
        session,
        pid_pub,
        policy,
        local_mk_backup,
    }
}

/// A trusted-SA `SdCreateRemoteBackup` request whose recipient is a local
/// sealing key of `kem`: the SATA-certified receiver `leaf` signs a
/// receiver key report over it (re-signed by `report_signer`, normally the
/// leaf), and the device's PID-signed report over `attested_kem` is the
/// trusted-SA evidence.  Returns the masked key, the evidence and the
/// request.
fn pq_remote_request(
    src: &TrustedSource,
    sata: &CaKey,
    sapota: &CaKey,
    kem: u8,
    report_signer: Option<&CaKey>,
) -> (Vec<u8>, ReceiverEvidence, TborSdCreateRemoteBackupReq) {
    let sid = src.session.session_id;
    let (masked, report) = kem_sealing_key_and_report(&src.ctx, sid, kem);
    let leaf = CaKey::generate();
    let receiver = make_chain(sata, &leaf.raw_pub());
    let mfgr = make_chain(&CaKey::generate(), &src.pid_pub);
    let owner = make_chain(&CaKey::generate(), &src.pid_pub);
    let part_owner = make_chain(sapota, &src.pid_pub);
    let mut evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);
    let kem_report = resign_key_report(&report, report_signer.unwrap_or(&leaf));
    let desc = evidence.push_report(&kem_report);
    let mut req = backup_request(sid, &evidence, &src.policy);
    req.receiver_key_report = vec![desc];
    (masked, evidence, req)
}

/// [`create_remote_backup_trusted`] sealed to a local PQ sealing key of
/// `kem` through a SATA-leaf-signed receiver key report.
fn create_pq_remote_backup_trusted(
    sata: &CaKey,
    sapota: &CaKey,
    pota: &CaKey,
    kem: u8,
) -> RemoteBackup {
    let src = trusted_source(sata, sapota, pota);
    let (masked, evidence, req) = pq_remote_request(&src, sata, sapota, kem, None);
    let resp = src
        .ctx
        .sd_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup PQ trusted-SA");
    assert!(resp.pok_remote_backup.len() > POK_REMOTE_BACKUP_LEN);
    RemoteBackup {
        pid_pub: src.pid_pub,
        masked_sealing_key: masked,
        evidence: evidence.with_report(&resp.report),
        policy: src.policy,
        src_remote_backup: resp.resp.pok_remote_backup,
        prev_sd_mk_backup: resp.resp.sd_mk_backup,
        local_mk_backup: src.local_mk_backup,
    }
}

/// Drive device 1 under a **trusted-SA-key** policy
/// (`require_trusted_sa_key` set): finalize, `CreateSD` with full
/// SAPOTA-anchored evidence, and capture everything device 2 needs to
/// restore the domain remotely with evidence verification enabled.
fn create_remote_backup_trusted(sata: &CaKey, sapota: &CaKey, pota: &CaKey) -> RemoteBackup {
    let TrustedSource {
        ctx,
        session,
        pid_pub,
        policy,
        local_mk_backup,
    } = trusted_source(sata, sapota, pota);
    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    // The sender/receiver chain leaf is the attested sealing key, SATA-
    // anchored; the evidence part-owner chain is SAPOTA-anchored and every
    // evidence leaf certifies `pid_pub` (the report signer).
    let receiver = make_chain(sata, &rcvr_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(sapota, &pid_pub);
    let evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);

    let req = backup_request(session.session_id, &evidence, &policy);
    let resp = ctx
        .sd_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup trusted-SA");

    RemoteBackup {
        pid_pub,
        masked_sealing_key: masked,
        evidence: evidence.with_report(&resp.report),
        policy,
        src_remote_backup: resp.resp.pok_remote_backup,
        prev_sd_mk_backup: resp.resp.sd_mk_backup,
        local_mk_backup,
    }
}

/// Assemble a `SdRestoreRemoteBackup` request from a captured backup.
fn restore_remote_req(session_id: u16, backup: &RemoteBackup) -> TborSdRestoreRemoteBackupReq {
    TborSdRestoreRemoteBackupReq {
        session_id,
        masked_sealing_key: backup.masked_sealing_key.clone(),
        policy: backup.policy.clone(),
        sender_pid_pub_key: backup.pid_pub.to_vec(),
        sender_mfgr_cert_chain: backup.evidence.mfgr.clone(),
        sender_owner_cert_chain: backup.evidence.owner.clone(),
        sender_part_owner_cert_chain: backup.evidence.part_owner.clone(),
        sender_report: backup.evidence.report,
        src_remote_backup: backup.src_remote_backup.clone(),
        prev_sd_mk_backup: backup.prev_sd_mk_backup,
    }
}

#[test]
fn sd_restore_remote_backup_roundtrip() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: finalize + CreateSD, capturing the remote backup.
    let backup = create_remote_backup(&seed, &sata, &pota);

    // Device 2 (reboot): restore PartLocalMK (so the captured sealing key
    // unmasks), then restore the SD from the remote backup.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, &seed, &backup.policy)
        .expect("PartInit (device 2)");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &backup.policy,
        &backup.local_mk_backup,
        &chain.der_items(),
    )
    .expect("PartFinal must restore PartLocalMK from the prior backup");
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);

    let req = restore_remote_req(session.session_id, &backup);
    let resp = ctx
        .sd_oob(&req, &backup.evidence.oob())
        .expect("SdRestoreRemoteBackup roundtrip");
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);

    // Local backup (BKS3 masked under PartLocalMK), 280 B, non-zero.
    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        resp.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );
    // Refreshed masking-key backup (SDMK re-masked under SDBMK), 264 B.
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        resp.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

#[test]
fn sd_restore_remote_backup_trusted_sa_roundtrip() {
    let sata = CaKey::generate();
    let sapota = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: finalize + CreateSD under a trusted-SA-key policy.
    let backup = create_remote_backup_trusted(&sata, &sapota, &pota);

    // Restore PartLocalMK and require SAPOTA authorization of the operation PID.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, &mach_seed(), &backup.policy)
        .expect("PartInit (device 2)");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &backup.policy,
        &backup.local_mk_backup,
        &chain.der_items(),
    )
    .expect("PartFinal must restore PartLocalMK from the prior backup");

    let req = restore_remote_req(session.session_id, &backup);
    let resp = ctx
        .sd_oob(&req, &backup.evidence.oob())
        .expect("SdRestoreRemoteBackup trusted-SA roundtrip");

    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        resp.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        resp.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

/// Remote backups sealed to ML-KEM-1024 and MLKEM1024-P384 sealing keys
/// (SATA-leaf-signed receiver key report) restore the SD on device 2.
#[test]
fn sd_restore_remote_backup_pq_trusted_sa_roundtrip() {
    for kem in [SD_SEALING_KEM_MLKEM1024, SD_SEALING_KEM_MLKEM1024_P384] {
        let sata = CaKey::generate();
        let sapota = CaKey::generate();
        let pota = CaKey::generate();
        let backup = create_pq_remote_backup_trusted(&sata, &sapota, &pota, kem);
        let (ctx, sid) = restore_target(&mach_seed(), &pota, &backup);
        let resp = ctx
            .sd_oob(&restore_remote_req(sid, &backup), &backup.evidence.oob())
            .expect("SdRestoreRemoteBackup PQ");
        assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
        assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
    }
}

/// The receiver key report must be signed by the SATA-certified leaf.
#[test]
fn sd_create_remote_backup_rejects_receiver_key_report_wrong_signer() {
    let (sata, sapota, pota) = (CaKey::generate(), CaKey::generate(), CaKey::generate());
    let src = trusted_source(&sata, &sapota, &pota);
    let impostor = CaKey::generate();
    let (_, evidence, req) = pq_remote_request(
        &src,
        &sata,
        &sapota,
        SD_SEALING_KEM_MLKEM1024,
        Some(&impostor),
    );
    src.ctx
        .expect_sd_reject(&req, &evidence.oob(), TborStatus::InvalidArg);
}

/// Under a trusted-SA policy the device-attested key must equal the KEM key
/// from the receiver key report, and at most one receiver key report is
/// accepted.
#[test]
fn sd_create_remote_backup_rejects_receiver_key_report_mismatch() {
    let (sata, sapota, pota) = (CaKey::generate(), CaKey::generate(), CaKey::generate());
    let src = trusted_source(&sata, &sapota, &pota);
    let sid = src.session.session_id;

    // Swap the trusted-SA evidence for a report over a different PQ key.
    let (_, evidence, req) =
        pq_remote_request(&src, &sata, &sapota, SD_SEALING_KEM_MLKEM1024_P384, None);
    let (_, other) = kem_sealing_key_and_report(&src.ctx, sid, SD_SEALING_KEM_MLKEM1024_P384);
    let swapped = evidence.with_report(&other);
    let mut mismatched = req.clone();
    mismatched.receiver_report = swapped.report;
    src.ctx
        .expect_sd_reject(&mismatched, &swapped.oob(), TborStatus::InvalidArg);

    // Two receiver key reports are rejected at decode (`max_len = 1`).
    let (_, evidence, mut req) =
        pq_remote_request(&src, &sata, &sapota, SD_SEALING_KEM_MLKEM1024, None);
    req.receiver_key_report.push(req.receiver_key_report[0]);
    src.ctx
        .expect_sd_reject(&req, &evidence.oob(), TborStatus::TborInvalidFixedLength);
    assert_part_state(&src.ctx, PART_STATE_INITIALIZED, false);
}

#[test]
fn sd_restore_remote_backup_is_one_shot() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // A single device that has just created its SD is already
    // SD-initialized, so a remote restore on the same incarnation is
    // rejected by the one-shot gate.
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

    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata, &report);
    let create_req = backup_request(session.session_id, &evidence, &policy);
    let created = ctx
        .sd_oob(&create_req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    let backup = RemoteBackup {
        pid_pub,
        masked_sealing_key: masked,
        evidence: evidence.with_report(&created.report),
        policy,
        src_remote_backup: created.resp.pok_remote_backup,
        prev_sd_mk_backup: created.resp.sd_mk_backup,
        local_mk_backup: Vec::new(),
    };
    let req = restore_remote_req(session.session_id, &backup);
    ctx.expect_sd_reject(
        &req,
        &backup.evidence.oob(),
        TborStatus::SdAlreadyInitialized,
    );
}

#[test]
fn sd_restore_remote_backup_rejects_before_finalize() {
    // A partition that has not been finalized is rejected at the lifecycle
    // gate before any evidence or crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let req = TborSdRestoreRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: vec![0u8; MASKED_SEALING_KEY_LEN],
        policy: Vec::new(),
        sender_pid_pub_key: vec![0u8; RAW_PUB_LEN],
        sender_mfgr_cert_chain: Vec::new(),
        sender_owner_cert_chain: Vec::new(),
        sender_part_owner_cert_chain: Vec::new(),
        sender_report: Default::default(),
        src_remote_backup: vec![0u8; POK_REMOTE_BACKUP_LEN],
        prev_sd_mk_backup: [0u8; SD_MK_BACKUP_LEN],
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Rejects a misaligned masked sealing key and one without its padding
/// entry; the decoder rejects before the OOB evidence is read.
#[test]
fn sd_restore_remote_backup_rejects_bad_masked_key_layout() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let backup = create_remote_backup(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, &seed, &backup.policy)
        .expect("PartInit (device 2)");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &backup.policy,
        &backup.local_mk_backup,
        &chain.der_items(),
    )
    .expect("PartFinal must restore PartLocalMK from the prior backup");

    assert_masked_key_layout_rejected(&ctx, &restore_remote_req(session.session_id, &backup));
}

fn restore_target(seed: &[u8], pota: &CaKey, backup: &RemoteBackup) -> (TestCtx, u16) {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, seed, &backup.policy)
        .expect("PartInit restore target");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &backup.policy,
        &backup.local_mk_backup,
        &chain.der_items(),
    )
    .expect("restore recipient's original masking key");
    (ctx, session.session_id)
}

#[test]
fn sd_restore_remote_backup_signature_only_requires_bound_operation_report_and_allows_retry() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let backup = create_remote_backup(&seed, &sata, &pota);
    let (ctx, sid) = restore_target(&seed, &pota, &backup);
    let mut valid = restore_remote_req(sid, &backup);
    valid.sender_mfgr_cert_chain.clear();
    valid.sender_owner_cert_chain.clear();
    valid.sender_part_owner_cert_chain.clear();

    let original = backup.evidence.oob()[valid.sender_report.index as usize].to_vec();
    let mut corrupt = original.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    let (_, public_key_report, _) = masked_key_report_and_pub(&ctx, sid);
    for report in [Vec::new(), corrupt, public_key_report] {
        let evidence = backup.evidence.clone().with_report(&report);
        let mut req = valid.clone();
        req.sender_report = evidence.report;
        assert!(ctx.sd_oob(&req, &evidence.oob()).is_err());
        assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
    }

    let mut wrong_signer = valid.clone();
    wrong_signer.sender_pid_pub_key.fill(0);
    assert!(ctx.sd_oob(&wrong_signer, &backup.evidence.oob()).is_err());

    let (other_receiver, _, _) = masked_key_report_and_pub(&ctx, sid);
    let mut wrong_recipient = valid.clone();
    wrong_recipient.masked_sealing_key = other_receiver;
    assert!(ctx
        .sd_oob(&wrong_recipient, &backup.evidence.oob())
        .is_err());

    for offset in [17, 65, 113, 161, POK_REMOTE_BACKUP_LEN - 1] {
        let mut req = valid.clone();
        req.src_remote_backup[offset] ^= 1;
        assert!(
            ctx.sd_oob(&req, &backup.evidence.oob()).is_err(),
            "offset {offset}"
        );
        assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
    }

    ctx.sd_oob(&valid, &backup.evidence.oob())
        .expect("signature-only restore with mandatory report and no identity chains");
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
}

#[test]
fn sd_restore_remote_backup_trusted_sa_requires_authorized_pid_and_allows_retry() {
    let sata = CaKey::generate();
    let sapota = CaKey::generate();
    let pota = CaKey::generate();
    let backup = create_remote_backup_trusted(&sata, &sapota, &pota);
    let (ctx, sid) = restore_target(&mach_seed(), &pota, &backup);
    let valid = restore_remote_req(sid, &backup);
    let wrong_anchor = backup
        .evidence
        .with_part_owner_chain(&make_chain(&CaKey::generate(), &backup.pid_pub));
    let mut req = valid.clone();
    req.sender_part_owner_cert_chain = wrong_anchor.part_owner.clone();
    assert!(ctx.sd_oob(&req, &wrong_anchor.oob()).is_err());

    let mut missing_identity = valid.clone();
    missing_identity.sender_mfgr_cert_chain.clear();
    missing_identity.sender_part_owner_cert_chain.clear();
    assert!(ctx
        .sd_oob(&missing_identity, &backup.evidence.oob())
        .is_err());

    let mut mismatched_pid = valid.clone();
    mismatched_pid.sender_pid_pub_key[0] ^= 1;
    assert!(ctx.sd_oob(&mismatched_pid, &backup.evidence.oob()).is_err());
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
    ctx.sd_oob(&valid, &backup.evidence.oob())
        .expect("authorized PID restore after failures");
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
}
