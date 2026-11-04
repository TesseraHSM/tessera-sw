// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdRestorePeerBackup` command.
//!
//! `SdRestorePeerBackup` restores a security domain from a **peer** backup:
//! it HPKE-Auth-opens the caller-supplied `pok_peer_backup` (an HPKE seal
//! of BKS3) with the receiver's masked SD-sealing key — authenticated by
//! the sender peer's attested key — recovers `SDMK` from `prev_sd_mk_backup`,
//! and returns the device-local backups.  It is `SdRestoreRemoteBackup`
//! plus an `allow_peer_cloning` policy gate.
//!
//! The **round-trip** test uses a self-peer backup (sender == receiver): a
//! first device finalizes, `CreateSD`s, and `CreatePeerBackup`s (producing
//! the `pok_peer_backup` / `prev_sd_mk_backup` this command consumes, plus
//! the `local_mk_backup`), then a second device (factory-reset, same machine
//! seed) restores `PartLocalMK` via `PartFinal` — so it can unmask the
//! captured sealing key — and restores the security domain from the peer
//! backup.
//!
//! Coverage:
//! * Round-trip — create-peer → reboot → PartFinal(restore PartLocalMK) →
//!   restore-peer returns non-zero refreshed local backups.
//! * One-shot — restore onto an already-initialized SD → `SdAlreadyInitialized`.
//! * Policy without `allow_peer_cloning` → `SdPeerCloningNotAllowed`.
//! * Restore before finalize → `InvalidArg`.

use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_types::PartPolicy;
use tsra_ddi_tbor_types::TborSdRestorePeerBackupReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MASKED_SD_LEN;
use tsra_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use tsra_ddi_tbor_types::PART_POLICY_LEN;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;
use zerocopy::TryFromBytes;

use crate::commands::part_info::assert_part_state;
use crate::commands::part_info::PART_STATE_INITIALIZED;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::sd_create_peer_backup::create_peer_req;
use crate::commands::sd_create_peer_backup::finalize_peer_partition;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_report_and_pub;
use crate::commands::sd_create_remote_backup::ReceiverEvidence;

/// A peer backup produced by the first device's `CreatePeerBackup`,
/// replayed on the second (rebooted) device to restore the security domain.
struct PeerBackup {
    /// The receiver's masked SD-sealing key (used to open the backup).
    masked_sealing_key: Vec<u8>,
    /// Sender attestation evidence (OOB items + descriptors).  In a
    /// self-peer backup this is the same evidence the seal used.
    evidence: ReceiverEvidence,
    /// The 584-byte `PartPolicy` image (with `allow_peer_cloning` set).
    policy: [u8; PART_POLICY_LEN],
    /// `pok_peer_backup` from `CreatePeerBackup` — the HPKE seal to restore.
    pok_peer_backup: [u8; POK_REMOTE_BACKUP_LEN],
    /// `sd_mk_backup` from `CreateSD` — the previous SDMK backup.
    prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
    /// `PartFinal`'s `local_mk_backup`, replayed to restore `PartLocalMK`.
    local_mk_backup: Vec<u8>,
}

/// Drive device 1: finalize a cloning-enabled backing partition, `CreateSD`,
/// and `CreatePeerBackup`, capturing everything device 2 needs to restore
/// the domain from the peer backup.
fn create_peer_backup(seed: &[u8], sata: &CaKey, pota: &CaKey) -> PeerBackup {
    let ctx = TestCtx::new();
    let part = finalize_peer_partition(&ctx, seed, sata, pota, true);
    let session_id = part.session.session_id;

    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session_id);
    let evidence = build_receiver_evidence(&part.pid_pub, &rcvr_pub, sata, &report);
    let created = ctx
        .tbor_oob(
            &backup_request(session_id, masked.clone(), &evidence, &part.policy),
            &evidence.oob(),
        )
        .expect("SdCreateRemoteBackup");
    let peer = ctx
        .tbor_oob(
            &create_peer_req(
                session_id,
                &masked,
                &evidence,
                &part.policy,
                &created.pok_local_backup,
            ),
            &evidence.oob(),
        )
        .expect("SdCreatePeerBackup");

    PeerBackup {
        masked_sealing_key: masked,
        evidence,
        policy: part.policy,
        pok_peer_backup: peer.pok_peer_backup,
        prev_sd_mk_backup: created.sd_mk_backup,
        local_mk_backup: part.local_mk_backup,
    }
}

/// Assemble a `SdRestorePeerBackup` request from a captured backup.
fn restore_peer_req(session_id: u16, backup: &PeerBackup) -> TborSdRestorePeerBackupReq {
    TborSdRestorePeerBackupReq {
        session_id,
        masked_sealing_key: backup
            .masked_sealing_key
            .as_slice()
            .try_into()
            .expect("masked sealing key is exactly MASKED_SEALING_KEY_LEN bytes"),
        policy: PartPolicy::try_read_from_bytes(&backup.policy).expect("policy image is canonical"),
        src_mfgr_cert_chain: backup.evidence.mfgr.clone(),
        src_owner_cert_chain: backup.evidence.owner.clone(),
        src_part_owner_cert_chain: backup.evidence.part_owner.clone(),
        src_report: backup.evidence.report,
        pok_peer_backup: backup.pok_peer_backup,
        prev_sd_mk_backup: backup.prev_sd_mk_backup,
    }
}

#[test]
fn sd_restore_peer_backup_roundtrip() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: finalize + CreateSD + CreatePeerBackup, capturing the peer
    // backup.
    let backup = create_peer_backup(&seed, &sata, &pota);

    // Device 2 (reboot): restore PartLocalMK (so the captured sealing key
    // unmasks), then restore the SD from the peer backup.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, &seed, &backup.policy, &pota_thumbprint())
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

    let req = restore_peer_req(session.session_id, &backup);
    let resp = ctx
        .tbor_oob(&req, &backup.evidence.oob())
        .expect("SdRestorePeerBackup roundtrip");
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
fn sd_restore_peer_backup_is_one_shot() {
    let ctx = TestCtx::new();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // A single device that has just created its SD (via CreateSD) is already
    // SD-initialized, so a peer restore on the same incarnation is rejected
    // by the one-shot gate.
    let part = finalize_peer_partition(&ctx, &mach_seed(), &sata, &pota, true);
    let session_id = part.session.session_id;

    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session_id);
    let evidence = build_receiver_evidence(&part.pid_pub, &rcvr_pub, &sata, &report);
    let created = ctx
        .tbor_oob(
            &backup_request(session_id, masked.clone(), &evidence, &part.policy),
            &evidence.oob(),
        )
        .expect("SdCreateRemoteBackup");
    let peer = ctx
        .tbor_oob(
            &create_peer_req(
                session_id,
                &masked,
                &evidence,
                &part.policy,
                &created.pok_local_backup,
            ),
            &evidence.oob(),
        )
        .expect("SdCreatePeerBackup");

    let backup = PeerBackup {
        masked_sealing_key: masked,
        evidence,
        policy: part.policy,
        pok_peer_backup: peer.pok_peer_backup,
        prev_sd_mk_backup: created.sd_mk_backup,
        local_mk_backup: Vec::new(),
    };
    let req = restore_peer_req(session_id, &backup);
    ctx.expect_fw_reject_oob(
        &req,
        &backup.evidence.oob(),
        TborStatus::SdAlreadyInitialized,
    );
}

#[test]
fn sd_restore_peer_backup_rejects_without_peer_cloning() {
    let ctx = TestCtx::new();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Finalize with a policy that does NOT opt into peer cloning.  The
    // peer-cloning gate fires in phase 1 (after the policy-hash re-check)
    // before any HPKE work, so dummy backup blobs are sufficient — but a
    // real sealing key and OOB evidence are needed to reach the gate.
    let part = finalize_peer_partition(&ctx, &mach_seed(), &sata, &pota, false);
    let session_id = part.session.session_id;

    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session_id);
    let evidence = build_receiver_evidence(&part.pid_pub, &rcvr_pub, &sata, &report);
    let backup = PeerBackup {
        masked_sealing_key: masked,
        evidence,
        policy: part.policy,
        pok_peer_backup: [0u8; POK_REMOTE_BACKUP_LEN],
        prev_sd_mk_backup: [0u8; SD_MK_BACKUP_LEN],
        local_mk_backup: Vec::new(),
    };
    let req = restore_peer_req(session_id, &backup);
    ctx.expect_fw_reject_oob(
        &req,
        &backup.evidence.oob(),
        TborStatus::SdPeerCloningNotAllowed,
    );
}

#[test]
fn sd_restore_peer_backup_rejects_before_finalize() {
    // A partition that has not been finalized is rejected at the lifecycle
    // gate before any evidence or crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let req = TborSdRestorePeerBackupReq {
        session_id: session.session_id,
        masked_sealing_key: [0u8; MASKED_SEALING_KEY_LEN],
        policy: PartPolicy::zeroed(),
        src_mfgr_cert_chain: Vec::new(),
        src_owner_cert_chain: Vec::new(),
        src_part_owner_cert_chain: Vec::new(),
        src_report: Default::default(),
        pok_peer_backup: [0u8; POK_REMOTE_BACKUP_LEN],
        prev_sd_mk_backup: [0u8; SD_MK_BACKUP_LEN],
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Finalize a fresh incarnation using the original partition's local-MK backup.
/// The SD is intentionally left uninitialized for negative restore tests.
fn peer_restore_target(backup: &PeerBackup, seed: &[u8], pota: &CaKey) -> (TestCtx, u16) {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, seed, &backup.policy, &pota_thumbprint())
        .expect("PartInit (restore target)");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &backup.policy,
        &backup.local_mk_backup,
        &chain.der_items(),
    )
    .expect("PartFinal (restore target)");
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
    (ctx, session.session_id)
}

/// Each case starts from a fresh restore target so a previous failure cannot
/// affect the result. Check the lifecycle state as well as the rejection.
fn assert_peer_restore_rejected<F>(mutate: F)
where
    F: FnOnce(&mut TborSdRestorePeerBackupReq),
{
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let backup = create_peer_backup(&seed, &sata, &pota);
    let (ctx, session_id) = peer_restore_target(&backup, &seed, &pota);
    let mut req = restore_peer_req(session_id, &backup);
    mutate(&mut req);
    assert!(
        ctx.tbor_oob(&req, &backup.evidence.oob()).is_err(),
        "mutated peer restore must be rejected"
    );
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
}

#[test]
fn sd_restore_peer_backup_rejects_inactive_session_id() {
    assert_peer_restore_rejected(|req| {
        assert_eq!(req.session_id, 0);

        // Session 0 is active. Session 2 is expected to be inactive.
        req.session_id = 2;
    });
}

#[test]
fn sd_restore_peer_backup_rejects_max_session_id() {
    assert_peer_restore_rejected(|req| req.session_id = u16::MAX);
}

#[test]
fn sd_restore_peer_backup_rejects_corrupted_peer_backup() {
    assert_peer_restore_rejected(|req| req.pok_peer_backup[0] ^= 0x80);
}

#[test]
fn sd_restore_peer_backup_rejects_corrupted_peer_backup_tail() {
    assert_peer_restore_rejected(|req| {
        let last = req.pok_peer_backup.len() - 1;
        req.pok_peer_backup[last] ^= 0x01;
    });
}

#[test]
fn sd_restore_peer_backup_rejects_corrupted_previous_sd_mk_backup() {
    assert_peer_restore_rejected(|req| req.prev_sd_mk_backup[0] ^= 0x80);
}

#[test]
fn sd_restore_peer_backup_rejects_corrupted_previous_sd_mk_backup_tail() {
    assert_peer_restore_rejected(|req| {
        let last = req.prev_sd_mk_backup.len() - 1;
        req.prev_sd_mk_backup[last] ^= 0x01;
    });
}

#[test]
fn sd_restore_peer_backup_rejects_corrupted_masked_sealing_key() {
    assert_peer_restore_rejected(|req| req.masked_sealing_key[0] ^= 0x80);
}

#[test]
fn sd_restore_peer_backup_rejects_zeroed_masked_sealing_key() {
    assert_peer_restore_rejected(|req| req.masked_sealing_key.fill(0));
}

#[test]
fn sd_restore_peer_backup_rejects_missing_manufacturer_chain() {
    assert_peer_restore_rejected(|req| req.src_mfgr_cert_chain.clear());
}

#[test]
fn sd_restore_peer_backup_rejects_missing_partition_owner_chain() {
    assert_peer_restore_rejected(|req| req.src_part_owner_cert_chain.clear());
}

#[test]
fn sd_restore_peer_backup_rejects_zeroed_peer_backup() {
    assert_peer_restore_rejected(|req| req.pok_peer_backup.fill(0));
}

#[test]
fn sd_restore_peer_backup_rejects_zeroed_previous_sd_mk_backup() {
    assert_peer_restore_rejected(|req| req.prev_sd_mk_backup.fill(0));
}

/// A rejected restore must not consume the one-shot initialization opportunity.
#[test]
fn sd_restore_peer_backup_failed_restore_then_valid_restore_succeeds() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let backup = create_peer_backup(&seed, &sata, &pota);
    let (ctx, session_id) = peer_restore_target(&backup, &seed, &pota);

    let mut corrupted = restore_peer_req(session_id, &backup);
    corrupted.pok_peer_backup[0] ^= 0x80;
    assert!(
        ctx.tbor_oob(&corrupted, &backup.evidence.oob()).is_err(),
        "corrupted peer backup must be rejected"
    );
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);

    let valid = restore_peer_req(session_id, &backup);
    let restored = ctx
        .tbor_oob(&valid, &backup.evidence.oob())
        .expect("valid restore should succeed after rejected restore");
    assert_eq!(restored.pok_local_backup.len(), MASKED_SD_LEN);
    assert_eq!(restored.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
}

/// A well-formed SDMK backup from another independently created domain
/// must not be silently accepted as the companion to this peer backup.
#[test]
fn sd_restore_peer_backup_rejects_unrelated_previous_sd_mk_backup() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let backup = create_peer_backup(&seed, &sata, &pota);
    let other = create_peer_backup(&seed, &sata, &pota);
    assert_ne!(backup.prev_sd_mk_backup, other.prev_sd_mk_backup);

    let (ctx, session_id) = peer_restore_target(&backup, &seed, &pota);
    let mut req = restore_peer_req(session_id, &backup);
    req.prev_sd_mk_backup = other.prev_sd_mk_backup;
    assert!(
        ctx.tbor_oob(&req, &backup.evidence.oob()).is_err(),
        "unrelated SDMK backup must be rejected"
    );
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
}

/// The device-owner chain is optional; the required manufacturer and
/// partition-owner chains remain present.
#[test]
fn sd_restore_peer_backup_accepts_missing_optional_owner_chain() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let backup = create_peer_backup(&seed, &sata, &pota);
    let (ctx, session_id) = peer_restore_target(&backup, &seed, &pota);
    let mut req = restore_peer_req(session_id, &backup);
    req.src_owner_cert_chain.clear();

    let restored = ctx
        .tbor_oob(&req, &backup.evidence.oob())
        .expect("optional device-owner chain should not be required");
    assert_eq!(restored.pok_local_backup.len(), MASKED_SD_LEN);
    assert_eq!(restored.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
}

/// Several independent failures must leave the restore target usable.
#[test]
fn sd_restore_peer_backup_multiple_failures_then_success() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let backup = create_peer_backup(&seed, &sata, &pota);
    let (ctx, session_id) = peer_restore_target(&backup, &seed, &pota);

    let mut bad_peer = restore_peer_req(session_id, &backup);
    bad_peer.pok_peer_backup[0] ^= 1;
    assert!(ctx.tbor_oob(&bad_peer, &backup.evidence.oob()).is_err());
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);

    let mut bad_mk = restore_peer_req(session_id, &backup);
    bad_mk.prev_sd_mk_backup[0] ^= 1;
    assert!(ctx.tbor_oob(&bad_mk, &backup.evidence.oob()).is_err());
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);

    let mut missing_chain = restore_peer_req(session_id, &backup);
    missing_chain.src_mfgr_cert_chain.clear();
    assert!(ctx
        .tbor_oob(&missing_chain, &backup.evidence.oob())
        .is_err());
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);

    let valid = restore_peer_req(session_id, &backup);
    ctx.tbor_oob(&valid, &backup.evidence.oob())
        .expect("valid restore should succeed after multiple rejected attempts");
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
}

/// Successful restore consumes the one-shot opportunity; a replay fails.
#[test]
fn sd_restore_peer_backup_rejects_replay_after_success() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let backup = create_peer_backup(&seed, &sata, &pota);
    let (ctx, session_id) = peer_restore_target(&backup, &seed, &pota);
    let req = restore_peer_req(session_id, &backup);

    ctx.tbor_oob(&req, &backup.evidence.oob())
        .expect("first peer restore should succeed");
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
    ctx.expect_fw_reject_oob(
        &req,
        &backup.evidence.oob(),
        TborStatus::SdAlreadyInitialized,
    );
}
