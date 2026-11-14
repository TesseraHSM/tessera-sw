// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level `SdCreateRemoteBackup` / `SdRestoreRemoteBackup` tests for the
//! **trusted Sealing Authority key** path, exercised against the emulator or
//! hardware backend.
//!
//! When the backing-partition policy sets `require_trusted_sa_key`, the
//! firmware validates the SATA recipient certificate chain on create and
//! SAPOTA-authorized PID chains on restore. Restore always consumes the
//! producer's v3 SdBackup operation report, bound to the supplied signer PID.
//! The sealing authority may have a different policy from the restored SD.
//! These tests cover both happy paths and fail-closed rejections.

use tsra_api::*;
use tsra_ddi_tbor_types::MASKED_SD_LEN;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::build_evidence;
use crate::utils::sd_provision::build_receiver_evidence_trusted;
use crate::utils::sd_provision::finalized_backing_session_trusted;
use crate::utils::sd_provision::masked_key_and_report;
use crate::utils::sd_provision::provision_backing;
use crate::utils::sd_provision::provision_backing_trusted;

/// Happy path: under a `require_trusted_sa_key` policy, a create whose
/// SAPOTA-anchored evidence report attests the same `RcvrPub` carried by
/// the SATA-anchored receiver certificate chain succeeds and returns three
/// non-zero backups of the pinned wire lengths.
#[test]
fn sd_create_remote_backup_trusted_sa_roundtrip() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session_trusted(&sata_key, &sapota_key);

    let (_masked, rcvr_pub, report) = masked_key_and_report(&session);
    let evidence =
        build_receiver_evidence_trusted(&pid_pub, &rcvr_pub, &sata_key, &sapota_key, &report);
    let result = evidence
        .with_create_backup(|rcvr_chain, receiver| {
            session.sd_create_remote_backup(&policy, rcvr_chain, receiver)
        })
        .expect("create remote backup under trusted-SA policy");

    assert_eq!(result.pok_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        result.pok_remote_backup.iter().any(|&b| b != 0),
        "pok_remote_backup must not be all-zero",
    );

    assert_eq!(result.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        result.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );

    assert_eq!(result.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        result.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

/// Rejection: under a `require_trusted_sa_key` policy, if the receiver
/// certificate chain certifies a key different from the one the evidence
/// report attests, the firmware rejects the create — the attested key must
/// equal the recovered `RcvrPub`.
#[test]
fn sd_create_remote_backup_trusted_sa_rcvr_pub_mismatch_is_rejected() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session_trusted(&sata_key, &sapota_key);

    let (_masked, _rcvr_pub, report) = masked_key_and_report(&session);

    // The receiver certificate chain certifies an unrelated key, so the
    // recovered `RcvrPub` differs from the sealing key the report attests.
    let wrong_rcvr_pub = CaKey::generate().raw_pub();
    let evidence =
        build_receiver_evidence_trusted(&pid_pub, &wrong_rcvr_pub, &sata_key, &sapota_key, &report);

    let outcome = evidence.with_create_backup(|rcvr_chain, receiver| {
        session.sd_create_remote_backup(&policy, rcvr_chain, receiver)
    });
    assert!(
        matches!(outcome, Err(HsmError::InvalidArgument)),
        "a receiver chain whose key differs from the attested RcvrPub must \
         be rejected with InvalidArg, got {outcome:?}",
    );
}

/// Happy path: under a `require_trusted_sa_key` policy, a self-backup
/// round trip (create on one incarnation, restore on a rebooted,
/// factory-reset same-seed incarnation) succeeds when the SAPOTA-anchored
/// operation report is signed by the SAPOTA-authorized source PID.
/// The restore returns non-zero refreshed
/// device-local backups of the pinned wire lengths.
#[test]
fn sd_restore_remote_backup_trusted_sa_roundtrip() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let sapota = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1 (trusted policy): finalize + create, capturing the remote
    // backup and the local_mk backup needed to restore PartLocalMK after
    // reboot.
    let (session1, policy, pid_pub, local_mk) =
        provision_backing_trusted(&sata, &sapota, &pota, None, None);
    let (masked, rcvr_pub, report) = masked_key_and_report(&session1);
    let evidence = build_receiver_evidence_trusted(&pid_pub, &rcvr_pub, &sata, &sapota, &report);
    let created = evidence
        .with_create_backup(|rcvr_chain, ev| {
            session1.sd_create_remote_backup(&policy, rcvr_chain, ev)
        })
        .expect("create remote backup under trusted-SA policy");
    drop(session1);
    let evidence = evidence.with_report(&created.report);

    // Device 2 (reboot, same seed, same trusted policy): restore the
    // security domain from the remote backup.
    let (session2, _policy2, _pid_pub2, _lmk2) =
        provision_backing_trusted(&sata, &sapota, &pota, Some(&policy), Some(&local_mk));
    let restored = evidence
        .with_hsm_evidence(|ev| {
            session2.sd_restore_remote_backup(
                &policy,
                &masked,
                &pid_pub,
                ev,
                &created.pok_remote_backup,
                &created.sd_mk_backup,
            )
        })
        .expect("restore remote backup under trusted-SA policy");

    assert_eq!(restored.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        restored.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );
    assert_eq!(restored.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        restored.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

/// A trusted restore rejects a provided PID different from the authorized
/// operation-report signer, before security-domain state is touched.
#[test]
fn sd_restore_remote_backup_trusted_sa_sndr_pub_mismatch_is_rejected() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let sapota = CaKey::generate();
    let pota = CaKey::generate();
    let (session, policy, pid_pub, local_mk) =
        provision_backing_trusted(&sata, &sapota, &pota, None, None);

    let (masked, rcvr_pub, report) = masked_key_and_report(&session);
    let wrong_sndr_pub = CaKey::generate().raw_pub();
    let evidence = build_receiver_evidence_trusted(&pid_pub, &rcvr_pub, &sata, &sapota, &report);
    let created = evidence
        .with_create_backup(|chain, ev| session.sd_create_remote_backup(&policy, chain, ev))
        .expect("create source operation report");
    let evidence = evidence.with_report(&created.report);
    drop(session);
    let (session, _, _, _) =
        provision_backing_trusted(&sata, &sapota, &pota, Some(&policy), Some(&local_mk));
    let outcome = evidence.with_hsm_evidence(|ev| {
        session.sd_restore_remote_backup(
            &policy,
            &masked,
            &wrong_sndr_pub,
            ev,
            &created.pok_remote_backup,
            &created.sd_mk_backup,
        )
    });
    assert!(
        matches!(outcome, Err(HsmError::InvalidArgument)),
        "a PID public key differing from the authorized report signer must \
         be rejected with InvalidArg, got {outcome:?}",
    );
}

/// A distinct-policy authority can reseal a real backup for trusted restore.
/// Destination policy binding, SAPOTA authorization, and report integrity remain
/// enforced. Sequential incarnations also exercise receiver-key persistence.
#[test]
fn sd_restore_remote_backup_trusted_sa_distinct_policy_roundtrip() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let sapota = CaKey::generate();
    let pota = CaKey::generate();
    let authority_pota = CaKey::generate();

    let (authority, authority_policy, authority_pid, authority_mk) =
        provision_backing(&sata, &authority_pota, None, None);
    let (authority_key, authority_pub, authority_report) = masked_key_and_report(&authority);
    let authority_evidence = build_receiver_evidence_trusted(
        &authority_pid,
        &authority_pub,
        &sata,
        &sapota,
        &authority_report,
    );
    drop(authority);

    let (source, policy, source_pid, source_mk) =
        provision_backing_trusted(&sata, &sapota, &pota, None, None);
    assert_ne!(authority_policy, policy);
    let (source_key, source_pub, source_report) = masked_key_and_report(&source);
    let created = authority_evidence
        .with_create_backup(|chain, evidence| {
            let evidence = HsmSdEvidence {
                owner_cert_chain: &[],
                ..*evidence
            };
            source.sd_create_remote_backup(&policy, chain, &evidence)
        })
        .expect("seal the SD backup to the external authority");
    let source_evidence = build_evidence(&source_pid, &source_pub, &sata, &pota, &created.report);
    let destination_evidence =
        build_evidence(&source_pid, &source_pub, &sata, &pota, &source_report);
    drop(source);

    let (authority, _, reseal_pid, _) = provision_backing(
        &sata,
        &authority_pota,
        Some(&authority_policy),
        Some(&authority_mk),
    );
    let resealed = source_evidence
        .with_hsm_evidence(|evidence| {
            let evidence = HsmSdEvidence {
                owner_cert_chain: &[],
                ..*evidence
            };
            destination_evidence.with_hsm_evidence(|destination| {
                let destination = HsmSdEvidence {
                    owner_cert_chain: &[],
                    ..*destination
                };
                authority.sd_reseal_remote_backup(
                    &policy,
                    &authority_key,
                    &evidence,
                    &destination,
                    &created.pok_remote_backup,
                )
            })
        })
        .expect("reseal to the original SD receiver");
    drop(authority);

    let (destination, restored_policy, _, _) =
        provision_backing_trusted(&sata, &sapota, &pota, Some(&policy), Some(&source_mk));
    assert_eq!(restored_policy, policy);
    let authority_pid = reseal_pid;
    let restore = |policy, evidence: &HsmSdEvidence<'_>| {
        let evidence = HsmSdEvidence {
            owner_cert_chain: &[],
            ..*evidence
        };
        destination.sd_restore_remote_backup(
            policy,
            &source_key,
            &authority_pid,
            &evidence,
            &resealed.backup,
            &created.sd_mk_backup,
        )
    };
    let authority_evidence = build_receiver_evidence_trusted(
        &authority_pid,
        &authority_pub,
        &sata,
        &sapota,
        &resealed.report,
    );
    let wrong_policy =
        authority_evidence.with_hsm_evidence(|evidence| restore(&authority_policy, evidence));
    assert!(
        matches!(wrong_policy, Err(HsmError::InvalidArgument)),
        "the restore request must match the destination's bound policy",
    );
    let unauthorized = build_receiver_evidence_trusted(
        &authority_pid,
        &authority_pub,
        &sata,
        &CaKey::generate(),
        &resealed.report,
    );
    assert!(
        unauthorized
            .with_hsm_evidence(|evidence| restore(&policy, evidence))
            .is_err(),
        "SAPOTA authorization remains required",
    );
    let mut tampered_report = resealed.report;
    *tampered_report.last_mut().expect("report signature") ^= 1;
    let tampered = build_receiver_evidence_trusted(
        &authority_pid,
        &authority_pub,
        &sata,
        &sapota,
        &tampered_report,
    );
    assert!(
        tampered
            .with_hsm_evidence(|evidence| restore(&policy, evidence))
            .is_err(),
        "a modified attestation report must be rejected",
    );
    let restored = authority_evidence
        .with_hsm_evidence(|evidence| restore(&policy, evidence))
        .expect("restore the same SD from a distinct-policy sealing authority");
    assert_eq!(restored.pok_local_backup.len(), MASKED_SD_LEN);
    assert_eq!(restored.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(restored.pok_local_backup.iter().any(|&byte| byte != 0));
    assert!(restored.sd_mk_backup.iter().any(|&byte| byte != 0));
}
