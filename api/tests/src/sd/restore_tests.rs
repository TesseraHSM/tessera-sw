// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level `SdRestoreRemoteBackup` round trip against the emulator or
//! hardware backend.
//!
//! Self-backup "reboot" flow: a first partition incarnation finalizes and
//! creates a remote backup (capturing its `pok_remote_backup` /
//! `sd_mk_backup` and the `local_mk_backup` from `part_final`), then a
//! second incarnation of the same partition — factory-reset with the same
//! deterministic machine seed — restores `PartLocalMK` via `part_final` (so
//! the captured sealing key unmasks) and restores the security domain from
//! the remote backup. A successful restore is itself the correctness check:
//! the HPKE open only succeeds after the PID-signed operation report binds
//! the complete envelope, recipient, and transferred policy.

use tsra_api::*;
use tsra_ddi_tbor_types::MASKED_SD_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::build_receiver_evidence;
use crate::utils::sd_provision::masked_key_and_report;
use crate::utils::sd_provision::provision_backing;

/// Happy path: create a remote backup on one incarnation, then restore it
/// on a rebooted (factory-reset, same-seed) incarnation; the restore
/// returns non-zero refreshed device-local backups of the pinned lengths.
#[test]
fn sd_restore_remote_backup_roundtrip() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: finalize + create, capturing the remote backup and the
    // local_mk backup needed to restore PartLocalMK after reboot.
    let (session1, policy, pid_pub, local_mk) = provision_backing(&sata, &pota, None, None);
    let (masked, rcvr_pub, report) = masked_key_and_report(&session1);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata, &report);
    let created = evidence
        .with_create_backup(|rcvr_chain, ev| {
            session1.sd_create_remote_backup(&policy, rcvr_chain, ev)
        })
        .expect("create remote backup");
    drop(session1);
    // Device 2 (reboot, same seed): restore PartLocalMK from device 1's
    // backup, then restore the security domain from the remote backup.
    let (session2, _policy2, _pid_pub2, _lmk2) =
        provision_backing(&sata, &pota, Some(&policy), Some(&local_mk));
    let restore = |receiver: &[u8], signer: &[u8], report: &[u8], backup: &[u8]| {
        session2.sd_restore_remote_backup(
            &policy,
            receiver,
            signer,
            &HsmSdEvidence {
                mfgr_cert_chain: &[],
                owner_cert_chain: &[],
                part_owner_cert_chain: &[],
                report,
            },
            backup,
            &created.sd_mk_backup,
        )
    };
    for report in [&[][..], evidence.report()] {
        assert!(
            restore(&masked, &pid_pub, report, &created.pok_remote_backup).is_err(),
            "empty and generic PublicKey reports cannot authorize SD restore",
        );
    }
    let mut tampered_report = created.report.clone();
    *tampered_report.last_mut().expect("report signature") ^= 1;
    assert!(
        restore(
            &masked,
            &pid_pub,
            &tampered_report,
            &created.pok_remote_backup
        )
        .is_err(),
        "optional SAPOTA does not disable operation-report signature verification",
    );
    let mut tampered_backup = created.pok_remote_backup.clone();
    *tampered_backup.last_mut().expect("envelope tag") ^= 1;
    assert!(
        restore(&masked, &pid_pub, &created.report, &tampered_backup).is_err(),
        "the operation report must bind the complete envelope",
    );
    let (wrong_receiver, _, _) = masked_key_and_report(&session2);
    assert!(
        restore(
            &wrong_receiver,
            &pid_pub,
            &created.report,
            &created.pok_remote_backup
        )
        .is_err(),
        "a valid report cannot authorize a different recipient",
    );
    let wrong_pid = CaKey::generate().raw_pub();
    assert!(
        restore(
            &masked,
            &wrong_pid,
            &created.report,
            &created.pok_remote_backup
        )
        .is_err(),
        "the supplied PID must verify the operation signature",
    );
    for len in [0, 95, 97] {
        let malformed_pid = vec![0; len];
        assert!(
            matches!(
                restore(
                    &masked,
                    &malformed_pid,
                    &created.report,
                    &created.pok_remote_backup
                ),
                Err(HsmError::InvalidArgument)
            ),
            "the signer PID must be exactly 96 bytes",
        );
    }
    let evidence = evidence.with_report(&created.report);
    let restored = evidence
        .with_hsm_evidence(|ev| {
            let ev = HsmSdEvidence {
                mfgr_cert_chain: &[],
                owner_cert_chain: &[],
                part_owner_cert_chain: &[],
                ..*ev
            };
            session2.sd_restore_remote_backup(
                &policy,
                &masked,
                &pid_pub,
                &ev,
                &created.pok_remote_backup,
                &created.sd_mk_backup,
            )
        })
        .expect("restore remote backup");

    // Local backup (BKS3 re-masked under PartLocalMK), 276 B, non-zero.
    assert_eq!(restored.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        restored.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );
    // Refreshed masking-key backup (SDMK re-masked under SDBMK), 260 B.
    assert_eq!(restored.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        restored.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

/// One-shot: an incarnation that just created its security domain is
/// already SD-initialized, so a restore on that same incarnation is
/// rejected by the firmware's one-shot gate.
#[test]
fn sd_restore_remote_backup_is_one_shot() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let (session, policy, pid_pub, _local_mk) = provision_backing(&sata, &pota, None, None);
    let (masked, rcvr_pub, report) = masked_key_and_report(&session);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata, &report);
    let created = evidence
        .with_create_backup(|rcvr_chain, ev| {
            session.sd_create_remote_backup(&policy, rcvr_chain, ev)
        })
        .expect("create remote backup");

    let evidence = evidence.with_report(&created.report);
    let restored = evidence.with_hsm_evidence(|ev| {
        session.sd_restore_remote_backup(
            &policy,
            &masked,
            &pid_pub,
            ev,
            &created.pok_remote_backup,
            &created.sd_mk_backup,
        )
    });
    assert!(
        matches!(restored, Err(HsmError::SdAlreadyInitialized)),
        "restore on an already-initialized SD must be rejected with \
         SdAlreadyInitialized, got {restored:?}",
    );
}
