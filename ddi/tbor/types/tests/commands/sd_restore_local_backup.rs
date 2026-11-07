// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdRestoreLocalBackup` command.
//!
//! `SdRestoreLocalBackup` restores a security domain from its device-local
//! backups (`pok_local_backup` = BKS3 masked under `PartLocalMK`,
//! `sd_mk_backup` = SDMK masked under the derived SDBMK), re-masks both at
//! the current SVN, and re-provisions the SD — the local-reboot recovery
//! path.  It needs no sender, HPKE, evidence, or out-of-band data.
//!
//! The **round-trip** test exercises the realistic recovery sequence: a
//! first device finalizes and `CreateSD`s (capturing the local backups and
//! the `local_mk_backup`), then a second device (factory-reset, same
//! machine seed) restores `PartLocalMK` via `PartFinal` and finally
//! restores the security domain from the captured local backups.
//!
//! Coverage:
//! * Round-trip — create → reboot → PartFinal(restore PartLocalMK) →
//!   restore-local returns non-zero refreshed backups.
//! * One-shot — restore onto an already-initialized SD → `SdAlreadyInitialized`.
//! * Restore before finalize → `InvalidArg`.
//! * A tampered `pok_local_backup` is rejected (AEAD tag mismatch).

use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MASKED_SD_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::commands::part_info::assert_part_state;
use crate::commands::part_info::PART_STATE_INITIALIZED;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_report_and_pub;

/// Material captured from the first device's `CreateSD`, replayed on the
/// second (rebooted) device to restore the security domain.
struct CreatedSd {
    /// The exact 584-byte `PartPolicy` image (needed verbatim to
    /// re-finalize and to re-derive SDBMK on the second device).
    policy: [u8; tsra_ddi_tbor_types::PART_POLICY_LEN],
    /// `PartFinal`'s `local_mk_backup`, replayed to restore `PartLocalMK`.
    local_mk_backup: Vec<u8>,
    /// The local SD backups from `CreateSD`.
    pok_local_backup: Vec<u8>,
    sd_mk_backup: Vec<u8>,
}

/// Drive device 1: finalize a backing partition, mint the SD via
/// `CreateSD`, and capture everything device 2 needs to recover.  The
/// `pota` / `sata` trust anchors and machine `seed` are supplied by the
/// caller so the second device can re-finalize with an identical policy /
/// certificate chain.
fn create_sd_on_first_device(seed: &[u8], sata: &CaKey, pota: &CaKey) -> CreatedSd {
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
        .part_init(&session, seed, &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal")
        .local_mk_backup;

    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, sata, &report);
    let req = backup_request(session.session_id, masked, &evidence, &policy);
    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    CreatedSd {
        policy,
        local_mk_backup,
        pok_local_backup: resp.pok_local_backup.to_vec(),
        sd_mk_backup: resp.sd_mk_backup.to_vec(),
    }
}

/// Drive device 2 (reboot): re-init with the same seed/policy, restore
/// `PartLocalMK` from `local_mk_backup`, and return the finalized session.
fn reboot_and_restore_part_local_mk(
    ctx: &TestCtx,
    seed: &[u8],
    pota: &CaKey,
    created: &CreatedSd,
) -> tsra_ddi_tbor_test_harness::SessionHandshake {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, seed, &created.policy, &pota_thumbprint())
        .expect("PartInit (device 2)");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &created.policy,
        &created.local_mk_backup,
        &chain.der_items(),
    )
    .expect("PartFinal must restore PartLocalMK from the prior backup");
    session
}

#[test]
fn sd_restore_local_backup_roundtrip() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: finalize + CreateSD, capturing the local backups.
    let created = create_sd_on_first_device(&seed, &sata, &pota);

    // Device 2 (reboot): restore PartLocalMK, then restore the SD locally.
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);

    let resp = ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        })
        .expect("SdRestoreLocalBackup roundtrip");
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);

    // Refreshed local backup (BKS3 re-masked under PartLocalMK), 280 B.
    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        resp.pok_local_backup.iter().any(|&b| b != 0),
        "refreshed pok_local_backup must not be all-zero",
    );
    // Refreshed masking-key backup (SDMK re-masked under SDBMK), 264 B.
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        resp.sd_mk_backup.iter().any(|&b| b != 0),
        "refreshed sd_mk_backup must not be all-zero",
    );
}

#[test]
fn sd_restore_local_backup_is_one_shot() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // A single device that has just created its SD is already
    // SD-initialized, so a local restore on the same incarnation is
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
    let init = ctx
        .part_init(&session, &seed, &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata, &report);
    let req = backup_request(session.session_id, masked, &evidence, &policy);
    let created = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.to_vec(),
            sd_mk_backup: created.sd_mk_backup.to_vec(),
        },
        TborStatus::SdAlreadyInitialized,
    );
}

#[test]
fn sd_restore_local_backup_rejects_before_finalize() {
    // A partition that has not been finalized has no PartLocalMK, so the
    // command is rejected at the lifecycle gate before any unmask.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: vec![0u8; MASKED_SD_LEN],
            sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
        },
        TborStatus::InvalidArg,
    );
}

#[test]
fn sd_restore_local_backup_rejects_tampered_pok() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    // Device 2 (reboot): restore PartLocalMK, then attempt a restore with a
    // byte-flipped local backup — the AEAD tag no longer verifies.
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered = created.pok_local_backup.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;

    // A byte-flipped local backup fails the AEAD tag check inside `unmask`;
    // assert the exact status so the contract is locked in — the command must
    // not succeed or provision the SD under any other failure mode.
    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: tampered,
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
    ctx.tbor(&TborSdRestoreLocalBackupReq {
        session_id: session.session_id,
        pok_local_backup: created.pok_local_backup,
        sd_mk_backup: created.sd_mk_backup,
    })
    .expect("valid restore must remain possible after a rejected backup");
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
}

/// Verify that restoring an already-restored security domain is rejected.
#[test]
fn sd_restore_local_backup_rejects_second_restore() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let req = TborSdRestoreLocalBackupReq {
        session_id: session.session_id,
        pok_local_backup: created.pok_local_backup.clone(),
        sd_mk_backup: created.sd_mk_backup.clone(),
    };

    ctx.tbor(&req).expect("First restore must succeed");

    ctx.expect_fw_reject(&req, TborStatus::SdAlreadyInitialized);
}

/// Verify that corruption at the beginning of the POK backup is rejected.
#[test]
fn sd_restore_local_backup_rejects_tampered_pok_first_byte() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered = created.pok_local_backup.clone();
    tampered[0] ^= 0x01;

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: tampered,
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::InvalidArg,
    );
}

/// Verify that corruption in the middle of the POK backup is rejected.
#[test]
fn sd_restore_local_backup_rejects_tampered_pok_middle() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered = created.pok_local_backup.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: tampered,
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Verify that a failed restore does not prevent a later valid restore.
#[test]
fn sd_restore_local_backup_succeeds_after_failed_restore() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered = created.pok_local_backup.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: tampered,
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );

    let resp = ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        })
        .expect("Valid restore must succeed after failed attempt");

    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
}

/// Verify that corruption of the SD masking-key backup is rejected.
#[test]
fn sd_restore_local_backup_rejects_tampered_sd_mk() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered = created.sd_mk_backup.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: tampered,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Verify that a zero session ID is rejected.
#[test]
fn sd_restore_local_backup_rejects_zero_session_id() {
    let ctx = TestCtx::new();

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: 0u16,
            pok_local_backup: vec![0u8; MASKED_SD_LEN],
            sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
        },
        TborStatus::SessionNotFound,
    );
}

/// Verify that an all-zero POK backup is rejected.
#[test]
fn sd_restore_local_backup_rejects_zeroed_pok_backup() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: vec![0u8; MASKED_SD_LEN],
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::InvalidArg,
    );
}

/// Verify that an all-zero SD masking-key backup is rejected.
#[test]
fn sd_restore_local_backup_rejects_zeroed_sd_mk_backup() {
    println!("START test");

    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    println!("Creating SD on first device");

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    println!("First device completed");

    let ctx = TestCtx::new();

    println!("Restoring PartLocalMK");

    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    println!("PartLocalMK restored");

    println!("Sending zeroed SDMK backup");

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
        },
        TborStatus::InvalidArg,
    );

    println!("TEST COMPLETE");
}

/// Verify that refreshed local backups can restore another fresh device.
#[test]
fn sd_restore_local_backup_refreshed_backups_roundtrip() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: create the security domain and capture its local backups.
    let mut created = create_sd_on_first_device(&seed, &sata, &pota);

    assert_eq!(created.pok_local_backup.len(), MASKED_SD_LEN);
    assert_eq!(created.sd_mk_backup.len(), SD_MK_BACKUP_LEN);

    // Device 2: restore the original local backups.
    // Use a separate scope to ensure the emulator context and session
    // are dropped before initializing Device 3.
    let (refreshed_pok, refreshed_sd_mk) = {
        let ctx = TestCtx::new();

        let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

        let resp = ctx
            .tbor(&TborSdRestoreLocalBackupReq {
                session_id: session.session_id,
                pok_local_backup: created.pok_local_backup.clone(),
                sd_mk_backup: created.sd_mk_backup.clone(),
            })
            .expect("Device 2 SD restore must succeed");

        assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
        assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);

        assert!(
            resp.pok_local_backup.iter().any(|&b| b != 0),
            "Refreshed POK backup must not be all-zero",
        );

        assert!(
            resp.sd_mk_backup.iter().any(|&b| b != 0),
            "Refreshed SDMK backup must not be all-zero",
        );

        // Copy refreshed backups so they remain available after
        // the Device 2 context is dropped.
        (resp.pok_local_backup.clone(), resp.sd_mk_backup.clone())
    };

    // Replace the original backups with the refreshed backups.
    created.pok_local_backup = refreshed_pok;
    created.sd_mk_backup = refreshed_sd_mk;

    // Device 3: simulate another reboot with the same machine seed
    // and partition policy.
    let ctx = TestCtx::new();

    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    // Attempt to restore the security domain using the refreshed backups.
    let resp = ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        })
        .expect("Device 3 restore using refreshed backups must succeed");

    // Verify that the second restoration returns correctly sized backups.
    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);

    // Verify that the returned backups contain non-zero data.
    assert!(
        resp.pok_local_backup.iter().any(|&b| b != 0),
        "Device 3 POK backup must not be all-zero",
    );

    assert!(
        resp.sd_mk_backup.iter().any(|&b| b != 0),
        "Device 3 SDMK backup must not be all-zero",
    );
}

/// Verify that the maximum session ID is rejected.
#[test]
fn sd_restore_local_backup_rejects_max_session_id() {
    let ctx = TestCtx::new();

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: u16::MAX,
            pok_local_backup: vec![0u8; MASKED_SD_LEN],
            sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
        },
        TborStatus::SessionNotFound,
    );
}

/// Verify that corruption in the SDMK backup ciphertext is rejected.
#[test]
fn sd_restore_local_backup_rejects_tampered_sd_mk_middle() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered = created.sd_mk_backup.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: tampered,
        },
        TborStatus::MaskedKeyDecodeFailed,
    );
}

/// Verify that two all-zero local backups cannot restore an SD.
#[test]
fn sd_restore_local_backup_rejects_both_backups_zeroed() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: vec![0u8; MASKED_SD_LEN],
            sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
        },
        TborStatus::InvalidArg,
    );
}
