// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level `SdResealRemoteBackup` round trip against the emulator or
//! hardware backend.
//!
//! Self-reseal on one partition: mint receiver / destination SD
//! sealing keys, use `sd_create_remote_backup` to produce a real source
//! PID-signed backup, then reseal it to
//! the destination. A successful reseal is itself the correctness check —
//! the HPKE open only succeeds if the report binds the envelope and recipient.

use tsra_api::*;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::RAW_PUB_LEN;
use crate::utils::sd_provision::build_evidence;
use crate::utils::sd_provision::build_receiver_evidence;
use crate::utils::sd_provision::masked_key_and_report;
use crate::utils::sd_provision::provision_backing;

/// Create a signed source backup and retain its producer identity.
fn create_source_backup(
    session: &HsmSession,
    sata_key: &CaKey,
    pid_pub: &[u8; RAW_PUB_LEN],
    receiver_pub: &[u8; RAW_PUB_LEN],
    receiver_report: &[u8],
    policy: &[u8],
) -> HsmSdRemoteBackupResult {
    let receiver = build_receiver_evidence(pid_pub, receiver_pub, sata_key, receiver_report);
    receiver
        .with_create_backup(|rcvr_chain, rcvr| {
            session.sd_create_remote_backup(policy, rcvr_chain, rcvr)
        })
        .expect("source backup")
}

/// Happy path: resealing a real source backup yields a fresh 431-byte,
/// non-zero backup distinct from the source ciphertext.
#[test]
fn sd_reseal_remote_backup_roundtrip() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let sata_key = CaKey::generate();
    let pota_key = CaKey::generate();
    let (session, policy, pid_pub, _local_mk) = provision_backing(&sata_key, &pota_key, None, None);

    // Receiver (unseals the source) and destination (the reseal target).
    let (masked_rcvr, rcvr_pub_rcvr, report_rcvr) = masked_key_and_report(&session);
    let (_masked_dst, rcvr_pub_dst, report_dst) = masked_key_and_report(&session);

    let src_backup = create_source_backup(
        &session,
        &sata_key,
        &pid_pub,
        &rcvr_pub_rcvr,
        &report_rcvr,
        &policy,
    );

    let src_ev = build_evidence(&pid_pub, &pid_pub, &sata_key, &pota_key, &[]);
    let dst_ev = build_evidence(&pid_pub, &rcvr_pub_dst, &sata_key, &pota_key, &report_dst);
    let generic_source =
        build_evidence(&pid_pub, &rcvr_pub_rcvr, &sata_key, &pota_key, &report_rcvr);
    assert!(
        generic_source
            .with_hsm_identity(|src| {
                dst_ev.with_hsm_evidence(|dest| {
                    session.sd_reseal_remote_backup(&policy, &masked_rcvr, src, dest, &report_rcvr)
                })
            })
            .is_err(),
        "a PublicKey report cannot replace the signed source backup",
    );
    let wrong_policy = PartPolicyBuilder::new()
        .pota_key(PolicyKeyFormat::EccP384, &pota_key.raw_pub())
        .sata_key(PolicyKeyFormat::EccP384, &sata_key.raw_pub())
        .allow_peer_cloning(true)
        .build()
        .expect("different client policy");
    assert!(
        src_ev
            .with_hsm_identity(|src| {
                dst_ev.with_hsm_evidence(|dest| {
                    session.sd_reseal_remote_backup(
                        &wrong_policy,
                        &masked_rcvr,
                        src,
                        dest,
                        &src_backup.pok_remote_backup,
                    )
                })
            })
            .is_err(),
        "the source operation and destination key must match the requested SD policy",
    );
    let dst_backup = src_ev
        .with_hsm_identity(|src| {
            dst_ev.with_hsm_evidence(|dest| {
                session.sd_reseal_remote_backup(
                    &policy,
                    &masked_rcvr,
                    src,
                    dest,
                    &src_backup.pok_remote_backup,
                )
            })
        })
        .expect("reseal remote backup");

    // A successful HPKE open -> seal yields a 431-byte, non-zero backup.
    assert_eq!(dst_backup.backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        dst_backup.backup.iter().any(|&b| b != 0),
        "dst_remote_backup must not be all-zero",
    );
    // The resealed backup is a fresh HPKE encapsulation, not the source.
    assert_ne!(
        dst_backup.backup, src_backup.pok_remote_backup,
        "reseal must produce a fresh encapsulation, not echo the source",
    );
}

/// Re-randomization: two reseals of the same source produce distinct
/// ciphertexts (a fresh HPKE ephemeral each call).
#[test]
fn sd_reseal_remote_backup_rerandomizes() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let sata_key = CaKey::generate();
    let pota_key = CaKey::generate();
    let (session, policy, pid_pub, _local_mk) = provision_backing(&sata_key, &pota_key, None, None);

    let (masked_rcvr, rcvr_pub_rcvr, report_rcvr) = masked_key_and_report(&session);
    let (_masked_dst, rcvr_pub_dst, report_dst) = masked_key_and_report(&session);

    let src_backup = create_source_backup(
        &session,
        &sata_key,
        &pid_pub,
        &rcvr_pub_rcvr,
        &report_rcvr,
        &policy,
    );

    let src_ev = build_evidence(&pid_pub, &pid_pub, &sata_key, &pota_key, &[]);
    let dst_ev = build_evidence(&pid_pub, &rcvr_pub_dst, &sata_key, &pota_key, &report_dst);
    let reseal = || {
        src_ev
            .with_hsm_identity(|src| {
                dst_ev.with_hsm_evidence(|dest| {
                    session.sd_reseal_remote_backup(
                        &policy,
                        &masked_rcvr,
                        src,
                        dest,
                        &src_backup.pok_remote_backup,
                    )
                })
            })
            .expect("reseal remote backup")
    };

    let first = reseal();
    let second = reseal();
    assert_ne!(
        first.backup, second.backup,
        "each reseal must re-randomize the HPKE encapsulation",
    );
}
