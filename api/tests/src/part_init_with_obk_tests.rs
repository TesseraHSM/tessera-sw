// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the owner-backup-key (OBK) partition-provisioning
//! session API (`HsmSession::part_init_with_obk`).
//!
//! `part_init_with_obk` provisions an `Enabled` partition from the OBK and
//! the partition owner's endorsement of the partition identity inside an
//! already-open Crypto Officer session, in place of the v1 partition `init`
//! (open the session first, then provision). The MOBK is resolved over MBOR
//! `InitBk3`, so these run on Uno-class backends (TBOR at API revision 1.1,
//! with MBOR) and return early otherwise.
//!
//! A raw OBK is masked on first use — `InitBk3` is a one-shot per partition
//! incarnation — so every case that reaches the device uses the raw OBK at
//! most once per incarnation, and the retry presents the returned MOBK.

use tsra_api::*;

use crate::utils::partition::TEST_OBK;
use crate::utils::partition::generate_pota_endorsement;
use crate::utils::partition_ex_helpers::*;
use crate::utils::sd_provision::ROTATED_CO_PSK;

/// Whether the backend supports the OBK flow: TBOR needs API revision 1.1+
/// and the MOBK comes from MBOR `InitBk3`, which a Duo (2.x) lacks.
fn obk_supported() -> bool {
    crate::utils::session::api_rev_at_least(1, 1) && !crate::utils::session::api_rev_at_least(2, 0)
}

/// Open a CO session under a rotated PSK on `part` — the default-PSK gate
/// rejects provisioning commands otherwise, and the device rejects a session
/// opened before the rotation.
fn rotated_co_session(part: &HsmPartition, rev: HsmApiRev) -> HsmSession {
    {
        let bootstrap = part
            .open_session_ex(
                rev,
                HsmSessionPsk::new(HsmPskId::CO),
                HsmSessionExType::Authenticated,
            )
            .expect("open bootstrap CO session");
        bootstrap
            .change_psk(&ROTATED_CO_PSK)
            .expect("rotate CO PSK");
    }

    part.open_session_ex(
        rev,
        HsmSessionPsk::with_psk(HsmPskId::CO, &ROTATED_CO_PSK),
        HsmSessionExType::Authenticated,
    )
    .expect("open rotated CO session")
}

/// The raw-OBK configuration and a caller-supplied POTA endorsement of
/// `part`'s current identity.
fn caller_inputs(part: &HsmPartition) -> (HsmOwnerBackupKeyConfig, HsmPotaEndorsement) {
    let (sig, pub_key_der) = generate_pota_endorsement(part);
    let obk = HsmOwnerBackupKey::from_obk(&TEST_OBK);
    let obk_config = HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, obk);
    let endorsement = HsmPotaEndorsementData::new(&sig, &pub_key_der);
    let pota = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(endorsement));
    (obk_config, pota)
}

/// A configuration presenting an already-masked owner backup key.
fn mobk_config(mobk: &[u8]) -> HsmOwnerBackupKeyConfig {
    let obk = HsmOwnerBackupKey::from_masked_key(mobk);
    HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, obk)
}

/// Provisioning returns the MOBK and a `local_mk` backup of the pinned
/// length, and the partition is then provisioned: a second call is rejected.
#[test]
fn part_init_with_obk_provisions_the_partition() {
    if !obk_supported() {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    let session = rotated_co_session(&part, rev);
    let (obk_config, pota) = caller_inputs(&part);

    let result = session
        .part_init_with_obk(&obk_config, &pota, None)
        .expect("part_init_with_obk");

    assert_eq!(result.local_mk_backup.len(), LOCAL_MK_BACKUP_LEN);
    assert!(!result.mobk.is_empty() && result.mobk.len() <= OBK_MOBK_MAX_LEN);

    // The raw OBK was masked by the first call, so the retry presents the
    // returned MOBK.
    let err = session
        .part_init_with_obk(&mobk_config(&result.mobk), &pota, None)
        .expect_err("a second provisioning must be rejected");
    assert_eq!(err, HsmError::PartitionAlreadyProvisioned);
}

/// A backup returned by one incarnation restores the partition after a
/// reset, and the restore returns a fresh backup.
#[test]
fn part_init_with_obk_restores_from_the_previous_backup() {
    if !obk_supported() {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    let session = rotated_co_session(&part, rev);
    let (obk_config, pota) = caller_inputs(&part);
    let first = session
        .part_init_with_obk(&obk_config, &pota, None)
        .expect("first provisioning");
    drop(session);

    // A reset stands in for NSSR: the identity is regenerated, so the new
    // incarnation re-endorses it and masks the same OBK again.
    part.reset().expect("reset the partition");
    let session = rotated_co_session(&part, rev);
    let (obk_config, pota) = caller_inputs(&part);

    let restored = session
        .part_init_with_obk(&obk_config, &pota, Some(&first.local_mk_backup))
        .expect("restore from the previous backup");
    assert_eq!(restored.local_mk_backup.len(), LOCAL_MK_BACKUP_LEN);
}

/// Inputs the host can reject without device state are rejected before the
/// one-shot `InitBk3` runs, so the raw OBK stays usable for a valid retry.
#[test]
fn part_init_with_obk_rejects_malformed_inputs_without_consuming_the_obk() {
    if !obk_supported() {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    let session = rotated_co_session(&part, rev);
    let (obk_config, pota) = caller_inputs(&part);
    let (sig, pub_key_der) = generate_pota_endorsement(&part);

    let short_backup = vec![0u8; LOCAL_MK_BACKUP_LEN - 1];
    let err = session
        .part_init_with_obk(&obk_config, &pota, Some(&short_backup))
        .expect_err("a wrong-length backup must be rejected");
    assert_eq!(err, HsmError::InvalidArgument);

    let missing = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, None);
    let err = session
        .part_init_with_obk(&obk_config, &missing, None)
        .expect_err("a missing endorsement must be rejected");
    assert_eq!(err, HsmError::InvalidArgument);

    let short_sig = HsmPotaEndorsementData::new(&sig[..sig.len() - 1], &pub_key_der);
    let short_sig = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(short_sig));
    let err = session
        .part_init_with_obk(&obk_config, &short_sig, None)
        .expect_err("a truncated signature must be rejected");
    assert_eq!(err, HsmError::InvalidArgument);

    let bad_key = HsmPotaEndorsementData::new(&sig, &[0u8; 4]);
    let bad_key = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(bad_key));
    let err = session
        .part_init_with_obk(&obk_config, &bad_key, None)
        .expect_err("a malformed public key must be rejected");
    assert_eq!(err, HsmError::InvalidKey);

    // None of the rejects consumed the raw OBK or touched the partition.
    session
        .part_init_with_obk(&obk_config, &pota, None)
        .expect("a valid call still provisions the partition");
}

/// A device rejection after the raw OBK was masked (the one-shot `InitBk3`)
/// must not lose the MOBK: it stays on the partition handle, and the retry
/// presents it.
#[test]
fn part_init_with_obk_keeps_the_mobk_after_a_device_rejection() {
    if !obk_supported() {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    let (obk_config, pota) = caller_inputs(&part);

    // The device gates provisioning under the unrotated default PSK, which it
    // only reports after the raw OBK was masked.
    let bootstrap = part
        .open_session_ex(
            rev,
            HsmSessionPsk::new(HsmPskId::CO),
            HsmSessionExType::Authenticated,
        )
        .expect("open bootstrap CO session");
    bootstrap
        .part_init_with_obk(&obk_config, &pota, None)
        .expect_err("the default PSK must be rotated first");
    let mobk = part.mobk_vec();
    assert!(!mobk.is_empty(), "the masked OBK must stay available");

    bootstrap
        .change_psk(&ROTATED_CO_PSK)
        .expect("rotate CO PSK");
    drop(bootstrap);
    let session = part
        .open_session_ex(
            rev,
            HsmSessionPsk::with_psk(HsmPskId::CO, &ROTATED_CO_PSK),
            HsmSessionExType::Authenticated,
        )
        .expect("open rotated CO session");

    // The raw OBK is spent for this power cycle; the kept MOBK finishes the job.
    let result = session
        .part_init_with_obk(&mobk_config(&mobk), &pota, None)
        .expect("retry with the kept MOBK");
    assert_eq!(result.mobk, mobk);
    assert_eq!(result.local_mk_backup.len(), LOCAL_MK_BACKUP_LEN);
}
