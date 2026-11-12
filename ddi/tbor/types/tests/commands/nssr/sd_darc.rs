// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR rows for the security-domain (SD) and DARC opcodes.
//!
//! The partition is provisioned under a backing-partition policy (peer
//! cloning allowed, DATA anchor set) and creates its security domain with
//! a self-backup before the reset; recovery then also replays the SD's
//! local backups (`SdRestoreLocalBackup`). Evidence is attested before the
//! reset because a reopened CO session cannot `KeyReport` (see
//! `keys::nssr_key_report`). TMKs are masked under the SD masking key, so
//! DARC rows that use one made before the reset also show the SD came back.

use tsra_ddi_interface::DdiResult;
use tsra_ddi_tbor_test_harness::x509_fixture::make_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::CertDescriptor;
use tsra_ddi_tbor_types::PartPolicy;
use tsra_ddi_tbor_types::TborDarcKexKeyGenReq;
use tsra_ddi_tbor_types::TborDarcKeyUnwrapReq;
use tsra_ddi_tbor_types::TborDarcKeyUnwrapResp;
use tsra_ddi_tbor_types::TborDarcKeyWrapReq;
use tsra_ddi_tbor_types::TborDarcTmkExportReq;
use tsra_ddi_tbor_types::TborDarcTmkGenReq;
use tsra_ddi_tbor_types::TborDarcTmkImportReq;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborEccGenerateKeyResp;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborSdCreateRemoteBackupResp;
use tsra_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use tsra_ddi_tbor_types::TborSdRestorePeerBackupReq;
use tsra_ddi_tbor_types::TborSdRestoreRemoteBackupReq;
use tsra_ddi_tbor_types::TborSdSealingKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::KEY_SCOPE_LOCAL;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::KEY_USAGE_VERIFY;
use tsra_ddi_tbor_types::MASKED_KEX_KEY_LEN;
use tsra_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_ddi_tbor_types::PART_POLICY_LEN;
use tsra_ddi_tbor_types::SEALED_TMK_LEN;
use zerocopy::TryFromBytes;

use super::assert_gated;
use super::assert_in_session_contract;
use super::expect_status;
use super::World;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::common::SCOPE_SECURITY_DOMAIN;
use crate::commands::darc_tmk_export::set_data_anchor;
use crate::commands::part_info::assert_part_state;
use crate::commands::part_info::PART_STATE_INITIALIZED;
use crate::commands::sd_create_peer_backup::create_peer_req;
use crate::commands::sd_create_peer_backup::ALLOW_PEER_CLONING;
use crate::commands::sd_create_peer_backup::OFF_FLAGS;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_evidence;
use crate::commands::sd_create_remote_backup::masked_key_report_and_pub;
use crate::commands::sd_create_remote_backup::ReceiverEvidence;
use crate::commands::sd_reseal_remote_backup::build_reseal_evidence;
use crate::commands::sd_reseal_remote_backup::reseal_request;

/// A partition provisioned as its own SD backing partition.
struct Sd {
    w: World,
    data: CaKey,
    pid_pub: [u8; RAW_PUB_LEN],
    /// Local-scope SD sealing key: sender and receiver of the self-backups.
    seal: Vec<u8>,
    /// `KeyReport` over `seal`, signed by the pre-reset identity key.
    report: Vec<u8>,
    evidence: ReceiverEvidence,
}

impl Sd {
    fn provisioned() -> Self {
        let ctx = TestCtx::new();
        let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
        let mut pid_pub = [0u8; RAW_PUB_LEN];
        pid_pub.copy_from_slice(&info.pid_pub_key);
        let (sata, pota, data) = (CaKey::generate(), CaKey::generate(), CaKey::generate());
        let mut policy = backing_part_policy(
            &info.pid,
            &info.pid_pub_key,
            &sata.raw_pub(),
            &pota.raw_pub(),
        );
        policy[OFF_FLAGS] |= ALLOW_PEER_CLONING;
        set_data_anchor(&mut policy, &data.raw_pub());

        let w = World::provisioned(ctx, pota, policy);
        let (seal, report, rcvr_pub) = masked_key_report_and_pub(&w.ctx, w.sid());
        let evidence = build_evidence(&pid_pub, &rcvr_pub, &sata, &w.pota, &report);
        Self {
            w,
            data,
            pid_pub,
            seal,
            report,
            evidence,
        }
    }

    /// Provisions the partition and creates its security domain.
    fn new() -> (Self, TborSdCreateRemoteBackupResp) {
        let mut sd = Self::provisioned();
        let created = create_sd(&sd.w.ctx, sd.w.sid(), &sd.seal, &sd.evidence, &sd.w.policy)
            .expect("SdCreateRemoteBackup");
        sd.w.sd_backups = Some((
            created.pok_local_backup.to_vec(),
            created.sd_mk_backup.to_vec(),
        ));
        (sd, created)
    }
}

fn create_sd(
    ctx: &TestCtx,
    session_id: u16,
    seal: &[u8],
    evidence: &ReceiverEvidence,
    policy: &[u8; PART_POLICY_LEN],
) -> DdiResult<TborSdCreateRemoteBackupResp> {
    ctx.tbor_oob(
        &backup_request(session_id, seal.to_vec(), evidence, policy),
        &evidence.oob(),
    )
}

fn part_policy(policy: &[u8; PART_POLICY_LEN]) -> PartPolicy {
    PartPolicy::try_read_from_bytes(policy).expect("policy image is canonical")
}

/// Descriptors for a two-certificate chain carried as OOB items 0 and 1.
fn chain_descriptors(der: &[&[u8]; 2]) -> Vec<CertDescriptor> {
    der.iter()
        .zip(0u8..)
        .map(|(der, index)| CertDescriptor {
            index,
            length: (der.len() as u16).into(),
        })
        .collect()
}

/// A Local-scope DARC key-exchange key: its masked blob and its public key
/// as raw big-endian `X ‖ Y` (the certificate-leaf format).
fn kex(ctx: &TestCtx, session_id: u16) -> ([u8; MASKED_KEX_KEY_LEN], [u8; RAW_PUB_LEN]) {
    let kex = ctx
        .tbor(&TborDarcKexKeyGenReq {
            session_id,
            scope: SCOPE_LOCAL,
        })
        .expect("DarcKexKeyGen");
    let mut pub_raw = [0u8; RAW_PUB_LEN];
    pub_raw.copy_from_slice(&kex.pub_key);
    let (x, y) = pub_raw.split_at_mut(RAW_PUB_LEN / 2);
    x.reverse();
    y.reverse();
    let masked = kex
        .masked_key
        .as_slice()
        .try_into()
        .expect("masked kex key");
    (masked, pub_raw)
}

/// A TMK masked under the SD masking key and a Local-scope P-256 key.
fn darc_keys(ctx: &TestCtx, session_id: u16) -> ([u8; MASKED_TMK_LEN], TborEccGenerateKeyResp) {
    let tmk = ctx
        .tbor(&TborDarcTmkGenReq { session_id })
        .expect("DarcTmkGen")
        .masked_tmk
        .as_slice()
        .try_into()
        .expect("masked TMK");
    let ec = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");
    (tmk, ec)
}

fn wrap(
    ctx: &TestCtx,
    session_id: u16,
    masked_tmk: [u8; MASKED_TMK_LEN],
    masked_key: &[u8],
) -> DdiResult<Vec<u8>> {
    ctx.tbor(&TborDarcKeyWrapReq {
        session_id,
        masked_tmk,
        masked_key: masked_key.to_vec(),
    })
    .map(|resp| resp.wrapped_key)
}

fn unwrap(
    ctx: &TestCtx,
    session_id: u16,
    masked_tmk: [u8; MASKED_TMK_LEN],
    wrapped_key: &[u8],
) -> DdiResult<TborDarcKeyUnwrapResp> {
    ctx.tbor(&TborDarcKeyUnwrapReq {
        session_id,
        scope: KEY_SCOPE_LOCAL,
        key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        masked_tmk,
        wrapped_key: wrapped_key.to_vec(),
    })
}

/// The SD masking key in force is the pre-reset one: a TMK masked under
/// it before the reset still wraps a key.
#[track_caller]
fn assert_sd_restored(w: &World, masked_tmk: [u8; MASKED_TMK_LEN], ec: &TborEccGenerateKeyResp) {
    assert_part_state(&w.ctx, PART_STATE_INITIALIZED, true);
    wrap(&w.ctx, w.sid(), masked_tmk, &ec.masked_key).expect("pre-NSSR TMK after restore");
}

#[test]
pub(super) fn nssr_sd_sealing_key_gen() {
    let (mut sd, _) = Sd::new();
    assert_in_session_contract(&mut sd.w, |ctx, session_id| {
        ctx.tbor(&TborSdSealingKeyGenReq {
            session_id,
            scope: SCOPE_SECURITY_DOMAIN,
        })
        .map(|resp| resp.pub_key.len())
    });
}

/// Once the SD is restored a create is refused as already initialized: the
/// host restores a security domain after a reset, it does not mint one.
#[test]
pub(super) fn nssr_sd_create_remote_backup() {
    let (mut sd, _) = Sd::new();
    let policy = sd.w.policy;
    let create = |ctx: &TestCtx, session_id| {
        create_sd(ctx, session_id, &sd.seal, &sd.evidence, &policy).map(|_| ())
    };
    assert_gated(&mut sd.w, create);
    sd.w.finish_recovery();
    expect_status(
        create(&sd.w.ctx, sd.w.sid()),
        TborStatus::SdAlreadyInitialized,
        "SdCreateRemoteBackup after the SD was restored",
    );
}

/// NSSR regenerates the partition identity key, so a backing-partition
/// policy built before the reset no longer names this partition. A reset
/// between `PartFinal` and SD creation therefore strands that policy.
#[test]
fn nssr_before_sd_create_strands_backing_policy() {
    let mut sd = Sd::provisioned();
    sd.w.nssr();
    sd.w.recover();
    let info = sd.w.ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    assert_ne!(
        info.pid_pub_key, sd.pid_pub,
        "NSSR must regenerate the identity key"
    );
    expect_status(
        create_sd(&sd.w.ctx, sd.w.sid(), &sd.seal, &sd.evidence, &sd.w.policy),
        TborStatus::InvalidArg,
        "SdCreateRemoteBackup under the pre-NSSR backing policy",
    );
}

#[test]
pub(super) fn nssr_sd_reseal_remote_backup() {
    let (mut sd, created) = Sd::new();
    let policy = sd.w.policy;
    let evidence =
        build_reseal_evidence(&sd.pid_pub, &sd.w.pota, &sd.w.pota, &sd.report, &sd.report);
    assert_in_session_contract(&mut sd.w, |ctx, session_id| {
        ctx.tbor_oob(
            &reseal_request(
                session_id,
                sd.seal.clone(),
                &evidence,
                &policy,
                &created.pok_remote_backup,
            ),
            &evidence.oob(),
        )
        .map(|resp| resp.dst_remote_backup.len())
    });
}

/// The local-reboot recovery path, which [`World::finish_recovery`] also
/// takes for every other SD/DARC row.
#[test]
pub(super) fn nssr_sd_restore_local_backup() {
    let (mut sd, created) = Sd::new();
    let (tmk, ec) = darc_keys(&sd.w.ctx, sd.w.sid());
    sd.w.sd_backups = None;
    let restore = |ctx: &TestCtx, session_id| {
        ctx.tbor(&TborSdRestoreLocalBackupReq {
            session_id,
            pok_local_backup: created.pok_local_backup.to_vec(),
            sd_mk_backup: created.sd_mk_backup.to_vec(),
        })
        .map(|_| ())
    };
    expect_status(
        restore(&sd.w.ctx, sd.w.sid()),
        TborStatus::SdAlreadyInitialized,
        "SdRestoreLocalBackup over the live SD",
    );
    assert_gated(&mut sd.w, restore);
    sd.w.finish_recovery();
    assert_part_state(&sd.w.ctx, PART_STATE_INITIALIZED, false);
    restore(&sd.w.ctx, sd.w.sid()).expect("SdRestoreLocalBackup after recovery");
    assert_sd_restored(&sd.w, tmk, &ec);
}

/// Recovery from the self-backup sealed to the partition's own Local-scope
/// sealing key instead of the local backups.
#[test]
pub(super) fn nssr_sd_restore_remote_backup() {
    let (mut sd, created) = Sd::new();
    let (tmk, ec) = darc_keys(&sd.w.ctx, sd.w.sid());
    sd.w.sd_backups = None;
    let policy = part_policy(&sd.w.policy);
    let restore = |ctx: &TestCtx, session_id| {
        let ev = &sd.evidence;
        ctx.tbor_oob(
            &TborSdRestoreRemoteBackupReq {
                session_id,
                masked_sealing_key: sd.seal.as_slice().try_into().expect("sealing key"),
                policy: policy.clone(),
                sender_cert_chain: ev.receiver.clone(),
                sender_mfgr_cert_chain: ev.mfgr.clone(),
                sender_owner_cert_chain: ev.owner.clone(),
                sender_part_owner_cert_chain: ev.part_owner.clone(),
                sender_report: ev.report,
                src_remote_backup: created.pok_remote_backup,
                prev_sd_mk_backup: created.sd_mk_backup,
            },
            &ev.oob(),
        )
        .map(|_| ())
    };
    expect_status(
        restore(&sd.w.ctx, sd.w.sid()),
        TborStatus::SdAlreadyInitialized,
        "SdRestoreRemoteBackup over the live SD",
    );
    assert_gated(&mut sd.w, restore);
    sd.w.finish_recovery();
    restore(&sd.w.ctx, sd.w.sid()).expect("SdRestoreRemoteBackup after recovery");
    assert_sd_restored(&sd.w, tmk, &ec);
}

#[test]
pub(super) fn nssr_sd_create_peer_backup() {
    let (mut sd, created) = Sd::new();
    let policy = sd.w.policy;
    assert_in_session_contract(&mut sd.w, |ctx, session_id| {
        ctx.tbor_oob(
            &create_peer_req(
                session_id,
                &sd.seal,
                &sd.evidence,
                &policy,
                &created.pok_local_backup,
            ),
            &sd.evidence.oob(),
        )
        .map(|resp| resp.pok_peer_backup.len())
    });
}

/// Recovery from a peer backup the partition sealed to itself.
#[test]
pub(super) fn nssr_sd_restore_peer_backup() {
    let (mut sd, created) = Sd::new();
    let (tmk, ec) = darc_keys(&sd.w.ctx, sd.w.sid());
    let pok_peer_backup =
        sd.w.ctx
            .tbor_oob(
                &create_peer_req(
                    sd.w.sid(),
                    &sd.seal,
                    &sd.evidence,
                    &sd.w.policy,
                    &created.pok_local_backup,
                ),
                &sd.evidence.oob(),
            )
            .expect("SdCreatePeerBackup")
            .pok_peer_backup;
    sd.w.sd_backups = None;
    let policy = part_policy(&sd.w.policy);
    let restore = |ctx: &TestCtx, session_id| {
        let ev = &sd.evidence;
        ctx.tbor_oob(
            &TborSdRestorePeerBackupReq {
                session_id,
                masked_sealing_key: sd.seal.as_slice().try_into().expect("sealing key"),
                policy: policy.clone(),
                src_mfgr_cert_chain: ev.mfgr.clone(),
                src_owner_cert_chain: ev.owner.clone(),
                src_part_owner_cert_chain: ev.part_owner.clone(),
                src_report: ev.report,
                pok_peer_backup,
                prev_sd_mk_backup: created.sd_mk_backup,
            },
            &ev.oob(),
        )
        .map(|_| ())
    };
    expect_status(
        restore(&sd.w.ctx, sd.w.sid()),
        TborStatus::SdAlreadyInitialized,
        "SdRestorePeerBackup over the live SD",
    );
    assert_gated(&mut sd.w, restore);
    sd.w.finish_recovery();
    restore(&sd.w.ctx, sd.w.sid()).expect("SdRestorePeerBackup after recovery");
    assert_sd_restored(&sd.w, tmk, &ec);
}

#[test]
pub(super) fn nssr_darc_kex_key_gen() {
    let mut w = World::new();
    assert_in_session_contract(&mut w, |ctx, session_id| {
        ctx.tbor(&TborDarcKexKeyGenReq {
            session_id,
            scope: SCOPE_LOCAL,
        })
        .map(|resp| resp.pub_key.len())
    });
}

#[test]
pub(super) fn nssr_darc_tmk_gen() {
    let (mut sd, _) = Sd::new();
    assert_in_session_contract(&mut sd.w, |ctx, session_id| {
        ctx.tbor(&TborDarcTmkGenReq { session_id })
            .map(|resp| resp.masked_tmk.len())
    });
}

/// Wraps a pre-reset key under a pre-reset TMK; unwrapping the result
/// must give back the same key.
#[test]
pub(super) fn nssr_darc_key_wrap() {
    let (mut sd, _) = Sd::new();
    let (tmk, ec) = darc_keys(&sd.w.ctx, sd.w.sid());
    assert_in_session_contract(&mut sd.w, |ctx, session_id| {
        let wrapped = wrap(ctx, session_id, tmk, &ec.masked_key)?;
        let unwrapped = unwrap(ctx, session_id, tmk, &wrapped).expect("DarcKeyUnwrap");
        assert_eq!(unwrapped.pub_key, ec.pub_key, "wrapped key must round-trip");
        Ok(())
    });
}

/// Unwraps a key wrapped before the reset.
#[test]
pub(super) fn nssr_darc_key_unwrap() {
    let (mut sd, _) = Sd::new();
    let (tmk, ec) = darc_keys(&sd.w.ctx, sd.w.sid());
    let wrapped = wrap(&sd.w.ctx, sd.w.sid(), tmk, &ec.masked_key).expect("DarcKeyWrap");
    assert_in_session_contract(&mut sd.w, |ctx, session_id| {
        let unwrapped = unwrap(ctx, session_id, tmk, &wrapped)?;
        assert_eq!(unwrapped.pub_key, ec.pub_key, "pre-NSSR wrapped key");
        Ok(())
    });
}

#[test]
pub(super) fn nssr_darc_tmk_export() {
    let (mut sd, _) = Sd::new();
    let (tmk, _) = darc_keys(&sd.w.ctx, sd.w.sid());
    let (sender, _) = kex(&sd.w.ctx, sd.w.sid());
    let (_, target_pub) = kex(&sd.w.ctx, sd.w.sid());
    let target_chain = make_chain(&sd.data, &target_pub);
    let policy = part_policy(&sd.w.policy);
    assert_in_session_contract(&mut sd.w, |ctx, session_id| {
        let der = target_chain.der_items();
        ctx.tbor_oob(
            &TborDarcTmkExportReq {
                session_id,
                masked_sender_key: sender,
                masked_tmk: tmk,
                policy: policy.clone(),
                target_cert_chain: chain_descriptors(&der),
            },
            &der,
        )
        .map(|resp| resp.sealed_tmk.len())
    });
}

/// Imports a TMK exported before the reset, then unwraps under it a key
/// wrapped under the original TMK before the reset.
#[test]
pub(super) fn nssr_darc_tmk_import() {
    let (mut sd, _) = Sd::new();
    let sid = sd.w.sid();
    let (tmk, ec) = darc_keys(&sd.w.ctx, sid);
    let wrapped = wrap(&sd.w.ctx, sid, tmk, &ec.masked_key).expect("DarcKeyWrap");
    let (sender, sender_pub) = kex(&sd.w.ctx, sid);
    let (target, target_pub) = kex(&sd.w.ctx, sid);
    let policy = part_policy(&sd.w.policy);
    let target_chain = make_chain(&sd.data, &target_pub);
    let der = target_chain.der_items();
    let sealed_tmk: [u8; SEALED_TMK_LEN] =
        sd.w.ctx
            .tbor_oob(
                &TborDarcTmkExportReq {
                    session_id: sid,
                    masked_sender_key: sender,
                    masked_tmk: tmk,
                    policy: policy.clone(),
                    target_cert_chain: chain_descriptors(&der),
                },
                &der,
            )
            .expect("DarcTmkExport")
            .sealed_tmk;
    let sender_chain = make_chain(&sd.w.pota, &sender_pub);
    assert_in_session_contract(&mut sd.w, |ctx, session_id| {
        let der = sender_chain.der_items();
        let imported = ctx
            .tbor_oob(
                &TborDarcTmkImportReq {
                    session_id,
                    masked_kex_key: target,
                    policy: policy.clone(),
                    sealed_tmk,
                    remote_cert_chain: chain_descriptors(&der),
                },
                &der,
            )?
            .masked_tmk
            .as_slice()
            .try_into()
            .expect("masked TMK");
        let unwrapped =
            unwrap(ctx, session_id, imported, &wrapped).expect("unwrap under the imported TMK");
        assert_eq!(
            unwrapped.pub_key, ec.pub_key,
            "imported TMK must be the exported one"
        );
        Ok(())
    });
}
