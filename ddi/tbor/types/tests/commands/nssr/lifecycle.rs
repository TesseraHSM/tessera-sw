// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR rows for the session-lifecycle and provisioning opcodes, and the
//! recovery paths built from them: a reset in the middle of a handshake
//! or of re-provisioning, a second reset before recovery completes,
//! Crypto-User recovery, and recovery through a fresh CO session.

use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::assertions::assert_session_rejects;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::SessionOpenInitOptions;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID;
use tsra_ddi_tbor_test_harness::CU_PSK_ID;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborHashReq;
use tsra_ddi_tbor_types::TborKeyReportReq;
use tsra_ddi_tbor_types::TborSdSealingKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::AES_KEY_SIZE_256;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::KEY_REPORT_DATA_LEN;

use super::expect_status;
use super::keys::aes_fingerprint;
use super::provision;
use super::World;
use crate::commands::aes_generate_key::generate_key;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::key_report::verify_key_report;
use crate::commands::part_info::assert_part_state;
use crate::commands::part_info::PART_STATE_INITIALIZING;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;

fn co_opts() -> SessionOpenInitOptions<'static> {
    SessionOpenInitOptions::new(CO_PSK_ID, SessionType::Authenticated)
}

/// A Local-scope AES key and its fingerprint, taken before the reset.
fn local_key(ctx: &TestCtx, session_id: u16) -> (Vec<u8>, Vec<u8>) {
    let key = generate_key(ctx, session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let fingerprint = aes_fingerprint(ctx, session_id, &key).expect("fingerprint");
    (key, fingerprint)
}

#[track_caller]
fn assert_key_restored(w: &World, key: &[u8], before: &[u8]) {
    let after = aes_fingerprint(&w.ctx, w.sid(), key).expect("Local key after recovery");
    assert_eq!(after, before, "Local key must survive the NSSR");
}

/// The CO's only slot is held for its reopen, so a fresh CO open is
/// refused. A CU opens under its reverted default PSK and is then held
/// at the default-PSK gate.
#[test]
pub(super) fn nssr_session_open_init() {
    let w = World::new();
    w.nssr();
    let other = TestCtx::new_with_path(w.ctx.path());
    expect_status(
        other
            .session_open_init(CO_PSK_ID, SessionType::Authenticated)
            .map(|pending| pending.session_id),
        TborStatus::VaultSessionLimitReached,
        "CO open while its slot awaits reopen",
    );
    let pending = other
        .session_open_init(CU_PSK_ID, SessionType::PlainText)
        .expect("CU open under the default PSK");
    let cu = other.session_open_finish(pending).expect("CU open finish");
    expect_status(
        other
            .tbor(&TborHashReq {
                session_id: cu.session_id,
                algo: HASH_ALGO_SHA256,
                out_len: None,
                msg: b"abc".to_vec(),
            })
            .map(|resp| resp.digest),
        TborStatus::DefaultPskMustRotate,
        "fresh CU session under the default PSK",
    );
}

/// The reset discards a Pending open; the host restarts the handshake.
#[test]
pub(super) fn nssr_session_open_finish() {
    let w = World::new();
    let other = TestCtx::new_with_path(w.ctx.path());
    let pending = other
        .session_open_init(CU_PSK_ID, SessionType::PlainText)
        .expect("CU open init");
    w.nssr();
    let err = other
        .session_open_finish(pending)
        .map(|session| session.session_id)
        .expect_err("open finish after the NSSR");
    assert_session_rejects(&err, TborStatus::SessionNotFound);
    let pending = other
        .session_open_init(CU_PSK_ID, SessionType::PlainText)
        .expect("restarted CU open init");
    other
        .session_open_finish(pending)
        .expect("restarted CU open finish");
}

/// Reopen runs under the role's current PSK, which the reset reverted:
/// a host still keyed with the rotated PSK cannot authenticate the
/// Phase-1 response, and retrying under the default PSK replaces that
/// pending reopen. Two resets in a row need no extra steps.
#[test]
pub(super) fn nssr_session_reopen_init() {
    let mut w = World::new();
    let (key, before) = local_key(&w.ctx, w.sid());
    w.nssr();
    w.nssr();
    let err = w
        .ctx
        .session_reopen_init(w.sid(), co_opts().with_psk(&ROTATED_CO_PSK))
        .map(|pending| pending.session_id)
        .expect_err("reopen keyed with the pre-NSSR PSK");
    assert!(
        matches!(err, DdiError::TborDecodeError),
        "host must reject the Phase-1 MAC: {err:?}"
    );
    w.recover();
    assert_key_restored(&w, &key, &before);
}

/// A reset between the two halves of a reopen reverts the slot to
/// NeedsRenegotiation; the host restarts the reopen.
#[test]
pub(super) fn nssr_session_reopen_finish() {
    let mut w = World::new();
    let (key, before) = local_key(&w.ctx, w.sid());
    w.nssr();
    let pending = w
        .ctx
        .session_reopen_init(w.sid(), co_opts())
        .expect("reopen init");
    w.nssr();
    expect_status(
        w.ctx
            .session_reopen_finish(pending, w.co.seed, &w.co.bmk_session)
            .map(|session| session.session_id),
        TborStatus::SessionNotPending,
        "reopen finish after a second NSSR",
    );
    w.recover();
    assert_key_restored(&w, &key, &before);
}

/// `SessionClose` may tear down a slot the reset left NeedsRenegotiation;
/// it can no longer be reopened.
#[test]
pub(super) fn nssr_session_close() {
    let w = World::new();
    w.nssr();
    w.ctx
        .session_close(w.sid())
        .expect("close the stale session");
    let err = w
        .ctx
        .session_reopen_init(w.sid(), co_opts())
        .map(|pending| pending.session_id)
        .expect_err("reopen of a closed slot");
    assert_session_rejects(&err, TborStatus::SessionNotFound);
}

/// `PskChange` is allowed under the default PSK, since it is how the host
/// leaves it, and stays one-shot per session. The reset re-arms the
/// budget the session spent before it.
#[test]
pub(super) fn nssr_psk_change() {
    let mut w = World::new();
    w.ctx
        .psk_change(&w.co, &ROTATED_CO_PSK)
        .expect("PskChange before the NSSR");
    w.nssr();
    expect_status(
        w.ctx.psk_change(&w.co, &ROTATED_CO_PSK),
        TborStatus::SessionNeedsRenegotiation,
        "stale session after NSSR",
    );
    w.reopen();
    w.ctx
        .psk_change(&w.co, &ROTATED_CO_PSK)
        .expect("PskChange under the default PSK");
    expect_status(
        w.ctx.psk_change(&w.co, &ROTATED_CO_PSK),
        TborStatus::InvalidPermissions,
        "second PskChange on the reopened session",
    );
    provision(&w.ctx, &w.co, &w.pota, &w.policy, &w.local_mk_backup);
}

/// The reset returns the partition to `Enabled`. `PartInit` with the
/// pre-reset inputs re-derives the same PTA key, so the host can keep
/// its PTA certificate.
#[test]
pub(super) fn nssr_part_init() {
    let mut w = World::new();
    let part_init = |w: &World| {
        w.ctx
            .part_init(&w.co, &mach_seed(), &w.policy, &pota_thumbprint())
            .map(|resp| pta_pub_from_csr(&resp.pta_csr))
    };
    w.nssr();
    expect_status(
        part_init(&w),
        TborStatus::SessionNeedsRenegotiation,
        "stale session after NSSR",
    );
    w.reopen();
    expect_status(
        part_init(&w),
        TborStatus::DefaultPskMustRotate,
        "session reopened under the default PSK",
    );
    w.ctx
        .psk_change(&w.co, &ROTATED_CO_PSK)
        .expect("re-rotate CO PSK");
    let pta_pub = part_init(&w).expect("PartInit after recovery");
    assert_eq!(pta_pub, w.pta_pub, "PartInit must re-derive the PTA key");
    assert_part_state(&w.ctx, PART_STATE_INITIALIZING, false);
}

/// A reset between `PartInit` and `PartFinal` (here, while recovering
/// from an earlier one) returns the partition to `Enabled`: `PartFinal`
/// alone is refused and the host restarts from `PartInit`.
#[test]
pub(super) fn nssr_part_final() {
    let mut w = World::new();
    let (key, before) = local_key(&w.ctx, w.sid());
    w.nssr();
    w.reopen();
    w.ctx
        .psk_change(&w.co, &ROTATED_CO_PSK)
        .expect("re-rotate CO PSK");
    let init = w
        .ctx
        .part_init(&w.co, &mach_seed(), &w.policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(&w.pota, &pta_pub_from_csr(&init.pta_csr));
    let part_final = |w: &World| {
        w.ctx
            .part_final(&w.co, &w.policy, &w.local_mk_backup, &chain.der_items())
            .map(|resp| resp.local_mk_backup)
    };

    w.nssr();
    expect_status(
        part_final(&w),
        TborStatus::SessionNeedsRenegotiation,
        "stale session after NSSR",
    );
    w.reopen();
    expect_status(
        part_final(&w),
        TborStatus::DefaultPskMustRotate,
        "session reopened under the default PSK",
    );
    w.ctx
        .psk_change(&w.co, &ROTATED_CO_PSK)
        .expect("re-rotate CO PSK");
    expect_status(
        part_final(&w),
        TborStatus::InvalidArg,
        "PartFinal without a PartInit after the NSSR",
    );
    provision(&w.ctx, &w.co, &w.pota, &w.policy, &w.local_mk_backup);
    assert_key_restored(&w, &key, &before);
}

/// A Crypto-User (PlainText) session recovers the same way once the CO
/// has re-provisioned the partition.
#[test]
fn nssr_cu_session_recovers() {
    let mut w = World::new();
    let cu_ctx = TestCtx::new_with_path(w.ctx.path());
    let cu = bootstrap_rotated_cu(&cu_ctx, &ROTATED_CU_PSK);
    let (key, before) = local_key(&cu_ctx, cu.session_id);

    w.nssr();
    expect_status(
        aes_fingerprint(&cu_ctx, cu.session_id, &key),
        TborStatus::SessionNeedsRenegotiation,
        "stale CU session after NSSR",
    );
    w.recover();
    let cu = cu_ctx
        .session_reopen(&cu, None)
        .expect("CU reopen under the default PSK");
    expect_status(
        aes_fingerprint(&cu_ctx, cu.session_id, &key),
        TborStatus::DefaultPskMustRotate,
        "CU session reopened under the default PSK",
    );
    cu_ctx
        .psk_change(&cu, &ROTATED_CU_PSK)
        .expect("re-rotate CU PSK");
    let after = aes_fingerprint(&cu_ctx, cu.session_id, &key).expect("CU key after recovery");
    assert_eq!(after, before, "Local key must survive the NSSR");
}

/// Recovery without a reopen: close the stale CO session, rotate the PSK
/// on a fresh one and re-provision. Local-scope keys come back from
/// `local_mk_backup` (Session-scope keys are lost with the old session),
/// and, unlike a reopened session, the fresh one can `KeyReport`.
#[test]
fn nssr_recover_through_fresh_co_session() {
    let w = World::new();
    let (key, before) = local_key(&w.ctx, w.sid());
    let seal = w
        .ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id: w.sid(),
            scope: SCOPE_LOCAL,
        })
        .expect("SdSealingKeyGen");

    w.nssr();
    w.ctx
        .session_close(w.sid())
        .expect("close the stale session");
    let co = bootstrap_rotated_co(&w.ctx, &ROTATED_CO_PSK);
    provision(&w.ctx, &co, &w.pota, &w.policy, &w.local_mk_backup);

    let after = aes_fingerprint(&w.ctx, co.session_id, &key).expect("Local key after recovery");
    assert_eq!(after, before, "Local key must survive the NSSR");
    let report_data = [0xA5; KEY_REPORT_DATA_LEN];
    let report = w
        .ctx
        .tbor(&TborKeyReportReq {
            session_id: co.session_id,
            masked_key: seal.masked_key.to_vec(),
            report_data,
            auth_envelope: Vec::new(),
        })
        .expect("KeyReport on a fresh session")
        .report;
    verify_key_report(&w.ctx, &report, &seal.pub_key, &report_data);
}
