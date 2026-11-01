// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `SessionReopenInit` / `SessionReopenFinish`.
//!
//! A partition reset (`erase`, i.e. NSSR on hardware) leaves every
//! open session NeedsRenegotiation and reverts partition PSKs to their
//! defaults. The host re-establishes each session under the same id by
//! replaying the session's `seed` and last `bmk_session`.

#![cfg(feature = "emu")]

use tsra_ddi_tbor_test_harness::assertions::assert_fw_rejects;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::build_mac_fin;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::SessionOpenInitOptions;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::CU_PSK_ID as CU;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborGetUnwrappingKeyReq;
use tsra_ddi_tbor_types::TborHashReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

fn hash(ctx: &TestCtx, session_id: u16) -> Result<Vec<u8>, tsra_ddi_interface::DdiError> {
    ctx.tbor(&TborHashReq {
        session_id,
        algo: HASH_ALGO_SHA256,
        msg: b"abc".to_vec(),
    })
    .map(|r| r.digest)
}

/// Rotated CU session, then partition reset.
fn erased_cu(ctx: &TestCtx) -> SessionHandshake {
    let session = bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK);
    hash(ctx, session.session_id).expect("hash before reset");
    ctx.erase().expect("erase");
    session
}

fn reopen_opts(prev: &SessionHandshake) -> SessionOpenInitOptions<'static> {
    SessionOpenInitOptions::new(prev.psk_id, prev.session_type)
}

/// After a reset, in-session ops fail until the session is reopened.
#[test]
fn reopen_cu_after_erase_restores_session() {
    let ctx = TestCtx::new();
    let prev = erased_cu(&ctx);

    let err = hash(&ctx, prev.session_id).expect_err("stale session must be rejected");
    assert_fw_rejects(&err, TborStatus::SessionNeedsRenegotiation);

    let reopened = ctx.session_reopen(&prev, None).expect("reopen");
    assert_eq!(reopened.session_id, prev.session_id);
    assert_eq!(reopened.seed, prev.seed);

    ctx.psk_change(&reopened, &ROTATED_CU_PSK)
        .expect("re-rotate CU PSK");
    hash(&ctx, reopened.session_id).expect("hash after reopen");
}

/// Authenticated CO sessions reopen too; the session can be reopened
/// again after a second reset using the refreshed `bmk_session`.
#[test]
fn reopen_co_authenticated_twice() {
    let ctx = TestCtx::new();
    let mut session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    for round in 0..2 {
        ctx.erase().expect("erase");
        session = ctx
            .session_reopen(&session, None)
            .unwrap_or_else(|e| panic!("reopen round {round}: {e:?}"));
        assert!(!session.bmk_session.is_empty());
        ctx.psk_change(&session, &ROTATED_CO_PSK)
            .expect("re-rotate CO PSK");
    }
}

/// An Active session cannot be reopened.
#[test]
fn reopen_active_session_rejected() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session");
    let err = ctx
        .session_reopen_init(session.session_id(), reopen_opts(session.handshake()))
        .expect_err("reopen of an active slot must fail");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// Session type must match the role bound to the session id.
#[test]
fn reopen_wrong_session_type_rejected() {
    let ctx = TestCtx::new();
    let prev = erased_cu(&ctx);
    let err = ctx
        .session_reopen_init(
            prev.session_id,
            SessionOpenInitOptions::new(CU, SessionType::Authenticated),
        )
        .expect_err("CU + Authenticated must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidSessionType);
    ctx.session_reopen(&prev, None)
        .expect("reopen after rejected init");
}

/// A bad Phase-2 MAC leaves the slot reopenable.
#[test]
fn reopen_finish_mac_tampered_then_retry() {
    let ctx = TestCtx::new();
    let prev = erased_cu(&ctx);
    let pending = ctx
        .session_reopen_init(prev.session_id, reopen_opts(&prev))
        .expect("reopen init");
    let mut mac_fin = build_mac_fin(&pending).expect("mac_fin");
    mac_fin[0] ^= 1;
    let err = ctx
        .session_reopen_finish_with_mac(pending, mac_fin, prev.seed, &prev.bmk_session)
        .expect_err("tampered MAC must fail");
    assert_fw_rejects(&err, TborStatus::SessionAuthFailure);

    let err = hash(&ctx, prev.session_id).expect_err("still needs renegotiation");
    assert_fw_rejects(&err, TborStatus::SessionNeedsRenegotiation);
    ctx.session_reopen(&prev, None).expect("retry reopen");
}

/// A tampered `bmk_session` fails authentication and can be retried.
#[test]
fn reopen_finish_bmk_tampered_then_retry() {
    let ctx = TestCtx::new();
    let prev = erased_cu(&ctx);
    let pending = ctx
        .session_reopen_init(prev.session_id, reopen_opts(&prev))
        .expect("reopen init");
    let mut bmk = prev.bmk_session.clone();
    let last = bmk.len() - 1;
    bmk[last] ^= 1;
    let err = ctx
        .session_reopen_finish(pending, prev.seed, &bmk)
        .expect_err("tampered bmk_session must fail");
    assert_fw_rejects(&err, TborStatus::SessionAuthFailure);
    ctx.session_reopen(&prev, None).expect("retry reopen");
}

/// `SessionOpenFinish` cannot complete a reopen handshake.
#[test]
fn open_finish_on_reopen_pending_rejected() {
    let ctx = TestCtx::new();
    let prev = erased_cu(&ctx);
    let pending = ctx
        .session_reopen_init(prev.session_id, reopen_opts(&prev))
        .expect("reopen init");
    let err = ctx
        .session_open_finish(pending)
        .expect_err("OpenFinish must not complete a reopen");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
    ctx.session_reopen(&prev, None)
        .expect("reopen after rejected finish");
}

/// `SessionReopenFinish` cannot complete a fresh open handshake.
#[test]
fn reopen_finish_on_open_pending_rejected() {
    let ctx = TestCtx::new();
    let prev = erased_cu(&ctx);
    // One session per fd: run the fresh open on a second handle.
    let other = TestCtx::new_with_path(ctx.path());
    let pending = other
        .session_open_init(CU, SessionType::PlainText)
        .expect("open init");
    let err = other
        .session_reopen_finish(pending, prev.seed, &prev.bmk_session)
        .expect_err("ReopenFinish must not complete a fresh open");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// A fresh open handshake does not disturb a pending reopen.
#[test]
fn open_init_does_not_disturb_reopen_pending() {
    let ctx = TestCtx::new();
    let prev = erased_cu(&ctx);
    let pending = ctx
        .session_reopen_init(prev.session_id, reopen_opts(&prev))
        .expect("reopen init");
    let other = TestCtx::new_with_path(ctx.path());
    other
        .open_session(CO, SessionType::Authenticated)
        .expect("fresh CO open")
        .close()
        .expect("close CO");
    ctx.session_reopen_finish(pending, prev.seed, &prev.bmk_session)
        .expect("reopen finish");
}

/// The partition unwrapping key survives a reset, so blobs wrapped before
/// the reset still unwrap after the session is reopened.
#[test]
fn unwrapping_key_stable_across_reset() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let get = |id| {
        ctx.tbor(&TborGetUnwrappingKeyReq { session_id: id })
            .expect("GetUnwrappingKey")
            .pub_key
    };
    let before = get(session.session_id);

    ctx.erase().expect("erase");
    let session = ctx.session_reopen(&session, None).expect("reopen");
    ctx.psk_change(&session, &ROTATED_CO_PSK)
        .expect("re-rotate CO PSK");

    assert_eq!(before, get(session.session_id));
}
