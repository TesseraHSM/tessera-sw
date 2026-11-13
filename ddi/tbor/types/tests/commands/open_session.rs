// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SessionOpenInit` /
//! `SessionOpenFinish` two-phase session handshake.
//!
//! Backend is selected at compile time by
//! [`tsra_ddi::TsraDdi::default`]. Happy-path sessions are owned
//! by a [`SessionGuard`](tsra_ddi_tbor_test_harness::SessionGuard) that closes on
//! `Drop`; negative paths drive `session_open_init` /
//! `session_open_finish` on `TestCtx` directly.

use tsra_ddi_tbor_test_harness::assertions::assert_fw_rejects;
use tsra_ddi_tbor_test_harness::build_mac_fin;
use tsra_ddi_tbor_test_harness::SessionSuite;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::CU_PSK_ID as CU;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborSessionOpenFinishReq;
use tsra_ddi_tbor_types::TborSessionOpenInitReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MAC_FIN_LEN;
use tsra_ddi_tbor_types::SEED_ENVELOPE_LEN;
use tsra_ddi_tbor_types::SESSION_MLKEM1024_PK_LEN;
use tsra_ddi_tbor_types::SESSION_P384_SEC1_LEN;
use tsra_ddi_tbor_types::SESSION_SUITE_ECDH_P384_ECDSA_P384;
use tsra_ddi_tbor_types::SESSION_SUITE_MLKEM1024_ECDSA_P384;
use tsra_session_ex_crypto::SessionInitiator;

/// Every key-establishment suite the host supports.
const SUITES: [SessionSuite; 2] = [SessionSuite::EcdhP384, SessionSuite::MlKem1024];

/// A raw `SessionOpenInit` request for a CU session.
fn raw_init_req(session_type: u8, suite_id: u8, pk_init: Vec<u8>) -> TborSessionOpenInitReq {
    TborSessionOpenInitReq {
        psk_id: CU,
        session_type,
        suite_id,
        pk_init,
    }
}

/// A raw ECDH P-384 `SessionOpenInit` request for a CU session.
fn raw_ecdh_init_req(pk_init: Vec<u8>) -> TborSessionOpenInitReq {
    raw_init_req(
        SessionType::Encrypted.to_u8(),
        SESSION_SUITE_ECDH_P384_ECDSA_P384,
        pk_init,
    )
}

/// Opens CO and CU sessions under every suite and verifies the handshake
/// metadata. The close travels encrypted under the session transport, so
/// a successful close also proves both sides derived the same keys.
#[test]
fn open_session_every_role_and_suite_happy() {
    let ctx = TestCtx::new();
    for suite in SUITES {
        for role in [CO, CU] {
            let session = ctx
                .open_session(role, suite)
                .expect("open_session must succeed");
            let h = session.handshake();
            assert_eq!(h.psk_id, role);
            assert_eq!(h.suite, suite);
            assert!(
                !h.bmk_session.is_empty(),
                "FW must return a non-empty bmk_session envelope",
            );
            session.close().expect("encrypted close must succeed");
        }
    }
}

/// Rejects every session type other than `Encrypted` (`0`), including the
/// retired authenticated value (`1`), for both roles.
#[test]
fn open_session_legacy_session_types_rejected() {
    let ctx = TestCtx::new();
    for (role, session_type) in [(CO, 1u8), (CU, 1), (CO, 2), (CU, 2)] {
        let mut req = raw_ecdh_init_req(vec![0x04u8; SESSION_P384_SEC1_LEN]);
        req.psk_id = role;
        req.session_type = session_type;
        ctx.expect_fw_reject(&req, TborStatus::InvalidSessionType);
    }
}

/// Rejects out-of-range PSK IDs before opening a session.
#[test]
fn open_session_invalid_psk_id() {
    // Only `0` (CO) and `1` (CU) are valid `psk_id` values. Spot-check
    // a small set of out-of-range values covering: the smallest invalid
    // value (`2`), a mid-range value (`0x7F`), and the all-ones byte
    // (`0xFF`). All must surface `InvalidPskId` from the FW
    // dispatcher's `psk_id`-validation arm before any KEM work.
    let ctx = TestCtx::new();
    for bad in [2u8, 0x7F, 0xFF] {
        let err = ctx
            .session_open_init(bad, SessionSuite::EcdhP384)
            .expect_err(&format!("psk_id {bad} must be rejected"));
        assert_fw_rejects(&err, TborStatus::InvalidPskId);
    }
}

/// Rejects an invalid raw session-type byte.
#[test]
fn open_session_invalid_session_type_byte() {
    // Bypass the typed `SessionType` enum to ship an out-of-range
    // byte directly. The FW `SessionType::from_u8` must reject.
    let ctx = TestCtx::new();
    let mut req = raw_ecdh_init_req(vec![0x04u8; SESSION_P384_SEC1_LEN]);
    req.session_type = 42;
    ctx.expect_fw_reject(&req, TborStatus::InvalidSessionType);
}

/// Rejects unsupported session-suite identifiers.
#[test]
fn open_session_unsupported_suite_id() {
    // Only 0x01 (ECDH P-384) and 0x02 (ML-KEM-1024) are defined; every
    // other byte must be rejected by `HsmSessionSuite::from_u8` before
    // any KEM work happens.
    let ctx = TestCtx::new();
    for bad in [0x00u8, 0x03, 0xff] {
        let req = raw_init_req(
            SessionType::Encrypted.to_u8(),
            bad,
            vec![0x04u8; SESSION_P384_SEC1_LEN],
        );
        ctx.expect_fw_reject(&req, TborStatus::UnsupportedSessionSuite);
    }
}

/// Rejects a `pk_init` whose length does not match the selected suite.
#[test]
fn open_session_pk_init_length_mismatch_rejected() {
    let ctx = TestCtx::new();
    let ecdh_pk = SessionInitiator::generate(SessionSuite::EcdhP384)
        .expect("generate ECDH ephemeral")
        .pk_init()
        .to_vec();
    let mlkem_pk = SessionInitiator::generate(SessionSuite::MlKem1024)
        .expect("generate ML-KEM ephemeral")
        .pk_init()
        .to_vec();
    assert_eq!(mlkem_pk.len(), SESSION_MLKEM1024_PK_LEN);
    for (suite_id, pk_init) in [
        (SESSION_SUITE_ECDH_P384_ECDSA_P384, mlkem_pk),
        (SESSION_SUITE_MLKEM1024_ECDSA_P384, ecdh_pk.clone()),
        (
            SESSION_SUITE_ECDH_P384_ECDSA_P384,
            ecdh_pk[..SESSION_P384_SEC1_LEN - 1].to_vec(),
        ),
    ] {
        let req = raw_init_req(SessionType::Encrypted.to_u8(), suite_id, pk_init);
        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }
}

/// Rejects MAC tampering at multiple positions during Phase-2.
#[test]
fn session_open_finish_mac_tampered() {
    let base = TestCtx::new();
    let path = base.path().to_owned();

    for index in [0, MAC_FIN_LEN / 2, MAC_FIN_LEN - 1] {
        let ctx = TestCtx::new_with_path(&path);

        let pending = ctx
            .session_open_init(CU, SessionSuite::EcdhP384)
            .unwrap_or_else(|e| panic!("phase 1 must succeed for MAC tamper index {index}: {e:?}"));

        let mut mac_fin = build_mac_fin(&pending)
            .unwrap_or_else(|e| panic!("build MAC for index {index}: {e:?}"));

        mac_fin[index] ^= 0x01;

        let err = ctx
            .session_open_finish_with_mac(pending, mac_fin)
            .expect_err(&format!("tampered MAC at index {index} must be rejected"));

        assert_fw_rejects(&err, TborStatus::SessionAuthFailure);
    }
}

/// Rejects a Phase-2 finish request for an unknown session.
#[test]
fn session_open_finish_unknown_session_id() {
    // Pick a session id that cannot possibly correspond to a live
    // pending slot. The FW pre-check fails to load the blob.
    let ctx = TestCtx::new();
    let req = TborSessionOpenFinishReq {
        session_id: 0xFFFF,
        mac_fin: [0u8; MAC_FIN_LEN],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let err = ctx
        .tbor(&req)
        .expect_err("finish against unknown session_id must fail");
    ctx.assert_unknown_session_rejects(&err, TborStatus::SessionNotFound);
}

/// Rejects a second finish request for an already active session.
#[test]
fn open_session_double_finish() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("open_session must succeed");
    // Replay the finish: pending slot is gone, FW must refuse.
    let req = TborSessionOpenFinishReq {
        session_id: session.session_id(),
        mac_fin: [0u8; MAC_FIN_LEN],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let err = ctx
        .tbor(&req)
        .expect_err("second finish against the same slot must fail");
    assert_fw_rejects(&err, TborStatus::SessionNotPending);
}

/// Rejects a malformed authenticated seed envelope during Phase-2.
#[test]
fn session_open_finish_seed_envelope_tampered() {
    // Build a finish request by hand so we can corrupt the seed_envelope
    // ciphertext byte after Phase-1 succeeds but before shipping it.
    let ctx = TestCtx::new();
    let pending = ctx
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect("phase 1 must succeed");
    let session_id = pending.session_id;
    let mac_fin = build_mac_fin(&pending).expect("build phase-2 mac");

    // Ship a syntactically-valid but cryptographically-bogus envelope:
    // "AEAD" magic + correct alg/aad_len framing but all-zero IV / CT /
    // tag. The FW's AEAD-open must fail and destroy the slot.
    let mut seed_envelope = [0u8; SEED_ENVELOPE_LEN];
    seed_envelope[0..4].copy_from_slice(b"AEAD");
    seed_envelope[4] = 0x03; // AeadAlg::AesGcm256

    let req = TborSessionOpenFinishReq {
        session_id,
        mac_fin,
        seed_envelope,
    };
    ctx.expect_fw_reject(&req, TborStatus::SessionAuthFailure);
}

/// Opens concurrent CU sessions with distinct session IDs on separate handles.
#[test]
fn open_session_multiple_concurrent() {
    let ctx_a = TestCtx::new();
    let a = ctx_a
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("open_session must succeed");

    // Second session lives on its own Dev — on hw the kernel driver
    // enforces `TSRA_MAX_SESSIONS_PER_FD = 1`, so overlapping
    // sessions must sit on separate fds bound to the same underlying
    // device (`ctx_a.path()`).
    let ctx_b = TestCtx::new_with_path(ctx_a.path());
    let b = ctx_b
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("open second session on extra dev");

    assert_ne!(
        a.session_id(),
        b.session_id(),
        "concurrent sessions must have distinct ids",
    );

    // Both sessions close on drop via their SessionGuards.
}

/// Enforces the per-file-descriptor limit of one active session.
#[test]
fn open_session_second_on_same_fd_rejected() {
    // Not applicable to the socket transport: a socket connection may hold
    // several sessions, so the one-session-per-handle limit doesn't apply.
    if tsra_ddi::sock_selected() {
        return;
    }
    let ctx = TestCtx::new();
    let _a = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("first open on a fresh fd must succeed");
    let err = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect_err("second open on the same fd must be rejected");
    assert_fw_rejects(&err, TborStatus::FileHandleSessionLimitReached);
}

// FW allocates a single 8-slot session table: slot 0 is reserved for
// CryptoOfficer (only 1 concurrent CO session), slots 1..=7 for
// CryptoUser (`CU_SESSION_LIMIT = 7` concurrent CU sessions). Limits
// are identical on emu (fw/plat/std) and hw (fw/plat/uno) — see
// `MAX_SESSIONS = 8` in
// `fw/plat/uno/fw/drivers/session_store/src/session_store.rs` and
// `fw/plat/std/common/src/drivers/session.rs`.

const CU_SESSION_LIMIT: usize = 7;

/// Verifies CU table exhaustion and slot recovery after a session closes.
#[test]
fn open_session_fills_cu_table_then_recovers() {
    let ctx = TestCtx::new();
    // Two-phase construction: allocate all secondary `TestCtx`s
    // first (each opens its own fd — required on hw where
    // `TSRA_MAX_SESSIONS_PER_FD = 1`), then borrow them to open
    // sessions and stash the `SessionGuard`s. The guards borrow
    // their ctx by reference, so ctxs must live at least as long as
    // guards; declaring ctxs first ensures rustc drops `guards`
    // before `ctxs`.
    let ctxs: Vec<_> = (0..CU_SESSION_LIMIT)
        .map(|_| TestCtx::new_with_path(ctx.path()))
        .collect();
    let mut guards: Vec<_> = ctxs
        .iter()
        .enumerate()
        .map(|(_i, c)| {
            c.open_session(CU, SessionSuite::EcdhP384)
                .unwrap_or_else(|e| {
                    panic!("CU session {_i} of {CU_SESSION_LIMIT} must succeed, got {e:?}")
                })
        })
        .collect();

    // One more CU open must be rejected — table is full.
    let overflow_ctx = TestCtx::new_with_path(ctx.path());
    let err = overflow_ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect_err("open_session past CU limit must be rejected");
    assert_fw_rejects(&err, TborStatus::VaultSessionLimitReached);
    drop(overflow_ctx);

    // Recovery: drop the last guard only (its `Drop` sends
    // SessionClose). That frees exactly one CU slot — enough for a
    // fresh open on the primary ctx to succeed. The remaining guards
    // stay alive and close at end of scope.
    guards.pop().expect("guards must not be empty");

    let _recovered = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("session table must recover after freeing one slot");
    // `_recovered` closes on drop at end of scope.
}

/// Verifies CO slot exhaustion and recovery after its session closes.
#[test]
fn open_session_fills_co_slot_then_recovers() {
    let ctx = TestCtx::new();

    let ctx_first = TestCtx::new_with_path(ctx.path());
    let first = ctx_first
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("first CO session must succeed");

    let ctx_second = TestCtx::new_with_path(ctx.path());
    let err = ctx_second
        .open_session(CO, SessionSuite::EcdhP384)
        .expect_err("second concurrent CO open must be rejected");
    assert_fw_rejects(&err, TborStatus::VaultSessionLimitReached);

    // Recovery: drop the first guard + fd; a fresh CO open must succeed.
    drop(first);
    drop(ctx_first);

    let _recovered = ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("CO slot must recover after the first fd is dropped");
    // `_recovered` closes on drop at end of scope.
}

/// Verifies independent CO and CU slot limits and recovery in a full table.
#[test]
fn open_session_fills_full_table_then_recovers() {
    let ctx = TestCtx::new();

    // CO slot: one guard + its own fd (hw needs one fd per session).
    let ctx_co = TestCtx::new_with_path(ctx.path());
    let co_guard = ctx_co
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("CO session must succeed");

    // CU slots: `CU_SESSION_LIMIT` guards, each on its own fd.
    let cu_ctxs: Vec<_> = (0..CU_SESSION_LIMIT)
        .map(|_| TestCtx::new_with_path(ctx.path()))
        .collect();
    let mut cu_guards: Vec<_> = cu_ctxs
        .iter()
        .enumerate()
        .map(|(_i, c)| {
            c.open_session(CU, SessionSuite::EcdhP384)
                .unwrap_or_else(|e| {
                    panic!("CU session {_i} of {CU_SESSION_LIMIT} must succeed, got {e:?}")
                })
        })
        .collect();

    // Table is full — one more CO open must be rejected.
    let overflow_co_ctx = TestCtx::new_with_path(ctx.path());
    let err_co = overflow_co_ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect_err("second concurrent CO open must be rejected");
    assert_fw_rejects(&err_co, TborStatus::VaultSessionLimitReached);
    drop(overflow_co_ctx);

    // One more CU open must be rejected too.
    let overflow_cu_ctx = TestCtx::new_with_path(ctx.path());
    let err_cu = overflow_cu_ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect_err("open_session past CU limit must be rejected");
    assert_fw_rejects(&err_cu, TborStatus::VaultSessionLimitReached);
    drop(overflow_cu_ctx);

    // Recovery-1: drop one CU guard. That frees exactly one CU slot;
    // a fresh CU open on a new fd must succeed. CO stays full.
    cu_guards.pop().expect("cu_guards must not be empty");
    let ctx_recover_cu = TestCtx::new_with_path(ctx.path());
    let _recovered_cu = ctx_recover_cu
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("CU slot must recover after freeing one CU guard");

    // Recovery-2: drop the CO guard + its fd. A fresh CO open on a
    // new fd must succeed. (A new fd is required because on hw
    // `TSRA_MAX_SESSIONS_PER_FD = 1`, so we cannot reuse
    // `ctx_recover_cu` — its fd already holds the CU session opened
    // in Recovery-1.)
    drop(co_guard);
    drop(ctx_co);
    let ctx_recover_co = TestCtx::new_with_path(ctx.path());
    let _recovered_co = ctx_recover_co
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("CO slot must recover after CO fd is dropped");
    // Remaining guards close on drop at end of scope.
}

/// Confirms a new session opens successfully after a prior session closes.
#[test]
fn open_close_then_open_new_session() {
    let ctx = TestCtx::new();
    let first = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("first handshake must succeed");
    first.close().expect("first SessionClose must succeed");

    let second = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("open new session after close must succeed");
    second.close().expect("second SessionClose must succeed");
}

/// Verifies independent handshakes bind distinct transcripts and derive
/// distinct host confirmations under every suite.
#[test]
fn handshakes_derive_unique_transcripts() {
    let ctx = TestCtx::new();
    for suite in SUITES {
        let a = ctx
            .session_open_init(CO, suite)
            .expect("first Phase-1 must succeed");
        let a_t1 = *a.keys.transcript_hash();
        let a_fin = build_mac_fin(&a).expect("first fin");
        ctx.session_open_finish(a)
            .and_then(|h| ctx.session_close(h.session_id))
            .expect("first session must open and close");

        let b = ctx
            .session_open_init(CO, suite)
            .expect("second Phase-1 must succeed");
        let b_t1 = *b.keys.transcript_hash();
        let b_fin = build_mac_fin(&b).expect("second fin");
        ctx.session_open_finish(b)
            .and_then(|h| ctx.session_close(h.session_id))
            .expect("second session must open and close");

        assert_ne!(
            a_t1, b_t1,
            "fresh ephemerals must yield distinct transcripts"
        );
        assert_ne!(a_fin, b_fin, "per-session host confirmations must differ");
    }
}

/// Verifies the partition identity certificate the handshake signature is
/// checked against is stable across handshakes.
#[test]
fn partition_pk_hsm_stable_across_handshakes() {
    let ctx = TestCtx::new();
    let leaf_a = ctx.leaf_certificate().expect("first leaf certificate");
    ctx.open_session(CU, SessionSuite::EcdhP384)
        .expect("handshake must succeed")
        .close()
        .expect("close must succeed");
    let leaf_b = ctx.leaf_certificate().expect("second leaf certificate");
    assert_eq!(
        leaf_a, leaf_b,
        "partition identity certificate must be stable across handshakes",
    );
}

/// Rejects an all-zero P-384 initialization public key.
#[test]
fn pk_init_all_zero_rejected() {
    let ctx = TestCtx::new();
    let req = raw_ecdh_init_req(vec![0u8; SESSION_P384_SEC1_LEN]);
    let err = ctx
        .tbor(&req)
        .expect_err("all-zero pk_init must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// Rejects an initialization public key whose coordinates are off-curve.
#[test]
fn pk_init_not_on_curve_rejected() {
    let ctx = TestCtx::new();
    let mut pk_init = vec![0xFFu8; SESSION_P384_SEC1_LEN];
    pk_init[0] = 0x04; // SEC1 uncompressed prefix
    let req = raw_ecdh_init_req(pk_init);
    let err = ctx
        .tbor(&req)
        .expect_err("off-curve pk_init must be rejected");
    assert_fw_rejects(&err, TborStatus::EccPublicKeyValidationFailed);
}

// Verbatim from MBOR `TEST_ECC_384_PUBLIC_KEY_X_AS_PRIME` /
// `TEST_ECC_384_PUBLIC_KEY_Y_AS_PRIME`. A coordinate equal to the
// field prime is a valid field element but off-curve — targeted
// regression for the on-curve validation stage.

/// P-384 field prime `p`, big-endian.
const P384_PRIME_BE: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
];

/// Filler Y paired with prime-as-X (verbatim from MBOR vectors).
const P384_INVALID_Y_FOR_X_AS_PRIME_BE: [u8; 48] = [
    0x53, 0xbf, 0xf4, 0x76, 0x31, 0x31, 0x33, 0xa3, 0x58, 0x3c, 0x11, 0x3d, 0xeb, 0x8d, 0xb6, 0xb7,
    0x47, 0x4a, 0xe3, 0x51, 0xd0, 0x38, 0x26, 0xac, 0xec, 0x11, 0x34, 0x33, 0x04, 0x0d, 0xc6, 0xc3,
    0x75, 0x37, 0xa1, 0x89, 0xdd, 0x4f, 0x66, 0x57, 0x72, 0xac, 0xc5, 0x3b, 0xb6, 0xc6, 0xb8, 0x0c,
];

/// Filler X paired with prime-as-Y (verbatim from MBOR vectors).
const P384_INVALID_X_FOR_Y_AS_PRIME_BE: [u8; 48] = [
    0xcf, 0x6b, 0x8d, 0x9a, 0x48, 0x75, 0xa9, 0x5a, 0x19, 0x89, 0x72, 0x18, 0xa4, 0x94, 0x4d, 0xef,
    0x0a, 0x93, 0xce, 0x5b, 0x8b, 0x8d, 0xf1, 0x37, 0x54, 0x09, 0x17, 0x89, 0xbc, 0xef, 0x69, 0xdb,
    0x6c, 0xa7, 0x9e, 0xf6, 0xb6, 0x4b, 0x5c, 0x13, 0xed, 0x3c, 0xbf, 0xed, 0x0b, 0x3d, 0xf1, 0x7e,
];

/// Pack (X, Y) as SEC1 uncompressed: `0x04 || X_be || Y_be`.
fn pack_sec1_uncompressed(x_be: &[u8; 48], y_be: &[u8; 48]) -> Vec<u8> {
    let mut out = vec![0u8; SESSION_P384_SEC1_LEN];
    out[0] = 0x04;
    out[1..49].copy_from_slice(x_be);
    out[49..97].copy_from_slice(y_be);
    out
}

/// Rejects a P-384 initialization public key with X equal to the field prime.
#[test]
fn pk_init_x_as_prime_rejected() {
    let ctx = TestCtx::new();
    let pk_init = pack_sec1_uncompressed(&P384_PRIME_BE, &P384_INVALID_Y_FOR_X_AS_PRIME_BE);
    let req = raw_ecdh_init_req(pk_init);
    let err = ctx
        .tbor(&req)
        .expect_err("pk_init with X = P-384 prime must be rejected");
    assert_fw_rejects(&err, TborStatus::EccPublicKeyValidationFailed);
}

/// Rejects a P-384 initialization public key with Y equal to the field prime.
#[test]
fn pk_init_y_as_prime_rejected() {
    let ctx = TestCtx::new();
    let pk_init = pack_sec1_uncompressed(&P384_INVALID_X_FOR_Y_AS_PRIME_BE, &P384_PRIME_BE);
    let req = raw_ecdh_init_req(pk_init);
    let err = ctx
        .tbor(&req)
        .expect_err("pk_init with Y = P-384 prime must be rejected");
    assert_fw_rejects(&err, TborStatus::EccPublicKeyValidationFailed);
}

/// Rejects a bit-flipped P-384 ephemeral initialization public key.
#[test]
fn pk_init_single_byte_tampered_rejected() {
    let ctx = TestCtx::new();
    let mut pk_init = SessionInitiator::generate(SessionSuite::EcdhP384)
        .expect("generate ECDH ephemeral")
        .pk_init()
        .to_vec();
    pk_init[8] ^= 0x01; // Inside X (X is bytes 1..49); avoids prefix + X/Y boundary.

    let req = raw_ecdh_init_req(pk_init);
    let err = ctx
        .tbor(&req)
        .expect_err("single-bit-tampered pk_init must be rejected");
    assert_fw_rejects(&err, TborStatus::EccPointValidationFailed);
}

/// Verifies concurrent native-backend CU opens all succeed with unique IDs.
#[test]
fn open_session_multi_threaded_all_should_open() {
    let ctx = TestCtx::new();
    let path = ctx.path();

    // Pre-allocate one ctx per racer on the main thread so the
    // spawned workers can borrow them and return `SessionGuard<'_>`
    // values whose borrow outlives `thread::scope`.
    let ctxs: Vec<_> = (0..CU_SESSION_LIMIT)
        .map(|_| TestCtx::new_with_path(path))
        .collect();

    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = ctxs
            .iter()
            .map(|c| s.spawn(move || c.open_session(CU, SessionSuite::EcdhP384)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("worker thread must not panic"))
            .collect()
    });

    let (winner_results, rejections): (Vec<_>, Vec<_>) =
        results.into_iter().partition(Result::is_ok);
    let winners: Vec<_> = winner_results.into_iter().map(Result::unwrap).collect();
    let rejections: Vec<_> = rejections.into_iter().map(Result::unwrap_err).collect();

    let mut sorted_ids: Vec<_> = winners.iter().map(|g| g.session_id()).collect();
    let winner_ids = sorted_ids.clone();
    sorted_ids.sort_unstable();
    sorted_ids.dedup();
    let unique_wins = sorted_ids.len();

    assert!(
        rejections.is_empty(),
        "all {CU_SESSION_LIMIT} concurrent CU opens must succeed; observed rejections: \
         {rejections:?}",
    );
    assert_eq!(
        winner_ids.len(),
        CU_SESSION_LIMIT,
        "expected {CU_SESSION_LIMIT} winning session ids, got {winner_ids:?}",
    );
    assert_eq!(
        unique_wins, CU_SESSION_LIMIT,
        "concurrent winners must have distinct session ids: {winner_ids:?}",
    );
}

/// Verifies a rejected session type leaves the handle reusable.
#[test]
fn rejected_session_type_does_not_poison_fd() {
    let ctx = TestCtx::new();

    let mut req = raw_ecdh_init_req(vec![0x04u8; SESSION_P384_SEC1_LEN]);
    req.session_type = 1;
    ctx.expect_fw_reject(&req, TborStatus::InvalidSessionType);

    let session = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("valid session must succeed after rejected Phase-1");

    session
        .close()
        .expect("session close after recovery must succeed");
}

/// Verifies an unsupported suite rejection does not consume CU capacity.
#[test]
fn rejected_suite_does_not_consume_session_slot() {
    let ctx = TestCtx::new();

    let req = raw_init_req(
        SessionType::Encrypted.to_u8(),
        0xff,
        vec![0x04u8; SESSION_P384_SEC1_LEN],
    );

    ctx.expect_fw_reject(&req, TborStatus::UnsupportedSessionSuite);

    let session = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("valid session must succeed after unsupported suite");

    session
        .close()
        .expect("session close after recovery must succeed");
    // Verify the rejected suite did not leak any CU session slots.
    let other_ctxs: Vec<_> = (0..CU_SESSION_LIMIT)
        .map(|_| TestCtx::new_with_path(ctx.path()))
        .collect();

    let _other_sessions: Vec<_> = other_ctxs
        .iter()
        .map(|other_ctx| {
            other_ctx
                .open_session(CU, SessionSuite::EcdhP384)
                .expect("CU session must succeed after unsupported suite rejection")
        })
        .collect();
    // All CU slots are occupied; one additional open must be rejected.
    let overflow_ctx = TestCtx::new_with_path(ctx.path());
    let err = overflow_ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect_err("eighth CU session must be rejected");

    assert_fw_rejects(&err, TborStatus::VaultSessionLimitReached);
}

/// Verifies an invalid public key rejection does not consume CU capacity.
#[test]
fn rejected_pk_init_does_not_consume_session_slot() {
    let ctx = TestCtx::new();

    let req = raw_ecdh_init_req(vec![0u8; SESSION_P384_SEC1_LEN]);

    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);

    let session = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("valid session must succeed after invalid pk_init");

    session
        .close()
        .expect("session close after recovery must succeed");

    // Verify the rejected public key did not leak any CU session slots.
    let other_ctxs: Vec<_> = (0..CU_SESSION_LIMIT)
        .map(|_| TestCtx::new_with_path(ctx.path()))
        .collect();

    let _other_sessions: Vec<_> = other_ctxs
        .iter()
        .map(|other_ctx| {
            other_ctx
                .open_session(CU, SessionSuite::EcdhP384)
                .expect("CU session must succeed after invalid pk_init rejection")
        })
        .collect();
    // All CU slots are occupied; one additional open must be rejected.
    let overflow_ctx = TestCtx::new_with_path(ctx.path());
    let err = overflow_ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect_err("eighth CU session must be rejected");

    assert_fw_rejects(&err, TborStatus::VaultSessionLimitReached);
}

/// Verifies a pending Phase-1 session blocks another open on the same handle.
#[test]
fn pending_session_blocks_second_open_on_same_fd() {
    // Not applicable to the socket transport: a socket connection may hold
    // several sessions, so the one-session-per-handle limit doesn't apply.
    if tsra_ddi::sock_selected() {
        return;
    }
    let ctx = TestCtx::new();

    let pending = ctx
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect("first Phase-1 must succeed");

    let err = ctx
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect_err("second Phase-1 on the same fd must be rejected");

    assert_fw_rejects(&err, TborStatus::FileHandleSessionLimitReached);

    let handshake = ctx
        .session_open_finish(pending)
        .expect("original pending session must still finish successfully");

    ctx.session_close(handshake.session_id)
        .expect("finished session must close successfully");
}

/// Verifies failed Phase-2 MAC authentication reclaims its pending CU slot.
#[test]
fn failed_finish_mac_reclaims_session_state() {
    let ctx = TestCtx::new();

    let pending = ctx
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect("Phase-1 must succeed");

    let session_id = pending.session_id;

    let mut mac_fin = build_mac_fin(&pending).expect("build Phase-2 mac");
    mac_fin[0] ^= 0x01;

    let err = ctx
        .session_open_finish_with_mac(pending, mac_fin)
        .expect_err("tampered mac_fin must be rejected");

    assert_fw_rejects(&err, TborStatus::SessionAuthFailure);

    // Confirm the failed authentication destroyed the FW pending slot.
    let replay = TborSessionOpenFinishReq {
        session_id,
        mac_fin: [0u8; MAC_FIN_LEN],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };

    let err = ctx
        .tbor(&replay)
        .expect_err("failed authentication must destroy the pending slot");

    ctx.assert_unknown_session_rejects(&err, TborStatus::SessionNotFound);

    // The original fd may remain session-bound after failed Phase-2.
    // Open the full CU capacity on fresh fds. If the failed pending slot
    // leaked, only CU_SESSION_LIMIT - 1 of these opens would succeed.
    let path = ctx.path().to_owned();

    let recovery_ctxs: Vec<_> = (0..CU_SESSION_LIMIT)
        .map(|_| TestCtx::new_with_path(&path))
        .collect();

    let _recovery_guards: Vec<_> = recovery_ctxs
        .iter()
        .map(|recovery_ctx| {
            recovery_ctx
                .open_session(CU, SessionSuite::EcdhP384)
                .expect("CU recovery session must succeed after failed Phase-2")
        })
        .collect();
}

/// Rejects cross-session MAC substitution without damaging the source session.
#[test]
fn session_open_finish_rejects_mac_from_another_session() {
    let ctx_a = TestCtx::new();

    let pending_a = ctx_a
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect("phase 1 for session A must succeed");

    let ctx_b = TestCtx::new_with_path(ctx_a.path());

    let pending_b = ctx_b
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect("phase 1 for session B must succeed");

    assert_ne!(
        pending_a.session_id, pending_b.session_id,
        "pending sessions must have distinct ids",
    );

    let mac_a = build_mac_fin(&pending_a).expect("build MAC for session A");

    let err = ctx_b
        .session_open_finish_with_mac(pending_b, mac_a)
        .expect_err("session A's MAC must not authenticate session B");

    assert_fw_rejects(&err, TborStatus::SessionAuthFailure);

    // Failure against B must not damage A.
    let mac_a = build_mac_fin(&pending_a).expect("rebuild MAC for session A");

    let handshake_a = ctx_a
        .session_open_finish_with_mac(pending_a, mac_a)
        .expect("session A must remain finishable");

    ctx_a
        .session_close(handshake_a.session_id)
        .expect("session A must close successfully");
}

/// Verifies an unknown finish request preserves an unrelated pending session.
#[test]
fn unknown_finish_does_not_destroy_pending_session() {
    let ctx = TestCtx::new();

    let pending = ctx
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect("phase 1 must succeed");

    let mac_fin = build_mac_fin(&pending).expect("build valid phase-2 MAC");

    let unknown = TborSessionOpenFinishReq {
        session_id: 0xFFFF,
        mac_fin: [0u8; MAC_FIN_LEN],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };

    let err = ctx
        .tbor(&unknown)
        .expect_err("unknown session id must be rejected");

    ctx.assert_unknown_session_rejects(&err, TborStatus::FileHandleSessionIdDoesNotMatch);

    let handshake = ctx
        .session_open_finish_with_mac(pending, mac_fin)
        .expect("valid pending session must remain finishable");

    ctx.session_close(handshake.session_id)
        .expect("session must close successfully");
}

/// Verifies failed Phase-2 authentication leaves the original handle session-bound.
#[test]
fn failed_finish_mac_keeps_original_fd_session_bound() {
    // Not applicable to the socket transport: a socket connection may hold
    // several sessions, so the one-session-per-handle limit doesn't apply.
    if tsra_ddi::sock_selected() {
        return;
    }
    let ctx = TestCtx::new();

    let pending = ctx
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect("Phase-1 must succeed");

    let mut mac_fin = build_mac_fin(&pending).expect("build Phase-2 mac");
    mac_fin[0] ^= 0x01;

    let err = ctx
        .session_open_finish_with_mac(pending, mac_fin)
        .expect_err("tampered mac_fin must be rejected");

    assert_fw_rejects(&err, TborStatus::SessionAuthFailure);

    let err = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect_err("original fd must remain session-bound");

    assert_fw_rejects(&err, TborStatus::FileHandleSessionLimitReached);
}

/// Socket connections support multiple Pending and Active sessions.
#[test]
fn socket_connection_supports_multiple_sessions() {
    // Only applicable to the socket transport: hardware limits each device
    // handle to one session.
    if !tsra_ddi::sock_selected() {
        return;
    }
    let ctx = TestCtx::new();
    let first = ctx
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect("first Pending session");
    let second = ctx
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect("second Pending session on the same connection");
    assert_ne!(first.session_id, second.session_id);
    let first = ctx
        .session_open_finish(first)
        .expect("activate first session");
    let second = ctx
        .session_open_finish(second)
        .expect("activate second session");
    ctx.session_close(first.session_id)
        .expect("close first session");
    ctx.session_close(second.session_id)
        .expect("close second session");
}

/// Failed authentication does not prevent a fresh open on a socket connection.
#[test]
fn socket_connection_can_open_after_failed_finish() {
    // Only applicable to the socket transport: hardware limits each device
    // handle to one session.
    if !tsra_ddi::sock_selected() {
        return;
    }
    let ctx = TestCtx::new();
    let pending = ctx
        .session_open_init(CU, SessionSuite::EcdhP384)
        .expect("Pending session");
    let mut mac = build_mac_fin(&pending).expect("phase 2 MAC");
    mac[0] ^= 1;
    let err = ctx
        .session_open_finish_with_mac(pending, mac)
        .expect_err("tampered MAC must fail");
    assert_fw_rejects(&err, TborStatus::SessionAuthFailure);
    let session = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("fresh session on the original connection");
    session.close().expect("close fresh session");
}
