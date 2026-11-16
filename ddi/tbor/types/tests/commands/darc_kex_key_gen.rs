// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `DarcKexKeyGen` command.
//!
//! Cross-test isolation comes from `open_dev`'s factory reset; no
//! per-test cleanup is required (see [`tsra_ddi_tbor_test_harness::fixture`]).
//!
//! The command generates a key-exchange keypair for the requested HPKE KEM
//! (P-384, ML-KEM-1024 or MLKEM1024-P384) and returns the
//! **masked** private key (masked under the requested scope's masking
//! key) plus the public key — nothing is stored on the device.  The
//! Ephemeral/Local masking keys are provisioned by `PartFinal`, so the
//! happy-path tests first drive `PartInit → PartFinal`.
//!
//! Coverage (mirrors `sd_sealing_key_gen`, the command this is modelled
//! on):
//! * Happy path (Ephemeral + Local) × every KEM — returns a non-zero masked
//!   key + public key of the KEM's length (P-384 280/96, ML-KEM-1024
//!   296/1568, MLKEM1024-P384 264/1665); a second call yields a distinct
//!   keypair.
//! * Unknown KEM → `InvalidArg`.
//! * Unsupported scope (Session + SecurityDomain) → `UnsupportedKeyScope`.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).
//!
//! `DarcKexKeyGen` itself carries no out-of-band data — the request is a
//! session id plus a 1-byte scope and a 1-byte KEM, and the response is the
//! masked key plus the public key — so the command runs on any transport.
//! The *setup* is what needs OOB: [`finalized_co_session`] drives
//! `PartFinal`, whose PTA chain travels out of band, so the tests that
//! need a finalized partition also need the driver's data-transfer path.

use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborDarcKexKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::KEX_PUB_KEY_LEN;
use tsra_ddi_tbor_types::KEX_PUB_KEY_MAX_LEN;
use tsra_ddi_tbor_types::MASKED_KEX_KEY_LEN;
use tsra_ddi_tbor_types::MASKED_KEX_KEY_MAX_LEN;
use tsra_ddi_tbor_types::MASKED_KEX_KEY_MIN_LEN;
use tsra_ddi_tbor_types::TRANSFER_KEM_MLKEM1024;
use tsra_ddi_tbor_types::TRANSFER_KEM_MLKEM1024_P384;
use tsra_ddi_tbor_types::TRANSFER_KEM_P384;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope` discriminants (wire mirror of the firmware `HsmKeyScope`).
const SCOPE_SESSION: u8 = 0b001;
const SCOPE_EPHEMERAL: u8 = 0b010;
const SCOPE_LOCAL: u8 = 0b011;
const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// Every supported KEM with its `(masked key, public key)` lengths.
const KEMS: [(u8, usize, usize); 3] = [
    (TRANSFER_KEM_P384, MASKED_KEX_KEY_LEN, KEX_PUB_KEY_LEN),
    (TRANSFER_KEM_MLKEM1024, MASKED_KEX_KEY_MAX_LEN, 1568),
    (
        TRANSFER_KEM_MLKEM1024_P384,
        MASKED_KEX_KEY_MIN_LEN,
        KEX_PUB_KEY_MAX_LEN,
    ),
];

/// Happy path for a supported `scope`, over every KEM: the masked key +
/// public key are full/non-zero, and a second call yields a distinct keypair.
fn roundtrip_for_scope(scope: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for (kem, masked_len, pub_len) in KEMS {
        roundtrip_for_kem(&ctx, session.session_id, scope, kem, masked_len, pub_len);
    }
}

fn roundtrip_for_kem(
    ctx: &TestCtx,
    session_id: u16,
    scope: u8,
    kem: u8,
    masked_len: usize,
    pub_len: usize,
) {
    let req = TborDarcKexKeyGenReq {
        session_id,
        scope,
        kem,
    };
    let resp = ctx.tbor(&req).expect("DarcKexKeyGen roundtrip");

    // Masked private key: exactly the KEM's pinned length, non-zero.
    assert_eq!(resp.masked_key.len(), masked_len);
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked_key must not be all-zero",
    );
    // Public key: the KEM's full, non-zero encoding.
    assert_eq!(resp.pub_key.len(), pub_len);
    assert!(
        resp.pub_key.iter().any(|&b| b != 0),
        "pub_key must not be all-zero",
    );

    // Each call generates fresh randomness → a distinct keypair.
    let resp2 = ctx.tbor(&req).expect("second DarcKexKeyGen");
    assert_ne!(
        resp.masked_key, resp2.masked_key,
        "each generation must yield a distinct masked key",
    );
    assert_ne!(
        resp.pub_key, resp2.pub_key,
        "each generation must yield a distinct public key",
    );
}

#[test]
fn darc_kex_key_gen_ephemeral_roundtrip() {
    roundtrip_for_scope(SCOPE_EPHEMERAL);
}

#[test]
fn darc_kex_key_gen_local_roundtrip() {
    roundtrip_for_scope(SCOPE_LOCAL);
}

#[test]
fn darc_kex_key_gen_rejects_unsupported_scope() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Session and SecurityDomain masking keys are not provisioned for
    // this command, so both must be rejected with the dedicated
    // UnsupportedKeyScope error.
    for scope in [SCOPE_SESSION, SCOPE_SECURITY_DOMAIN] {
        let req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope,
            kem: TRANSFER_KEM_P384,
        };
        ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
    }
}

#[test]
fn darc_kex_key_gen_rejects_unknown_kem() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let req = TborDarcKexKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
        kem: TRANSFER_KEM_MLKEM1024_P384 + 1,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[test]
fn darc_kex_key_gen_rejects_before_finalize() {
    let ctx = TestCtx::new();
    // Rotated CO session but no PartInit/PartFinal → the partition is not
    // Initialized, so the scope's masking key does not exist yet.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let req = TborDarcKexKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
        kem: TRANSFER_KEM_P384,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[test]
fn darc_kex_key_gen_rejected_on_cu_session() {
    let ctx = TestCtx::new();

    // Rotate the CU PSK out of the default so the dispatcher's default-PSK
    // gate does not fire first; then reopen a CU session under the rotated
    // PSK.  CU sessions are pinned to `SessionType::PlainText` (CO-only is
    // `Authenticated`).
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    // DarcKexKeyGen is Crypto-Officer-only: the handler's role gate
    // (checked before the scope/state gates) rejects a CU session.
    let req = TborDarcKexKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
        kem: TRANSFER_KEM_P384,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
}

#[test]
fn darc_kex_key_gen_rejected_on_default_psk() {
    let ctx = TestCtx::new();
    // Open a CO session WITHOUT rotating the PSK (still the public
    // default) — the dispatcher's default-PSK gate must reject the command
    // before the handler runs.
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");

    let req = TborDarcKexKeyGenReq {
        session_id: session.session_id(),
        scope: SCOPE_EPHEMERAL,
        kem: TRANSFER_KEM_P384,
    };
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}
