// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `DarcKexKeyGen` command.
//!
//! Cross-test isolation comes from `open_dev`'s NSSR; no
//! per-test cleanup is required (see [`tsra_ddi_tbor_test_harness::fixture`]).
//!
//! The command generates a P-384 key-exchange keypair and returns the
//! **masked** private key (masked under the requested scope's masking
//! key) plus the public key — nothing is stored on the device.  The
//! Ephemeral/Local masking keys are provisioned by `PartFinal`, so the
//! happy-path tests first drive `PartInit → PartFinal`.
//!
//! Coverage (mirrors `sd_sealing_key_gen`, the command this is modelled
//! on):
//! * Happy path (Ephemeral + Local) — returns a non-zero 280-byte masked
//!   key + 96-byte public key; a second call yields a distinct keypair.
//! * Unsupported scope (Session + SecurityDomain) → `UnsupportedKeyScope`.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).
//! * Rejection recovery and alternating scopes preserve fresh key generation.
//! * Permission/default-PSK error precedence over unsupported scope.
//!
//! `DarcKexKeyGen` itself carries no out-of-band data — the request is a
//! session id plus a 1-byte scope, and the response is a 280-byte masked
//! key plus a 96-byte public key — so the command runs on any transport.
//! The *setup* is what needs OOB: [`finalized_co_session`] drives
//! `PartFinal`, whose PTA chain travels out of band, so the tests that
//! need a finalized partition also need the driver's data-transfer path.

use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::SessionSuite;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::TborDarcKexKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::KEX_PUB_KEY_LEN;
use tsra_ddi_tbor_types::MASKED_KEX_KEY_LEN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope` discriminants (wire mirror of the firmware `HsmKeyScope`).
const SCOPE_SESSION: u8 = 0b001;
const SCOPE_EPHEMERAL: u8 = 0b010;
const SCOPE_LOCAL: u8 = 0b011;
const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// Happy path for a supported `scope`: the masked key + public key are
/// full/non-zero, and a second call yields a distinct keypair.
fn roundtrip_for_scope(scope: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let req = TborDarcKexKeyGenReq {
        session_id: session.session_id,
        scope,
    };
    let resp = ctx.tbor(&req).expect("DarcKexKeyGen roundtrip");

    // Masked private key: exactly the pinned length, non-zero.
    assert_eq!(resp.masked_key.len(), MASKED_KEX_KEY_LEN);
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked_key must not be all-zero",
    );
    // Public key: a full, non-zero P-384 point.
    assert_eq!(resp.pub_key.len(), KEX_PUB_KEY_LEN);
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

/// Generates distinct, nonzero keypairs using the Ephemeral masking scope.
#[test]
fn darc_kex_key_gen_ephemeral_roundtrip() {
    roundtrip_for_scope(SCOPE_EPHEMERAL);
}

/// Generates distinct, nonzero keypairs using the Local masking scope.
#[test]
fn darc_kex_key_gen_local_roundtrip() {
    roundtrip_for_scope(SCOPE_LOCAL);
}

/// Rejects Session and SecurityDomain scopes after partition finalization.
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
        };
        ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
    }
}

/// Rejects Ephemeral key generation before partition finalization.
#[test]
fn darc_kex_key_gen_rejects_before_finalize() {
    let ctx = TestCtx::new();
    // Rotated CO session but no PartInit/PartFinal → the partition is not
    // Initialized, so the scope's masking key does not exist yet.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let req = TborDarcKexKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Rejects an Ephemeral key-generation request from a Crypto-User session.
#[test]
fn darc_kex_key_gen_rejected_on_cu_session() {
    let ctx = TestCtx::new();

    // Rotate the CU PSK out of the default so the dispatcher's default-PSK
    // gate does not fire first; then reopen a CU session under the rotated
    // PSK.  CU sessions are pinned to `SessionSuite::EcdhP384` (CO-only is
    // `Authenticated`).
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    // DarcKexKeyGen is Crypto-Officer-only: the handler's role gate
    // (checked before the scope/state gates) rejects a CU session.
    let req = TborDarcKexKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
}

/// Requires PSK rotation before Crypto-Officer key generation.
#[test]
fn darc_kex_key_gen_rejected_on_default_psk() {
    let ctx = TestCtx::new();
    // Open a CO session WITHOUT rotating the PSK (still the public
    // default) — the dispatcher's default-PSK gate must reject the command
    // before the handler runs.
    let session = ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("open_session must succeed");

    let req = TborDarcKexKeyGenReq {
        session_id: session.session_id(),
        scope: SCOPE_EPHEMERAL,
    };
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}

/// Rejects both supported scopes until the partition is finalized.
#[test]
fn darc_kex_key_gen_rejects_both_scopes_before_finalize() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    // Neither masking key is available before PartFinal.
    for scope in [SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        let req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope,
        };

        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }
}

/// Enforces Crypto-Officer authorization for both supported scopes.
#[test]
fn darc_kex_key_gen_rejects_both_scopes_on_cu_session() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    // Both supported scopes require Crypto-Officer permissions.
    for scope in [SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        let req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope,
        };

        ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
    }
}

/// Enforces the default-PSK gate for both supported scopes.
#[test]
fn darc_kex_key_gen_rejects_both_scopes_on_default_psk() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("open default-PSK CO session");

    // Default-PSK restrictions must apply regardless of scope.
    for scope in [SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        let req = TborDarcKexKeyGenReq {
            session_id: session.session_id(),
            scope,
        };

        ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
    }
}

/// Produces eight distinct keypairs for each supported scope.
#[test]
fn darc_kex_key_gen_multiple_generations_are_unique() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Repeated requests must generate fresh keypairs.
    for scope in [SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        let req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope,
        };

        let mut masked_keys = Vec::new();
        let mut public_keys = Vec::new();

        for index in 0..8 {
            let resp = ctx.tbor(&req).expect("repeated DarcKexKeyGen");

            assert_eq!(
                resp.masked_key.len(),
                MASKED_KEX_KEY_LEN,
                "scope={scope}, iteration={index}",
            );

            assert_eq!(
                resp.pub_key.len(),
                KEX_PUB_KEY_LEN,
                "scope={scope}, iteration={index}",
            );

            assert!(
                resp.masked_key.iter().any(|&b| b != 0),
                "masked key is zero: scope={scope}, iteration={index}",
            );

            assert!(
                resp.pub_key.iter().any(|&b| b != 0),
                "public key is zero: scope={scope}, iteration={index}",
            );

            assert!(
                !masked_keys.contains(&resp.masked_key),
                "duplicate masked key: scope={scope}, iteration={index}",
            );

            assert!(
                !public_keys.contains(&resp.pub_key),
                "duplicate public key: scope={scope}, iteration={index}",
            );

            masked_keys.push(resp.masked_key);
            public_keys.push(resp.pub_key);
        }
    }
}

/// Keeps public keys unique across interleaved scope requests.
#[test]
fn darc_kex_key_gen_interleaved_scopes_generate_unique_keys() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let scopes = [
        SCOPE_EPHEMERAL,
        SCOPE_LOCAL,
        SCOPE_EPHEMERAL,
        SCOPE_LOCAL,
        SCOPE_LOCAL,
        SCOPE_EPHEMERAL,
    ];

    let mut public_keys = Vec::new();

    for (index, scope) in scopes.into_iter().enumerate() {
        let req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope,
        };

        let resp = ctx.tbor(&req).expect("interleaved DarcKexKeyGen");

        assert_eq!(resp.masked_key.len(), MASKED_KEX_KEY_LEN);
        assert_eq!(resp.pub_key.len(), KEX_PUB_KEY_LEN);

        assert!(
            !public_keys.contains(&resp.pub_key),
            "duplicate public key at iteration={index}",
        );

        public_keys.push(resp.pub_key);
    }
}

/// Keeps the session usable after unsupported-scope errors.
#[test]
fn darc_kex_key_gen_unsupported_scope_does_not_break_session() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for scope in [SCOPE_SESSION, SCOPE_SECURITY_DOMAIN] {
        let invalid_req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope,
        };

        ctx.expect_fw_reject(&invalid_req, TborStatus::UnsupportedKeyScope);

        // An invalid request must not prevent later valid operations.
        let valid_req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope: SCOPE_EPHEMERAL,
        };

        let resp = ctx
            .tbor(&valid_req)
            .expect("valid request after unsupported scope");

        assert_eq!(resp.masked_key.len(), MASKED_KEX_KEY_LEN);
        assert_eq!(resp.pub_key.len(), KEX_PUB_KEY_LEN);
    }
}

/// Allows Local key generation after repeated unsupported-scope errors.
#[test]
fn darc_kex_key_gen_valid_requests_survive_repeated_rejections() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let valid_req = TborDarcKexKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
    };

    let first = ctx.tbor(&valid_req).expect("initial valid key generation");

    // Repeated invalid requests must not corrupt partition state.
    for _ in 0..5 {
        let invalid_req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope: SCOPE_SECURITY_DOMAIN,
        };

        ctx.expect_fw_reject(&invalid_req, TborStatus::UnsupportedKeyScope);
    }

    let second = ctx
        .tbor(&valid_req)
        .expect("valid key generation after repeated rejections");

    assert_eq!(second.masked_key.len(), MASKED_KEX_KEY_LEN);
    assert_eq!(second.pub_key.len(), KEX_PUB_KEY_LEN);

    assert_ne!(first.masked_key, second.masked_key);
    assert_ne!(first.pub_key, second.pub_key);
}

/// Checks that failed scope requests do not disrupt alternating valid scopes.
#[test]
fn darc_kex_key_gen_alternating_valid_scopes_survive_invalid_requests() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mut public_keys = Vec::new();
    let mut masked_keys = Vec::new();

    for (index, scope) in [SCOPE_LOCAL, SCOPE_EPHEMERAL, SCOPE_LOCAL, SCOPE_EPHEMERAL]
        .into_iter()
        .enumerate()
    {
        // Exercise both unsupported scopes between successful generations.
        let invalid_req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope: if index % 2 == 0 {
                SCOPE_SESSION
            } else {
                SCOPE_SECURITY_DOMAIN
            },
        };
        ctx.expect_fw_reject(&invalid_req, TborStatus::UnsupportedKeyScope);

        let req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope,
        };
        let resp = ctx.tbor(&req).expect("valid key generation after failure");
        assert_eq!(resp.masked_key.len(), MASKED_KEX_KEY_LEN);
        assert_eq!(resp.pub_key.len(), KEX_PUB_KEY_LEN);
        assert!(resp.masked_key.iter().any(|&byte| byte != 0));
        assert!(resp.pub_key.iter().any(|&byte| byte != 0));
        assert!(
            !masked_keys.contains(&resp.masked_key),
            "duplicate masked key after rejection at iteration {index}",
        );
        assert!(
            !public_keys.contains(&resp.pub_key),
            "duplicate public key after rejection at iteration {index}",
        );
        masked_keys.push(resp.masked_key);
        public_keys.push(resp.pub_key);
    }
}

/// Checks that the Crypto-User permission gate precedes scope validation.
#[test]
fn darc_kex_key_gen_cu_permission_gate_precedes_scope_validation() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    for scope in [SCOPE_SESSION, SCOPE_SECURITY_DOMAIN] {
        let req = TborDarcKexKeyGenReq {
            session_id: session.session_id,
            scope,
        };
        ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
    }
}

/// Checks that default-PSK rejection precedes unsupported-scope validation.
#[test]
fn darc_kex_key_gen_default_psk_gate_precedes_scope_validation() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("open default-PSK CO session");

    for scope in [SCOPE_SESSION, SCOPE_SECURITY_DOMAIN] {
        let req = TborDarcKexKeyGenReq {
            session_id: session.session_id(),
            scope,
        };
        ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
    }
}
