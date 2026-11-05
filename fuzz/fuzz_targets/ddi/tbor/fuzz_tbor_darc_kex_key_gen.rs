// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Semantic fuzzing of DARC key-exchange key generation through the TBOR
//! transport. Dedicated success scenarios reach key generation and masking;
//! negative scenarios check transport, dispatcher, and handler precedence.
//! Typed requests exercise normal decoding, not malformed TBOR framing.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary::*;
use libfuzzer_sys::*;
use tsra_crypto::*;
use tsra_ddi_tbor_test_harness::assertions::*;
use tsra_ddi_tbor_test_harness::x509_fixture::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// Fixture choices keep successful key generation independent of arbitrary
/// session IDs and unsupported scopes for a quarter of the scenarios.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Scenario {
    Ephemeral,
    Local,
    SupportedScope,
    SecurityDomain,
    ArbitraryScope,
    Uninitialized,
    Initializing,
    SecurityDomainAbsent,
    CryptoUser,
    FinalizedCryptoUser,
    DefaultCo,
    DefaultCu,
    MismatchedSession,
    ClosedSession,
    ArbitrarySession,
    Combined,
}

/// Both request fields have unrestricted arbitrary modes as well as
/// coverage-guided valid choices. Controls select scope/session modes,
/// occasional freshness checks, and the combined scenario's role/PSK.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scenario: Scenario,
    fuzzed_session_id: u16,
    fuzzed_scope: u8,
    controls: u8,
}

impl FuzzInput {
    /// Select supported scopes frequently without losing the full u8 domain.
    fn scope(&self) -> u8 {
        match self.scenario {
            Scenario::Ephemeral => common::KEY_SCOPE_EPHEMERAL,
            Scenario::Local => common::KEY_SCOPE_LOCAL,
            Scenario::SecurityDomain | Scenario::SecurityDomainAbsent => {
                common::KEY_SCOPE_SECURITY_DOMAIN
            }
            Scenario::SupportedScope => {
                if self.controls & 1 == 0 {
                    common::KEY_SCOPE_EPHEMERAL
                } else {
                    common::KEY_SCOPE_LOCAL
                }
            }
            _ => match self.controls & 3 {
                0 => common::KEY_SCOPE_EPHEMERAL,
                1 => common::KEY_SCOPE_LOCAL,
                2 => common::derive_valid_key_scope(self.fuzzed_scope),
                _ => self.fuzzed_scope,
            },
        }
    }

    /// Return the effective request ID and whether to close its bound session.
    ///
    /// The combined closed-handle mode uses an arbitrary ID too, exercising
    /// missing-session precedence over ID mismatch and firmware gates.
    fn request_session(&self, active_id: u16) -> (u16, bool) {
        match self.scenario {
            Scenario::MismatchedSession => (active_id ^ 1, false),
            Scenario::ClosedSession => (active_id, true),
            Scenario::ArbitrarySession => (self.fuzzed_session_id, false),
            Scenario::Combined => match (self.controls >> 2) & 3 {
                0 => (active_id, false),
                1 => (self.fuzzed_session_id, false),
                2 => (active_id ^ 1, false),
                _ => (self.fuzzed_session_id, true),
            },
            _ => (active_id, false),
        }
    }
}

/// Known fixture facts, recorded only after the corresponding setup succeeds.
struct FixtureState {
    session_id: u16,
    session_bound: bool,
    crypto_officer: bool,
    default_psk: bool,
    partition_initialized: bool,
    security_domain_provisioned: bool,
}

/// Construct an isolated fixture without provisioning through a CU session
/// or rotating the calling role's PSK in default-PSK scenarios.
fn prepare_fixture<'ctx>(
    ctx: &'ctx TestCtx,
    input: &FuzzInput,
) -> (SessionGuard<'ctx>, FixtureState) {
    let default_psk = matches!(input.scenario, Scenario::DefaultCo | Scenario::DefaultCu)
        || matches!(input.scenario, Scenario::Combined) && input.controls & 0x20 != 0;
    let crypto_officer = match input.scenario {
        Scenario::CryptoUser | Scenario::FinalizedCryptoUser | Scenario::DefaultCu => false,
        Scenario::Combined => input.controls & 0x40 == 0,
        _ => true,
    };
    let mut partition_initialized = false;
    let mut security_domain_provisioned = false;

    let session = if default_psk {
        let (psk_id, session_type) = if crypto_officer {
            (CO_PSK_ID, SessionType::Authenticated)
        } else {
            (CU_PSK_ID, SessionType::PlainText)
        };
        ctx.open_session(psk_id, session_type)
            .expect("default-PSK session should open")
    } else {
        let setup_as_co = crypto_officer || matches!(input.scenario, Scenario::FinalizedCryptoUser);
        let session = if setup_as_co {
            SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK))
        } else {
            SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK))
        };

        match input.scenario {
            Scenario::SecurityDomain => {
                common::create_test_security_domain(ctx, session.handshake());
                partition_initialized = true;
                security_domain_provisioned = true;
            }
            Scenario::Ephemeral
            | Scenario::Local
            | Scenario::SupportedScope
            | Scenario::ArbitraryScope
            | Scenario::SecurityDomainAbsent
            | Scenario::FinalizedCryptoUser
            | Scenario::MismatchedSession
            | Scenario::ClosedSession
            | Scenario::ArbitrarySession => {
                common::finalize_partition(ctx, session.handshake());
                partition_initialized = true;
            }
            Scenario::Initializing => {
                let pota = CaKey::generate();
                let policy = common::known_good_part_policy(pota.raw_pub());
                ctx.part_init(
                    session.handshake(),
                    &common::mach_seed(),
                    &policy,
                    &common::pota_thumbprint(),
                )
                .expect("PartInit without PartFinal should succeed");
            }
            _ => {}
        }

        if !crypto_officer && setup_as_co {
            session.close().expect("close provisioning CO session");
            SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK))
        } else {
            session
        }
    };

    let state = FixtureState {
        session_id: session.session_id(),
        session_bound: true,
        crypto_officer,
        default_psk,
        partition_initialized,
        security_domain_provisioned,
    };
    (session, state)
}

/// Predicted outcome, independent of the command's actual response.
#[derive(Debug)]
enum Expected {
    Success,
    Reject(TborStatus),
}

/// Apply emulator ownership gates before dispatcher and handler gates.
///
/// Closed/mismatched IDs are transport rejections, not coverage of the
/// handler's inactive-session branch. Arbitrary IDs equal to the bound ID
/// must proceed normally. SecurityDomain is supported only after provisioning.
fn expected_outcome(state: &FixtureState, req: &TborDarcKexKeyGenReq) -> Expected {
    if !state.session_bound {
        return Expected::Reject(TborStatus::SessionNotFound);
    }
    if req.session_id != state.session_id {
        return Expected::Reject(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    if state.default_psk {
        return Expected::Reject(TborStatus::DefaultPskMustRotate);
    }
    if !state.crypto_officer {
        return Expected::Reject(TborStatus::InvalidPermissions);
    }
    if !state.partition_initialized {
        return Expected::Reject(TborStatus::InvalidArg);
    }
    match req.scope {
        common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => Expected::Success,
        common::KEY_SCOPE_SECURITY_DOMAIN if state.security_domain_provisioned => Expected::Success,
        _ => Expected::Reject(TborStatus::UnsupportedKeyScope),
    }
}

/// Check the generated envelope and validate the raw little-endian P-384
/// public point using the existing crypto backend's big-endian point API.
fn assert_success(resp: &TborDarcKexKeyGenResp) {
    assert_eq!(resp.masked_key.len(), MASKED_KEX_KEY_LEN);
    assert_eq!(resp.pub_key.len(), KEX_PUB_KEY_LEN);
    assert!(
        resp.masked_key.iter().any(|&byte| byte != 0),
        "DarcKex masked key must not be all-zero"
    );
    assert!(
        resp.pub_key.iter().any(|&byte| byte != 0),
        "DarcKex public key must not be all-zero"
    );

    let curve = EccCurve::P384;
    let mut point = resp.pub_key;
    let (x, y) = point.split_at_mut(curve.point_size());
    x.reverse();
    y.reverse();
    assert!(
        curve.coordinate_in_range(x) && curve.coordinate_in_range(y),
        "DarcKex public coordinates must be in the P-384 field"
    );
    assert!(
        EccPublicKey::is_on_curve(curve, x, y).expect("P-384 point validation should execute"),
        "DarcKex public key must be a non-identity point on P-384"
    );
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let (session, mut state) = prepare_fixture(ctx, &input);
        let (session_id, close_session) = input.request_session(state.session_id);
        let session = if close_session {
            session
                .close()
                .expect("close session before fuzzed request");
            state.session_bound = false;
            None
        } else {
            Some(session)
        };
        let req = TborDarcKexKeyGenReq {
            session_id,
            scope: input.scope(),
        };
        let expected = expected_outcome(&state, &req);

        match (expected, ctx.tbor(&req)) {
            (Expected::Success, Ok(resp)) => {
                assert_success(&resp);
                if input.controls & 0x10 != 0 {
                    let again = ctx
                        .tbor(&req)
                        .expect("repeated valid DarcKexKeyGen should succeed");
                    assert_success(&again);
                    assert!(
                        resp.pub_key != again.pub_key,
                        "DarcKexKeyGen must generate a fresh public key"
                    );
                    assert!(
                        resp.masked_key != again.masked_key,
                        "DarcKexKeyGen must generate a fresh masked key"
                    );
                }
            }
            (Expected::Success, Err(err)) => {
                panic!("valid DarcKexKeyGen failed: {err:?}; {req:?}; {input:?}");
            }
            (Expected::Reject(status), Ok(_)) => {
                panic!("expected DarcKexKeyGen rejection {status:?}; {req:?}; {input:?}");
            }
            (Expected::Reject(status), Err(err)) => {
                assert_session_rejects(&err, status);
            }
        }

        if let Some(session) = session {
            session.close().expect("close DarcKexKeyGen session");
        }
    });
});
