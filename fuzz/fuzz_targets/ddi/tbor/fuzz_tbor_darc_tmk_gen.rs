// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Semantic DARC TMK generation through the real TBOR transport.
//!
//! Dedicated success lanes reach RNG generation, SDMK masking, and response
//! encoding. An input/fixture-derived oracle checks exact transport, dispatcher,
//! and handler rejections; successful envelopes are inspected and authenticated
//! with VerifyKey. Typed requests do not fuzz malformed TBOR framing, and
//! closed/mismatched IDs exercise transport ownership, not inactive-handler
//! sessions. Inconsistent SD provisioning and PAL fault injection are out of scope.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary::*;
use libfuzzer_sys::*;
use tsra_crypto::aead_envelope;
use tsra_ddi_tbor_test_harness::assertions::*;
use tsra_ddi_tbor_test_harness::x509_fixture::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;
use tsra_fw_core_crypto_key_masking::aead::*;
use zerocopy::FromBytes;

/// Wire kind from `HsmVaultKeyKind::DarcTmk` in `fw\pal\traits\src\vault.rs`;
/// that type is not re-exported by the fuzz package's direct dependencies.
const DARC_TMK_KEY_KIND: u8 = 45;

/// Single-fault lanes isolate gates; combined controls check their precedence.
#[derive(Clone, Copy, Debug)]
enum Scenario {
    Success,
    Uninitialized,
    Initializing,
    NoSecurityDomain,
    CryptoUser,
    ProvisionedCryptoUser,
    DefaultCo,
    DefaultCu,
    MismatchedSession,
    ClosedSession,
    ArbitrarySession,
    ZeroSession,
    MaxSession,
    Combined,
}

impl Scenario {
    /// Reserve eight of 24 selector values for fully provisioned CO success.
    fn from_byte(value: u8) -> Self {
        match value % 24 {
            0..=7 => Self::Success,
            8 => Self::Uninitialized,
            9 => Self::Initializing,
            10 => Self::NoSecurityDomain,
            11 => Self::CryptoUser,
            12 => Self::ProvisionedCryptoUser,
            13 => Self::DefaultCo,
            14 => Self::DefaultCu,
            15 => Self::MismatchedSession,
            16 => Self::ClosedSession,
            17 => Self::ArbitrarySession,
            18 => Self::ZeroSession,
            19 => Self::MaxSession,
            _ => Self::Combined,
        }
    }
}

/// Four bytes cover scenario selection, fixture/freshness controls, and the
/// unrestricted u16 domain of the request's only field, `session_id`.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scenario: u8,
    controls: u8,
    session_id: u16,
}

impl FuzzInput {
    /// Select the bound ID, a guaranteed mismatch, a stale ID, or any u16.
    fn request_session(&self, active_id: u16) -> (u16, bool) {
        match Scenario::from_byte(self.scenario) {
            Scenario::MismatchedSession => (active_id ^ 1, false),
            Scenario::ClosedSession => (active_id, true),
            Scenario::ArbitrarySession => (self.session_id, false),
            Scenario::ZeroSession => (0, false),
            Scenario::MaxSession => (u16::MAX, false),
            Scenario::Combined => match (self.controls >> 4) & 3 {
                0 => (active_id, false),
                1 => (self.session_id, false),
                2 => (active_id ^ 1, false),
                _ => (self.session_id, true),
            },
            _ => (active_id, false),
        }
    }
}

/// Provisioning stages reachable through normal public command sequences.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Partition {
    Uninitialized,
    Initializing,
    Initialized,
    SecurityDomain,
}

/// Facts recorded after successful setup, independently of DarcTmkGen's result.
#[derive(Debug)]
struct FixtureState {
    session_id: u16,
    session_bound: bool,
    crypto_officer: bool,
    default_psk: bool,
    partition: Partition,
}

/// Prepare isolated session/lifecycle gates, provisioning as CO before switching
/// to CU and leaving default-PSK roles unrotated.
fn prepare_fixture<'ctx>(
    ctx: &'ctx TestCtx,
    input: &FuzzInput,
) -> (SessionGuard<'ctx>, FixtureState) {
    let scenario = Scenario::from_byte(input.scenario);
    let crypto_officer = match scenario {
        Scenario::CryptoUser | Scenario::ProvisionedCryptoUser | Scenario::DefaultCu => false,
        Scenario::Combined => input.controls & 1 == 0,
        _ => true,
    };
    let default_psk = matches!(scenario, Scenario::DefaultCo | Scenario::DefaultCu)
        || matches!(scenario, Scenario::Combined) && input.controls & 2 != 0;
    let desired_partition = match scenario {
        Scenario::Uninitialized
        | Scenario::CryptoUser
        | Scenario::DefaultCo
        | Scenario::DefaultCu => Partition::Uninitialized,
        Scenario::Initializing => Partition::Initializing,
        Scenario::NoSecurityDomain => Partition::Initialized,
        Scenario::Combined => match (input.controls >> 2) & 3 {
            0 => Partition::Uninitialized,
            1 => Partition::Initializing,
            2 => Partition::Initialized,
            _ => Partition::SecurityDomain,
        },
        _ => Partition::SecurityDomain,
    };
    let mut partition = Partition::Uninitialized;

    let session = if default_psk {
        let (psk_id, session_type) = if crypto_officer {
            (CO_PSK_ID, SessionType::Authenticated)
        } else {
            (CU_PSK_ID, SessionType::PlainText)
        };
        ctx.open_session(psk_id, session_type)
            .expect("open default-PSK session")
    } else {
        let setup_as_co = crypto_officer || desired_partition != Partition::Uninitialized;
        let session = if setup_as_co {
            SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK))
        } else {
            SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK))
        };
        match desired_partition {
            Partition::Uninitialized => {}
            Partition::Initializing => {
                let pota = CaKey::generate();
                let policy = common::known_good_part_policy(pota.raw_pub());
                ctx.part_init(
                    session.handshake(),
                    &common::mach_seed(),
                    &policy,
                    &common::pota_thumbprint(),
                )
                .expect("PartInit without PartFinal");
            }
            Partition::Initialized => common::finalize_partition(ctx, session.handshake()),
            Partition::SecurityDomain => {
                common::create_test_security_domain(ctx, session.handshake());
            }
        }
        partition = desired_partition;

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
        partition,
    };
    (session, state)
}

/// Expected outcome calculated before issuing the command.
#[derive(Debug)]
enum Expected {
    Success,
    Reject(TborStatus),
}

/// Apply emulator ownership, dispatcher PSK, and handler role/lifecycle gates.
///
/// Arbitrary IDs equal to the bound ID proceed normally. An initialized
/// partition without an SD fails before SDMK resolution, with InvalidArg.
fn expected_outcome(state: &FixtureState, req: &TborDarcTmkGenReq) -> Expected {
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
    if !matches!(
        state.partition,
        Partition::Initialized | Partition::SecurityDomain
    ) {
        return Expected::Reject(TborStatus::InvalidArg);
    }
    if state.partition != Partition::SecurityDomain {
        return Expected::Reject(TborStatus::InvalidArg);
    }
    Expected::Success
}

/// Inspect the public envelope/metadata without DMA casts or secret recovery,
/// then authenticate the unchanged envelope on-device using VerifyKey.
fn assert_success(ctx: &TestCtx, session_id: u16, resp: &TborDarcTmkGenResp) {
    let masked = &resp.masked_tmk;
    assert_eq!(masked.len(), MASKED_TMK_LEN);
    assert!(masked.iter().any(|&byte| byte != 0), "all-zero masked TMK");
    let envelope = aead_envelope::inspect(masked).expect("valid AEAD envelope framing");
    assert_eq!(envelope.alg, aead_envelope::AeadAlg::AesGcm256);
    assert_eq!(envelope.payload.len(), TMK_LEN);
    let metadata =
        MaskedKeyMetadata::ref_from_bytes(envelope.aad).expect("fixed masked-key metadata");
    assert_eq!(metadata.magic, META_MAGIC);
    assert_eq!(metadata.version.get(), META_VERSION_V1);
    assert_eq!(metadata.key_kind().0, DARC_TMK_KEY_KIND);
    assert_eq!(metadata.key_label().expect("valid key label"), b"DarcTmk");
    assert!(
        metadata.key_label[usize::from(metadata.key_label_len)..]
            .iter()
            .all(|&byte| byte == 0),
        "nonzero label padding"
    );
    assert_eq!(metadata.data_pad_len, 0);
    assert!(metadata._reserved.iter().all(|&byte| byte == 0));
    let attrs = metadata.usage_flags();
    assert_eq!(attrs.scope().0, common::KEY_SCOPE_SECURITY_DOMAIN);
    assert!(attrs.derive());
    assert!(attrs.local());
    assert!(attrs.private());
    assert!(attrs.never_extractable());
    assert!(!attrs.extractable());
    assert!(
        !attrs.encrypt()
            && !attrs.decrypt()
            && !attrs.sign()
            && !attrs.verify()
            && !attrs.wrap()
            && !attrs.unwrap(),
        "TMK must be derive-only"
    );

    // Inspection is key-free; only VerifyKey authenticates the returned blob.
    ctx.tbor(&TborVerifyKeyReq {
        session_id,
        masked_key: masked.clone(),
    })
    .expect("generated TMK must authenticate under the security-domain key");
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let (session, mut state) = prepare_fixture(ctx, &input);
        let (session_id, close_session) = input.request_session(state.session_id);
        let session = if close_session {
            session.close().expect("close session before request");
            state.session_bound = false;
            None
        } else {
            Some(session)
        };
        let req = TborDarcTmkGenReq { session_id };
        let expected = expected_outcome(&state, &req);
        match (expected, ctx.tbor(&req)) {
            (Expected::Success, Ok(resp)) => {
                assert_success(ctx, session_id, &resp);
                if input.controls & 0x40 != 0 {
                    let again = ctx.tbor(&req).expect("repeated DarcTmkGen must succeed");
                    assert_success(ctx, session_id, &again);
                    assert_ne!(
                        resp.masked_tmk, again.masked_tmk,
                        "fresh generation must produce distinct masked envelopes"
                    );
                }
            }
            (Expected::Success, Err(err)) => {
                panic!("valid DarcTmkGen failed: {err:?}; {req:?}; {input:?}; {state:?}");
            }
            (Expected::Reject(status), Ok(_)) => {
                panic!("expected rejection {status:?}; {req:?}; {input:?}; {state:?}");
            }
            (Expected::Reject(status), Err(err)) => {
                assert_session_rejects(&err, status);
            }
        }

        if let Some(session) = session {
            session.close().expect("close DarcTmkGen session");
        }
    });
});
