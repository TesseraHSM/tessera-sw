// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured ML-KEM key-generation fuzzing with a state-aware, exact oracle.
//!
//! Frequent session-scoped successes reach key generation without partition
//! setup. Independent fixtures exercise provisioned and unavailable scopes,
//! both roles, isolated rejects, and combined-invalid validation precedence.
//! Selected successes also exercise encapsulation and masked-key use; this
//! does not prove shared-secret agreement or cover PAL faults and DMA wiping.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary::*;
use libfuzzer_sys::*;
use tsra_ddi_tbor_test_harness::pqc::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// Masking-key provisioning established independently of request field values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureState {
    BeforeFinal,
    Finalized,
    SecurityDomain,
}

/// Eight-byte corpus layout: scenario, fixture, role, controls (u8 each),
/// session id (little-endian u16), scope, and key kind (u8 each).
///
/// Scenarios modulo 16: 0..=5 valid, 6 named scope, 7 raw scope, 8 invalid
/// kind boundary, 9 raw kind, 10 mismatched id, 11 boundary/raw id, 12 closed
/// session, 13 default PSK, 14 raw scope/kind, and 15 all raw request fields.
/// Fixture modulo 16: 0..=12 pre-final, 13..=14 finalized, 15 security domain.
/// Role parity selects CO/CU. Controls select boundaries, optional combined
/// faults in closed/default sessions, and a functional check when divisible
/// by 16. Default-PSK scenarios always use an unprovisioned fixture.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scenario: u8,
    fixture: u8,
    role: u8,
    controls: u8,
    session_id: u16,
    scope: u8,
    key_kind: u8,
}

impl FuzzInput {
    /// Favor cheap pre-final sessions without coupling provisioning to scope.
    fn fixture_state(&self) -> FixtureState {
        if self.scenario % 16 == 13 {
            return FixtureState::BeforeFinal;
        }
        match self.fixture % 16 {
            13..=14 => FixtureState::Finalized,
            15 => FixtureState::SecurityDomain,
            _ => FixtureState::BeforeFinal,
        }
    }

    /// Construct valid baselines, isolated rejects, and unrestricted fields.
    fn request(&self, active_id: u16, fixture: FixtureState) -> TborMlKemGenerateKeyReq {
        let scopes = [
            common::KEY_SCOPE_SESSION,
            common::KEY_SCOPE_EPHEMERAL,
            common::KEY_SCOPE_LOCAL,
            common::KEY_SCOPE_SECURITY_DOMAIN,
        ];
        let available = match fixture {
            FixtureState::BeforeFinal => 1,
            FixtureState::Finalized => 3,
            FixtureState::SecurityDomain => 4,
        };
        let params = [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024];
        let mut req = TborMlKemGenerateKeyReq {
            session_id: active_id,
            scope: scopes[usize::from(self.scope) % available],
            key_kind: params[usize::from(self.key_kind % 3)].key_kind,
        };
        match self.scenario % 16 {
            6 => req.scope = common::derive_valid_key_scope(self.scope),
            7 => req.scope = self.scope,
            8 => {
                req.key_kind = [
                    0,
                    MLKEM_KEY_KIND_512_SEED - 1,
                    MLKEM_KEY_KIND_1024_SEED + 1,
                    u8::MAX,
                ][usize::from(self.controls % 4)];
            }
            9 => req.key_kind = self.key_kind,
            10 => req.session_id ^= 1u16 << (self.session_id % 16),
            11 => {
                req.session_id = match self.controls % 8 {
                    0 => 0,
                    1 => 1,
                    2 => i16::MAX as u16,
                    3 => 1 << 15,
                    4 => u16::MAX,
                    _ => self.session_id,
                };
            }
            12 | 13 if self.controls & 1 != 0 => {
                req.scope = self.scope;
                req.key_kind = self.key_kind;
                if self.controls & 2 != 0 {
                    req.session_id = self.session_id;
                }
            }
            14 | 15 => {
                req.scope = self.scope;
                req.key_kind = self.key_kind;
                if self.scenario % 16 == 15 {
                    req.session_id = self.session_id;
                }
            }
            _ => {}
        }
        req
    }
}

/// Provision with CO before switching roles, or retain an unrotated PSK.
fn open_session<'a>(
    ctx: &'a TestCtx,
    input: &FuzzInput,
    fixture: FixtureState,
) -> SessionGuard<'a> {
    let role = if input.role & 1 == 0 {
        common::FuzzRole::Co
    } else {
        common::FuzzRole::Cu
    };
    if input.scenario % 16 == 13 {
        return ctx
            .open_session(role.psk_id(), role.session_type())
            .expect("open default-PSK session");
    }

    if fixture != FixtureState::BeforeFinal {
        let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
        match fixture {
            FixtureState::Finalized => common::finalize_partition(ctx, co.handshake()),
            FixtureState::SecurityDomain => {
                common::create_test_security_domain(ctx, co.handshake());
            }
            FixtureState::BeforeFinal => unreachable!(),
        }
        if matches!(role, common::FuzzRole::Co) {
            return co;
        }
        co.close().expect("close provisioning CO before opening CU");
    }
    let handshake = match role {
        common::FuzzRole::Co => bootstrap_rotated_co(ctx, &ROTATED_CO_PSK),
        common::FuzzRole::Cu => bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK),
    };
    SessionGuard::new(ctx, handshake)
}

/// Predict rejection from actual fields and independently established state.
///
/// Handle binding precedes the default-PSK gate, then the handler checks the
/// key kind and finally resolves the masking key, after generating the keypair.
/// `None` requires success; unexpected transport or decoding errors never pass.
fn expected_rejection(
    req: &TborMlKemGenerateKeyReq,
    active_id: u16,
    closed: bool,
    default_psk: bool,
    fixture: FixtureState,
) -> Option<TborStatus> {
    if closed {
        return Some(TborStatus::SessionNotFound);
    }
    if req.session_id != active_id {
        return Some(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    if default_psk {
        return Some(TborStatus::DefaultPskMustRotate);
    }
    if !matches!(
        req.key_kind,
        MLKEM_KEY_KIND_512_SEED | MLKEM_KEY_KIND_768_SEED | MLKEM_KEY_KIND_1024_SEED
    ) {
        return Some(TborStatus::InvalidArg);
    }
    let available = match req.scope {
        common::KEY_SCOPE_SESSION => true,
        common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => {
            fixture != FixtureState::BeforeFinal
        }
        common::KEY_SCOPE_SECURITY_DOMAIN => fixture == FixtureState::SecurityDomain,
        _ => false,
    };
    if available {
        None
    } else {
        Some(TborStatus::UnsupportedKeyScope)
    }
}

/// Check parameter-specific lengths and reject empty or zero-filled outputs.
fn check_response(
    req: &TborMlKemGenerateKeyReq,
    resp: &TborMlKemGenerateKeyResp,
) -> &'static MlKemParams {
    let params = match req.key_kind {
        MLKEM_KEY_KIND_512_SEED => &ML_KEM_512,
        MLKEM_KEY_KIND_768_SEED => &ML_KEM_768,
        MLKEM_KEY_KIND_1024_SEED => &ML_KEM_1024,
        _ => panic!("unsupported key kind unexpectedly succeeded"),
    };
    assert_eq!(resp.pub_key.len(), params.pub_key_len);
    assert_eq!(resp.masked_key.len(), params.masked_key_len);
    assert!(resp.pub_key.len() <= MLKEM_PUB_KEY_MAX_LEN);
    assert!(resp.masked_key.len() <= MASKED_MLKEM_KEY_MAX_LEN);
    assert!(resp.pub_key.iter().any(|&byte| byte != 0));
    assert!(resp.masked_key.iter().any(|&byte| byte != 0));
    assert_not_truncated_at_page(&resp.pub_key, params.name);
    assert_not_truncated_at_page(&resp.masked_key, params.name);
    params
}

/// Exercise generated key material without comparing randomized masked secrets.
///
/// Successful decapsulation checks usable masking metadata and permissions,
/// not keypair agreement: ML-KEM can implicitly reject an incorrect ciphertext.
fn check_key_use(
    ctx: &TestCtx,
    req: &TborMlKemGenerateKeyReq,
    resp: TborMlKemGenerateKeyResp,
    params: &MlKemParams,
) {
    let encap = ctx
        .tbor(&TborMlKemEncapsulateReq {
            session_id: req.session_id,
            scope: req.scope,
            pub_key: resp.pub_key,
        })
        .expect("generated public key must support encapsulation");
    assert_eq!(encap.ciphertext.len(), params.ciphertext_len);
    assert_eq!(
        encap.masked_shared_secret.len(),
        MASKED_MLKEM_SHARED_SECRET_MAX_LEN,
    );
    assert!(encap.ciphertext.iter().any(|&byte| byte != 0));
    assert!(encap.masked_shared_secret.iter().any(|&byte| byte != 0));
    let decap = ctx
        .tbor(&TborMlKemDecapsulateReq {
            session_id: req.session_id,
            scope: req.scope,
            masked_key: resp.masked_key,
            ciphertext: encap.ciphertext,
        })
        .expect("generated masked private key must support decapsulation");
    assert_eq!(
        decap.masked_shared_secret.len(),
        MASKED_MLKEM_SHARED_SECRET_MAX_LEN,
    );
    assert!(decap.masked_shared_secret.iter().any(|&byte| byte != 0));
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx, _path| {
        let fixture = input.fixture_state();
        let session = open_session(ctx, &input, fixture);
        let active_id = session.session_id();
        let closed = input.scenario % 16 == 12;
        let default_psk = input.scenario % 16 == 13;
        let live_session = if closed {
            session.close().expect("close session before negative test");
            None
        } else {
            Some(session)
        };
        let req = input.request(active_id, fixture);
        let expected = expected_rejection(&req, active_id, closed, default_psk, fixture);
        match expected {
            Some(status) if closed || req.session_id != active_id => {
                ctx.expect_session_reject(&req, status);
            }
            Some(status) => {
                ctx.expect_fw_reject(&req, status);
            }
            None => {
                let resp = ctx
                    .tbor(&req)
                    .expect("valid ML-KEM generation must succeed");
                let params = check_response(&req, &resp);
                if input.controls & 15 == 0 {
                    check_key_use(ctx, &req, resp, params);
                }
            }
        }
        if let Some(session) = live_session {
            session.close().expect("close fuzz session");
        }
    });
});
