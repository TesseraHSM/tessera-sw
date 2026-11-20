// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured ML-DSA generation with an independent, state-aware status oracle.
//!
//! Cheap session-scoped successes dominate; selected inputs provision partition
//! or security-domain masking, isolate rejects, or combine arbitrary fields.
//! Successful outputs are size/page checked and selectively host-verified after
//! signing. The oracle targets emu scope availability; handle-level session
//! rejects do not reach the handler. PAL faults, allocation failures, and secret
//! wiping need separate tests.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;
use tsra_crypto::*;
use tsra_ddi_tbor_test_harness::pqc::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// Partition/session state established independently of the fuzzed request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    Unfinalized,
    Finalized,
    SecurityDomain,
    Closed,
    DefaultPsk,
}

/// Eight-byte header: scenario, role, kind, scope, session ID (u16 LE),
/// check selector, context length selector; then context (at most 32 bytes)
/// and message (at most 256 bytes). Missing bytes default to zero.
///
/// Scenarios modulo 32: 0..15 valid Session; 16 valid partition scope;
/// 17 valid SD; 18/19 scope sweep before/after finalization; 20 invalid
/// kind; 21 mismatched ID; 22 closed; 23 default PSK; 24..26 mixed
/// before/finalized/SD; 27 raw; 28 mixed default; 29 mixed closed;
/// 30 mixed mismatch; 31 raw. Role bit 0 selects CU rather than CO.
/// Check bit 0 skips signing, bit 1 selects raw IDs in mixed cases,
/// and bit 2 selects unrestricted rather than known scopes in scope sweeps.
struct FuzzInput<'a> {
    scenario: u8,
    role: common::FuzzRole,
    key_kind: u8,
    scope: u8,
    session_id: u16,
    checks: u8,
    context: &'a [u8],
    message: &'a [u8],
}

impl<'a> FuzzInput<'a> {
    /// Decode bounded input, including a complete happy path for empty inputs.
    fn from_bytes(data: &'a [u8]) -> Self {
        let byte = |index| data.get(index).copied().unwrap_or(0);
        let tail = data.get(8..).unwrap_or_default();
        let context_len = usize::from(byte(7) % 33).min(tail.len());
        let (context, message) = tail.split_at(context_len);
        Self {
            scenario: byte(0) % 32,
            role: if byte(1) & 1 == 0 {
                common::FuzzRole::Co
            } else {
                common::FuzzRole::Cu
            },
            key_kind: byte(2),
            scope: byte(3),
            session_id: u16::from_le_bytes([byte(4), byte(5)]),
            checks: byte(6),
            context,
            message: &message[..message.len().min(256)],
        }
    }

    /// Keep costly provisioning rare while making every lifecycle reachable.
    fn lifecycle(&self) -> Lifecycle {
        match self.scenario {
            16 | 19 | 25 => Lifecycle::Finalized,
            17 | 26 => Lifecycle::SecurityDomain,
            22 | 29 => Lifecycle::Closed,
            23 | 28 => Lifecycle::DefaultPsk,
            _ => Lifecycle::Unfinalized,
        }
    }

    /// Construct valid baselines, single-field rejects, and unrestricted fields.
    fn request(&self, active_session_id: u16) -> TborMlDsaGenerateKeyReq {
        let params = [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87];
        let mut req = TborMlDsaGenerateKeyReq {
            session_id: active_session_id,
            scope: match self.scenario {
                16 => [
                    common::KEY_SCOPE_SESSION,
                    common::KEY_SCOPE_EPHEMERAL,
                    common::KEY_SCOPE_LOCAL,
                ][usize::from(self.scope % 3)],
                17 => common::KEY_SCOPE_SECURITY_DOMAIN,
                _ => common::KEY_SCOPE_SESSION,
            },
            key_kind: params[usize::from(self.key_kind % 3)].key_kind,
        };
        match self.scenario {
            18 | 19 => {
                req.scope = if self.checks & 4 == 0 {
                    common::derive_valid_key_scope(self.scope)
                } else {
                    self.scope
                };
            }
            20 => {
                req.key_kind = if parameters(self.key_kind).is_some() {
                    0
                } else {
                    self.key_kind
                };
            }
            21 => req.session_id ^= 1u16 << (self.session_id % 16),
            24..=26 | 28..=30 => {
                req.scope = self.scope;
                req.key_kind = self.key_kind;
                if self.scenario == 30 {
                    req.session_id ^= 1u16 << (self.session_id % 16);
                } else if self.checks & 2 != 0 {
                    req.session_id = self.session_id;
                }
            }
            27 | 31 => {
                req.session_id = self.session_id;
                req.scope = self.scope;
                req.key_kind = self.key_kind;
            }
            _ => {}
        }
        req
    }
}

/// Match a wire kind to the independent harness's parameter/length table.
fn parameters(key_kind: u8) -> Option<&'static MlDsaParams> {
    [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87]
        .into_iter()
        .find(|params| params.key_kind == key_kind)
}

/// Provision with CO before switching to CU; leave default PSKs untouched only
/// in dedicated default-PSK scenarios. Never hold two sessions on one handle.
fn setup_session<'a>(ctx: &'a TestCtx, input: &FuzzInput<'_>) -> SessionGuard<'a> {
    let lifecycle = input.lifecycle();
    if lifecycle == Lifecycle::DefaultPsk {
        return ctx
            .open_session(input.role.psk_id(), input.role.session_type())
            .expect("open default-PSK session");
    }
    if matches!(input.role, common::FuzzRole::Co)
        || matches!(lifecycle, Lifecycle::Finalized | Lifecycle::SecurityDomain)
    {
        let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
        match lifecycle {
            Lifecycle::Finalized => common::finalize_partition(ctx, co.handshake()),
            Lifecycle::SecurityDomain => common::create_test_security_domain(ctx, co.handshake()),
            _ => {}
        }
        if matches!(input.role, common::FuzzRole::Co) {
            return co;
        }
        co.close().expect("close provisioning CO session");
    }
    SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK))
}

/// Predict the first rejection from the actual request and established state:
/// handle binding, default-PSK gate, key kind, then masking-key availability.
/// Unknown open-enum bytes decode normally; there is no partition-final gate.
fn expected_outcome(
    req: &TborMlDsaGenerateKeyReq,
    active_session_id: u16,
    lifecycle: Lifecycle,
) -> Result<(), TborStatus> {
    if lifecycle == Lifecycle::Closed {
        return Err(TborStatus::SessionNotFound);
    }
    if req.session_id != active_session_id {
        return Err(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    if lifecycle == Lifecycle::DefaultPsk {
        return Err(TborStatus::DefaultPskMustRotate);
    }
    if parameters(req.key_kind).is_none() {
        return Err(TborStatus::InvalidArg);
    }
    let available = match req.scope {
        common::KEY_SCOPE_SESSION => true,
        common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => {
            matches!(lifecycle, Lifecycle::Finalized | Lifecycle::SecurityDomain)
        }
        common::KEY_SCOPE_SECURITY_DOMAIN => lifecycle == Lifecycle::SecurityDomain,
        _ => false,
    };
    if available {
        Ok(())
    } else {
        Err(TborStatus::UnsupportedKeyScope)
    }
}

/// Check exact seed-plus-expanded-key response sizes and nonzero DMA tails.
fn check_response(req: &TborMlDsaGenerateKeyReq, resp: &TborMlDsaGenerateKeyResp) {
    let params = parameters(req.key_kind).expect("successful kind must be supported");
    assert_eq!(resp.pub_key.len(), params.pub_key_len, "public-key length");
    assert_eq!(
        resp.masked_key.len(),
        params.masked_key_len,
        "masked-key length"
    );
    assert!(resp.pub_key.len() <= MLDSA_PUB_KEY_MAX_LEN);
    assert!(resp.masked_key.len() <= MASKED_MLDSA_KEY_MAX_LEN);
    assert!(resp.pub_key.iter().any(|&byte| byte != 0));
    assert!(resp.masked_key.iter().any(|&byte| byte != 0));
    assert_not_truncated_at_page(&resp.pub_key, params.name);
    assert_not_truncated_at_page(&resp.masked_key, params.name);
}

/// Sign host-computed external mu and independently verify the bounded message
/// and context, proving the masked private key matches the returned public key.
fn check_signing_key(
    ctx: &TestCtx,
    input: &FuzzInput<'_>,
    req: &TborMlDsaGenerateKeyReq,
    resp: TborMlDsaGenerateKeyResp,
) {
    let params = parameters(req.key_kind).expect("successful kind must be supported");
    let public = MlDsaPublicKey::from_bytes(&resp.pub_key).expect("import generated public key");
    let mu = HashAlgo::mldsa_mu(&public, input.context)
        .and_then(|mut algo| Hasher::hash_vec(&mut algo, input.message))
        .expect("compute external mu");
    assert_eq!(mu.len(), tsra_ddi_tbor_types::MLDSA_MU_LEN);
    let signature = ctx
        .tbor(&TborMlDsaSignReq {
            session_id: req.session_id,
            masked_key: resp.masked_key,
            mu,
            hedge: MLDSA_HEDGE_PREFERRED,
        })
        .expect("generated private key must unmask and sign")
        .signature;
    assert_eq!(signature.len(), params.sig_len, "signature length");
    assert!(signature.len() <= MLDSA_SIGNATURE_MAX_LEN);
    assert_not_truncated_at_page(&signature, params.name);
    assert!(
        MlDsaAlgo::new(input.context)
            .expect("create host verifier")
            .verify(&public, input.message, &signature)
            .expect("host verification must run"),
        "generated private key must match returned public key",
    );
}

/// Execute one isolated scenario, computing its oracle before issuing the
/// request. Session-binding rejects are distinguished from firmware rejects.
fn run(input: &FuzzInput<'_>) {
    common::common_fuzz_test(&|ctx, _path| {
        let session = setup_session(ctx, input);
        let active_session_id = session.session_id();
        let lifecycle = input.lifecycle();
        let req = input.request(active_session_id);
        let expected = expected_outcome(&req, active_session_id, lifecycle);
        let session = if lifecycle == Lifecycle::Closed {
            session.close().expect("close session before request");
            None
        } else {
            Some(session)
        };
        match expected {
            Ok(()) => {
                let resp = ctx
                    .tbor(&req)
                    .expect("valid ML-DSA generation must succeed");
                check_response(&req, &resp);
                if input.checks & 1 == 0 {
                    check_signing_key(ctx, input, &req, resp);
                }
            }
            Err(status) => {
                if matches!(
                    status,
                    TborStatus::SessionNotFound | TborStatus::FileHandleSessionIdDoesNotMatch
                ) {
                    ctx.expect_session_reject(&req, status);
                } else {
                    ctx.expect_fw_reject(&req, status);
                }
            }
        }
        if let Some(session) = session {
            session.close().expect("close fuzz session");
        }
    });
}

fuzz_target!(|data: &[u8]| {
    run(&FuzzInput::from_bytes(data));
});
