// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary::*;
use libfuzzer_sys::*;
use tsra_ddi_interface::*;
use tsra_ddi_tbor_test_harness::assertions::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// Partition state established independently of the requested scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureState {
    BeforeFinal,
    Finalized,
    SecurityDomain,
}

/// Structured inputs retain arbitrary field values while making deep,
/// successful handler calls and isolated single-field failures common.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Mixed fields, isolated session/scope/usage/label, or valid request.
    scenario: u8,
    /// Four pre-final, three finalized, and one security-domain selection.
    fixture: u8,
    role: common::FuzzRole,
    /// Active (five selections), arbitrary, mismatched, or closed session.
    session_mode: u8,
    session_id: u16,
    /// Choose a named discriminant rather than the unmodified scope byte.
    known_scope: bool,
    scope: u8,
    /// Exact permissions (four selections), zero, individual, extra, or raw.
    usage_mode: u8,
    key_usage: u64,
    /// Empty, 127, 128, 129, bounded interior, or bounded oversized label.
    label_mode: u8,
    label_len: u16,
    /// Select occasional freshness and functional checks independently.
    checks: u8,
    plaintext: [u8; 32],
    tweak: [u8; XTS_TWEAK_LEN],
    /// Repeated as needed so short inputs can still produce boundary lengths.
    key_label: Vec<u8>,
}

impl FuzzInput {
    /// Select fixture state without consulting any request field.
    fn fixture_state(&self) -> FixtureState {
        match self.fixture % 8 {
            0..=3 => FixtureState::BeforeFinal,
            4..=6 => FixtureState::Finalized,
            _ => FixtureState::SecurityDomain,
        }
    }

    /// Construct all request fields, preserving raw and isolated-invalid
    /// cases alongside deliberately valid requests. Return whether to close
    /// the session before submission.
    fn request(
        &self,
        active_session_id: u16,
        fixture: FixtureState,
    ) -> (TborAesXtsGenerateKeyReq, bool) {
        let scenario = self.scenario % 8;
        let fuzz_session = matches!(scenario, 0 | 1);
        let session_mode = if fuzz_session {
            self.session_mode % 8
        } else {
            0
        };
        let session_id = match session_mode {
            5 => self.session_id,
            6 => active_session_id.wrapping_add(1),
            _ => active_session_id,
        };
        let scope = match scenario {
            0 | 2 if self.known_scope => common::derive_valid_key_scope(self.scope),
            0 | 2 => self.scope,
            5..=7 => match fixture {
                FixtureState::BeforeFinal => common::KEY_SCOPE_SESSION,
                FixtureState::Finalized => common::KEY_SCOPE_SESSION + self.scope % 3,
                FixtureState::SecurityDomain => common::KEY_SCOPE_SESSION + self.scope % 4,
            },
            _ => common::KEY_SCOPE_SESSION,
        };
        let valid_usage = KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT;
        let key_usage = if matches!(scenario, 0 | 3) {
            match self.usage_mode % 9 {
                0..=3 => valid_usage,
                4 => 0,
                5 => KEY_USAGE_ENCRYPT,
                6 => KEY_USAGE_DECRYPT,
                7 => valid_usage | (1u64 << 63),
                _ => self.key_usage,
            }
        } else {
            valid_usage
        };
        let label_len = match self.label_mode % 6 {
            0 => 0,
            1 => TBOR_KEY_LABEL_MAX_LEN - 1,
            2 => TBOR_KEY_LABEL_MAX_LEN,
            3 => TBOR_KEY_LABEL_MAX_LEN + 1,
            4 => usize::from(self.label_len) % (TBOR_KEY_LABEL_MAX_LEN + 1),
            _ => TBOR_KEY_LABEL_MAX_LEN + 1 + usize::from(self.label_len) % TBOR_KEY_LABEL_MAX_LEN,
        };
        let label_len = if matches!(scenario, 0 | 4) {
            label_len
        } else {
            label_len.min(TBOR_KEY_LABEL_MAX_LEN)
        };
        let key_label = (0..label_len)
            .map(|index| {
                self.key_label
                    .get(index % self.key_label.len().max(1))
                    .copied()
                    .unwrap_or(0)
            })
            .collect();
        (
            TborAesXtsGenerateKeyReq {
                session_id,
                scope,
                key_usage,
                key_label,
            },
            session_mode == 7,
        )
    }
}

/// Predict emulator rejection from the actual request and fixture state.
///
/// Handle binding precedes firmware schema decoding; label decoding precedes
/// the handler's partition-state, usage, and masking-key checks, in that order.
/// `None` means that the command must succeed.
fn expected_rejection(
    req: &TborAesXtsGenerateKeyReq,
    active_session_id: u16,
    closed: bool,
    fixture: FixtureState,
) -> Option<TborStatus> {
    if closed {
        return Some(TborStatus::SessionNotFound);
    }
    if req.session_id != active_session_id {
        return Some(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    if req.key_label.len() > TBOR_KEY_LABEL_MAX_LEN {
        return Some(TborStatus::TborInvalidFixedLength);
    }
    if req.scope != common::KEY_SCOPE_SESSION && fixture == FixtureState::BeforeFinal {
        return Some(TborStatus::InvalidArg);
    }
    if req.key_usage != (KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT) {
        return Some(TborStatus::InvalidPermissions);
    }
    match req.scope {
        common::KEY_SCOPE_SESSION | common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => None,
        common::KEY_SCOPE_SECURITY_DOMAIN if fixture == FixtureState::SecurityDomain => None,
        _ => Some(TborStatus::UnsupportedKeyScope),
    }
}

/// Assert the fixed-size masked-key response is populated without inspecting
/// or exposing the plaintext key.
fn assert_masked_key(resp: &TborAesXtsGenerateKeyResp) {
    assert_eq!(resp.masked_key.len(), MASKED_AES_XTS_KEY_LEN);
    assert!(
        resp.masked_key.iter().any(|&byte| byte != 0),
        "generated masked XTS key must not be all-zero"
    );
}

/// Use a generated key for a small, valid OOB XTS round trip, checking that
/// its kind, permissions, and masking metadata permit actual use.
fn assert_roundtrip(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: &[u8],
    plaintext: &[u8; 32],
    tweak: &[u8; XTS_TWEAK_LEN],
) {
    let mut req = TborAesXtsEncryptDecryptReq {
        session_id,
        op: AES_OP_ENCRYPT,
        data_len: plaintext.len() as u16,
        dul: plaintext.len() as u16,
        in_index: 0,
        out_index: 1,
        tweak: u64::from_le_bytes(*tweak)
            .min(u64::MAX - 1)
            .to_le_bytes()
            .to_vec(),
        masked_key: masked_key.to_vec(),
    };
    let mut ciphertext = [0u8; 32];
    ctx.tbor_oob_io(
        &req,
        &mut [
            TborOobItem::In(plaintext),
            TborOobItem::Out(&mut ciphertext),
        ],
    )
    .expect("generated XTS key should encrypt a valid data unit");
    req.op = AES_OP_DECRYPT;
    let mut decrypted = [0u8; 32];
    ctx.tbor_oob_io(
        &req,
        &mut [
            TborOobItem::In(&ciphertext),
            TborOobItem::Out(&mut decrypted),
        ],
    )
    .expect("generated XTS key should decrypt a valid data unit");
    assert_eq!(&decrypted, plaintext, "XTS round trip must recover input");
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let fixture = input.fixture_state();
        let co_session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        match fixture {
            FixtureState::BeforeFinal => {}
            FixtureState::Finalized => common::finalize_partition(ctx, &co_session),
            FixtureState::SecurityDomain => common::create_test_security_domain(ctx, &co_session),
        }
        let session = match input.role {
            common::FuzzRole::Co => co_session,
            common::FuzzRole::Cu => {
                ctx.session_close(co_session.session_id)
                    .expect("close provisioning CO session before opening CU");
                bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK)
            }
        };
        let (req, closed) = input.request(session.session_id, fixture);
        if closed {
            ctx.session_close(session.session_id)
                .expect("close session before fuzzed request");
        }
        let expected = expected_rejection(&req, session.session_id, closed, fixture);
        match ctx.tbor(&req) {
            Ok(resp) => {
                assert!(
                    expected.is_none(),
                    "invalid XTS generation request succeeded: {req:?}, expected {expected:?}"
                );
                assert_masked_key(&resp);
                if input.checks & 7 == 1 {
                    let fresh = ctx
                        .tbor(&req)
                        .expect("repeated valid generation must succeed");
                    assert_masked_key(&fresh);
                    assert_ne!(
                        resp.masked_key, fresh.masked_key,
                        "keys must be freshly masked"
                    );
                }
                if input.checks & 0x38 == 8 {
                    assert_roundtrip(
                        ctx,
                        session.session_id,
                        &resp.masked_key,
                        &input.plaintext,
                        &input.tweak,
                    );
                }
            }
            Err(err @ DdiError::DriverError(_)) => panic!("Crash Detected: {err:?}"),
            Err(err) => {
                let status = expected.unwrap_or_else(|| {
                    panic!("valid XTS generation request failed: {req:?}: {err:?}")
                });
                if closed || req.session_id != session.session_id {
                    assert_session_rejects(&err, status);
                } else {
                    assert_fw_rejects(&err, status);
                }
            }
        }
        if !closed {
            ctx.session_close(session.session_id)
                .expect("close fuzz session");
        }
    });
});
