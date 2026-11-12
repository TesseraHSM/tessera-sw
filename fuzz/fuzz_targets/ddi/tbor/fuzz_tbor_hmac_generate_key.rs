// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured HMAC key-generation scenarios with an independent rejection
//! oracle and unmask-on-use checks for every successful generation.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;
use tsra_crypto::aead_envelope::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// Masked-key metadata occupies the fixed 192-byte authenticated AAD.
const MASKED_KEY_AAD_LEN: usize = 192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PartitionState {
    BeforeFinal,
    Initialized,
    SecurityDomain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Valid,
    Scope,
    Hash,
    Length,
    Label,
    SessionId,
    ClosedSession,
    DefaultPsk,
    Mixed,
}

#[derive(Debug)]
struct FuzzInput<'a> {
    scenario: Scenario,
    role: common::FuzzRole,
    partition: PartitionState,
    session_id: Option<u16>,
    scope: u8,
    hash_algo: u8,
    key_length: u8,
    key_label: Vec<u8>,
    msg: &'a [u8],
}

impl<'a> FuzzInput<'a> {
    /// Decode a ten-byte control prefix, defaulting missing bytes to zero
    /// so even one-byte inputs execute a complete scenario. The bounded
    /// tail supplies binary label content and the unmask-on-use message.
    fn from_bytes(data: &'a [u8]) -> Self {
        let byte = |index| data.get(index).copied().unwrap_or(0);
        let scenario = match byte(0) % 16 {
            0..=3 => Scenario::Valid,
            4 => Scenario::Scope,
            5 => Scenario::Hash,
            6..=7 => Scenario::Length,
            8 => Scenario::Label,
            9 => Scenario::SessionId,
            10 => Scenario::ClosedSession,
            11 => Scenario::DefaultPsk,
            _ => Scenario::Mixed,
        };
        let role = if byte(1) & 1 == 0 {
            common::FuzzRole::Co
        } else {
            common::FuzzRole::Cu
        };
        let partition = if scenario == Scenario::DefaultPsk {
            PartitionState::BeforeFinal
        } else {
            match byte(2) % 3 {
                0 => PartitionState::BeforeFinal,
                1 => PartitionState::Initialized,
                _ => PartitionState::SecurityDomain,
            }
        };
        let scope = match scenario {
            Scenario::Scope if byte(1) & 2 == 0 => common::derive_valid_key_scope(byte(5)),
            Scenario::Scope | Scenario::Mixed => byte(5),
            _ => match partition {
                PartitionState::BeforeFinal => common::KEY_SCOPE_SESSION,
                PartitionState::Initialized => [
                    common::KeyScope::Session,
                    common::KeyScope::Ephemeral,
                    common::KeyScope::Local,
                ][usize::from(byte(5) % 3)]
                .to_tbor(),
                PartitionState::SecurityDomain => [
                    common::KeyScope::Session,
                    common::KeyScope::Ephemeral,
                    common::KeyScope::Local,
                    common::KeyScope::SecurityDomain,
                ][usize::from(byte(5) % 4)]
                .to_tbor(),
            },
        };
        let hash_algo = if matches!(scenario, Scenario::Hash | Scenario::Mixed) {
            byte(6)
        } else {
            [HMAC_HASH_SHA256, HMAC_HASH_SHA384, HMAC_HASH_SHA512][usize::from(byte(6) % 3)]
        };
        let (min, max, _) = hmac_variant(hash_algo).unwrap_or((32, 64, 32));
        let key_length = match scenario {
            Scenario::Mixed => byte(7),
            Scenario::Length if byte(0) % 16 == 7 => byte(7),
            Scenario::Length => [
                0,
                min - 1,
                min,
                min + 1,
                max - 1,
                max,
                max + 1,
                u8::MAX,
                33,
                49,
                63,
                65,
                127,
                16,
                byte(7),
                byte(7),
            ][usize::from(byte(7) % 16)],
            _ => min + byte(7) % (max - min + 1),
        };
        let label_len = match byte(8) % 6 {
            0 => 0,
            1 => 1,
            2 => TBOR_KEY_LABEL_MAX_LEN - 1,
            3 => TBOR_KEY_LABEL_MAX_LEN,
            4 => TBOR_KEY_LABEL_MAX_LEN + 1,
            _ => usize::from(byte(9)) % (TBOR_KEY_LABEL_MAX_LEN + 2),
        };
        let label_len = if matches!(scenario, Scenario::Label | Scenario::Mixed) {
            label_len
        } else {
            label_len.min(TBOR_KEY_LABEL_MAX_LEN)
        };
        let tail = data.get(10..).unwrap_or_default();
        let mut key_label = vec![0; label_len];
        if !tail.is_empty() {
            for (index, value) in key_label.iter_mut().enumerate() {
                *value = tail[index % tail.len()];
            }
        }
        Self {
            scenario,
            role,
            partition,
            session_id: if scenario == Scenario::SessionId
                || (scenario == Scenario::Mixed && byte(0) & 1 != 0)
            {
                Some(u16::from_le_bytes([byte(3), byte(4)]))
            } else {
                None
            },
            scope,
            hash_algo,
            key_length,
            key_label,
            msg: &tail[..tail.len().min(256)],
        }
    }

    /// Use the full-width arbitrary ID when selected; half the mixed
    /// scenarios retain the active ID to reach deeper error precedence.
    fn request(&self, active_session_id: u16) -> TborHmacGenerateKeyReq {
        TborHmacGenerateKeyReq {
            session_id: self.session_id.unwrap_or(active_session_id),
            scope: self.scope,
            hash_algo: self.hash_algo,
            key_length: self.key_length,
            key_label: self.key_label.clone(),
        }
    }
}

/// Return the supported key-length bounds and digest length for a wire
/// hash discriminant. SHA-1 and unknown values are deliberately excluded.
fn hmac_variant(hash_algo: u8) -> Option<(u8, u8, usize)> {
    match hash_algo {
        HMAC_HASH_SHA256 => Some((32, 64, 32)),
        HMAC_HASH_SHA384 => Some((48, 128, 48)),
        HMAC_HASH_SHA512 => Some((64, 128, 64)),
        _ => None,
    }
}

/// Provision the selected partition state using an active rotated CO
/// session. SD setup already performs PartInit and PartFinal itself.
fn provision(ctx: &TestCtx, session: &SessionHandshake, partition: PartitionState) {
    match partition {
        PartitionState::BeforeFinal => {}
        PartitionState::Initialized => common::finalize_partition(ctx, session),
        PartitionState::SecurityDomain => common::create_test_security_domain(ctx, session),
    }
}

/// Open the caller's session, provisioning with CO before switching to
/// CU when necessary. Only the dedicated default-PSK scenario skips rotation.
fn setup_session<'a>(ctx: &'a TestCtx, input: &FuzzInput<'_>) -> SessionGuard<'a> {
    if input.scenario == Scenario::DefaultPsk {
        return ctx
            .open_session(input.role.psk_id(), input.role.session_type())
            .expect("open default-PSK session");
    }
    if matches!(input.role, common::FuzzRole::Co) || input.partition != PartitionState::BeforeFinal
    {
        let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
        provision(ctx, co.handshake(), input.partition);
        if matches!(input.role, common::FuzzRole::Co) {
            return co;
        }
        co.close().expect("close provisioning CO session");
    }
    SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK))
}

/// Predict the exact outcome before submission: handle checks precede
/// the default-PSK gate, schema decoding, partition/hash/length checks,
/// and finally masking-key resolution. Raw values may be valid by chance.
fn expected_outcome(
    req: &TborHmacGenerateKeyReq,
    active_session_id: u16,
    input: &FuzzInput<'_>,
) -> Result<(), TborStatus> {
    if input.scenario == Scenario::ClosedSession {
        return Err(TborStatus::SessionNotFound);
    }
    if req.session_id != active_session_id {
        return Err(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    if input.scenario == Scenario::DefaultPsk {
        return Err(TborStatus::DefaultPskMustRotate);
    }
    if req.key_label.len() > TBOR_KEY_LABEL_MAX_LEN {
        return Err(TborStatus::TborInvalidFixedLength);
    }
    if req.scope != common::KEY_SCOPE_SESSION && input.partition == PartitionState::BeforeFinal {
        return Err(TborStatus::InvalidArg);
    }
    let (min, max, _) = hmac_variant(req.hash_algo).ok_or(TborStatus::InvalidArg)?;
    if !(min..=max).contains(&req.key_length) {
        return Err(TborStatus::InvalidKeyLength);
    }
    match req.scope {
        common::KEY_SCOPE_SESSION | common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => Ok(()),
        common::KEY_SCOPE_SECURITY_DOMAIN if input.partition == PartitionState::SecurityDomain => {
            Ok(())
        }
        _ => Err(TborStatus::UnsupportedKeyScope),
    }
}

/// Require a correctly framed, exactly sized masked key, then unmask it
/// through Hmac twice to check the selected variant and determinism.
fn assert_success(ctx: &TestCtx, req: &TborHmacGenerateKeyReq, msg: &[u8]) {
    let resp = ctx.tbor(req).expect("valid HmacGenerateKey must succeed");
    let padded_len = usize::from(req.key_length).next_multiple_of(16);
    let expected_len = AeadAlg::AesGcm256.envelope_len(padded_len, MASKED_KEY_AAD_LEN);
    assert_eq!(resp.masked_key.len(), expected_len, "masked-key length");
    assert!((MASKED_HMAC_KEY_MIN_LEN..=MASKED_HMAC_KEY_MAX_LEN).contains(&resp.masked_key.len()));
    assert!(resp.masked_key.iter().any(|&byte| byte != 0));
    let envelope = inspect(&resp.masked_key).expect("generated envelope must parse");
    assert_eq!(envelope.alg, AeadAlg::AesGcm256);
    assert_eq!(envelope.aad.len(), MASKED_KEY_AAD_LEN);
    assert_eq!(envelope.payload.len(), padded_len);
    let mac_req = TborHmacReq {
        session_id: req.session_id,
        masked_key: resp.masked_key,
        msg: msg.to_vec(),
    };
    let tag = ctx
        .tbor(&mac_req)
        .expect("generated key must unmask for Hmac")
        .tag;
    let (_, _, digest_len) =
        hmac_variant(req.hash_algo).expect("successful hash must be supported");
    assert_eq!(tag.len(), digest_len);
    assert_eq!(
        tag,
        ctx.tbor(&mac_req).expect("repeated Hmac must succeed").tag,
        "Hmac must be deterministic",
    );
}

/// Execute one isolated scenario and its precomputed oracle. Rejections
/// with a live rotated session also check that valid keygen still works.
fn run(input: &FuzzInput<'_>) {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = setup_session(ctx, input);
        let active_session_id = session.session_id();
        let req = input.request(active_session_id);
        let expected = expected_outcome(&req, active_session_id, input);
        let session = if input.scenario == Scenario::ClosedSession {
            session.close().expect("close session before request");
            None
        } else {
            Some(session)
        };
        match expected {
            Ok(()) => assert_success(ctx, &req, input.msg),
            Err(status) => {
                ctx.expect_fw_reject(&req, status);
                if session.is_some() && input.scenario != Scenario::DefaultPsk {
                    let follow_up = TborHmacGenerateKeyReq {
                        session_id: active_session_id,
                        scope: common::KEY_SCOPE_SESSION,
                        hash_algo: HMAC_HASH_SHA256,
                        key_length: 32,
                        key_label: Vec::new(),
                    };
                    assert_success(ctx, &follow_up, input.msg);
                }
            }
        }
        if let Some(session) = session {
            session.close().expect("close caller session");
        }
    });
}

fuzz_target!(|data: &[u8]| {
    run(&FuzzInput::from_bytes(data));
});
