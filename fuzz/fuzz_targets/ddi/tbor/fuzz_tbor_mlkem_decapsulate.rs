// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured ML-KEM decapsulation: round trips, implicit rejection,
//! isolated faults, and combinations across all three parameter sets.
//!
//! Generated keys keep authentication from hiding the crypto paths.
//! Permission and authenticated plaintext-length rejects cannot be reached
//! with the public key-generation fixtures: they always grant derive and
//! produce correctly sized keys. Tampering with their metadata does not
//! cover those branches, since it invalidates authentication first.
//! Response checks establish structure, not plaintext secret agreement:
//! the harness exposes no host-side unmasking of the returned secrets.

#![no_main]

#[path = "../../common.rs"]
mod common;

use arbitrary::*;
use libfuzzer_sys::*;
use tsra_crypto::aead_envelope;
use tsra_ddi_interface::*;
use tsra_ddi_tbor_test_harness::pqc::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;
use tsra_fw_core_crypto_key_masking::aead;
use zerocopy::*;

/// Bound extensions while retaining schema maximum + 1 cases.
const EXTRA_BYTES: usize = 16;
/// Number of isolated and combined scenarios selected by the first byte.
const SCENARIOS: u8 = 40;
/// Only the first 12 bytes of the stored IV affect authentication.
const NONCE_END: usize = aead_envelope::HEADER_LEN + 12;
/// End of the 16-byte stored IV, including its ignored suffix.
const IV_END: usize = aead_envelope::HEADER_LEN + 16;

/// Scalar controls precede bounded vectors so small corpus entries reach crypto.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scenario: u8,
    parameter_set: u8,
    role: u8,
    session_id: u16,
    scope: u8,
    length: u16,
    offset: u16,
    mask: u8,
    switches: u8,
    pattern: [u8; 16],
    raw_key: BoundedBytes<{ MASKED_MLKEM_KEY_MAX_LEN + 1 }>,
    raw_ciphertext: BoundedBytes<{ MLKEM_CIPHERTEXT_MAX_LEN + 1 }>,
}

/// Bounded bytes whose size hint describes their wire prefix, not a `Vec`.
#[derive(Debug)]
struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<'a, const MAX: usize> Arbitrary<'a> for BoundedBytes<MAX> {
    /// Consume only bytes available after a bounded two-byte length prefix.
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = (usize::from(u16::arbitrary(u)?) % (MAX + 1)).min(u.len());
        Ok(Self(u.bytes(len)?.to_vec()))
    }

    /// Keep the minimum input size independent of the maximum payload size.
    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (size_of::<u16>(), Some(size_of::<u16>() + MAX))
    }
}

/// Prediction made before submission, without consulting the command result.
#[derive(Debug)]
enum Expected {
    Success,
    Session(TborStatus),
    Status(TborStatus),
    /// Arbitrary or altered envelopes may fail framing, scope resolution,
    /// or authentication; an authenticated forgery has negligible probability.
    BadKey,
}

/// Open the selected role, provisioning persisted scopes under CO only when needed.
fn session<'ctx>(ctx: &'ctx TestCtx, input: &FuzzInput, provisioning: u8) -> SessionGuard<'ctx> {
    let role = if input.role & 1 == 0 {
        common::FuzzRole::Co
    } else {
        common::FuzzRole::Cu
    };
    if provisioning != 0 {
        let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
        if provisioning == 2 {
            common::create_test_security_domain(ctx, co.handshake());
        } else {
            common::finalize_partition(ctx, co.handshake());
        }
        if matches!(role, common::FuzzRole::Co) {
            return co;
        }
        co.close().expect("close provisioning CO session");
    }
    let handshake = match role {
        common::FuzzRole::Co => bootstrap_rotated_co(ctx, &ROTATED_CO_PSK),
        common::FuzzRole::Cu => bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK),
    };
    SessionGuard::new(ctx, handshake)
}

/// Expand fuzz bytes to a controlled length without requiring a large corpus entry.
fn ciphertext(input: &FuzzInput, len: usize) -> Vec<u8> {
    let bytes = if input.raw_ciphertext.0.is_empty() {
        &input.pattern[..]
    } else {
        &input.raw_ciphertext.0
    };
    bytes.iter().copied().cycle().take(len).collect()
}

/// Compare authenticated bytes while ignoring the unused stored-IV suffix.
fn unchanged_key(key: &[u8], pristine: &[u8]) -> bool {
    key.len() == pristine.len()
        && key[..NONCE_END] == pristine[..NONCE_END]
        && key[IV_END..] == pristine[IV_END..]
}

/// Predict transport, schema, unmasking, crypto, then output-scope validation.
fn expected(
    req: &TborMlKemDecapsulateReq,
    sid: u16,
    closed: bool,
    pristine: &[u8],
    params: &MlKemParams,
    scenario: u8,
    provisioning: u8,
) -> Expected {
    if closed {
        return Expected::Session(TborStatus::SessionNotFound);
    }
    if req.session_id != sid {
        return Expected::Session(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    // Host max_len annotations are not enforced by the encoder. Both
    // buffers fit the transport; firmware rejects oversized fields at decode.
    if req.masked_key.len() > MASKED_MLKEM_KEY_MAX_LEN
        || req.ciphertext.len() > MLKEM_CIPHERTEXT_MAX_LEN
    {
        return Expected::Status(TborStatus::TborInvalidFixedLength);
    }
    if !unchanged_key(&req.masked_key, pristine) {
        return if scenario == 22 {
            Expected::Status(TborStatus::AesGcmDecryptTagDoesNotMatch)
        } else {
            Expected::BadKey
        };
    }
    if scenario == 34 {
        return Expected::Status(TborStatus::InvalidKeyType);
    }
    if req.ciphertext.len() != params.ciphertext_len {
        return Expected::Status(TborStatus::InvalidArg);
    }
    let scope_available = match req.scope {
        common::KEY_SCOPE_SESSION => true,
        common::KEY_SCOPE_LOCAL | common::KEY_SCOPE_EPHEMERAL => provisioning != 0,
        common::KEY_SCOPE_SECURITY_DOMAIN => provisioning == 2,
        _ => false,
    };
    if !scope_available {
        return Expected::Status(TborStatus::UnsupportedKeyScope);
    }
    Expected::Success
}

/// Check the output envelope and its public bindings without comparing masked secrets.
fn check_response(resp: &TborMlKemDecapsulateResp, scope: u8, params: &MlKemParams) {
    let blob = &resp.masked_shared_secret;
    assert_eq!(blob.len(), MASKED_MLKEM_SHARED_SECRET_MAX_LEN);
    assert!(blob.iter().any(|&b| b != 0), "all-zero masked secret");
    let envelope = aead_envelope::inspect(blob).expect("well-formed shared-secret envelope");
    assert_eq!(envelope.alg, aead_envelope::AeadAlg::AesGcm256);
    assert_eq!(envelope.payload.len(), tsra_crypto::MLKEM_SHARED_SECRET_LEN);
    let metadata = aead::MaskedKeyMetadata::ref_from_bytes(envelope.aad)
        .expect("shared-secret metadata shape");
    assert_eq!(metadata.magic, aead::META_MAGIC);
    assert_eq!(metadata.version.get(), aead::META_VERSION_V1);
    assert_eq!(metadata.usage_flags().scope().0, scope);
    assert!(metadata.usage_flags().derive());
    // The handler currently records the producing ML-KEM seed kind.
    assert_eq!(metadata.key_kind, params.key_kind);
    assert_eq!(
        metadata.key_label().expect("shared-secret label"),
        b"MlKemSs"
    );
    assert_eq!(metadata.data_pad_len, 0);
    assert!(metadata._reserved.iter().all(|&b| b == 0));
    assert_not_truncated_at_page(blob, params.name);
}

/// Construct one bounded request, predict the outcome, and check its actual result.
fn exercise(ctx: &TestCtx, input: &FuzzInput) {
    let scenario = input.scenario % SCENARIOS;
    let params = [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024][usize::from(input.parameter_set) % 3];
    let provisioning = match scenario {
        30..=32 => 1,
        33 => 2,
        _ => 0,
    };
    let session = session(ctx, input, provisioning);
    let sid = session.session_id();
    let input_scope = match scenario {
        30 => common::KEY_SCOPE_LOCAL,
        31 => common::KEY_SCOPE_EPHEMERAL,
        33 => common::KEY_SCOPE_SECURITY_DOMAIN,
        _ => common::KEY_SCOPE_SESSION,
    };
    let (pristine, pub_key) = if scenario == 34 {
        let key = ctx
            .tbor(&TborMlDsaGenerateKeyReq {
                session_id: sid,
                scope: input_scope,
                key_kind: ML_DSA_44.key_kind,
            })
            .expect("generate authenticated wrong-class key");
        (key.masked_key, Vec::new())
    } else {
        let key = ctx
            .tbor(&TborMlKemGenerateKeyReq {
                session_id: sid,
                scope: input_scope,
                key_kind: params.key_kind,
            })
            .expect("generate fixture ML-KEM key");
        assert_eq!(key.masked_key.len(), params.masked_key_len);
        assert_eq!(key.pub_key.len(), params.pub_key_len);
        (key.masked_key, key.pub_key)
    };
    let mut req = TborMlKemDecapsulateReq {
        session_id: sid,
        scope: input_scope,
        masked_key: pristine.clone(),
        ciphertext: ciphertext(input, params.ciphertext_len),
    };
    if matches!(scenario, 0..=6 | 30..=33) {
        let encap = ctx
            .tbor(&TborMlKemEncapsulateReq {
                session_id: sid,
                scope: input_scope,
                pub_key,
            })
            .expect("encapsulate fixture ML-KEM key");
        assert_eq!(encap.ciphertext.len(), params.ciphertext_len);
        req.ciphertext = encap.ciphertext;
    }
    let mutation = match scenario {
        19 | 35 => common::EnvelopeMutation::FlipByte {
            offset: input.offset,
            mask: input.mask,
        },
        20 => common::EnvelopeMutation::Truncate { len: input.length },
        21 => common::EnvelopeMutation::Append(
            input.raw_key.0.iter().copied().take(EXTRA_BYTES).collect(),
        ),
        _ => common::EnvelopeMutation::None,
    };
    if scenario != 35 || input.switches & 1 != 0 {
        let noop = mutation.is_noop(&req.masked_key);
        mutation.apply(&mut req.masked_key);
        if noop {
            assert_eq!(req.masked_key, pristine, "envelope mutation no-op");
        }
    }
    match scenario {
        0..=5 | 18..=21 => {}
        6 => req.ciphertext[usize::from(input.offset) % params.ciphertext_len] ^= input.mask | 1,
        7 => req.ciphertext.fill(0),
        8 => {}
        9 => req.ciphertext = input.raw_ciphertext.0.clone(),
        10 => {
            let lengths = [
                0,
                1,
                params.ciphertext_len - 1,
                params.ciphertext_len,
                params.ciphertext_len + 1,
                ML_KEM_512.ciphertext_len,
                ML_KEM_768.ciphertext_len,
                ML_KEM_1024.ciphertext_len,
                MLKEM_CIPHERTEXT_MAX_LEN + 1,
            ];
            req.ciphertext = ciphertext(input, lengths[usize::from(input.length) % lengths.len()]);
        }
        11 => {
            req.ciphertext = ciphertext(
                input,
                usize::from(input.length) % (MLKEM_CIPHERTEXT_MAX_LEN + 2),
            );
        }
        12 => req.session_id = input.session_id,
        13 => req.session_id = sid.wrapping_add(1 + input.session_id % u16::MAX),
        14 => req.session_id = if input.mask & 1 == 0 { 0 } else { u16::MAX },
        15 => {}
        16 => req.scope = input.scope,
        17 => req.scope = common::derive_valid_key_scope(input.scope),
        22 => {
            let last = req.masked_key.len() - 1;
            req.masked_key[last] ^= input.mask | 1;
        }
        23 => req.masked_key = input.raw_key.0.clone(),
        24 => {
            let lengths = [
                0,
                1,
                params.masked_key_len - 1,
                params.masked_key_len,
                params.masked_key_len + 1,
                MASKED_MLKEM_KEY_MAX_LEN - 1,
                MASKED_MLKEM_KEY_MAX_LEN,
                MASKED_MLKEM_KEY_MAX_LEN + 1,
            ];
            req.masked_key.resize(
                lengths[usize::from(input.length) % lengths.len()],
                input.mask,
            );
        }
        25..=29 => {
            let payload_at = aead::payload_offset(aead::AeadAlg::AesGcm256);
            let tag_at = pristine.len() - aead::AeadAlg::AesGcm256.tag_len();
            let (start, end) = match scenario {
                25 => (0, aead_envelope::HEADER_LEN),
                26 => (aead_envelope::HEADER_LEN, NONCE_END),
                27 => (IV_END, payload_at),
                28 => (payload_at, tag_at),
                _ => (NONCE_END, IV_END),
            };
            req.masked_key[start + usize::from(input.offset) % (end - start)] ^= input.mask;
        }
        30 | 31 => {
            req.scope = [
                common::KEY_SCOPE_SESSION,
                common::KEY_SCOPE_LOCAL,
                common::KEY_SCOPE_EPHEMERAL,
            ][usize::from(input.scope) % 3];
        }
        32 => {
            req.scope = if input.mask & 1 == 0 {
                common::KEY_SCOPE_LOCAL
            } else {
                common::KEY_SCOPE_EPHEMERAL
            };
        }
        33 => {
            req.scope = [
                common::KEY_SCOPE_SECURITY_DOMAIN,
                common::KEY_SCOPE_SESSION,
                common::KEY_SCOPE_LOCAL,
                common::KEY_SCOPE_EPHEMERAL,
            ][usize::from(input.scope) % 4];
        }
        34 => {}
        35 => {
            if input.switches & 2 != 0 {
                req.session_id = input.session_id;
            }
            if input.switches & 4 != 0 {
                req.scope = input.scope;
            }
            if input.switches & 8 != 0 {
                req.ciphertext = input.raw_ciphertext.0.clone();
            }
            if input.switches & 16 != 0 {
                req.masked_key = input.raw_key.0.clone();
            }
        }
        36 => {
            let at = usize::from(input.offset) % req.masked_key.len();
            req.masked_key[at] ^= input.mask;
            req.masked_key[at] ^= input.mask;
        }
        37 => {
            common::EnvelopeMutation::Truncate {
                len: pristine.len() as u16,
            }
            .apply(&mut req.masked_key);
        }
        38 => common::EnvelopeMutation::Append(Vec::new()).apply(&mut req.masked_key),
        39 => {
            req.scope = [
                common::KeyScope::Local,
                common::KeyScope::Ephemeral,
                common::KeyScope::SecurityDomain,
            ][usize::from(input.scope) % 3]
                .to_tbor();
        }
        _ => unreachable!("scenario reduced modulo SCENARIOS"),
    }
    let closed = scenario == 15;
    let expected = expected(&req, sid, closed, &pristine, params, scenario, provisioning);
    if closed {
        session
            .close()
            .expect("close fixture session before request");
    } else {
        // Keep the guard alive until after submission; close the real id,
        // never the potentially fuzzed request id.
        check_result(ctx, &req, expected, params, scenario);
        session.close().expect("close fixture session");
        return;
    }
    check_result(ctx, &req, expected, params, scenario);
}

/// Submit exactly once and reject unexpected successes, statuses, and backend failures.
fn check_result(
    ctx: &TestCtx,
    req: &TborMlKemDecapsulateReq,
    expected: Expected,
    params: &MlKemParams,
    scenario: u8,
) {
    let result = ctx.tbor(req);
    match expected {
        Expected::Success => {
            let resp = result.unwrap_or_else(|err| {
                panic!(
                    "valid ML-KEM {} scenario {scenario} failed: {err}",
                    params.name
                )
            });
            check_response(&resp, req.scope, params);
        }
        Expected::Session(status) => {
            let err = result.expect_err("invalid session unexpectedly accepted");
            assertions::assert_session_rejects(&err, status);
        }
        Expected::Status(status) => {
            let err = result.expect_err("invalid decapsulation unexpectedly succeeded");
            assertions::assert_fw_rejects(&err, status);
        }
        Expected::BadKey => {
            let err = result.expect_err("altered/arbitrary key unexpectedly authenticated");
            // Envelope parser errors map to InvalidArg; masked-key alignment
            // or AAD errors to MaskedKeyDecodeFailed; peeked scopes may have
            // no masking key; otherwise authentication must fail.
            assert!(
                matches!(err, DdiError::TborStatus(status) if [
                    TborStatus::InvalidArg,
                    TborStatus::MaskedKeyDecodeFailed,
                    TborStatus::UnsupportedKeyScope,
                    TborStatus::AesGcmDecryptTagDoesNotMatch,
                ].contains(&status)),
                "unexpected key rejection in scenario {scenario}: {err}"
            );
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx, _path| exercise(ctx, &input));
});
