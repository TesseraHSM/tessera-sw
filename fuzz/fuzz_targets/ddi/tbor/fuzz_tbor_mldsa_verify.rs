// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware external-mu ML-DSA verification with exact rejection oracles.
//!
//! A one-time sweep covers every parameter set and principal handler outcome;
//! subsequent inputs generate reproducible keys and independently vary all four
//! request fields. The host oracle shares tsra_crypto with the emulator, so it
//! checks firmware semantics, not an independent cryptographic implementation.
//! Typed requests do not cover malformed wire structures or injected PAL faults.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::sync::Once;

use libfuzzer_sys::arbitrary::*;
use libfuzzer_sys::*;
use tsra_crypto as crypto;
use tsra_ddi_tbor_test_harness::assertions::*;
use tsra_ddi_tbor_test_harness::pqc::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// Harness-owned parameter sizes, also used to infer the set from final bytes.
const PARAMS: [&MlDsaParams; 3] = [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87];

/// Small controls precede a bounded payload that supplies key seeds, mu, and
/// replacement bytes. Short inputs also serve as payload, keeping small corpus
/// entries useful; missing controls default to zero so empty inputs execute.
#[derive(Debug)]
struct FuzzInput {
    scenario: u8,
    params: u8,
    session_mode: u8,
    session_id: u16,
    pub_mode: u8,
    mu_mode: u8,
    sig_mode: u8,
    length: u16,
    offset: u16,
    mask: u8,
    bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    /// Decode compact selectors without rejecting short corpus entries. Reuse
    /// the controls as payload when no trailing bytes remain.
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let bytes = u.bytes(u.len().min(MLDSA_SIGNATURE_MAX_LEN + MLDSA_MU_LEN))?;
        let mut controls = Unstructured::new(bytes);
        let mut input = Self {
            scenario: controls.arbitrary().unwrap_or_default(),
            params: controls.arbitrary().unwrap_or_default(),
            session_mode: controls.arbitrary().unwrap_or_default(),
            session_id: controls.arbitrary().unwrap_or_default(),
            pub_mode: controls.arbitrary().unwrap_or_default(),
            mu_mode: controls.arbitrary().unwrap_or_default(),
            sig_mode: controls.arbitrary().unwrap_or_default(),
            length: controls.arbitrary().unwrap_or_default(),
            offset: controls.arbitrary().unwrap_or_default(),
            mask: controls.arbitrary().unwrap_or_default(),
            bytes: Vec::new(),
        };
        let payload = controls.bytes(controls.len())?;
        input.bytes = if payload.is_empty() { bytes } else { payload }.to_vec();
        Ok(input)
    }
}

/// Predicted outcome, computed before issuing the final request.
#[derive(Debug, PartialEq, Eq)]
enum Expected {
    Success,
    Reject(TborStatus),
}

/// Repeat a bounded payload to reach interesting lengths even from short inputs.
fn repeated_bytes(bytes: &[u8], len: usize, offset: usize) -> Vec<u8> {
    (0..len)
        .map(|index| {
            if bytes.is_empty() {
                0
            } else {
                bytes[(index + offset) % bytes.len()]
            }
        })
        .collect()
}

/// Generate and cross-check a deterministic external-mu signature without
/// provisioning device keys or exporting any private-key material.
fn valid_request(input: &FuzzInput, p: &MlDsaParams, session_id: u16) -> TborMlDsaVerifyReq {
    let variant = match p.key_kind {
        MLDSA_KEY_KIND_44_SEED => crypto::MlDsaVariant::MlDsa44,
        MLDSA_KEY_KIND_65_SEED => crypto::MlDsaVariant::MlDsa65,
        MLDSA_KEY_KIND_87_SEED => crypto::MlDsaVariant::MlDsa87,
        _ => unreachable!("harness ML-DSA parameter set"),
    };
    let seed = repeated_bytes(&input.bytes, crypto::MLDSA_SEED_LEN, 0);
    let key = crypto::MlDsaPrivateKey::from_seed(variant, &seed).expect("host ML-DSA keygen");
    let public = crypto::PrivateKey::public_key(&key).expect("derive host ML-DSA public key");
    let mut pub_key = vec![0; p.pub_key_len];
    let written = crypto::ExportableKey::to_bytes(&public, Some(&mut pub_key))
        .expect("export host ML-DSA public key");
    assert_eq!(written, p.pub_key_len);
    let mu = repeated_bytes(&input.bytes, MLDSA_MU_LEN, crypto::MLDSA_SEED_LEN);
    let signature = crypto::Signer::sign_vec(
        &mut crypto::MlDsaAlgo::external_mu().deterministic(),
        &key,
        &mu,
    )
    .expect("host external-mu signing");
    assert_eq!(signature.len(), p.sig_len);
    assert_not_truncated_at_page(&signature, p.name);
    let req = TborMlDsaVerifyReq {
        session_id,
        pub_key,
        mu,
        signature,
    };
    assert_eq!(
        expected_outcome(&req, Some(session_id)),
        Expected::Success,
        "generated tuple must verify on host"
    );
    req
}

/// Predict transport, schema, handler-length, then PAL verification outcomes.
///
/// The std PAL maps host key import and verification API errors to InvalidArg;
/// a completed false verdict instead becomes MlDsaVerifyFailed in the handler.
fn expected_outcome(req: &TborMlDsaVerifyReq, bound_session: Option<u16>) -> Expected {
    let Some(bound) = bound_session else {
        return Expected::Reject(TborStatus::SessionNotFound);
    };
    if req.session_id != bound {
        return Expected::Reject(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    if req.pub_key.len() > MLDSA_PUB_KEY_MAX_LEN
        || req.mu.len() != MLDSA_MU_LEN
        || req.signature.len() > MLDSA_SIGNATURE_MAX_LEN
    {
        return Expected::Reject(TborStatus::TborInvalidFixedLength);
    }
    let Some(p) = PARAMS.iter().find(|p| p.pub_key_len == req.pub_key.len()) else {
        return Expected::Reject(TborStatus::InvalidArg);
    };
    if req.signature.len() != p.sig_len {
        return Expected::Reject(TborStatus::InvalidArg);
    }
    let key = <crypto::MlDsaPublicKey as crypto::ImportableKey>::from_bytes(&req.pub_key);
    match key.and_then(|key| {
        crypto::Verifier::verify(
            &mut crypto::MlDsaAlgo::external_mu(),
            &key,
            &req.mu,
            &req.signature,
        )
    }) {
        Ok(true) => Expected::Success,
        Ok(false) => Expected::Reject(TborStatus::MlDsaVerifyFailed),
        Err(_) => Expected::Reject(TborStatus::InvalidArg),
    }
}

/// Enforce both directions of the oracle; unexpected transport, driver, and
/// decoding errors cannot masquerade as an expected firmware rejection.
fn check_request(ctx: &TestCtx, req: &TborMlDsaVerifyReq, bound_session: Option<u16>) {
    let expected = expected_outcome(req, bound_session);
    match (expected, ctx.tbor(req)) {
        (Expected::Success, Ok(TborMlDsaVerifyResp)) => {}
        (Expected::Success, Err(err)) => panic!("valid ML-DSA verification failed: {err:?}"),
        (Expected::Reject(status), Ok(_)) => {
            panic!("ML-DSA verification unexpectedly succeeded; expected {status:?}");
        }
        (Expected::Reject(status), Err(err)) => {
            if bound_session != Some(req.session_id) {
                assert_session_rejects(&err, status);
            } else {
                assert_fw_rejects(&err, status);
            }
        }
    }
}

/// Choose empty, each valid length and its neighbors, maximum+1, or any bounded
/// length. The three fields' combined maxima remain below the transport limit.
fn boundary_len(mode: u8, raw: u16, valid: &[usize], maximum: usize) -> usize {
    let choice = usize::from(mode) % (valid.len() * 3 + 3);
    if choice == 0 {
        0
    } else if choice <= valid.len() * 3 {
        let index = choice - 1;
        valid[index / 3] + index % 3 - 1
    } else if choice == valid.len() * 3 + 1 {
        maximum + 1
    } else {
        usize::from(raw) % (maximum + 2)
    }
}

/// Vary contents without changing length, retaining genuine no-ops. Offset
/// selectors target endpoints and both sides of the host-DMA page boundary.
fn mutate_contents(buf: &mut [u8], mode: u8, input: &FuzzInput) {
    match mode % 6 {
        0 => {}
        1 if !buf.is_empty() => {
            let offset = match input.offset % 8 {
                0 => 0,
                1 => buf.len() - 1,
                2 => 4095,
                3 => 4096,
                4 => 4097,
                _ => usize::from(input.offset),
            } % buf.len();
            buf[offset] ^= input.mask;
        }
        2 => buf.fill(0),
        3 => buf.fill(input.mask),
        4 => buf.copy_from_slice(&repeated_bytes(
            &input.bytes,
            buf.len(),
            usize::from(input.offset),
        )),
        _ => buf.reverse(),
    }
}

/// Construct isolated and mixed mutations while keeping valid requests common.
/// Only explicit session scenarios change binding; arbitrary IDs may be valid.
fn fuzzed_request(input: &FuzzInput, base: &TborMlDsaVerifyReq) -> (TborMlDsaVerifyReq, bool) {
    let mut req = base.clone();
    let scenario = input.scenario % 16;
    let mixed = scenario == 14;
    if scenario == 4 || mixed {
        mutate_contents(&mut req.pub_key, input.pub_mode, input);
    }
    if scenario == 5 || mixed {
        mutate_contents(&mut req.mu, input.mu_mode, input);
    }
    if scenario == 6 || mixed {
        mutate_contents(&mut req.signature, input.sig_mode, input);
    }
    if scenario == 7 || mixed {
        let lengths = PARAMS.map(|p| p.pub_key_len);
        req.pub_key.resize(
            boundary_len(
                input.pub_mode,
                input.length,
                &lengths,
                MLDSA_PUB_KEY_MAX_LEN,
            ),
            input.mask,
        );
    }
    if scenario == 8 || mixed {
        req.mu.resize(
            boundary_len(input.mu_mode, input.length, &[MLDSA_MU_LEN], MLDSA_MU_LEN),
            input.mask,
        );
    }
    if scenario == 9 || mixed {
        let lengths = PARAMS.map(|p| p.sig_len);
        req.signature.resize(
            boundary_len(
                input.sig_mode,
                input.length,
                &lengths,
                MLDSA_SIGNATURE_MAX_LEN,
            ),
            input.mask,
        );
    }
    match scenario {
        10 => mutate_contents(&mut req.pub_key, 4, input),
        11 => mutate_contents(&mut req.mu, 4, input),
        12 => mutate_contents(&mut req.signature, 4, input),
        15 => {
            let other = PARAMS[(usize::from(input.params) + 1) % PARAMS.len()];
            req.signature.resize(other.sig_len, input.mask);
        }
        _ => {}
    }
    let session_mode = if scenario == 13 || mixed {
        input.session_mode % 8
    } else {
        0
    };
    req.session_id = match session_mode {
        3 => input.session_id,
        4 => 0,
        5 => u16::MAX,
        6 => base.session_id.wrapping_add(1),
        _ => base.session_id,
    };
    (req, session_mode == 7)
}

/// Cover all parameter sets and core statuses once per process, independently of
/// corpus discovery. Each case changes only one field of a known-valid tuple.
fn baseline_sweep(ctx: &TestCtx, input: &FuzzInput, session_id: u16) {
    for p in PARAMS {
        let base = valid_request(input, p, session_id);
        check_request(ctx, &base, Some(session_id));
        let mut req = base.clone();
        req.mu[0] ^= 1;
        assert_eq!(
            expected_outcome(&req, Some(session_id)),
            Expected::Reject(TborStatus::MlDsaVerifyFailed)
        );
        check_request(ctx, &req, Some(session_id));
        req = base.clone();
        let tail = req.signature.len() - 1;
        req.signature[tail] ^= 1;
        check_request(ctx, &req, Some(session_id));
        req = base.clone();
        req.pub_key.pop();
        check_request(ctx, &req, Some(session_id));
        req = base.clone();
        req.signature.pop();
        check_request(ctx, &req, Some(session_id));
        req = base;
        req.mu.pop();
        check_request(ctx, &req, Some(session_id));
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        static BASELINE: Once = Once::new();
        let session = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
        let session_id = session.session_id();
        BASELINE.call_once(|| baseline_sweep(ctx, &input, session_id));

        let p = PARAMS[usize::from(input.params) % PARAMS.len()];
        let base = valid_request(&input, p, session_id);
        check_request(ctx, &base, Some(session_id));
        let (req, closed) = fuzzed_request(&input, &base);
        if closed {
            session
                .close()
                .expect("close session before stale-ID request");
            check_request(ctx, &req, None);
        } else {
            check_request(ctx, &req, Some(session_id));
            session.close().expect("close fuzz session");
        }
    });
});
