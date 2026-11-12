// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured VerifyKey requests with authentic keys and independent rejection oracles.
//!
//! Short inputs default to a valid AES/session-scope baseline. Controls select both
//! roles, provisioned scopes, key families, session transitions, and isolated faults.
//! Framing and scope checks precede the provenance-based authentication oracle;
//! it assumes altered authenticated bytes cannot forge a GCM tag. The four unused
//! stored-IV suffix bytes are deliberately excluded from the authenticity comparison.
//! Metadata corruption without a new tag exercises authentication rejection, not
//! post-authentication metadata-invariant rejection. No masking secrets are needed.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::sync::OnceLock;

use libfuzzer_sys::*;
use tsra_crypto::*;
use tsra_ddi_interface::DdiResult;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;
use tsra_fw_core_crypto_key_masking::aead::MaskedKeyMetadata;

/// AES-GCM consumes the first twelve bytes of the sixteen-byte stored IV.
const GCM_NONCE_LEN: usize = 12;

/// Single faults reach deep paths; combined faults exercise early-gate precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Valid,
    ArbitrarySession,
    MismatchedSession,
    ClosedSession,
    WrongMaskingSession,
    PersistedReopen,
    DefaultPsk,
    HeaderMagic,
    HeaderAlgorithm,
    HeaderReserved,
    HeaderAad,
    Nonce,
    IgnoredIvSuffix,
    Metadata,
    Scope,
    Ciphertext,
    Tag,
    Mutation,
    Boundary,
    RawMalformed,
    RawExploratory,
    WrongAad,
    UnalignedPayload,
    AlignedAppend,
    SessionAndLength,
    DefaultAndFraming,
    ClosedAndFraming,
    MissingScope,
}

/// Byte-oriented controls make empty inputs and synthesized large blobs executable.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    /// Read a control byte, defaulting missing controls to the valid baseline.
    fn byte(&self, index: usize) -> u8 {
        self.0.get(index).copied().unwrap_or(0)
    }

    /// Read a full-width little-endian control without requiring a long input.
    fn word(&self, index: usize) -> u16 {
        u16::from_le_bytes([self.byte(index), self.byte(index + 1)])
    }

    /// Reserve thirteen of forty selections for unchanged authentic requests.
    fn scenario(&self) -> Scenario {
        match self.byte(0) % 40 {
            0..=11 | 39 => Scenario::Valid,
            12 => Scenario::ArbitrarySession,
            13 => Scenario::MismatchedSession,
            14 => Scenario::ClosedSession,
            15 => Scenario::WrongMaskingSession,
            16 => Scenario::PersistedReopen,
            17 => Scenario::DefaultPsk,
            18 => Scenario::HeaderMagic,
            19 => Scenario::HeaderAlgorithm,
            20 => Scenario::HeaderReserved,
            21 => Scenario::HeaderAad,
            22 => Scenario::Nonce,
            23 => Scenario::IgnoredIvSuffix,
            24 => Scenario::Metadata,
            25 => Scenario::Scope,
            26 => Scenario::Ciphertext,
            27 => Scenario::Tag,
            28 => Scenario::Mutation,
            29 => Scenario::Boundary,
            30 => Scenario::RawMalformed,
            31 => Scenario::RawExploratory,
            32 => Scenario::WrongAad,
            33 => Scenario::UnalignedPayload,
            34 => Scenario::AlignedAppend,
            35 => Scenario::SessionAndLength,
            36 => Scenario::DefaultAndFraming,
            37 => Scenario::ClosedAndFraming,
            _ => Scenario::MissingScope,
        }
    }

    /// Select the harness's canonical CO/authenticated or CU/plaintext profile.
    fn role(&self) -> common::FuzzRole {
        if self.byte(4) & 1 == 0 {
            common::FuzzRole::Co
        } else {
            common::FuzzRole::Cu
        }
    }

    /// Favor cheap session scope while retaining every provisioned masking scope.
    fn scope(&self) -> u8 {
        match self.scenario() {
            Scenario::WrongMaskingSession | Scenario::MissingScope => common::KEY_SCOPE_SESSION,
            Scenario::PersistedReopen => common::KEY_SCOPE_EPHEMERAL + self.byte(3) % 3,
            _ => match self.byte(3) % 16 {
                0..=11 => common::KEY_SCOPE_SESSION,
                12 => common::KEY_SCOPE_EPHEMERAL,
                13 | 14 => common::KEY_SCOPE_LOCAL,
                _ => common::KEY_SCOPE_SECURITY_DOMAIN,
            },
        }
    }

    /// Expand the fuzz tail to a caller-bounded length, even for short corpus entries.
    fn bytes(&self, len: usize) -> Vec<u8> {
        let tail = self.0.get(16..).unwrap_or_default();
        (0..len)
            .map(|index| {
                tail.get(index % tail.len().max(1))
                    .copied()
                    .unwrap_or(self.byte(15))
            })
            .collect()
    }

    /// Exercise empty, interior, and maximum producer labels without invalid setup.
    fn label(&self) -> Vec<u8> {
        let len = match self.byte(5) % 4 {
            0 => 0,
            1 => TBOR_KEY_LABEL_MAX_LEN,
            2 => TBOR_KEY_LABEL_MAX_LEN - 1,
            _ => usize::from(self.word(10)) % (TBOR_KEY_LABEL_MAX_LEN + 1),
        };
        self.bytes(len)
    }

    /// Reuse shared envelope mutations, preserving zero-mask and empty-append no-ops.
    fn mutation(&self) -> common::EnvelopeMutation {
        match self.byte(6) % 4 {
            0 => common::EnvelopeMutation::None,
            1 => common::EnvelopeMutation::FlipByte {
                offset: self.word(8),
                mask: self.byte(7),
            },
            2 => common::EnvelopeMutation::Truncate { len: self.word(10) },
            _ => common::EnvelopeMutation::Append(self.bytes(usize::from(self.byte(15) % 33))),
        }
    }
}

/// Import immutable host RSA material through the real OAEP/KWP producer command.
fn import_rsa(ctx: &TestCtx, session_id: u16, scope: u8, input: &Input<'_>) -> Vec<u8> {
    static KEYS: [OnceLock<Vec<u8>>; 3] = [const { OnceLock::new() }; 3];
    let size = usize::from(input.byte(2) % 3);
    let der = KEYS[size].get_or_init(|| {
        RsaPrivateKey::generate([256, 384, 512][size])
            .expect("host RSA fixture generation")
            .to_vec()
            .expect("host RSA fixture export")
    });
    let wire = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .expect("GetUnwrappingKey fixture")
        .pub_key;
    let modulus_len = wire.len() - core::mem::size_of::<u32>();
    let public_be: Vec<u8> = wire[..modulus_len]
        .iter()
        .rev()
        .chain(wire[modulus_len..].iter().rev())
        .copied()
        .collect();
    let public = RsaPublicKey::from_hsm_bytes(&public_be).expect("unwrapping public key");
    let kek_bytes = Rng::rand_vec(32).expect("host KEK generation");
    let mut wrapped = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &public,
        &kek_bytes,
    )
    .expect("OAEP fixture wrapping");
    wrapped.reverse();
    let kek = AesKey::from_bytes(&kek_bytes).expect("AES fixture KEK");
    wrapped.extend(
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, der)
            .expect("KWP fixture wrapping"),
    );
    ctx.tbor(&TborUnwrapKeyReq {
        session_id,
        scope,
        key_class: if input.byte(1) % 16 == 12 {
            KEY_CLASS_RSA
        } else {
            KEY_CLASS_RSA_CRT
        },
        key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        oaep_hash_algo: HASH_ALGO_SHA256,
        wrapped_blob: wrapped,
        key_label: input.label(),
    })
    .expect("RSA import fixture")
    .masked_key
}

/// Produce one authentic key, weighting inexpensive AES/ECC ahead of RSA and PQC.
fn generate_key(ctx: &TestCtx, session_id: u16, scope: u8, input: &Input<'_>) -> Vec<u8> {
    let parameter = usize::from(input.byte(2) % 3);
    let key_label = input.label();
    let masked = match input.byte(1) % 16 {
        0..=5 => {
            ctx.tbor(&TborAesGenerateKeyReq {
                session_id,
                scope,
                key_size: [
                    common::AesKeySize::Aes128,
                    common::AesKeySize::Aes192,
                    common::AesKeySize::Aes256,
                ][parameter]
                    .to_tbor(),
                key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                key_label,
            })
            .expect("AES fixture generation")
            .masked_key
        }
        6..=9 => {
            ctx.tbor(&TborEccGenerateKeyReq {
                session_id,
                scope,
                curve: [
                    common::EccCurve::P256,
                    common::EccCurve::P384,
                    common::EccCurve::P521,
                ][parameter]
                    .to_tbor(),
                key_usage: if input.byte(15) & 1 == 0 {
                    KEY_USAGE_SIGN
                } else {
                    KEY_USAGE_DERIVE
                },
                key_label,
            })
            .expect("ECC fixture generation")
            .masked_key
        }
        10 => {
            let (min, max) = [(32, 64), (48, 128), (64, 128)][parameter];
            ctx.tbor(&TborHmacGenerateKeyReq {
                session_id,
                scope,
                hash_algo: [HMAC_HASH_SHA256, HMAC_HASH_SHA384, HMAC_HASH_SHA512][parameter],
                key_length: min + input.byte(15) % (max - min + 1),
                key_label,
            })
            .expect("HMAC fixture generation")
            .masked_key
        }
        11 => {
            ctx.tbor(&TborAesXtsGenerateKeyReq {
                session_id,
                scope,
                key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                key_label,
            })
            .expect("AES-XTS fixture generation")
            .masked_key
        }
        12 | 13 => import_rsa(ctx, session_id, scope, input),
        14 => {
            let params = [&pqc::ML_DSA_44, &pqc::ML_DSA_65, &pqc::ML_DSA_87][parameter];
            let resp = ctx
                .tbor(&TborMlDsaGenerateKeyReq {
                    session_id,
                    scope,
                    key_kind: params.key_kind,
                })
                .expect("ML-DSA fixture generation");
            assert_eq!(resp.masked_key.len(), params.masked_key_len);
            resp.masked_key
        }
        _ => {
            let params = [&pqc::ML_KEM_512, &pqc::ML_KEM_768, &pqc::ML_KEM_1024][parameter];
            let resp = ctx
                .tbor(&TborMlKemGenerateKeyReq {
                    session_id,
                    scope,
                    key_kind: params.key_kind,
                })
                .expect("ML-KEM fixture generation");
            assert_eq!(resp.masked_key.len(), params.masked_key_len);
            resp.masked_key
        }
    };
    assert!(masked.len() <= VERIFY_KEY_MASKED_KEY_MAX_LEN);
    pqc::assert_not_truncated_at_page(&masked, "VerifyKey fixture");
    masked
}

/// Provision masking keys through CO and switch to the requested role on the same handle.
fn setup<'ctx>(ctx: &'ctx TestCtx, input: &Input<'_>, scope: u8) -> SessionGuard<'ctx> {
    let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
    match scope {
        common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => {
            common::finalize_partition(ctx, co.handshake());
        }
        common::KEY_SCOPE_SECURITY_DOMAIN => {
            common::create_test_security_domain(ctx, co.handshake());
        }
        _ => {}
    }
    match input.role() {
        common::FuzzRole::Co => co,
        common::FuzzRole::Cu => {
            co.close().expect("close provisioning CO session");
            SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK))
        }
    }
}

/// Close and reopen under the already-rotated role PSK without resetting partition state.
fn reopen<'ctx>(
    ctx: &'ctx TestCtx,
    session: SessionGuard<'ctx>,
    role: &common::FuzzRole,
) -> SessionGuard<'ctx> {
    session.close().expect("close originating session");
    let psk = match role {
        common::FuzzRole::Co => &ROTATED_CO_PSK,
        common::FuzzRole::Cu => &ROTATED_CU_PSK,
    };
    let options = SessionOpenInitOptions::new(role.psk_id(), role.session_type()).with_psk(psk);
    let pending = ctx
        .session_open_init_with_options(options)
        .expect("replacement session init");
    SessionGuard::new(
        ctx,
        ctx.session_open_finish(pending)
            .expect("replacement session finish"),
    )
}

/// Select lengths on both sides of framing, producer, and schema boundaries.
fn boundary_len(original_len: usize, selector: u8) -> usize {
    let alg = aead_envelope::AeadAlg::AesGcm256;
    let header = aead_envelope::HEADER_LEN;
    let aad = header + alg.iv_len();
    let payload = aad + core::mem::size_of::<MaskedKeyMetadata>();
    let minimum = payload + alg.tag_len();
    let lengths = [
        0,
        1,
        header - 1,
        header,
        aad - 1,
        aad,
        payload - 1,
        payload,
        minimum - 1,
        minimum,
        minimum + 1,
        original_len - 1,
        original_len,
        original_len + 1,
        VERIFY_KEY_MASKED_KEY_MAX_LEN - 1,
        VERIFY_KEY_MASKED_KEY_MAX_LEN,
        VERIFY_KEY_MASKED_KEY_MAX_LEN + 1,
    ];
    lengths[usize::from(selector) % lengths.len()]
}

/// Mutate a clone of an authentic envelope, retaining isolated and no-op cases.
fn mutate(masked: &mut Vec<u8>, input: &Input<'_>) {
    let env = aead_envelope::inspect(masked).expect("producer envelope framing");
    let iv_len = env.iv.len();
    let aad_len = env.aad.len();
    let payload_len = env.payload.len();
    let tag_len = env.tag.len();
    let aad = aead_envelope::HEADER_LEN + env.iv.len();
    let payload = aad + aad_len;
    let tag = masked.len() - tag_len;
    let offset = usize::from(input.word(8));
    let mask = input.byte(7) | 1;
    match input.scenario() {
        Scenario::HeaderMagic => masked[offset % aead_envelope::FORMAT_TAG.len()] ^= mask,
        Scenario::HeaderAlgorithm => masked[4] = input.byte(6),
        Scenario::HeaderReserved => masked[5] ^= mask,
        Scenario::HeaderAad => {
            let len = [0u16, 32, 160, 192, 224, 193, u16::MAX][usize::from(input.byte(6) % 7)];
            masked[6..8].copy_from_slice(&len.to_be_bytes());
        }
        Scenario::Nonce => masked[aead_envelope::HEADER_LEN + offset % GCM_NONCE_LEN] ^= mask,
        Scenario::IgnoredIvSuffix => {
            let suffix = aead_envelope::HEADER_LEN + GCM_NONCE_LEN;
            masked[suffix + offset % (iv_len - GCM_NONCE_LEN)] ^= mask;
        }
        Scenario::Metadata => masked[aad + offset % aad_len] ^= mask,
        Scenario::Scope | Scenario::MissingScope => {
            let scope = if input.scenario() == Scenario::MissingScope {
                common::KEY_SCOPE_EPHEMERAL + input.byte(6) % 3
            } else {
                input.byte(6) & 7
            };
            // usage_flags is metadata bytes 8..16; scope occupies bits 17..19.
            masked[aad + 10] = (masked[aad + 10] & !0x0E) | (scope << 1);
        }
        Scenario::Ciphertext => masked[payload + offset % payload_len] ^= mask,
        Scenario::Tag => masked[tag + offset % tag_len] ^= mask,
        Scenario::Mutation => {
            let mutation = input.mutation();
            let noop = mutation.is_noop(masked);
            let original = masked.clone();
            mutation.apply(masked);
            assert_eq!(noop, *masked == original, "shared mutation no-op contract");
        }
        Scenario::Boundary => {
            masked.resize(boundary_len(masked.len(), input.byte(6)), input.byte(15));
        }
        Scenario::RawMalformed | Scenario::RawExploratory => {
            *masked =
                input.bytes(usize::from(input.word(10)) % (VERIFY_KEY_MASKED_KEY_MAX_LEN + 2));
            if input.scenario() == Scenario::RawMalformed && !masked.is_empty() {
                masked[0] = 0;
            }
        }
        Scenario::WrongAad => masked[6..8].copy_from_slice(&0u16.to_be_bytes()),
        Scenario::UnalignedPayload => masked.push(input.byte(15)),
        Scenario::AlignedAppend => masked.extend(input.bytes(16)),
        Scenario::SessionAndLength => masked.resize(VERIFY_KEY_MASKED_KEY_MAX_LEN + 1, 0),
        Scenario::ClosedAndFraming => masked.clear(),
        _ => {}
    }
}

/// Compare all meaningful envelope bytes, ignoring only the unused stored-IV suffix.
fn same_authenticated_envelope(masked: &[u8], original: &[u8]) -> bool {
    let suffix = aead_envelope::HEADER_LEN + GCM_NONCE_LEN;
    let aad = aead_envelope::HEADER_LEN + aead_envelope::AeadAlg::AesGcm256.iv_len();
    masked.len() == original.len()
        && masked.len() >= aad
        && masked[..suffix] == original[..suffix]
        && masked[aad..] == original[aad..]
}

/// Predict schema, framing, scope, then authentication outcomes before submission.
fn expected_blob(
    masked: &[u8],
    original: &[u8],
    provisioned_scope: u8,
    changed_session_key: bool,
) -> Option<TborStatus> {
    if masked.len() > VERIFY_KEY_MASKED_KEY_MAX_LEN {
        return Some(TborStatus::TborInvalidFixedLength);
    }
    let Ok(env) = aead_envelope::inspect(masked) else {
        return Some(TborStatus::InvalidArg);
    };
    if env.aad.len() != core::mem::size_of::<MaskedKeyMetadata>()
        || !env.payload.len().is_multiple_of(16)
    {
        return Some(TborStatus::MaskedKeyDecodeFailed);
    }
    let flags = u64::from_le_bytes(env.aad[8..16].try_into().expect("metadata usage field"));
    let scope = ((flags >> 17) & 7) as u8;
    let available = match scope {
        common::KEY_SCOPE_SESSION => true,
        common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => {
            provisioned_scope != common::KEY_SCOPE_SESSION
        }
        common::KEY_SCOPE_SECURITY_DOMAIN => provisioned_scope == common::KEY_SCOPE_SECURITY_DOMAIN,
        _ => false,
    };
    if !available {
        return Some(TborStatus::UnsupportedKeyScope);
    }
    if !changed_session_key && same_authenticated_envelope(masked, original) {
        None
    } else {
        Some(TborStatus::AesGcmDecryptTagDoesNotMatch)
    }
}

/// Assert both directions of the oracle, allowing socket-side session rejections.
fn check_result(
    result: DdiResult<TborVerifyKeyResp>,
    expected: Option<TborStatus>,
    scenario: Scenario,
) {
    match (result, expected) {
        (Ok(response), None) => assert_eq!(response, TborVerifyKeyResp),
        (Err(err), Some(status)) => assertions::assert_session_rejects(&err, status),
        (Ok(_), Some(status)) => {
            panic!("VerifyKey {scenario:?} unexpectedly succeeded; expected {status:?}");
        }
        (Err(err), None) => panic!("valid VerifyKey {scenario:?} failed: {err:?}"),
    }
}

/// Exercise default-PSK gating separately, including precedence over malformed framing.
fn default_psk_case(ctx: &TestCtx, input: &Input<'_>) {
    let role = input.role();
    let session = ctx
        .open_session(role.psk_id(), role.session_type())
        .expect("default-PSK fixture session");
    let req = TborVerifyKeyReq {
        session_id: session.session_id(),
        masked_key: if input.scenario() == Scenario::DefaultAndFraming {
            Vec::new()
        } else {
            input.bytes(64)
        },
    };
    check_result(
        ctx.tbor(&req),
        Some(TborStatus::DefaultPskMustRotate),
        input.scenario(),
    );
    session.close().expect("close default-PSK session");
}

/// Run one state-isolated scenario and probe that rejection does not consume a valid key.
fn run_case(ctx: &TestCtx, input: &Input<'_>) {
    let scenario = input.scenario();
    if matches!(scenario, Scenario::DefaultPsk | Scenario::DefaultAndFraming) {
        default_psk_case(ctx, input);
        return;
    }
    let scope = input.scope();
    let mut session = setup(ctx, input, scope);
    let original = generate_key(ctx, session.session_id(), scope, input);
    let mut req = TborVerifyKeyReq {
        session_id: session.session_id(),
        masked_key: original.clone(),
    };
    mutate(&mut req.masked_key, input);
    let changed_session_key = scenario == Scenario::WrongMaskingSession;
    if matches!(
        scenario,
        Scenario::WrongMaskingSession | Scenario::PersistedReopen
    ) {
        session = reopen(ctx, session, &input.role());
        req.session_id = session.session_id();
    }
    let active = session.session_id();
    match scenario {
        Scenario::ArbitrarySession => req.session_id = input.word(12),
        Scenario::MismatchedSession | Scenario::SessionAndLength => {
            req.session_id = active.wrapping_add(1);
        }
        _ => {}
    }
    let closed = matches!(
        scenario,
        Scenario::ClosedSession | Scenario::ClosedAndFraming
    );
    let live_session = if closed {
        session.close().expect("close negative-case session");
        None
    } else {
        Some(session)
    };
    let expected = if closed {
        Some(TborStatus::SessionNotFound)
    } else if req.session_id != active {
        Some(TborStatus::FileHandleSessionIdDoesNotMatch)
    } else {
        expected_blob(&req.masked_key, &original, scope, changed_session_key)
    };
    check_result(ctx.tbor(&req), expected, scenario);
    if live_session.is_some() && !changed_session_key {
        let pristine = TborVerifyKeyReq {
            session_id: active,
            masked_key: original,
        };
        check_result(ctx.tbor(&pristine), None, scenario);
        if expected.is_none() {
            check_result(ctx.tbor(&req), None, scenario);
        }
    }
    if let Some(session) = live_session {
        session.close().expect("close fuzz session");
    }
}

fuzz_target!(|bytes: &[u8]| {
    common::common_fuzz_test(&|ctx, _path| run_case(ctx, &Input(bytes)));
});
