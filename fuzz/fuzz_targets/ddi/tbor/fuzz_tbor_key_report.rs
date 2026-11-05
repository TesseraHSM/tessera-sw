// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured KeyReport requests, authenticated mutations, and signed-report oracles.
//!
//! The first byte selects a scenario; missing bytes default to zero so even
//! short corpus entries reach firmware. Valid key producers and request
//! authentication keep deep paths reachable without guessing cryptographic tags.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::sync::OnceLock;

use common::*;
use libfuzzer_sys::arbitrary::*;
use tsra_crypto::*;
use tsra_ddi_interface::DdiError;
use tsra_ddi_mbor_test_helpers::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;
use tsra_session_ex_crypto::seal_key_report_auth;
use x509::*;

const FLAG_IMPORTED: u32 = 1;
const FLAG_GENERATED: u32 = 1 << 2;
const FLAG_SIGN: u32 = 1 << 5;
const FLAG_VERIFY: u32 = 1 << 6;
const FLAG_DERIVE: u32 = 1 << 9;
const FLAG_SD_SEALING: u32 = 1 << 10;
const AUTH_MAX_LEN: usize = 160;
const GCM_NONCE_LEN: usize = 12;

/// Isolated faults prevent early gates from hiding authentication and unmasking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Valid,
    CoEmptyAuth,
    CoAuthenticated,
    CuAuthenticated,
    DefaultPsk,
    Unfinalized,
    ArbitrarySession,
    ClosedSession,
    StaleCredential,
    Symmetric,
    RawKey,
    KeyBoundary,
    KeyMutation,
    KeyHeader,
    KeyIv,
    KeyMetadata,
    KeyCiphertext,
    KeyTag,
    MissingCuAuth,
    InvalidCoAuth,
    RawAuth,
    AuthBoundary,
    AuthMutation,
    WrongDigest,
    WrongAad,
    WrongParamKey,
    ChangedReportData,
    ChangedMaskedKey,
    ReplayAuth,
    WrongMaskingSession,
    UnsupportedScope,
}

const SCENARIOS: &[Scenario] = &[
    Scenario::Valid,
    Scenario::CoEmptyAuth,
    Scenario::CoAuthenticated,
    Scenario::CuAuthenticated,
    Scenario::DefaultPsk,
    Scenario::Unfinalized,
    Scenario::ArbitrarySession,
    Scenario::ClosedSession,
    Scenario::StaleCredential,
    Scenario::Symmetric,
    Scenario::RawKey,
    Scenario::KeyBoundary,
    Scenario::KeyMutation,
    Scenario::KeyHeader,
    Scenario::KeyIv,
    Scenario::KeyMetadata,
    Scenario::KeyCiphertext,
    Scenario::KeyTag,
    Scenario::MissingCuAuth,
    Scenario::InvalidCoAuth,
    Scenario::RawAuth,
    Scenario::AuthBoundary,
    Scenario::AuthMutation,
    Scenario::WrongDigest,
    Scenario::WrongAad,
    Scenario::WrongParamKey,
    Scenario::ChangedReportData,
    Scenario::ChangedMaskedKey,
    Scenario::ReplayAuth,
    Scenario::WrongMaskingSession,
    Scenario::UnsupportedScope,
];

#[derive(Debug)]
struct FuzzInput {
    scenario: Scenario,
    cu: bool,
    source: u8,
    scope: u8,
    curve: common::EccCurve,
    size: u8,
    mask: u8,
    offset: u16,
    session_id: u16,
    length: u16,
    mutation: u8,
    derive: bool,
    report_data: [u8; KEY_REPORT_DATA_LEN],
    bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    /// Decode bounded selectors and payloads, retaining useful empty-input defaults.
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let scenario = SCENARIOS[usize::from(u.arbitrary::<u8>().unwrap_or(0)) % SCENARIOS.len()];
        let cu = u.arbitrary().unwrap_or(false);
        let source = u.arbitrary().unwrap_or(0);
        let scope = u.arbitrary().unwrap_or(0);
        let curve = match u.arbitrary::<u8>().unwrap_or(0) % 3 {
            0 => common::EccCurve::P256,
            1 => common::EccCurve::P384,
            _ => common::EccCurve::P521,
        };
        let size = u.arbitrary().unwrap_or(0);
        let mask = u.arbitrary().unwrap_or(0);
        let offset = u.arbitrary().unwrap_or(0);
        let session_id = u.arbitrary().unwrap_or(0);
        let length = u.arbitrary().unwrap_or(0);
        let mutation = u.arbitrary().unwrap_or(0);
        let derive = u.arbitrary().unwrap_or(false);
        let mut report_data = [0; KEY_REPORT_DATA_LEN];
        for byte in &mut report_data {
            *byte = u.arbitrary().unwrap_or(0);
        }
        let bytes = u
            .bytes(u.len().min(KEY_REPORT_MASKED_KEY_MAX_LEN + 1))?
            .to_vec();
        Ok(Self {
            scenario,
            cu,
            source,
            scope,
            curve,
            size,
            mask,
            offset,
            session_id,
            length,
            mutation,
            derive,
            report_data,
            bytes,
        })
    }
}

impl FuzzInput {
    /// Reuse shared envelope mutations, including their deliberately possible no-ops.
    fn envelope_mutation(&self) -> EnvelopeMutation {
        match self.mutation % 4 {
            0 => EnvelopeMutation::None,
            1 => EnvelopeMutation::FlipByte {
                offset: self.offset,
                mask: self.mask,
            },
            2 => EnvelopeMutation::Truncate { len: self.length },
            _ => EnvelopeMutation::Append(self.bytes[..self.bytes.len().min(32)].to_vec()),
        }
    }
}

enum PublicKey {
    Ecc {
        curve: common::EccCurve,
        wire: Vec<u8>,
    },
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    Symmetric,
}

struct KeyMaterial {
    masked: Vec<u8>,
    public: PublicKey,
    flags: u32,
}

struct RsaFixture {
    der: Vec<u8>,
    n: Vec<u8>,
    e: Vec<u8>,
}

/// Cache host RSA material by modulus size, never per-device masked envelopes.
fn rsa_fixture(size: u8) -> &'static RsaFixture {
    static KEYS: [OnceLock<RsaFixture>; 3] = [const { OnceLock::new() }; 3];
    let index = usize::from(size % 3);
    KEYS[index].get_or_init(|| {
        let key = RsaPrivateKey::generate([256, 384, 512][index]).expect("host RSA generation");
        RsaFixture {
            der: key.to_vec().expect("export RSA private key"),
            n: key.n_vec().expect("host RSA modulus"),
            e: key.e_vec().expect("host RSA exponent"),
        }
    })
}

/// Import host material through the real RSA-OAEP/AES-KWP UnwrapKey command.
fn import_key(ctx: &TestCtx, session_id: u16, scope: u8, class: u8, der: &[u8]) -> Vec<u8> {
    let wire = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .expect("GetUnwrappingKey")
        .pub_key;
    let modulus_len = wire.len() - core::mem::size_of::<u32>();
    let public_be: Vec<u8> = wire[..modulus_len]
        .iter()
        .rev()
        .chain(wire[modulus_len..].iter().rev())
        .copied()
        .collect();
    let public = RsaPublicKey::from_hsm_bytes(&public_be).expect("unwrapping public key");
    let kek_bytes = Rng::rand_vec(32).expect("host KEK");
    let mut wrapped = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &public,
        &kek_bytes,
    )
    .expect("RSA-OAEP wrap KEK");
    wrapped.reverse();
    let kek = AesKey::from_bytes(&kek_bytes).expect("AES KEK");
    wrapped.extend(
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, der)
            .expect("AES-KWP wrap private key"),
    );
    ctx.tbor(&TborUnwrapKeyReq {
        session_id,
        scope,
        key_class: class,
        key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        oaep_hash_algo: HASH_ALGO_SHA256,
        wrapped_blob: wrapped,
        key_label: Vec::new(),
    })
    .expect("UnwrapKey")
    .masked_key
}

/// Produce an authentic masked key and independently retain its expected public data.
fn make_key(ctx: &TestCtx, session_id: u16, scope: u8, input: &FuzzInput) -> KeyMaterial {
    let label = input.bytes[..input.bytes.len().min(TBOR_KEY_LABEL_MAX_LEN)].to_vec();
    if input.scenario == Scenario::Symmetric {
        let masked = if input.source.is_multiple_of(2) {
            let size = match input.size % 3 {
                0 => common::AesKeySize::Aes128,
                1 => common::AesKeySize::Aes192,
                _ => common::AesKeySize::Aes256,
            };
            ctx.tbor(&TborAesGenerateKeyReq {
                session_id,
                scope,
                key_size: size.to_tbor(),
                key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                key_label: label,
            })
            .expect("AES generation")
            .masked_key
        } else {
            ctx.tbor(&TborHmacGenerateKeyReq {
                session_id,
                scope,
                hash_algo: [HMAC_HASH_SHA256, HMAC_HASH_SHA384, HMAC_HASH_SHA512]
                    [usize::from(input.size % 3)],
                key_length: [32, 48, 64][usize::from(input.size % 3)],
                key_label: label,
            })
            .expect("HMAC generation")
            .masked_key
        };
        return KeyMaterial {
            masked,
            public: PublicKey::Symmetric,
            flags: 0,
        };
    }
    let source = if input.scenario == Scenario::WrongMaskingSession {
        0
    } else {
        input.source % 5
    };
    match source {
        1 if scope != common::KEY_SCOPE_SESSION => {
            let key = ctx
                .tbor(&TborSdSealingKeyGenReq { session_id, scope })
                .expect("SD sealing-key generation");
            KeyMaterial {
                masked: key.masked_key.to_vec(),
                public: PublicKey::Ecc {
                    curve: common::EccCurve::P384,
                    wire: key.pub_key.to_vec(),
                },
                flags: FLAG_GENERATED | FLAG_DERIVE | FLAG_SD_SEALING,
            }
        }
        2 => {
            let curve = match input.curve {
                common::EccCurve::P256 => tsra_crypto::EccCurve::P256,
                common::EccCurve::P384 => tsra_crypto::EccCurve::P384,
                common::EccCurve::P521 => tsra_crypto::EccCurve::P521,
            };
            let key = tsra_crypto::EccPrivateKey::from_curve(curve).expect("host ECC generation");
            let (x, y) = key.coord_vec().expect("host ECC public coordinates");
            let wire_len = input.curve.wire_pub_key_len() / 2;
            let mut wire: Vec<u8> = x.iter().rev().copied().collect();
            wire.resize(wire_len, 0);
            wire.extend(y.iter().rev());
            wire.resize(2 * wire_len, 0);
            KeyMaterial {
                masked: import_key(
                    ctx,
                    session_id,
                    scope,
                    KEY_CLASS_ECC,
                    &key.to_vec().expect("export ECC private key"),
                ),
                public: PublicKey::Ecc {
                    curve: input.curve,
                    wire,
                },
                flags: FLAG_IMPORTED | FLAG_SIGN | FLAG_VERIFY,
            }
        }
        3 | 4 => {
            let key = rsa_fixture(input.size);
            KeyMaterial {
                masked: import_key(
                    ctx,
                    session_id,
                    scope,
                    if source == 3 {
                        KEY_CLASS_RSA
                    } else {
                        KEY_CLASS_RSA_CRT
                    },
                    &key.der,
                ),
                public: PublicKey::Rsa {
                    n: key.n.clone(),
                    e: key.e.clone(),
                },
                flags: FLAG_IMPORTED | FLAG_SIGN | FLAG_VERIFY,
            }
        }
        _ => {
            let key = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id,
                    scope,
                    curve: input.curve.to_tbor(),
                    key_usage: if input.derive {
                        KEY_USAGE_DERIVE
                    } else {
                        KEY_USAGE_SIGN
                    },
                    key_label: label,
                })
                .expect("ECC generation");
            KeyMaterial {
                masked: key.masked_key,
                public: PublicKey::Ecc {
                    curve: input.curve,
                    wire: key.pub_key,
                },
                flags: FLAG_GENERATED | if input.derive { FLAG_DERIVE } else { FLAG_SIGN },
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Expected {
    Success,
    Status(TborStatus),
    /// Arbitrary envelopes may fail framing, metadata, scope resolution, or GCM.
    MalformedKey,
}

/// Compare authenticated envelope bytes, ignoring the unused four-byte IV suffix.
fn same_envelope(left: &[u8], right: &[u8]) -> bool {
    let suffix = aead_envelope::HEADER_LEN + GCM_NONCE_LEN;
    let end = aead_envelope::HEADER_LEN + aead_envelope::AeadAlg::AesGcm256.iv_len();
    left.len() == right.len()
        && left.len() >= end
        && left[..suffix] == right[..suffix]
        && left[end..] == right[end..]
}

/// Classify key mutations without deriving expectations from the firmware result.
fn key_outcome(masked: &[u8], original: &[u8]) -> Expected {
    if masked.len() > KEY_REPORT_MASKED_KEY_MAX_LEN {
        Expected::Status(TborStatus::TborInvalidFixedLength)
    } else if same_envelope(masked, original) {
        Expected::Success
    } else if aead_envelope::inspect(masked).is_err() {
        Expected::Status(TborStatus::InvalidArg)
    } else {
        Expected::MalformedKey
    }
}

/// Assert both directions of the oracle; transport and unexpected errors are fatal.
fn check_result(
    result: Result<TborKeyReportResp, DdiError>,
    expected: Expected,
) -> Option<TborKeyReportResp> {
    match (result, expected) {
        (Ok(response), Expected::Success) => Some(response),
        (Ok(_), _) => panic!("invalid KeyReport unexpectedly succeeded: {expected:?}"),
        (Err(error), Expected::Success) => panic!("valid KeyReport failed: {error:?}"),
        (Err(DdiError::TborStatus(status)), Expected::Status(wanted)) => {
            assert_eq!(status, wanted, "KeyReport rejection");
            None
        }
        (Err(DdiError::TborStatus(status)), Expected::MalformedKey) => {
            // These are the only input-dependent failures before public-key derivation:
            // envelope parse, metadata validation, missing scope key, and GCM verification.
            assert!(
                matches!(
                    status,
                    TborStatus::InvalidArg
                        | TborStatus::MaskedKeyDecodeFailed
                        | TborStatus::UnsupportedKeyScope
                        | TborStatus::AesGcmDecryptTagDoesNotMatch
                ),
                "unexpected malformed-key rejection: {status:?}"
            );
            None
        }
        (Err(error), _) => panic!("unexpected KeyReport error for {expected:?}: {error:?}"),
    }
}

/// Remove public-integer leading zero padding before comparing RSA exponents.
fn unpad_integer(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len())..]
}

/// Verify PID signature, v2 payload, public-key binding, flags, and authenticated AppId.
fn verify_report(
    ctx: &TestCtx,
    response: &TborKeyReportResp,
    request: &TborKeyReportReq,
    key: &KeyMaterial,
    app_id: &[u8],
) {
    assert!(!response.report.is_empty() && response.report.len() <= KEY_REPORT_MAX_LEN);
    assert_eq!(response.report.first(), Some(&0xD2));
    let info = ctx.cert_chain_info().expect("certificate-chain info");
    assert!(info.data.num_certs > 0);
    let leaf = ctx
        .get_certificate(info.data.num_certs - 1)
        .expect("PID leaf");
    let cert =
        X509Certificate::from_der(leaf.data.certificate.as_slice()).expect("PID certificate");
    let public = EccPublicKey::from_bytes(&cert.get_public_key_der().expect("PID SPKI"))
        .expect("PID public key");
    let cose = CoseSign1Object::decode(&response.report).expect("COSE envelope");
    let mut tbs = vec![0u8; 64 + cose.protected_header.len() + cose.payload.len()];
    let tbs_len = encode_sig_struct(&cose.protected_header, cose.payload, &mut tbs)
        .expect("encode COSE Sig_structure");
    let digest = Hasher::hash_vec(&mut HashAlgo::sha384(), &tbs[..tbs_len]).expect("SHA-384");
    let verified = Verifier::verify(&mut EccAlgo::default(), &public, &digest, &cose.signature)
        .expect("PID signature");
    assert!(
        verified,
        "KeyReport must be signed by the partition PID key"
    );
    let payload: KeyAttestationReport = minicbor::decode(cose.payload).expect("report payload");
    assert_eq!(payload.version, 2);
    assert_eq!(payload.report_data, request.report_data);
    assert_eq!(payload.app_uuid.as_slice(), app_id);
    assert_eq!(payload.flags, key.flags);

    // The shared report view predates v2's policy hash; inspect that entry separately.
    let mut decoder = minicbor::Decoder::new(cose.payload);
    let mut policy_hash = None;
    for _ in 0..decoder
        .map()
        .expect("payload map")
        .expect("definite payload map")
    {
        if decoder.u8().expect("payload label") == 7 {
            policy_hash = Some(decoder.bytes().expect("policy hash"));
        } else {
            decoder.skip().expect("skip payload value");
        }
    }
    assert_eq!(policy_hash.expect("v2 policy hash").len(), 48);

    let public_bytes = payload
        .public_key
        .get(..usize::from(payload.public_key_size))
        .expect("bounded COSE public-key size");
    let mut decoder = minicbor::Decoder::new(public_bytes);
    let entries = decoder
        .map()
        .expect("COSE key map")
        .expect("definite COSE key");
    let (mut kty, mut curve_id, mut first, mut second) = (None, None, None, None);
    for _ in 0..entries {
        match decoder.i64().expect("COSE key label") {
            1 => kty = Some(decoder.u8().expect("COSE key type")),
            -1 if matches!(key.public, PublicKey::Ecc { .. }) => {
                curve_id = Some(decoder.u8().expect("COSE curve"));
            }
            -1 => first = Some(decoder.bytes().expect("RSA modulus")),
            -2 if matches!(key.public, PublicKey::Ecc { .. }) => {
                first = Some(decoder.bytes().expect("ECC X"));
            }
            -2 | -3 => second = Some(decoder.bytes().expect("public-key component")),
            _ => decoder.skip().expect("skip COSE key entry"),
        }
    }
    let first = first.expect("first public-key component");
    let second = second.expect("second public-key component");
    match &key.public {
        PublicKey::Ecc { curve, wire } => {
            assert_eq!(kty, Some(2));
            assert_eq!(curve_id, Some(curve.to_tbor()));
            let (wire_len, raw_len) = coord_sizes(wire.len());
            assert_eq!(first.len(), raw_len);
            assert_eq!(second.len(), raw_len);
            for (be, le) in [first, second].into_iter().zip(wire.chunks_exact(wire_len)) {
                assert!(be.iter().rev().eq(le[..raw_len].iter()));
                assert!(le[raw_len..].iter().all(|&b| b == 0));
            }
        }
        PublicKey::Rsa { n, e } => {
            assert_eq!(kty, Some(3));
            assert_eq!(first, n);
            assert_eq!(unpad_integer(second), unpad_integer(e));
        }
        PublicKey::Symmetric => panic!("symmetric key cannot have a report"),
    }
}

/// Authenticate deliberately incorrect semantic content with a valid AEAD tag.
fn semantic_auth(
    session: &SessionHandshake,
    request: &TborKeyReportReq,
    wrong_aad: bool,
) -> Vec<u8> {
    let mut data = request.masked_key.clone();
    data.extend_from_slice(&request.report_data);
    let mut digest = [0; 48];
    HashAlgo::sha384()
        .hash(&data, Some(&mut digest))
        .expect("request digest");
    let mut aad = build_key_report_auth_aad(request.session_id);
    if wrong_aad {
        aad[0] ^= 1;
    } else {
        digest[0] ^= 1;
    }
    let iv = Rng::rand_vec(aead_envelope::AeadAlg::AesGcm256.iv_len()).expect("auth IV");
    common::seal_aead_envelope(&session.param_key, &iv, &aad, &digest)
}

/// Execute one isolated scenario on freshly reset state, retaining a valid retry.
fn run_case(ctx: &TestCtx, path: &str, input: &FuzzInput) {
    let scenario = input.scenario;
    let cu = match scenario {
        Scenario::CoEmptyAuth | Scenario::CoAuthenticated | Scenario::InvalidCoAuth => false,
        Scenario::CuAuthenticated
        | Scenario::MissingCuAuth
        | Scenario::StaleCredential
        | Scenario::WrongParamKey
        | Scenario::ReplayAuth
        | Scenario::WrongMaskingSession => true,
        _ => input.cu,
    };
    let (psk_id, session_type, psk) = if cu {
        (CU_PSK_ID, SessionType::PlainText, &ROTATED_CU_PSK)
    } else {
        (CO_PSK_ID, SessionType::Authenticated, &ROTATED_CO_PSK)
    };
    if scenario == Scenario::DefaultPsk {
        let session = ctx
            .open_session(psk_id, session_type)
            .expect("default-PSK session");
        let req = TborKeyReportReq {
            session_id: session.session_id(),
            masked_key: Vec::new(),
            report_data: input.report_data,
            auth_envelope: Vec::new(),
        };
        check_result(
            ctx.tbor(&req),
            Expected::Status(TborStatus::DefaultPskMustRotate),
        );
        session.close().expect("close default-PSK session");
        return;
    }
    let co = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let co_id = co.session_id;
    let scope = if scenario == Scenario::WrongMaskingSession {
        common::KEY_SCOPE_SESSION
    } else if scenario == Scenario::StaleCredential {
        common::KEY_SCOPE_LOCAL
    } else {
        [
            common::KeyScope::Ephemeral,
            common::KeyScope::Local,
            common::KeyScope::Session,
            common::KeyScope::SecurityDomain,
        ][usize::from(input.scope % 4)]
        .to_tbor()
    };
    if scenario != Scenario::Unfinalized {
        if scope == common::KEY_SCOPE_SECURITY_DOMAIN {
            common::create_test_security_domain(ctx, &co);
        } else {
            common::finalize_partition(ctx, &co);
        }
    }
    let secondary = cu.then(|| TestCtx::new_with_path(path));
    let caller = secondary.as_ref().unwrap_or(ctx);
    let mut session = if cu {
        bootstrap_rotated_cu(caller, &ROTATED_CU_PSK)
    } else {
        co
    };
    let mut req = TborKeyReportReq {
        session_id: session.session_id,
        masked_key: Vec::new(),
        report_data: input.report_data,
        auth_envelope: Vec::new(),
    };
    if scenario == Scenario::Unfinalized {
        req.auth_envelope = seal_key_report_auth(&session.param_key, &req).expect("authenticate");
        check_result(caller.tbor(&req), Expected::Status(TborStatus::InvalidArg));
        caller
            .session_close(session.session_id)
            .expect("close unfinalized session");
        if cu {
            ctx.session_close(co_id).expect("close setup CO");
        }
        return;
    }
    let co_producer = cu
        && input.source % 5 == 1
        && scope != common::KEY_SCOPE_SESSION
        && !matches!(
            scenario,
            Scenario::Symmetric | Scenario::WrongMaskingSession
        );
    let key = make_key(
        if co_producer { ctx } else { caller },
        if co_producer {
            co_id
        } else {
            session.session_id
        },
        scope,
        input,
    );
    req.masked_key = key.masked.clone();
    req.auth_envelope = seal_key_report_auth(&session.param_key, &req).expect("authenticate");
    let original = req.clone();
    let mut expected = Expected::Success;
    let mut closed = false;
    let mut extra = None;

    match scenario {
        Scenario::CoEmptyAuth => req.auth_envelope.clear(),
        Scenario::ArbitrarySession => {
            req.session_id = input.session_id;
            if req.session_id != session.session_id {
                expected = Expected::Status(TborStatus::FileHandleSessionIdDoesNotMatch);
            }
        }
        Scenario::ClosedSession => {
            caller
                .session_close(session.session_id)
                .expect("close before request");
            closed = true;
            expected = Expected::Status(TborStatus::SessionNotFound);
        }
        Scenario::StaleCredential => {
            let other = TestCtx::new_with_path(path);
            let pending = other
                .session_open_init_with_options(
                    SessionOpenInitOptions::new(psk_id, session_type).with_psk(psk),
                )
                .expect("credential-rotation session init");
            let current = other
                .session_open_finish(pending)
                .expect("credential-rotation session");
            let mut next_psk = *psk;
            next_psk[0] ^= 1;
            other
                .psk_change(&current, &next_psk)
                .expect("rotate current credential");
            other
                .session_close(current.session_id)
                .expect("close rotation session");
            let pending = other
                .session_open_init_with_options(
                    SessionOpenInitOptions::new(psk_id, session_type).with_psk(&next_psk),
                )
                .expect("fresh credential session init");
            let fresh = other
                .session_open_finish(pending)
                .expect("fresh credential session");
            let mut fresh_req = req.clone();
            fresh_req.session_id = fresh.session_id;
            fresh_req.auth_envelope = seal_key_report_auth(&fresh.param_key, &fresh_req)
                .expect("authenticate fresh credential");
            let response = check_result(other.tbor(&fresh_req), Expected::Success)
                .expect("fresh credential remains valid");
            verify_report(ctx, &response, &fresh_req, &key, &next_psk[..16]);
            other
                .session_close(fresh.session_id)
                .expect("close fresh session");
            expected = Expected::Status(TborStatus::SessionAuthFailure);
        }
        Scenario::Symmetric => expected = Expected::Status(TborStatus::UnsupportedKeyType),
        Scenario::RawKey | Scenario::KeyBoundary | Scenario::KeyMutation => {
            if scenario == Scenario::RawKey {
                req.masked_key = input.bytes.clone();
            } else if scenario == Scenario::KeyBoundary {
                let lengths = [
                    0,
                    1,
                    KEY_REPORT_MASKED_KEY_MAX_LEN - 1,
                    KEY_REPORT_MASKED_KEY_MAX_LEN,
                    KEY_REPORT_MASKED_KEY_MAX_LEN + 1,
                ];
                req.masked_key
                    .resize(lengths[usize::from(input.size) % lengths.len()], 0);
            } else {
                let mutation = input.envelope_mutation();
                let noop = mutation.is_noop(&req.masked_key);
                mutation.apply(&mut req.masked_key);
                assert_eq!(noop, req.masked_key == original.masked_key);
            }
            expected = key_outcome(&req.masked_key, &original.masked_key);
            req.auth_envelope =
                seal_key_report_auth(&session.param_key, &req).expect("authenticate mutated key");
        }
        Scenario::KeyHeader
        | Scenario::KeyIv
        | Scenario::KeyMetadata
        | Scenario::KeyCiphertext
        | Scenario::KeyTag
        | Scenario::UnsupportedScope => {
            let aad_offset = aead_envelope::HEADER_LEN + aead_envelope::AeadAlg::AesGcm256.iv_len();
            let payload_offset = req.masked_key.len()
                - aead_envelope::AeadAlg::AesGcm256.tag_len()
                - aead_envelope::inspect(&req.masked_key)
                    .expect("generated envelope")
                    .payload
                    .len();
            let (offset, status) = match scenario {
                Scenario::KeyHeader => (0, TborStatus::InvalidArg),
                Scenario::KeyIv => (
                    aead_envelope::HEADER_LEN + usize::from(input.offset) % GCM_NONCE_LEN,
                    TborStatus::AesGcmDecryptTagDoesNotMatch,
                ),
                Scenario::KeyMetadata => (
                    aad_offset + 16 + usize::from(input.offset) % 10,
                    TborStatus::AesGcmDecryptTagDoesNotMatch,
                ),
                Scenario::KeyCiphertext => {
                    (payload_offset, TborStatus::AesGcmDecryptTagDoesNotMatch)
                }
                Scenario::KeyTag => (
                    req.masked_key.len() - 1,
                    TborStatus::AesGcmDecryptTagDoesNotMatch,
                ),
                Scenario::UnsupportedScope => (aad_offset + 10, TborStatus::UnsupportedKeyScope),
                _ => unreachable!(),
            };
            if scenario == Scenario::UnsupportedScope {
                // Scope occupies usage_flags bits 17..19; preserve all other metadata.
                req.masked_key[offset] =
                    (req.masked_key[offset] & !0x0E) | (common::KEY_SCOPE_INTERNAL << 1);
            } else {
                req.masked_key[offset] ^= input.mask | 1;
            }
            req.auth_envelope =
                seal_key_report_auth(&session.param_key, &req).expect("authenticate corrupted key");
            expected = Expected::Status(status);
        }
        Scenario::MissingCuAuth => {
            req.auth_envelope.clear();
            expected = Expected::Status(TborStatus::AeadEnvelopeAuthFailed);
        }
        Scenario::InvalidCoAuth
        | Scenario::RawAuth
        | Scenario::AuthBoundary
        | Scenario::AuthMutation => {
            match scenario {
                Scenario::InvalidCoAuth => req.auth_envelope = vec![input.mask],
                Scenario::RawAuth => {
                    req.auth_envelope =
                        input.bytes[..input.bytes.len().min(AUTH_MAX_LEN + 1)].to_vec()
                }
                Scenario::AuthBoundary => {
                    let lengths = [
                        0,
                        1,
                        KEY_REPORT_AUTH_ENVELOPE_LEN - 1,
                        KEY_REPORT_AUTH_ENVELOPE_LEN,
                        KEY_REPORT_AUTH_ENVELOPE_LEN + 1,
                        AUTH_MAX_LEN - 1,
                        AUTH_MAX_LEN,
                        AUTH_MAX_LEN + 1,
                    ];
                    req.auth_envelope
                        .resize(lengths[usize::from(input.size) % lengths.len()], 0);
                }
                _ => {
                    let mutation = input.envelope_mutation();
                    let noop = mutation.is_noop(&req.auth_envelope);
                    mutation.apply(&mut req.auth_envelope);
                    assert_eq!(noop, req.auth_envelope == original.auth_envelope);
                }
            }
            expected = if req.auth_envelope.len() > AUTH_MAX_LEN {
                Expected::Status(TborStatus::TborInvalidFixedLength)
            } else if (!cu && req.auth_envelope.is_empty())
                || same_envelope(&req.auth_envelope, &original.auth_envelope)
            {
                Expected::Success
            } else {
                Expected::Status(TborStatus::AeadEnvelopeAuthFailed)
            };
        }
        Scenario::WrongDigest | Scenario::WrongAad => {
            req.auth_envelope = semantic_auth(&session, &req, scenario == Scenario::WrongAad);
            expected = Expected::Status(TborStatus::AeadEnvelopeAuthFailed);
        }
        Scenario::ChangedReportData | Scenario::ChangedMaskedKey => {
            if scenario == Scenario::ChangedReportData {
                req.report_data[usize::from(input.offset) % KEY_REPORT_DATA_LEN] ^= input.mask | 1;
            } else {
                let index = usize::from(input.offset) % req.masked_key.len();
                req.masked_key[index] ^= input.mask | 1;
            }
            expected = Expected::Status(TborStatus::AeadEnvelopeAuthFailed);
        }
        Scenario::WrongParamKey | Scenario::ReplayAuth | Scenario::WrongMaskingSession => {
            let other = TestCtx::new_with_path(path);
            let pending = other
                .session_open_init_with_options(
                    SessionOpenInitOptions::new(psk_id, session_type).with_psk(psk),
                )
                .expect("second session init");
            let other_session = other
                .session_open_finish(pending)
                .expect("second session finish");
            if scenario == Scenario::WrongParamKey {
                req.auth_envelope = seal_key_report_auth(&other_session.param_key, &req)
                    .expect("wrong-key authentication");
                other
                    .session_close(other_session.session_id)
                    .expect("close wrong-key session");
                expected = Expected::Status(TborStatus::AeadEnvelopeAuthFailed);
            } else {
                req.session_id = other_session.session_id;
                if scenario == Scenario::WrongMaskingSession {
                    req.auth_envelope = seal_key_report_auth(&other_session.param_key, &req)
                        .expect("authenticate wrong masking session");
                    expected = Expected::Status(TborStatus::AesGcmDecryptTagDoesNotMatch);
                } else {
                    expected = Expected::Status(TborStatus::AeadEnvelopeAuthFailed);
                }
                session = other_session;
                extra = Some(other);
            }
        }
        _ => {}
    }
    let request_ctx = extra.as_ref().unwrap_or(caller);
    if let Some(response) = check_result(request_ctx.tbor(&req), expected) {
        verify_report(ctx, &response, &req, &key, &psk[..16]);
    }
    if !matches!(expected, Expected::Success)
        && !closed
        && !matches!(scenario, Scenario::StaleCredential | Scenario::Symmetric)
    {
        let response =
            check_result(caller.tbor(&original), Expected::Success).expect("valid retry");
        verify_report(ctx, &response, &original, &key, &psk[..16]);
    }
    if !closed {
        request_ctx
            .session_close(session.session_id)
            .expect("close calling session");
    }
    if extra.is_some() {
        caller
            .session_close(original.session_id)
            .expect("close original session");
    }
    if cu {
        ctx.session_close(co_id).expect("close setup CO");
    }
}

libfuzzer_sys::fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx, path| run_case(ctx, path, &input));
});
