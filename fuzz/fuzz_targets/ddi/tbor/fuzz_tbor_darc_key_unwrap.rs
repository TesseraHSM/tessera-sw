// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Semantic DARC key import fuzzing through the real TBOR transport.
//! Valid imports reach EC consistency checking and output masking; isolated
//! envelope, KWP, and COSE mutations retain the preceding cryptographic layers.
//! An input/fixture-derived oracle checks exact rejection statuses and public
//! response semantics. Typed requests do not fuzz malformed TBOR framing.

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

/// Six independent success lanes keep deep coverage frequent.
#[derive(Clone, Copy, Debug)]
enum Scenario {
    Sign,
    Verify,
    DeriveKey,
    DeriveBits,
    PartialSignAndDerive,
    FilteredGroups,
    ArbitrarySession,
    ClosedSession,
    CryptoUser,
    Unfinalized,
    NoSecurityDomain,
    ArbitraryScope,
    ArbitraryUsage,
    MaskedTmkFlip,
    RawMaskedTmk,
    WrappedFlip,
    WrappedLength,
    RawWrapped,
    Cose,
    WrongKind,
    ArbitraryAlgorithm,
    WrappedTruncate,
    WrappedAppend,
    MismatchedSession,
}

/// Compact controls precede optional bytes; even empty inputs select a valid
/// P-256 signing import. Optional bytes vary the TMK, key ID, and raw payloads.
#[derive(Debug)]
struct FuzzInput<'a> {
    scenario: Scenario,
    curve: common::EccCurve,
    scope: u8,
    controls: u8,
    session_id: u16,
    usage: u64,
    scalar: u64,
    offset: u16,
    mask: u8,
    alg: i32,
    extra: &'a [u8],
}

impl<'a> Arbitrary<'a> for FuzzInput<'a> {
    /// Decode fixed-width controls with zero defaults for missing bytes.
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let scenario = match u.arbitrary::<u8>()? % 24 {
            0 => Scenario::Sign,
            1 => Scenario::Verify,
            2 => Scenario::DeriveKey,
            3 => Scenario::DeriveBits,
            4 => Scenario::PartialSignAndDerive,
            5 => Scenario::FilteredGroups,
            6 => Scenario::ArbitrarySession,
            7 => Scenario::ClosedSession,
            8 => Scenario::CryptoUser,
            9 => Scenario::Unfinalized,
            10 => Scenario::NoSecurityDomain,
            11 => Scenario::ArbitraryScope,
            12 => Scenario::ArbitraryUsage,
            13 => Scenario::MaskedTmkFlip,
            14 => Scenario::RawMaskedTmk,
            15 => Scenario::WrappedFlip,
            16 => Scenario::WrappedLength,
            17 => Scenario::RawWrapped,
            18 => Scenario::Cose,
            19 => Scenario::WrongKind,
            20 => Scenario::ArbitraryAlgorithm,
            21 => Scenario::WrappedTruncate,
            22 => Scenario::WrappedAppend,
            _ => Scenario::MismatchedSession,
        };
        let curve = match u.arbitrary::<u8>()? % 3 {
            0 => common::EccCurve::P256,
            1 => common::EccCurve::P384,
            _ => common::EccCurve::P521,
        };
        Ok(Self {
            scenario,
            curve,
            scope: u.arbitrary()?,
            controls: u.arbitrary()?,
            session_id: u.arbitrary()?,
            usage: u.arbitrary()?,
            scalar: u.arbitrary()?,
            offset: u.arbitrary()?,
            mask: u.arbitrary()?,
            alg: u.arbitrary()?,
            extra: u.bytes(u.len())?,
        })
    }
}

/// Mutations stay inside a valid KWP wrapper, including width-correct EC
/// inconsistencies which reach beyond the COSE parser.
#[derive(Clone, Copy)]
enum CoseMutation {
    None,
    Missing,
    Duplicate,
    Unknown,
    WrongType,
    Truncate,
    IndefiniteMap,
    Trailing,
    WrongKty,
    WrongCurve,
    DeprecatedAlgorithm,
    EmptyOps,
    DuplicateOp,
    InvalidOp,
    IndefiniteOps,
    WrongWidth,
    MismatchX,
    MismatchY,
    MismatchScalar,
}

impl CoseMutation {
    /// Select a deliberate violation without making other fields invalid.
    fn from_byte(value: u8) -> Self {
        match value % 19 {
            0 => Self::None,
            1 => Self::Missing,
            2 => Self::Duplicate,
            3 => Self::Unknown,
            4 => Self::WrongType,
            5 => Self::Truncate,
            6 => Self::IndefiniteMap,
            7 => Self::Trailing,
            8 => Self::WrongKty,
            9 => Self::WrongCurve,
            10 => Self::DeprecatedAlgorithm,
            11 => Self::EmptyOps,
            12 => Self::DuplicateOp,
            13 => Self::InvalidOp,
            14 => Self::IndefiniteOps,
            15 => Self::WrongWidth,
            16 => Self::MismatchX,
            17 => Self::MismatchY,
            _ => Self::MismatchScalar,
        }
    }
}

/// Independent predictions distinguish host encoding errors from FW errors.
#[derive(Clone, Copy, Debug)]
enum Expected {
    Success,
    Reject(TborStatus),
}

/// Big-endian field elements and independently computed wire public key.
struct HostKey {
    curve: common::EccCurve,
    d: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
    wire_pub: Vec<u8>,
}

impl HostKey {
    /// Import a nonzero, at-most-64-bit scalar, below every supported order.
    fn new(curve: common::EccCurve, seed: u64) -> Self {
        let mut d = vec![0; curve.coord_len()];
        let end = d.len();
        d[end - 8..].copy_from_slice(&seed.max(1).to_be_bytes());
        let host_curve = match curve {
            common::EccCurve::P256 => tsra_crypto::EccCurve::P256,
            common::EccCurve::P384 => tsra_crypto::EccCurve::P384,
            common::EccCurve::P521 => tsra_crypto::EccCurve::P521,
        };
        let key = EccPrivateKey::from_scalar(host_curve, &d).expect("bounded scalar");
        let (x, y) = key.coord_vec().expect("public coordinates");
        let mut wire_pub = Vec::with_capacity(curve.wire_pub_key_len());
        for coordinate in [&x, &y] {
            let mut le = coordinate.clone();
            le.reverse();
            le.resize(curve.wire_pub_key_len() / 2, 0);
            wire_pub.extend_from_slice(&le);
        }
        Self {
            curve,
            d,
            x,
            y,
            wire_pub,
        }
    }

    /// Return the exact private-key kind expected for the selected curve.
    fn kind(&self) -> u8 {
        match self.curve {
            common::EccCurve::P256 => KEY_KIND_ECC256_PRIVATE,
            common::EccCurve::P384 => KEY_KIND_ECC384_PRIVATE,
            common::EccCurve::P521 => KEY_KIND_ECC521_PRIVATE,
        }
    }
}

/// Derive varied test-only key bytes without an external random dependency.
fn tmk_bytes(input: &FuzzInput<'_>) -> [u8; TMK_LEN] {
    core::array::from_fn(|i| {
        input.scalar.rotate_left(i as u32) as u8 ^ input.extra.get(i).copied().unwrap_or(i as u8)
    })
}

/// Recover a host-known TMK through the real POTA-authenticated import flow.
fn import_tmk(
    ctx: &TestCtx,
    session_id: u16,
    fixture: common::SecurityDomainFixture,
    tmk: &[u8; TMK_LEN],
) -> [u8; MASKED_TMK_LEN] {
    let kex = ctx
        .tbor(&TborDarcKexKeyGenReq {
            session_id,
            scope: common::KEY_SCOPE_LOCAL,
        })
        .expect("DarcKexKeyGen");
    let mut recipient_be = kex.pub_key;
    recipient_be[..common::COORD_LEN].reverse();
    recipient_be[common::COORD_LEN..].reverse();
    let recipient = EccPublicKey::from_hsm_bytes(&recipient_be).expect("recipient public key");
    let sender = EccPrivateKey::from_curve(tsra_crypto::EccCurve::P384).expect("sender key");
    let (x, y) = sender.coord_vec().expect("sender public coordinates");
    let mut sender_pub = [0; RAW_PUB_LEN];
    sender_pub[..common::COORD_LEN].copy_from_slice(&x);
    sender_pub[common::COORD_LEN..].copy_from_slice(&y);
    let chain = make_chain(&fixture.pota, &sender_pub);
    let sealed = seal_vec(
        &HpkeSealConfig::auth(
            HpkeSuite::DHKemP384Sha384AesGcm256,
            &recipient,
            &[],
            &[],
            &sender,
        ),
        tmk,
    )
    .expect("seal known TMK");
    let (ex, ey) = sealed
        .enc
        .coord_vec()
        .expect("encapsulated public coordinates");
    let mut sealed_tmk = [0; SEALED_TMK_LEN];
    sealed_tmk[0] = 4;
    sealed_tmk[1..1 + common::COORD_LEN].copy_from_slice(&ex);
    sealed_tmk[1 + common::COORD_LEN..SEC1_PUB_LEN].copy_from_slice(&ey);
    sealed_tmk[SEC1_PUB_LEN..].copy_from_slice(&sealed.ct);
    let mut evidence = Vec::new();
    let remote_cert_chain = chain
        .der_items()
        .iter()
        .map(|der| common::add_evidence_item(&mut evidence, der))
        .collect();
    let oob = evidence.iter().map(Vec::as_slice).collect::<Vec<_>>();
    ctx.tbor_oob(
        &TborDarcTmkImportReq {
            session_id,
            masked_kex_key: kex.masked_key,
            policy: fixture.policy,
            sealed_tmk,
            remote_cert_chain,
        },
        &oob,
    )
    .expect("import known TMK")
    .masked_tmk
    .try_into()
    .expect("TMK envelope length")
}

/// Choose granted operations and requested permissions independently of FW.
fn permissions(input: &FuzzInput<'_>) -> (Vec<u8>, u64) {
    let signing = KEY_USAGE_SIGN | KEY_USAGE_VERIFY;
    match input.scenario {
        Scenario::Verify => (vec![2], signing),
        Scenario::DeriveKey => (vec![7], KEY_USAGE_DERIVE),
        Scenario::DeriveBits => (vec![8], KEY_USAGE_DERIVE),
        Scenario::PartialSignAndDerive => (vec![1, 8], KEY_USAGE_SIGN | KEY_USAGE_DERIVE),
        Scenario::FilteredGroups => (vec![1, 2, 3], signing | KEY_USAGE_DERIVE | input.usage & !7),
        Scenario::ArbitraryUsage => {
            let ops = match input.controls % 10 {
                0 => vec![1],
                1 => vec![2],
                2 => vec![1, 2],
                3 => vec![7],
                4 => vec![8],
                5 => vec![7, 8],
                6 => vec![1, 7],
                7 => vec![2, 8],
                8 => vec![3, 4, 5, 6, 9, 10],
                _ => vec![1, 2, 7, 8],
            };
            let usage = match input.mask % 8 {
                0 => input.usage,
                1 => 0,
                2 => KEY_USAGE_SIGN,
                3 => KEY_USAGE_VERIFY,
                4 => KEY_USAGE_DERIVE,
                5 => signing,
                6 => signing | KEY_USAGE_DERIVE,
                _ => KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT | KEY_USAGE_WRAP | KEY_USAGE_UNWRAP,
            };
            (ops, usage)
        }
        _ => (vec![1], signing),
    }
}

/// Apply the two effective-usage groups; unrelated bits are intersected away.
fn valid_permissions(ops: &[u8], requested: u64) -> bool {
    let mut allowed = 0;
    if ops.contains(&1) || ops.contains(&2) {
        allowed |= KEY_USAGE_SIGN | KEY_USAGE_VERIFY;
    }
    if ops.contains(&7) || ops.contains(&8) {
        allowed |= KEY_USAGE_DERIVE;
    }
    let effective = requested & allowed;
    let signing =
        effective & (KEY_USAGE_SIGN | KEY_USAGE_VERIFY) == KEY_USAGE_SIGN | KEY_USAGE_VERIFY;
    signing ^ (effective & KEY_USAGE_DERIVE != 0)
}

/// Encode valid or deliberately malformed COSE without using the FW parser.
fn encode_cose(
    key: &HostKey,
    input: &FuzzInput<'_>,
    ops: &[u8],
    mutation: CoseMutation,
) -> Vec<u8> {
    let mut fields = Vec::new();
    let labels = [1, 2, 3, 4, -1, -2, -3, -4];
    let selected = input.offset as usize % labels.len();
    for (index, label) in labels.into_iter().enumerate() {
        if matches!(mutation, CoseMutation::Missing) && index == selected {
            continue;
        }
        let mut enc = minicbor::Encoder::new(Vec::new());
        enc.i32(
            if matches!(mutation, CoseMutation::Unknown) && index == selected {
                99
            } else {
                label
            },
        )
        .expect("COSE label");
        if matches!(mutation, CoseMutation::WrongType) && index == selected {
            enc.bool(false).expect("wrong field type");
        } else {
            match label {
                1 => {
                    enc.u8(if matches!(mutation, CoseMutation::WrongKty) {
                        1
                    } else {
                        2
                    })
                    .expect("kty");
                }
                2 => {
                    enc.bytes(&input.extra[..input.extra.len().min(64)])
                        .expect("kid");
                }
                3 => {
                    let alg = if matches!(mutation, CoseMutation::DeprecatedAlgorithm) {
                        [-7, -35, -36][input.mask as usize % 3]
                    } else if matches!(input.scenario, Scenario::ArbitraryAlgorithm) {
                        input.alg
                    } else {
                        match key.curve {
                            common::EccCurve::P256 => -9,
                            common::EccCurve::P384 => -51,
                            common::EccCurve::P521 => -52,
                        }
                    };
                    enc.i32(alg).expect("algorithm");
                }
                4 => {
                    let mut values = ops.to_vec();
                    match mutation {
                        CoseMutation::EmptyOps => values.clear(),
                        CoseMutation::DuplicateOp => values.push(ops[0]),
                        CoseMutation::InvalidOp => values.push(if input.mask & 1 == 0 {
                            0
                        } else {
                            11 + input.mask % 245
                        }),
                        _ => {}
                    }
                    if matches!(mutation, CoseMutation::IndefiniteOps) {
                        enc.begin_array().expect("indefinite operations");
                    } else {
                        enc.array(values.len() as u64).expect("operations");
                    }
                    for op in values {
                        enc.u8(op).expect("operation");
                    }
                    if matches!(mutation, CoseMutation::IndefiniteOps) {
                        enc.end().expect("operations end");
                    }
                }
                -1 => {
                    let crv = if matches!(mutation, CoseMutation::WrongCurve) {
                        4
                    } else {
                        match key.curve {
                            common::EccCurve::P256 => 1,
                            common::EccCurve::P384 => 2,
                            common::EccCurve::P521 => 3,
                        }
                    };
                    enc.i32(crv).expect("curve");
                }
                _ => {
                    let mut value = match label {
                        -2 => key.x.clone(),
                        -3 => key.y.clone(),
                        _ => key.d.clone(),
                    };
                    if matches!(
                        (mutation, label),
                        (CoseMutation::MismatchX, -2)
                            | (CoseMutation::MismatchY, -3)
                            | (CoseMutation::MismatchScalar, -4)
                    ) {
                        let last = value.len() - 1;
                        value[last] ^= 0x80;
                    }
                    if matches!(mutation, CoseMutation::WrongWidth) && index == 5 + selected % 3 {
                        if input.mask & 1 == 0 {
                            value.pop();
                        } else {
                            value.push(0);
                        }
                    }
                    enc.bytes(&value).expect("field element");
                }
            }
        }
        let bytes = enc.into_writer();
        fields.push(bytes.clone());
        if matches!(mutation, CoseMutation::Duplicate) && index == selected {
            fields.push(bytes);
        }
    }
    let count = fields.len();
    fields.rotate_left(input.controls as usize % count);
    if input.controls & 0x80 != 0 {
        fields.reverse();
    }
    let mut enc = minicbor::Encoder::new(Vec::new());
    if matches!(mutation, CoseMutation::IndefiniteMap) {
        enc.begin_map().expect("indefinite map");
    } else {
        enc.map(count as u64).expect("COSE map");
    }
    let mut bytes = enc.into_writer();
    for field in fields {
        bytes.extend_from_slice(&field);
    }
    match mutation {
        CoseMutation::IndefiniteMap => bytes.push(0xff),
        CoseMutation::Trailing => bytes.push(input.mask),
        CoseMutation::Truncate => {
            bytes.pop();
        }
        _ => {}
    }
    bytes
}

/// AES-KWP-wrap bounded plaintext under the exact TMK imported by the fixture.
fn wrap(tmk: &[u8; TMK_LEN], plaintext: &[u8]) -> Vec<u8> {
    let key = AesKey::from_bytes(tmk).expect("TMK AES key");
    Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &key, plaintext).expect("wrap COSE")
}

/// Predict a single-byte envelope mutation, including ignored IV suffix bytes.
///
/// The public host inspector supplies envelope framing. The small metadata
/// checks below describe the wire format, not a call to the handler's decoder.
fn masked_tmk_outcome(original: &[u8], changed: &[u8]) -> Expected {
    let Ok(env) = aead_envelope::inspect(changed) else {
        return Expected::Reject(TborStatus::InvalidArg);
    };
    let aad = env.aad;
    if aad.len() != 192 || !env.payload.len().is_multiple_of(16) {
        return Expected::Reject(TborStatus::MaskedKeyDecodeFailed);
    }
    let label_len = aad[7] as usize;
    if &aad[..4] != b"MKEY"
        || aad[4..6] != [1, 0]
        || label_len > 128
        || aad[154] > 15
        || aad[155..].iter().any(|b| *b != 0)
        || aad[26 + label_len..154].iter().any(|b| *b != 0)
    {
        return Expected::Reject(TborStatus::MaskedKeyDecodeFailed);
    }
    let attrs = u64::from_le_bytes(aad[8..16].try_into().expect("usage flags"));
    let scope = ((attrs >> 17) & 7) as u8;
    if !matches!(
        scope,
        common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL | common::KEY_SCOPE_SECURITY_DOMAIN
    ) {
        return Expected::Reject(TborStatus::UnsupportedKeyScope);
    }
    let baseline = aead_envelope::inspect(original).expect("real TMK envelope");
    if env.iv[..12] == baseline.iv[..12]
        && aad == baseline.aad
        && env.payload == baseline.payload
        && env.tag == baseline.tag
    {
        Expected::Success
    } else {
        Expected::Reject(TborStatus::AesGcmDecryptTagDoesNotMatch)
    }
}

/// Verify public material and cleartext output framing, without trusting the
/// returned metadata as authenticated or exposing secret bytes in diagnostics.
fn assert_success(resp: &TborDarcKeyUnwrapResp, key: &HostKey, scope: u8) {
    assert_eq!(resp.key_kind, key.kind(), "recovered key kind");
    assert_eq!(resp.pub_key.len(), key.curve.wire_pub_key_len());
    assert!(
        resp.pub_key == key.wire_pub,
        "recovered public key mismatch"
    );
    assert!(!resp.masked_key.is_empty());
    assert!(resp.masked_key.len() <= DARC_UNWRAP_MASKED_KEY_MAX_LEN);
    let env = aead_envelope::inspect(&resp.masked_key).expect("output envelope framing");
    assert_eq!(env.aad.len(), 192);
    assert_eq!(env.payload.len(), key.curve.coord_len().div_ceil(16) * 16);
    assert_eq!(env.aad[6], key.kind());
    let attrs = u64::from_le_bytes(env.aad[8..16].try_into().expect("output usage flags"));
    assert_eq!(((attrs >> 17) & 7) as u8, scope);
    let label_len = env.aad[7] as usize;
    assert_eq!(
        env.aad.get(26..26 + label_len),
        Some(b"DarcKeyUnwrap".as_slice())
    );
}

/// Compare the observed result with the prediction made before submission.
fn check(ctx: &TestCtx, req: &TborDarcKeyUnwrapReq, expected: Expected, key: &HostKey) {
    match expected {
        Expected::Success => {
            let resp = ctx.tbor(req).expect("valid DarcKeyUnwrap must succeed");
            assert_success(&resp, key, req.scope);
        }
        Expected::Reject(status) => {
            let err = ctx.tbor(req).expect_err("invalid DarcKeyUnwrap must fail");
            assert_session_rejects(&err, status);
        }
    }
}

/// Execute one isolated scenario, avoiding expensive provisioning at early gates.
fn run(ctx: &TestCtx, input: &FuzzInput<'_>) {
    let cu = matches!(input.scenario, Scenario::CryptoUser);
    let session = if cu {
        bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK)
    } else {
        bootstrap_rotated_co(ctx, &ROTATED_CO_PSK)
    };
    let active_id = session.session_id;
    let mut session = Some(SessionGuard::new(ctx, session));
    let scope = if input.scope & 1 == 0 {
        common::KEY_SCOPE_LOCAL
    } else {
        common::KEY_SCOPE_EPHEMERAL
    };
    let key = HostKey::new(input.curve, input.scalar);
    let (ops, usage) = permissions(input);
    let mut req = TborDarcKeyUnwrapReq {
        session_id: active_id,
        scope,
        key_usage: usage,
        masked_tmk: [0; MASKED_TMK_LEN],
        wrapped_key: vec![0; 24],
    };
    let early = match input.scenario {
        Scenario::CryptoUser => Some(TborStatus::InvalidPermissions),
        Scenario::Unfinalized => Some(TborStatus::InvalidArg),
        Scenario::NoSecurityDomain => {
            common::finalize_partition(ctx, session.as_ref().expect("session").handshake());
            Some(TborStatus::InvalidArg)
        }
        Scenario::ClosedSession => {
            session
                .take()
                .expect("session")
                .close()
                .expect("close before request");
            Some(TborStatus::SessionNotFound)
        }
        Scenario::MismatchedSession => {
            req.session_id ^= 1;
            Some(TborStatus::FileHandleSessionIdDoesNotMatch)
        }
        Scenario::ArbitrarySession if input.session_id != active_id => {
            req.session_id = input.session_id;
            Some(TborStatus::FileHandleSessionIdDoesNotMatch)
        }
        _ => None,
    };
    if let Some(status) = early {
        check(ctx, &req, Expected::Reject(status), &key);
    } else {
        let fixture = common::create_test_security_domain_with_policy(
            ctx,
            session.as_ref().expect("session").handshake(),
        );
        let tmk = tmk_bytes(input);
        req.masked_tmk = import_tmk(ctx, active_id, fixture, &tmk);
        let mutation = if matches!(input.scenario, Scenario::Cose) {
            CoseMutation::from_byte(input.controls)
        } else {
            CoseMutation::None
        };
        let cose = encode_cose(&key, input, &ops, mutation);
        req.wrapped_key = wrap(&tmk, &cose);
        let mut expected = if !matches!(mutation, CoseMutation::None)
            || matches!(input.scenario, Scenario::ArbitraryAlgorithm)
                && matches!(input.alg, -7 | -35 | -36)
        {
            Expected::Reject(TborStatus::InvalidArg)
        } else if valid_permissions(&ops, usage) {
            Expected::Success
        } else {
            Expected::Reject(TborStatus::InvalidPermissions)
        };

        match input.scenario {
            Scenario::ArbitraryScope => {
                req.scope = input.scope;
                if !matches!(
                    req.scope,
                    common::KEY_SCOPE_LOCAL | common::KEY_SCOPE_EPHEMERAL
                ) {
                    expected = Expected::Reject(TborStatus::UnsupportedKeyScope);
                }
            }
            Scenario::MaskedTmkFlip => {
                let original = req.masked_tmk;
                let mut changed = original.to_vec();
                common::EnvelopeMutation::FlipByte {
                    offset: input.offset,
                    mask: input.mask,
                }
                .apply(&mut changed);
                expected = masked_tmk_outcome(&original, &changed);
                req.masked_tmk.copy_from_slice(&changed);
            }
            Scenario::RawMaskedTmk => {
                req.masked_tmk = core::array::from_fn(|i| {
                    input.extra.get(i).copied().unwrap_or(tmk[i % TMK_LEN])
                });
                req.masked_tmk[0] = 0; // Guarantee bad magic independently of arbitrary contents.
                expected = Expected::Reject(TborStatus::InvalidArg);
            }
            Scenario::WrappedFlip => {
                common::EnvelopeMutation::FlipByte {
                    offset: input.offset,
                    mask: input.mask,
                }
                .apply(&mut req.wrapped_key);
                if input.mask != 0 {
                    let aes = AesKey::from_bytes(&tmk).expect("TMK");
                    assert!(
                        Decrypter::decrypt_vec(
                            &mut AesKeyWrapPadAlgo::default(),
                            &aes,
                            &req.wrapped_key
                        )
                        .is_err(),
                        "ciphertext mutation must violate KWP integrity"
                    );
                    expected = Expected::Reject(TborStatus::AesUnwrapFailed);
                }
            }
            Scenario::WrappedLength => {
                let lengths = [0, 1, 7, 8, 15, 16, 17, 23, 24, 511, 512, 513];
                let len = lengths[input.offset as usize % lengths.len()];
                req.wrapped_key = if len >= 16 && len % 8 == 0 {
                    // A valid KWP layer whose plaintext is not a CBOR map.
                    wrap(&tmk, &vec![0; len - 8])
                } else {
                    vec![input.mask; len]
                };
                assert_eq!(req.wrapped_key.len(), len);
                expected = if len > DARC_UNWRAP_WRAPPED_KEY_MAX_LEN {
                    Expected::Reject(TborStatus::TborInvalidFixedLength)
                } else {
                    Expected::Reject(TborStatus::InvalidArg)
                };
            }
            Scenario::RawWrapped => {
                req.wrapped_key =
                    input.extra[..input.extra.len().min(DARC_UNWRAP_WRAPPED_KEY_MAX_LEN)].to_vec();
                if req.wrapped_key.len().is_multiple_of(8) {
                    req.wrapped_key.push(input.mask);
                }
                expected = if req.wrapped_key.len() > DARC_UNWRAP_WRAPPED_KEY_MAX_LEN {
                    Expected::Reject(TborStatus::TborInvalidFixedLength)
                } else {
                    Expected::Reject(TborStatus::InvalidArg)
                };
            }
            Scenario::WrappedTruncate => {
                let original_len = req.wrapped_key.len();
                let mut len = input.offset as usize % (original_len + 1);
                if len != original_len && len.is_multiple_of(8) {
                    len += 1;
                }
                req.wrapped_key.truncate(len);
                if len != original_len {
                    expected = Expected::Reject(TborStatus::InvalidArg);
                }
            }
            Scenario::WrappedAppend => {
                let mut len = input.extra.len().min(32);
                if len > 0 && len.is_multiple_of(8) {
                    len -= 1;
                }
                req.wrapped_key.extend_from_slice(&input.extra[..len]);
                if len > 0 {
                    expected = Expected::Reject(TborStatus::InvalidArg);
                }
            }
            Scenario::WrongKind => {
                let donor = HostKey::new(common::EccCurve::P256, input.scalar);
                let donor_req = TborDarcKeyUnwrapReq {
                    wrapped_key: wrap(&tmk, &encode_cose(&donor, input, &ops, CoseMutation::None)),
                    ..req.clone()
                };
                let resp = ctx.tbor(&donor_req).expect("authentic wrong-kind donor");
                assert_success(&resp, &donor, scope);
                req.masked_tmk = resp
                    .masked_key
                    .try_into()
                    .expect("P-256 envelope fits TMK field");
                expected = Expected::Reject(TborStatus::UnsupportedKeyType);
            }
            _ => {}
        }
        check(ctx, &req, expected, &key);
    }
    if let Some(session) = session {
        session.close().expect("close session");
    }
}

fuzz_target!(|input: FuzzInput<'_>| {
    common::common_fuzz_test(&|ctx, _path| run(ctx, &input));
});
