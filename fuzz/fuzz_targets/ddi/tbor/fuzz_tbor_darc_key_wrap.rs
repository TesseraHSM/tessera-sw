// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Semantic DARC key export fuzzing through the real TBOR transport.
//! Dedicated success lanes exercise every curve, usage group, key scope, and
//! label length. Independent predictions check isolated failures and precedence;
//! round trips and host crypto check successful exports. Typed requests do not
//! exercise arbitrary malformed TBOR framing. Authenticated invalid scalars,
//! unusable vault attributes, PAL padding faults, and hardware failures cannot
//! be manufactured by mutating ciphertext and are not claimed as coverage.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::*;
use tsra_crypto::*;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;
use tsra_fw_core_crypto_key_masking::aead::*;

/// Metadata offsets follow the documented v1 masked-key wire layout.
const META_LEN: usize = core::mem::size_of::<MaskedKeyMetadata>();
const META_KIND: usize = 6;
const META_LABEL_LEN: usize = 7;
const META_ATTRS: usize = 8;
const META_LABEL: usize = 26;
const META_PAD: usize = META_LABEL + TBOR_KEY_LABEL_MAX_LEN;
const SCOPE_SHIFT: u32 = 17;
const GCM_NONCE_LEN: usize = 12;

/// A quarter of selector values are explicit successful exports.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Valid,
    HostKnownTmk,
    ArbitrarySession,
    MismatchedSession,
    ClosedSession,
    DefaultPsk,
    CryptoUser,
    Unfinalized,
    NoSecurityDomain,
    TmkFlip,
    KeyFlip,
    RawTmk,
    RawKey,
    WrongTmkKind,
    WrongKeyKind,
    SessionScope,
    KeyLength,
    KeyTruncate,
    KeyAppend,
    TmkMetadata,
    KeyMetadata,
    TmkScope,
    KeyScope,
    PeekBeforeAuthentication,
    EncodeError,
}

/// Eleven optional control bytes precede at most 512 payload bytes.
///
/// Layout: scenario, curve, scope, usage, mutation control, session ID (LE),
/// mutation offset (LE), XOR mask, label length, then payload. Missing bytes
/// default to zero, so even the empty input reaches a valid P-256 export.
struct FuzzInput<'a> {
    scenario: Scenario,
    curve: common::EccCurve,
    scope: u8,
    derive: bool,
    control: u8,
    session_id: u16,
    offset: u16,
    mask: u8,
    label_len: usize,
    extra: &'a [u8],
}

impl<'a> FuzzInput<'a> {
    /// Decode compact controls without rejecting short or empty inputs.
    fn new(data: &'a [u8]) -> Self {
        let byte = |index| data.get(index).copied().unwrap_or(0);
        let scenario = match byte(0) % 32 {
            0..=7 => Scenario::Valid,
            8 => Scenario::HostKnownTmk,
            9 => Scenario::ArbitrarySession,
            10 => Scenario::MismatchedSession,
            11 => Scenario::ClosedSession,
            12 => Scenario::DefaultPsk,
            13 => Scenario::CryptoUser,
            14 => Scenario::Unfinalized,
            15 => Scenario::NoSecurityDomain,
            16 => Scenario::TmkFlip,
            17 => Scenario::KeyFlip,
            18 => Scenario::RawTmk,
            19 => Scenario::RawKey,
            20 => Scenario::WrongTmkKind,
            21 => Scenario::WrongKeyKind,
            22 => Scenario::SessionScope,
            23 => Scenario::KeyLength,
            24 => Scenario::KeyTruncate,
            25 => Scenario::KeyAppend,
            26 => Scenario::TmkMetadata,
            27 => Scenario::KeyMetadata,
            28 => Scenario::TmkScope,
            29 => Scenario::KeyScope,
            30 => Scenario::PeekBeforeAuthentication,
            _ => Scenario::EncodeError,
        };
        Self {
            scenario,
            curve: match byte(1) % 3 {
                0 => common::EccCurve::P256,
                1 => common::EccCurve::P384,
                _ => common::EccCurve::P521,
            },
            scope: [
                common::KEY_SCOPE_LOCAL,
                common::KEY_SCOPE_EPHEMERAL,
                common::KEY_SCOPE_SECURITY_DOMAIN,
            ][byte(2) as usize % 3],
            derive: byte(3) & 1 != 0,
            control: byte(4),
            session_id: u16::from_le_bytes([byte(5), byte(6)]),
            offset: u16::from_le_bytes([byte(7), byte(8)]),
            mask: byte(9),
            label_len: byte(10) as usize % (TBOR_KEY_LABEL_MAX_LEN + 1),
            extra: &data[data.len().min(11)..data.len().min(11 + 512)],
        }
    }

    /// Fill a bounded fixture or raw field with repeatable fuzz-controlled data.
    fn bytes(&self, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                if self.extra.is_empty() {
                    (i as u8) ^ self.mask
                } else {
                    self.extra[i % self.extra.len()]
                }
            })
            .collect()
    }

    /// Request exactly one supported key-generation permission group.
    fn usage(&self) -> u64 {
        if self.derive {
            KEY_USAGE_DERIVE
        } else {
            KEY_USAGE_SIGN
        }
    }
}

/// Predictions distinguish host encoding, firmware rejection, and success.
enum Expected {
    Success,
    Reject(TborStatus),
    EncodeError,
}

/// Independently inspect framing, metadata invariants, and scope routing.
///
/// This deliberately does not call the firmware metadata decoder. Metadata
/// fields are not authenticated yet; the handler peeks both inputs first.
fn peek_status(blob: &[u8]) -> Result<(), TborStatus> {
    let env = aead_envelope::inspect(blob).map_err(|_| TborStatus::InvalidArg)?;
    let aad = env.aad;
    if aad.len() != META_LEN || !env.payload.len().is_multiple_of(16) {
        return Err(TborStatus::MaskedKeyDecodeFailed);
    }
    let label_len = aad[META_LABEL_LEN] as usize;
    if aad[..4] != META_MAGIC
        || aad[4..6] != META_VERSION_V1.to_le_bytes()
        || label_len > TBOR_KEY_LABEL_MAX_LEN
        || aad[META_PAD] > 15
        || aad[META_PAD + 1..].iter().any(|&b| b != 0)
        || aad[META_LABEL + label_len..META_PAD]
            .iter()
            .any(|&b| b != 0)
    {
        return Err(TborStatus::MaskedKeyDecodeFailed);
    }
    let attrs = u64::from_le_bytes(
        aad[META_ATTRS..META_ATTRS + 8]
            .try_into()
            .expect("attributes"),
    );
    let scope = ((attrs >> SCOPE_SHIFT) & 7) as u8;
    if !matches!(
        scope,
        common::KEY_SCOPE_LOCAL | common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_SECURITY_DOMAIN
    ) {
        return Err(TborStatus::UnsupportedKeyScope);
    }
    Ok(())
}

/// Compare authenticated regions with their authentic fixture, ignoring IV suffix.
///
/// A single effective byte mutation cannot authenticate under the fixture key.
/// Length-changing scenarios alter framing or authenticated regions, not merely
/// unused IV bytes. No result from the command under test influences this check.
fn authentication_status(original: &[u8], changed: &[u8]) -> Result<(), TborStatus> {
    let original = aead_envelope::inspect(original).expect("authentic envelope framing");
    let changed = aead_envelope::inspect(changed).expect("peek already validated envelope");
    if changed.iv[..GCM_NONCE_LEN] == original.iv[..GCM_NONCE_LEN]
        && changed.aad == original.aad
        && changed.payload == original.payload
        && changed.tag == original.tag
    {
        Ok(())
    } else {
        Err(TborStatus::AesGcmDecryptTagDoesNotMatch)
    }
}

/// Predict deep-path errors in handler order using only authentic fixture facts.
fn expected_outcome(
    req: &TborDarcKeyWrapReq,
    original_tmk: &[u8],
    original_key: &[u8],
    scenario: Scenario,
) -> Expected {
    if req.masked_key.len() > u16::MAX as usize {
        return Expected::EncodeError;
    }
    if req.masked_key.len() > DARC_WRAP_MASKED_KEY_MAX_LEN {
        return Expected::Reject(TborStatus::TborInvalidFixedLength);
    }
    let prediction = || -> Result<(), TborStatus> {
        peek_status(&req.masked_tmk)?;
        peek_status(&req.masked_key)?;
        authentication_status(original_tmk, &req.masked_tmk)?;
        if scenario == Scenario::WrongTmkKind {
            return Err(TborStatus::UnsupportedKeyType);
        }
        authentication_status(original_key, &req.masked_key)?;
        if scenario == Scenario::WrongKeyKind {
            return Err(TborStatus::UnsupportedKeyType);
        }
        Ok(())
    };
    match prediction() {
        Ok(()) => Expected::Success,
        Err(status) => Expected::Reject(status),
    }
}

/// Mutate a documented metadata member while retaining the surrounding envelope.
fn mutate_metadata(blob: &mut [u8], input: &FuzzInput<'_>, scope_only: bool) {
    let aad_at = aead_envelope::HEADER_LEN
        + aead_envelope::inspect(blob)
            .expect("fixture framing")
            .iv
            .len();
    if scope_only {
        let start = aad_at + META_ATTRS;
        let mut attrs = u64::from_le_bytes(blob[start..start + 8].try_into().expect("attributes"));
        attrs = (attrs & !(7 << SCOPE_SHIFT)) | (u64::from(input.control & 7) << SCOPE_SHIFT);
        blob[start..start + 8].copy_from_slice(&attrs.to_le_bytes());
    } else {
        let offsets = [
            0,
            4,
            META_KIND,
            META_LABEL_LEN,
            META_ATTRS,
            META_LABEL,
            META_PAD,
            META_PAD + 1,
        ];
        let index = aad_at + offsets[input.control as usize % offsets.len()];
        blob[index] ^= input.mask;
    }
}

/// Apply isolated mutations; retain authentic snapshots for the independent oracle.
fn mutate(req: &mut TborDarcKeyWrapReq, input: &FuzzInput<'_>) {
    match input.scenario {
        Scenario::TmkFlip => {
            let mut tmk = req.masked_tmk.to_vec();
            common::EnvelopeMutation::FlipByte {
                offset: input.offset,
                mask: input.mask,
            }
            .apply(&mut tmk);
            req.masked_tmk.copy_from_slice(&tmk);
        }
        Scenario::KeyFlip => {
            common::EnvelopeMutation::FlipByte {
                offset: input.offset,
                mask: input.mask,
            }
            .apply(&mut req.masked_key);
        }
        Scenario::RawTmk => {
            req.masked_tmk.copy_from_slice(&input.bytes(MASKED_TMK_LEN));
            req.masked_tmk[0] = 0;
        }
        Scenario::RawKey => {
            req.masked_key =
                input.bytes(input.offset as usize % (DARC_WRAP_MASKED_KEY_MAX_LEN + 2));
            if let Some(first) = req.masked_key.first_mut() {
                *first = 0;
            }
        }
        Scenario::KeyLength => {
            let overhead = AeadAlg::AesGcm256.envelope_len(0, META_LEN);
            let lengths = [
                0,
                1,
                aead_envelope::HEADER_LEN - 1,
                aead_envelope::HEADER_LEN,
                overhead - 1,
                overhead,
                overhead + 1,
                MASKED_ECC_KEY_MIN_LEN - 1,
                MASKED_ECC_KEY_MIN_LEN,
                MASKED_ECC_KEY_MIN_LEN + 1,
                MASKED_ECC_KEY_MAX_LEN - 1,
                MASKED_ECC_KEY_MAX_LEN,
                DARC_WRAP_MASKED_KEY_MAX_LEN,
                DARC_WRAP_MASKED_KEY_MAX_LEN + 1,
            ];
            req.masked_key
                .resize(lengths[input.control as usize % lengths.len()], input.mask);
        }
        Scenario::KeyTruncate => {
            let mutation = common::EnvelopeMutation::Truncate { len: input.offset };
            let noop = mutation.is_noop(&req.masked_key);
            let original_len = req.masked_key.len();
            mutation.apply(&mut req.masked_key);
            assert_eq!(noop, req.masked_key.len() == original_len);
        }
        Scenario::KeyAppend => {
            let mutation =
                common::EnvelopeMutation::Append(input.bytes(input.control as usize % 33));
            let noop = mutation.is_noop(&req.masked_key);
            let original_len = req.masked_key.len();
            mutation.apply(&mut req.masked_key);
            assert_eq!(noop, req.masked_key.len() == original_len);
        }
        Scenario::TmkMetadata | Scenario::KeyMetadata => {
            let blob: &mut [u8] = if input.scenario == Scenario::TmkMetadata {
                &mut req.masked_tmk
            } else {
                &mut req.masked_key
            };
            mutate_metadata(blob, input, false);
        }
        Scenario::TmkScope | Scenario::KeyScope => {
            let blob: &mut [u8] = if input.scenario == Scenario::TmkScope {
                &mut req.masked_tmk
            } else {
                &mut req.masked_key
            };
            mutate_metadata(blob, input, true);
        }
        Scenario::PeekBeforeAuthentication => {
            let tag_at = req.masked_tmk.len() - AeadAlg::AesGcm256.tag_len();
            req.masked_tmk[tag_at] ^= 1;
            let aad_at = aead_envelope::HEADER_LEN + AeadAlg::AesGcm256.iv_len();
            req.masked_key[aad_at] ^= 1;
        }
        Scenario::EncodeError => req.masked_key = input.bytes(u16::MAX as usize + 1),
        _ => {}
    }
}

/// Convert padded wire-LE public coordinates to raw host big-endian coordinates.
fn public_be(curve: common::EccCurve, wire: &[u8]) -> Vec<u8> {
    assert_eq!(wire.len(), curve.wire_pub_key_len());
    let mut result = Vec::with_capacity(2 * curve.coord_len());
    for coordinate in wire.chunks_exact(curve.wire_coord_len()) {
        assert!(
            coordinate[curve.coord_len()..].iter().all(|&b| b == 0),
            "wire public padding"
        );
        result.extend(coordinate[..curve.coord_len()].iter().rev().copied());
    }
    result
}

/// Map the shared wire curve selector to the host crypto curve selector.
fn host_curve(curve: common::EccCurve) -> tsra_crypto::EccCurve {
    match curve {
        common::EccCurve::P256 => tsra_crypto::EccCurve::P256,
        common::EccCurve::P384 => tsra_crypto::EccCurve::P384,
        common::EccCurve::P521 => tsra_crypto::EccCurve::P521,
    }
}

/// Independently decrypt and inspect all eight COSE fields without logging secrets.
fn assert_host_cose(
    input: &FuzzInput<'_>,
    tmk: &[u8; TMK_LEN],
    wrapped: &[u8],
    public: &[u8],
    label: &[u8],
) {
    let aes = AesKey::from_bytes(tmk).expect("host-known AES key");
    let mut plaintext = Decrypter::decrypt_vec(&mut AesKeyWrapPadAlgo::default(), &aes, wrapped)
        .expect("exported KWP integrity");
    let mut decoder = minicbor::Decoder::new(&plaintext);
    assert_eq!(decoder.map().expect("COSE map"), Some(8));
    let mut seen = 0u8;
    let mut fields = [None; 4];
    let (crv, alg) = match input.curve {
        common::EccCurve::P256 => (1, -9),
        common::EccCurve::P384 => (2, -51),
        common::EccCurve::P521 => (3, -52),
    };
    for _ in 0..8 {
        let field = decoder.i32().expect("COSE field label");
        let index = [1, 2, 3, 4, -1, -2, -3, -4]
            .iter()
            .position(|&value| value == field)
            .expect("known COSE field");
        assert_eq!(seen & (1 << index), 0, "duplicate COSE field");
        seen |= 1 << index;
        match field {
            1 => assert_eq!(decoder.u8().expect("kty"), 2),
            2 => fields[0] = Some(decoder.bytes().expect("kid")),
            3 => assert_eq!(decoder.i32().expect("alg"), alg),
            4 => {
                assert_eq!(decoder.array().expect("key_ops"), Some(2));
                let expected = if input.derive { [7, 8] } else { [1, 2] };
                for op in expected {
                    assert_eq!(decoder.u8().expect("key operation"), op);
                }
            }
            -1 => assert_eq!(decoder.i32().expect("crv"), crv),
            -2 => fields[1] = Some(decoder.bytes().expect("x")),
            -3 => fields[2] = Some(decoder.bytes().expect("y")),
            -4 => fields[3] = Some(decoder.bytes().expect("d")),
            _ => unreachable!("label checked"),
        }
    }
    assert_eq!(seen, u8::MAX);
    assert_eq!(
        decoder.position(),
        plaintext.len(),
        "no trailing COSE bytes"
    );
    let [kid, x, y, d] = fields.map(|value| value.expect("all COSE fields"));
    assert!(kid == label, "COSE kid must preserve the source label");
    for coordinate in [x, y, d] {
        assert_eq!(
            coordinate.len(),
            input.curve.coord_len(),
            "COSE field width"
        );
    }
    let expected_public = public_be(input.curve, public);
    assert!(x == &expected_public[..x.len()], "COSE public x");
    assert!(y == &expected_public[x.len()..], "COSE public y");
    let private =
        EccPrivateKey::from_scalar(host_curve(input.curve), d).expect("COSE private scalar");
    let (derived_x, derived_y) = private
        .coord_vec()
        .expect("host-derived public coordinates");
    assert!(
        derived_x == x && derived_y == y,
        "COSE scalar/public consistency"
    );
    plaintext.fill(0);
}

/// Check round-trip public material, effective permissions, and signing usability.
fn assert_success(
    ctx: &TestCtx,
    req: &TborDarcKeyWrapReq,
    resp: &TborDarcKeyWrapResp,
    input: &FuzzInput<'_>,
    original_public: &[u8],
    known_tmk: Option<&[u8; TMK_LEN]>,
) {
    assert!(resp.wrapped_key.len() >= 16);
    assert!(resp.wrapped_key.len() <= DARC_WRAP_WRAPPED_KEY_MAX_LEN);
    assert!(resp.wrapped_key.len().is_multiple_of(8));
    let usage = if input.derive {
        KEY_USAGE_DERIVE
    } else {
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY
    };
    let mut unwrap = TborDarcKeyUnwrapReq {
        session_id: req.session_id,
        scope: common::KEY_SCOPE_LOCAL,
        key_usage: usage,
        masked_tmk: req.masked_tmk,
        wrapped_key: resp.wrapped_key.clone(),
    };
    let recovered = ctx.tbor(&unwrap).expect("unwrap successful export");
    let kind = match input.curve {
        common::EccCurve::P256 => KEY_KIND_ECC256_PRIVATE,
        common::EccCurve::P384 => KEY_KIND_ECC384_PRIVATE,
        common::EccCurve::P521 => KEY_KIND_ECC521_PRIVATE,
    };
    assert_eq!(recovered.key_kind, kind);
    assert_eq!(recovered.pub_key.len(), input.curve.wire_pub_key_len());
    assert!(
        recovered.pub_key == original_public,
        "wrap/unwrap public key mismatch"
    );
    unwrap.key_usage = if input.derive {
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY
    } else {
        KEY_USAGE_DERIVE
    };
    ctx.expect_fw_reject(&unwrap, TborStatus::InvalidPermissions);

    if !input.derive {
        let digest = input.bytes(input.curve.max_digest_len());
        let signature = ctx
            .tbor(&TborEccSignReq {
                session_id: req.session_id,
                masked_key: recovered.masked_key,
                digest: digest.clone(),
            })
            .expect("sign with round-tripped key")
            .signature;
        assert_eq!(signature.len(), input.curve.wire_sig_len());
        let mut raw_signature = Vec::new();
        for component in signature.chunks_exact(input.curve.wire_coord_len()) {
            assert!(
                component[input.curve.coord_len()..].iter().all(|&b| b == 0),
                "signature padding"
            );
            raw_signature.extend(component[..input.curve.coord_len()].iter().rev().copied());
        }
        let public_coordinates = public_be(input.curve, original_public);
        let (x, y) = public_coordinates.split_at(input.curve.coord_len());
        let public =
            EccPublicKey::from_coordinates(host_curve(input.curve), x, y).expect("host public key");
        let digest_be: Vec<_> = digest.iter().rev().copied().collect();
        assert!(
            Verifier::verify(&mut EccAlgo::default(), &public, &digest_be, &raw_signature)
                .expect("host signature verification"),
            "round-tripped signature"
        );
    }
    if let Some(tmk) = known_tmk {
        assert_host_cose(
            input,
            tmk,
            &resp.wrapped_key,
            original_public,
            &input.bytes(input.label_len),
        );
    }
}

/// Require an exact rejection; infrastructure failures are never valid rejections.
fn assert_rejection(ctx: &TestCtx, req: &TborDarcKeyWrapReq, status: TborStatus) {
    let error = ctx.tbor(req).expect_err("invalid DarcKeyWrap must fail");
    assertions::assert_session_rejects(&error, status);
}

/// Execute one isolated scenario, avoiding provisioning when an early gate rejects.
fn run(ctx: &TestCtx, input: &FuzzInput<'_>) {
    let session = match input.scenario {
        Scenario::DefaultPsk => ctx
            .open_session(CO_PSK_ID, SessionType::Authenticated)
            .expect("default-PSK session"),
        Scenario::CryptoUser => SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK)),
        _ => SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK)),
    };
    let mut req = TborDarcKeyWrapReq {
        session_id: session.session_id(),
        masked_tmk: [0; MASKED_TMK_LEN],
        masked_key: vec![0; MASKED_ECC_KEY_MIN_LEN],
    };
    let early = match input.scenario {
        Scenario::DefaultPsk => Some(TborStatus::DefaultPskMustRotate),
        Scenario::CryptoUser => Some(TborStatus::InvalidPermissions),
        Scenario::Unfinalized => Some(TborStatus::InvalidArg),
        Scenario::NoSecurityDomain => {
            common::finalize_partition(ctx, session.handshake());
            Some(TborStatus::InvalidArg)
        }
        Scenario::MismatchedSession => {
            req.session_id ^= 1;
            Some(TborStatus::FileHandleSessionIdDoesNotMatch)
        }
        Scenario::ArbitrarySession if input.session_id != req.session_id => {
            req.session_id = input.session_id;
            Some(TborStatus::FileHandleSessionIdDoesNotMatch)
        }
        Scenario::ClosedSession => {
            session.close().expect("close before export");
            assert_rejection(ctx, &req, TborStatus::SessionNotFound);
            return;
        }
        _ => None,
    };
    if let Some(status) = early {
        assert_rejection(ctx, &req, status);
        session.close().expect("close early-gate session");
        return;
    }

    let known_tmk: Option<[u8; TMK_LEN]> = if input.scenario == Scenario::HostKnownTmk {
        let fixture = common::create_test_security_domain_with_policy(ctx, session.handshake());
        let tmk = input.bytes(TMK_LEN).try_into().expect("host TMK size");
        req.masked_tmk = common::import_darc_tmk(ctx, req.session_id, &fixture, &tmk);
        Some(tmk)
    } else {
        common::create_test_security_domain(ctx, session.handshake());
        req.masked_tmk = ctx
            .tbor(&TborDarcTmkGenReq {
                session_id: req.session_id,
            })
            .expect("generate authentic TMK")
            .masked_tmk
            .try_into()
            .expect("TMK envelope length");
        None
    };
    let key = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: req.session_id,
            scope: if input.scenario == Scenario::SessionScope {
                common::KEY_SCOPE_SESSION
            } else {
                input.scope
            },
            curve: input.curve.to_tbor(),
            key_usage: input.usage(),
            key_label: input.bytes(input.label_len),
        })
        .expect("generate authentic source EC key");
    req.masked_key = key.masked_key;
    if input.scenario == Scenario::WrongTmkKind {
        let donor = ctx
            .tbor(&TborEccGenerateKeyReq {
                session_id: req.session_id,
                scope: common::KEY_SCOPE_LOCAL,
                curve: ECC_CURVE_P256,
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            })
            .expect("authentic P-256 wrong-kind donor");
        req.masked_tmk = donor
            .masked_key
            .try_into()
            .expect("P-256 envelope fits TMK field");
    } else if input.scenario == Scenario::WrongKeyKind {
        req.masked_key = req.masked_tmk.to_vec();
    }
    let original_tmk = req.masked_tmk;
    let original_key = req.masked_key.clone();
    mutate(&mut req, input);
    let expected = expected_outcome(&req, &original_tmk, &original_key, input.scenario);
    match expected {
        Expected::Success => {
            let resp = ctx.tbor(&req).expect("valid DarcKeyWrap must succeed");
            assert_success(ctx, &req, &resp, input, &key.pub_key, known_tmk.as_ref());
        }
        Expected::Reject(status) => assert_rejection(ctx, &req, status),
        Expected::EncodeError => assert!(
            matches!(ctx.tbor(&req), Err(DdiError::TborEncodeError)),
            "unrepresentable buffer length must fail host encoding",
        ),
    }
    session.close().expect("close export session");
}

fuzz_target!(|data: &[u8]| {
    let input = FuzzInput::new(data);
    common::common_fuzz_test(&|ctx, _path| run(ctx, &input));
});
