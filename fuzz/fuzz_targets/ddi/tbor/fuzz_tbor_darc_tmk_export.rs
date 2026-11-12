// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Semantic DARC TMK export fuzzing through the real TBOR transport.
//!
//! Authentic fixtures reach HPKE sealing; host-side authenticated opening
//! checks the exported plaintext independently. Isolated mutations preserve
//! preceding gates, with exact, input-derived rejection predictions. Three
//! bounded wire lanes additionally exercise fixed-buffer and descriptor sizes.
//! Authenticated wrong-length TMKs and unavailable SDMK states are not forged:
//! public provisioning cannot construct those states independently of earlier
//! validation. Ownership rejections are not handler inactive-session coverage.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::*;
use tsra_crypto::*;
use tsra_ddi_tbor_test_harness::assertions::*;
use tsra_ddi_tbor_test_harness::x509_fixture::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;
use tsra_fw_core_crypto_key_masking::aead::*;
use zerocopy::*;

/// Eight selectors out of 44 are dedicated known-plaintext success cases.
/// Generated-TMK and relocated-evidence cases provide two more success lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Valid,
    Generated,
    Relocated,
    ArbitrarySession,
    MismatchedSession,
    ClosedSession,
    CryptoUser,
    DefaultPsk,
    Unfinalized,
    Initializing,
    NoSecurityDomain,
    MissingOob,
    Policy,
    NoDataAnchor,
    ForeignAnchor,
    DescriptorCount,
    DescriptorIndex,
    DescriptorLength,
    ReversedChain,
    MissingItem,
    CertificateTruncate,
    CertificateDer,
    CertificateSignature,
    SenderFlip,
    TmkFlip,
    RawSender,
    RawTmk,
    SenderMetadata,
    TmkMetadata,
    SenderScope,
    TmkScope,
    WrongSenderKind,
    WrongTmkKind,
    WireChainLength,
    WireSenderLength,
    WireTmkLength,
    Combined,
}

/// Optional bytes follow nine compact controls; missing bytes default to zero,
/// so even empty input executes a known-plaintext successful export.
struct FuzzInput<'a> {
    scenario: Scenario,
    controls: u8,
    offset: u16,
    mask: u8,
    session_id: u16,
    value: u16,
    extra: &'a [u8],
}

impl<'a> FuzzInput<'a> {
    /// Decode bounded controls without rejecting short libFuzzer inputs.
    fn new(bytes: &'a [u8]) -> Self {
        let byte = |i| bytes.get(i).copied().unwrap_or(0);
        let scenario = match byte(0) % 44 {
            0..=7 => Scenario::Valid,
            8 => Scenario::Generated,
            9 => Scenario::Relocated,
            10 => Scenario::ArbitrarySession,
            11 => Scenario::MismatchedSession,
            12 => Scenario::ClosedSession,
            13 => Scenario::CryptoUser,
            14 => Scenario::DefaultPsk,
            15 => Scenario::Unfinalized,
            16 => Scenario::Initializing,
            17 => Scenario::NoSecurityDomain,
            18 => Scenario::MissingOob,
            19 => Scenario::Policy,
            20 => Scenario::NoDataAnchor,
            21 => Scenario::ForeignAnchor,
            22 => Scenario::DescriptorCount,
            23 => Scenario::DescriptorIndex,
            24 => Scenario::DescriptorLength,
            25 => Scenario::ReversedChain,
            26 => Scenario::MissingItem,
            27 => Scenario::CertificateTruncate,
            28 => Scenario::CertificateDer,
            29 => Scenario::CertificateSignature,
            30 => Scenario::SenderFlip,
            31 => Scenario::TmkFlip,
            32 => Scenario::RawSender,
            33 => Scenario::RawTmk,
            34 => Scenario::SenderMetadata,
            35 => Scenario::TmkMetadata,
            36 => Scenario::SenderScope,
            37 => Scenario::TmkScope,
            38 => Scenario::WrongSenderKind,
            39 => Scenario::WrongTmkKind,
            40 => Scenario::WireChainLength,
            41 => Scenario::WireSenderLength,
            42 => Scenario::WireTmkLength,
            _ => Scenario::Combined,
        };
        Self {
            scenario,
            controls: byte(1),
            offset: u16::from_le_bytes([byte(2), byte(3)]),
            mask: byte(4),
            session_id: u16::from_le_bytes([byte(5), byte(6)]),
            value: u16::from_le_bytes([byte(7), byte(8)]),
            extra: bytes.get(9..bytes.len().min(2057)).unwrap_or_default(),
        }
    }

    /// Supply arbitrary payload bytes with a deterministic short-input fallback.
    fn byte(&self, index: usize) -> u8 {
        self.extra.get(index).copied().unwrap_or(index as u8)
    }
}

/// Separate pre-authentication routing failures from later unmask failures.
#[derive(Clone, Copy, Debug)]
enum EnvelopeOutcome {
    Authentic,
    PeekReject(TborStatus),
    UnmaskReject,
}

/// A prediction fixed before submission, never inferred from export's response.
#[derive(Clone, Copy, Debug)]
enum Expected {
    Success,
    Reject(TborStatus),
}

/// Convert independently reversed wire coordinates to host big-endian points.
fn host_public(wire: &[u8; RAW_PUB_LEN]) -> EccPublicKey {
    let mut raw = *wire;
    raw[..common::COORD_LEN].reverse();
    raw[common::COORD_LEN..].reverse();
    EccPublicKey::from_hsm_bytes(&raw).expect("generated P-384 public point")
}

/// Return certificate-format coordinates for a host-owned P-384 key.
fn raw_public(key: &EccPrivateKey) -> [u8; RAW_PUB_LEN] {
    let (x, y) = key.coord_vec().expect("host public coordinates");
    let mut raw = [0; RAW_PUB_LEN];
    raw[..common::COORD_LEN].copy_from_slice(&x);
    raw[common::COORD_LEN..].copy_from_slice(&y);
    raw
}

/// Predict public framing/metadata gates and effective AEAD changes.
///
/// This reads the public metadata layout, not the firmware decoder. GCM uses
/// only the first 12 IV bytes: changes to its stored four-byte suffix are
/// deliberately classified as authentic, not as tag failures.
fn envelope_outcome(original: &[u8], changed: &[u8]) -> EnvelopeOutcome {
    let Ok(env) = aead_envelope::inspect(changed) else {
        return EnvelopeOutcome::PeekReject(TborStatus::InvalidArg);
    };
    if env.aad.len() != core::mem::size_of::<MaskedKeyMetadata>()
        || !env.payload.len().is_multiple_of(16)
    {
        return EnvelopeOutcome::PeekReject(TborStatus::MaskedKeyDecodeFailed);
    }
    let metadata = MaskedKeyMetadata::read_from_bytes(env.aad).expect("metadata size");
    let label_len = usize::from(metadata.key_label_len);
    if metadata.magic != META_MAGIC
        || metadata.version.get() != META_VERSION_V1
        || metadata.data_pad_len > 15
        || label_len > KEY_LABEL_MAX
        || metadata._reserved.iter().any(|&b| b != 0)
        || metadata.key_label[label_len..].iter().any(|&b| b != 0)
    {
        return EnvelopeOutcome::PeekReject(TborStatus::MaskedKeyDecodeFailed);
    }
    if !matches!(
        metadata.usage_flags().scope().0,
        common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL | common::KEY_SCOPE_SECURITY_DOMAIN
    ) {
        return EnvelopeOutcome::PeekReject(TborStatus::UnsupportedKeyScope);
    }
    let baseline = aead_envelope::inspect(original).expect("authentic envelope framing");
    if env.iv[..12] == baseline.iv[..12]
        && env.aad == baseline.aad
        && env.payload == baseline.payload
        && env.tag == baseline.tag
    {
        EnvelopeOutcome::Authentic
    } else {
        EnvelopeOutcome::UnmaskReject
    }
}

/// Mutate either arbitrary envelope bytes, typed metadata fields, or scope.
///
/// The original stays available to the oracle; zero masks and unchanged scopes
/// are real no-ops. Raw replacements force invalid magic independently of data.
fn mutate_envelope(blob: &mut [u8], input: &FuzzInput<'_>) {
    match input.scenario {
        Scenario::RawSender | Scenario::RawTmk => {
            for (i, byte) in blob.iter_mut().enumerate() {
                *byte = input.byte(i);
            }
            blob[0] = 0;
        }
        Scenario::SenderScope | Scenario::TmkScope => {
            let env = aead_envelope::inspect(blob).expect("original envelope");
            let mut metadata = MaskedKeyMetadata::read_from_bytes(env.aad).expect("metadata");
            let mut scope = metadata.usage_flags().scope();
            scope.0 = input.controls & 7;
            metadata.usage_flags = metadata.usage_flags().with_scope(scope).into_bits().into();
            let start = aead_envelope::HEADER_LEN + aead_envelope::AeadAlg::AesGcm256.iv_len();
            blob[start..start + core::mem::size_of::<MaskedKeyMetadata>()]
                .copy_from_slice(metadata.as_bytes());
        }
        _ => {
            let offset = if matches!(
                input.scenario,
                Scenario::SenderMetadata | Scenario::TmkMetadata
            ) {
                let fields = [
                    core::mem::offset_of!(MaskedKeyMetadata, magic),
                    core::mem::offset_of!(MaskedKeyMetadata, version),
                    core::mem::offset_of!(MaskedKeyMetadata, key_kind),
                    core::mem::offset_of!(MaskedKeyMetadata, key_label_len),
                    core::mem::offset_of!(MaskedKeyMetadata, usage_flags),
                    core::mem::offset_of!(MaskedKeyMetadata, data_pad_len),
                    core::mem::offset_of!(MaskedKeyMetadata, _reserved),
                ];
                aead_envelope::HEADER_LEN
                    + aead_envelope::AeadAlg::AesGcm256.iv_len()
                    + fields[usize::from(input.offset) % fields.len()]
            } else {
                usize::from(input.offset) % blob.len()
            };
            let mut changed = blob.to_vec();
            common::EnvelopeMutation::FlipByte {
                offset: u16::try_from(offset).expect("bounded envelope offset"),
                mask: input.mask,
            }
            .apply(&mut changed);
            blob.copy_from_slice(&changed);
        }
    }
}

/// Encode one deliberately resized buffer while retaining in-session routing.
struct WireRequest<'a> {
    req: &'a TborDarcTmkExportReq,
    field: usize,
    len: usize,
}

impl TborOpReq for WireRequest<'_> {
    const OPCODE: u8 = TBOR_OP_DARC_TMK_EXPORT;
    type OpResp = TborDarcTmkExportResp;

    /// Bind the raw request to the same live transport session as its template.
    fn get_session_id(&self) -> Option<u16> {
        Some(self.req.session_id)
    }

    /// Preserve the normal request's SQE session-control kind.
    fn session_ctrl(&self) -> SessionControlKind {
        SessionControlKind::InSession
    }

    /// Build valid framing around exactly one fuzz-controlled buffer length.
    fn encode_request<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8], codec::EncodeError> {
        let mut fields = [
            self.req.masked_sender_key.to_vec(),
            self.req.masked_tmk.to_vec(),
            self.req.target_cert_chain.as_slice().as_bytes().to_vec(),
        ];
        fields[self.field].resize(self.len, 0);
        codec::RequestEncoder::new(buf, codec::PROTOCOL_VERSION, Self::OPCODE)
            .session_id(self.req.session_id)?
            .buffer(&fields[0])?
            .buffer(&fields[1])?
            .buffer(self.req.policy.as_bytes())?
            .buffer(&fields[2])?
            .finish()
    }
}

/// Submit exactly once and check its precomputed outcome without dumping keys.
fn execute<R: TborOpReq<OpResp = TborDarcTmkExportResp>>(
    ctx: &TestCtx,
    req: &R,
    items: Option<&[Vec<u8>]>,
    expected: Expected,
    input: &FuzzInput<'_>,
) -> Option<TborDarcTmkExportResp> {
    let result = if let Some(items) = items {
        let oob = items.iter().map(Vec::as_slice).collect::<Vec<_>>();
        ctx.tbor_oob(req, &oob)
    } else {
        ctx.tbor(req)
    };
    match (expected, result) {
        (Expected::Success, Ok(resp)) => Some(resp),
        (Expected::Reject(status), Err(err)) => {
            if !matches!(
                &err,
                tsra_ddi_interface::DdiError::TborStatus(actual) if *actual == status
            ) {
                eprintln!(
                    "{:?} controls={} offset={} expected {status:?}: {err}",
                    input.scenario, input.controls, input.offset,
                );
            }
            assert_session_rejects(&err, status);
            None
        }
        (Expected::Success, Err(err)) => panic!(
            "{:?} controls={} offset={} expected success: {err}",
            input.scenario, input.controls, input.offset,
        ),
        (Expected::Reject(status), Ok(_)) => panic!(
            "{:?} controls={} offset={} unexpectedly accepted, expected {status:?}",
            input.scenario, input.controls, input.offset,
        ),
    }
}

/// Authenticate the seal with host-owned receiver material and the real sender.
///
/// Plaintext comparisons deliberately omit byte values from assertion output.
fn assert_success(
    resp: &TborDarcTmkExportResp,
    receiver: &EccPrivateKey,
    sender_pub: &EccPublicKey,
    known_tmk: Option<&[u8; TMK_LEN]>,
) -> Vec<u8> {
    assert_eq!(resp.sealed_tmk.len(), SEALED_TMK_LEN);
    assert_eq!(resp.sealed_tmk[0], 4, "SEC1 uncompressed point");
    let enc_raw = &resp.sealed_tmk[1..SEC1_PUB_LEN];
    let (x, y) = enc_raw.split_at(common::COORD_LEN);
    assert!(
        EccPublicKey::is_on_curve(EccCurve::P384, x, y).expect("point validation"),
        "encapsulated point must be on P-384",
    );
    let enc = EccPublicKey::from_hsm_bytes(enc_raw).expect("encapsulated public key");
    let receiver_pub = receiver.public_key().expect("receiver public key");
    let plain = open_vec(
        &HpkeOpenConfig::auth(
            HpkeSuite::DHKemP384Sha384AesGcm256,
            receiver,
            &receiver_pub,
            &[],
            &[],
            sender_pub,
        ),
        &enc,
        &resp.sealed_tmk[SEC1_PUB_LEN..],
    )
    .expect("exported TMK must authenticate");
    assert_eq!(plain.len(), TMK_LEN);
    if let Some(tmk) = known_tmk {
        assert!(plain.as_slice() == tmk, "exported TMK plaintext mismatch");
    }
    plain
}

/// Exercise cheap ownership, role, and lifecycle gates before crypto setup.
///
/// The placeholder decodes normally, but its crypto material is never used.
fn early_case(ctx: &TestCtx, input: &FuzzInput<'_>) -> bool {
    let early = matches!(
        input.scenario,
        Scenario::MismatchedSession
            | Scenario::ClosedSession
            | Scenario::CryptoUser
            | Scenario::DefaultPsk
            | Scenario::Unfinalized
            | Scenario::Initializing
            | Scenario::NoSecurityDomain
    );
    if !early {
        return false;
    }
    let session = match input.scenario {
        Scenario::DefaultPsk => ctx
            .open_session(CO_PSK_ID, SessionType::Authenticated)
            .expect("default-PSK session"),
        Scenario::CryptoUser => SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK)),
        _ => SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK)),
    };
    let mut req = TborDarcTmkExportReq {
        session_id: session.session_id(),
        masked_sender_key: [0; MASKED_KEX_KEY_LEN],
        masked_tmk: [0; MASKED_TMK_LEN],
        policy: PartPolicy::zeroed(),
        target_cert_chain: vec![CertDescriptor {
            index: 0,
            length: 1u16.into(),
        }],
    };
    let mut session = Some(session);
    let status = match input.scenario {
        Scenario::MismatchedSession => {
            req.session_id ^= 1;
            TborStatus::FileHandleSessionIdDoesNotMatch
        }
        Scenario::ClosedSession => {
            session
                .take()
                .expect("live session")
                .close()
                .expect("close session");
            TborStatus::SessionNotFound
        }
        Scenario::CryptoUser => TborStatus::InvalidPermissions,
        Scenario::DefaultPsk => TborStatus::DefaultPskMustRotate,
        Scenario::Initializing => {
            let pota = CaKey::generate();
            ctx.part_init(
                session.as_ref().expect("live session").handshake(),
                &common::mach_seed(),
                &common::known_good_part_policy(pota.raw_pub()),
                &common::pota_thumbprint(),
            )
            .expect("initializing partition");
            TborStatus::InvalidArg
        }
        Scenario::NoSecurityDomain => {
            common::finalize_partition(ctx, session.as_ref().expect("live session").handshake());
            TborStatus::InvalidArg
        }
        _ => TborStatus::InvalidArg,
    };
    execute(ctx, &req, None, Expected::Reject(status), input);
    if let Some(session) = session {
        session.close().expect("close gating session");
    }
    true
}

/// Apply one isolated request/evidence defect and predict its exact rejection.
///
/// Index mutations rely on the fixture's distinct root/leaf lengths: selecting
/// the other in-range item fails OOB length agreement, not arbitrary parsing.
fn mutate_request(
    ctx: &TestCtx,
    req: &mut TborDarcTmkExportReq,
    items: &mut Vec<Vec<u8>>,
    input: &FuzzInput<'_>,
) -> Expected {
    let selected = usize::from(input.controls & 1);
    let mut expected = Expected::Success;
    match input.scenario {
        Scenario::Policy => {
            let mut bytes = req.policy.as_bytes().to_vec();
            let len = bytes.len();
            bytes[usize::from(input.offset) % len] ^= input.mask;
            req.policy = PartPolicy::try_read_from_bytes(&bytes).expect("policy image layout");
            if input.mask != 0 {
                expected = Expected::Reject(TborStatus::InvalidArg);
            }
        }
        Scenario::NoDataAnchor | Scenario::ForeignAnchor | Scenario::MissingOob => {
            expected = Expected::Reject(TborStatus::InvalidArg);
        }
        Scenario::DescriptorCount => {
            let count = usize::from(input.controls % 5);
            req.target_cert_chain
                .resize(count, req.target_cert_chain[0]);
            expected = match count {
                2 => Expected::Success,
                1 => Expected::Reject(TborStatus::InvalidArg),
                _ => Expected::Reject(TborStatus::TborInvalidFixedLength),
            };
        }
        Scenario::DescriptorIndex => {
            let original = req.target_cert_chain[selected].index;
            req.target_cert_chain[selected].index = input.value as u8;
            if input.value as u8 != original {
                expected = Expected::Reject(TborStatus::InvalidArg);
            }
        }
        Scenario::DescriptorLength => {
            let original = req.target_cert_chain[selected].length.get();
            req.target_cert_chain[selected].length = input.value.into();
            if input.value != original {
                expected = Expected::Reject(TborStatus::InvalidArg);
            }
        }
        Scenario::ReversedChain => {
            req.target_cert_chain.reverse();
            expected = Expected::Reject(TborStatus::X509NotSelfSigned);
        }
        Scenario::MissingItem => {
            items.pop();
            expected = Expected::Reject(TborStatus::InvalidArg);
        }
        Scenario::CertificateTruncate => {
            let len = usize::from(input.value) % (items[selected].len() + 1);
            if len < items[selected].len() {
                // Empty OOB items are rejected by the transport. Keep backing
                // storage so a zero-length descriptor reaches firmware.
                items[selected].truncate(len.max(1));
                req.target_cert_chain[selected].length =
                    u16::try_from(len).expect("bounded DER length").into();
                expected = Expected::Reject(if len == 0 {
                    TborStatus::InvalidArg
                } else {
                    TborStatus::X509ParseError
                });
            }
        }
        Scenario::CertificateDer => {
            for (i, byte) in items[selected].iter_mut().enumerate() {
                *byte = input.byte(i);
            }
            items[selected][0] = 0;
            expected = Expected::Reject(TborStatus::X509ParseError);
        }
        Scenario::CertificateSignature => {
            let last = items[selected].last_mut().expect("nonempty certificate");
            *last ^= input.mask;
            if input.mask != 0 {
                expected = Expected::Reject(TborStatus::X509SignatureInvalid);
            }
        }
        Scenario::SenderFlip
        | Scenario::SenderMetadata
        | Scenario::SenderScope
        | Scenario::RawSender => {
            let original = req.masked_sender_key;
            mutate_envelope(&mut req.masked_sender_key, input);
            expected = envelope_expected(envelope_outcome(&original, &req.masked_sender_key));
        }
        Scenario::TmkFlip | Scenario::TmkMetadata | Scenario::TmkScope | Scenario::RawTmk => {
            let original = req.masked_tmk;
            mutate_envelope(&mut req.masked_tmk, input);
            expected = envelope_expected(envelope_outcome(&original, &req.masked_tmk));
        }
        Scenario::WrongSenderKind => {
            req.masked_sender_key = ctx
                .tbor(&TborSdSealingKeyGenReq {
                    session_id: req.session_id,
                    scope: common::KEY_SCOPE_LOCAL,
                })
                .expect("authentic wrong-kind sender")
                .masked_key;
            expected = Expected::Reject(TborStatus::UnsupportedKeyType);
        }
        Scenario::WrongTmkKind => {
            let donor = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id: req.session_id,
                    scope: common::KEY_SCOPE_LOCAL,
                    curve: ECC_CURVE_P256,
                    key_usage: KEY_USAGE_DERIVE,
                    key_label: Vec::new(),
                })
                .expect("authentic P-256 wrong-kind TMK");
            req.masked_tmk = donor
                .masked_key
                .try_into()
                .expect("32-byte private-key envelope");
            expected = Expected::Reject(TborStatus::UnsupportedKeyType);
        }
        Scenario::Combined => {
            req.policy.info[0] ^= 1;
            match input.controls % 3 {
                0 => {
                    let last = req.masked_tmk.last_mut().expect("TMK tag");
                    *last ^= 1;
                    expected = Expected::Reject(TborStatus::InvalidArg);
                }
                1 => {
                    let start =
                        aead_envelope::HEADER_LEN + aead_envelope::AeadAlg::AesGcm256.iv_len();
                    req.masked_sender_key[start] ^= 1;
                    expected = Expected::Reject(TborStatus::MaskedKeyDecodeFailed);
                }
                _ => {
                    let mut controls = FuzzInput::new(&[]);
                    controls.scenario = Scenario::TmkScope;
                    controls.controls = common::KEY_SCOPE_SESSION;
                    mutate_envelope(&mut req.masked_tmk, &controls);
                    expected = Expected::Reject(TborStatus::UnsupportedKeyScope);
                }
            }
        }
        _ => {}
    }
    expected
}

/// Translate independent envelope predictions for an otherwise valid request.
fn envelope_expected(outcome: EnvelopeOutcome) -> Expected {
    match outcome {
        EnvelopeOutcome::Authentic => Expected::Success,
        EnvelopeOutcome::PeekReject(status) => Expected::Reject(status),
        EnvelopeOutcome::UnmaskReject => Expected::Reject(TborStatus::AesGcmDecryptTagDoesNotMatch),
    }
}

/// Execute a fresh semantic fixture, preserving a valid request for recovery.
fn run(ctx: &TestCtx, input: &FuzzInput<'_>) {
    if early_case(ctx, input) {
        return;
    }
    let session = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
    if input.scenario == Scenario::ArbitrarySession && input.session_id != session.session_id() {
        let req = TborDarcTmkExportReq {
            session_id: input.session_id,
            masked_sender_key: [0; MASKED_KEX_KEY_LEN],
            masked_tmk: [0; MASKED_TMK_LEN],
            policy: PartPolicy::zeroed(),
            target_cert_chain: vec![CertDescriptor {
                index: 0,
                length: 1u16.into(),
            }],
        };
        execute(
            ctx,
            &req,
            None,
            Expected::Reject(TborStatus::FileHandleSessionIdDoesNotMatch),
            input,
        );
        session.close().expect("close arbitrary-ID session");
        return;
    }
    let data = CaKey::generate();
    let fixture = common::create_test_security_domain_with_custom_policy(
        ctx,
        session.handshake(),
        |policy| {
            policy.version.minor = input.controls;
            for (i, byte) in policy.info.iter_mut().enumerate() {
                *byte = input.byte(i);
            }
            if input.scenario != Scenario::NoDataAnchor {
                policy.data_pub_key = PolicyPubKey::new(
                    PolicyKeyKind::Ecc384,
                    POLICY_MAX_KEY_LEN as u16,
                    data.raw_pub(),
                );
            }
        },
    );
    let scopes = [
        common::KEY_SCOPE_LOCAL,
        common::KEY_SCOPE_EPHEMERAL,
        common::KEY_SCOPE_SECURITY_DOMAIN,
    ];
    let sender = ctx
        .tbor(&TborDarcKexKeyGenReq {
            session_id: session.session_id(),
            scope: scopes[usize::from(input.controls) % scopes.len()],
        })
        .expect("export sender generation");
    let known_tmk: [u8; TMK_LEN] = core::array::from_fn(|i| input.byte(i));
    let generated = input.scenario == Scenario::Generated;
    let masked_tmk = if generated {
        ctx.tbor(&TborDarcTmkGenReq {
            session_id: session.session_id(),
        })
        .expect("generate TMK")
        .masked_tmk
        .try_into()
        .expect("generated TMK size")
    } else {
        common::import_darc_tmk(ctx, session.session_id(), &fixture, &known_tmk)
    };
    let mut scalar = [0; common::COORD_LEN];
    let seed = u64::from_le_bytes(core::array::from_fn(|i| input.byte(i))).max(1);
    scalar[common::COORD_LEN - 8..].copy_from_slice(&seed.to_be_bytes());
    let receiver =
        EccPrivateKey::from_scalar(EccCurve::P384, &scalar).expect("bounded receiver scalar");
    let foreign = (input.scenario == Scenario::ForeignAnchor).then(CaKey::generate);
    let chain = make_chain(foreign.as_ref().unwrap_or(&data), &raw_public(&receiver));
    assert_ne!(
        chain.root_der.len(),
        chain.leaf_der.len(),
        "descriptor-index oracle lengths"
    );
    let mut items = Vec::new();
    if input.scenario == Scenario::Relocated {
        for _ in 0..usize::from(input.controls % 8) {
            items.push(vec![input.mask]);
        }
    }
    let target_cert_chain = chain
        .der_items()
        .iter()
        .map(|der| common::add_evidence_item(&mut items, der))
        .collect();
    let valid = TborDarcTmkExportReq {
        session_id: session.session_id(),
        masked_sender_key: sender.masked_key,
        masked_tmk,
        policy: fixture.policy,
        target_cert_chain,
    };
    let mut req = valid.clone();
    let mut mutated_items = items.clone();
    let expected = mutate_request(ctx, &mut req, &mut mutated_items, input);
    let result = match input.scenario {
        Scenario::WireChainLength | Scenario::WireSenderLength | Scenario::WireTmkLength => {
            let field = match input.scenario {
                Scenario::WireSenderLength => 0,
                Scenario::WireTmkLength => 1,
                _ => 2,
            };
            let original_len = [
                MASKED_KEX_KEY_LEN,
                MASKED_TMK_LEN,
                2 * core::mem::size_of::<CertDescriptor>(),
            ][field];
            let len = if field == 2 {
                usize::from(input.value % 8)
            } else {
                [0, 1, original_len - 1, original_len, original_len + 1]
                    [usize::from(input.controls % 5)]
            };
            let expected = if len == original_len {
                Expected::Success
            } else if field == 2 && (3..=6).contains(&len) {
                Expected::Reject(TborStatus::InvalidArg)
            } else {
                Expected::Reject(TborStatus::TborInvalidFixedLength)
            };
            execute(
                ctx,
                &WireRequest {
                    req: &req,
                    field,
                    len,
                },
                Some(&mutated_items),
                expected,
                input,
            )
        }
        _ => execute(
            ctx,
            &req,
            (input.scenario != Scenario::MissingOob).then_some(mutated_items.as_slice()),
            expected,
            input,
        ),
    };
    let sender_pub = host_public(&sender.pub_key);
    if let Some(resp) = result.as_ref() {
        let plain = assert_success(
            resp,
            &receiver,
            &sender_pub,
            (!generated).then_some(&known_tmk),
        );
        if input.controls & 0x80 != 0 {
            let again = execute(ctx, &valid, Some(&items), Expected::Success, input)
                .expect("second export");
            let other = assert_success(
                &again,
                &receiver,
                &sender_pub,
                (!generated).then_some(&known_tmk),
            );
            assert!(plain == other, "repeated export plaintext changed");
            assert!(
                resp.sealed_tmk != again.sealed_tmk,
                "export must use a fresh ephemeral"
            );
        }
    } else if input.scenario != Scenario::NoDataAnchor && input.scenario != Scenario::ForeignAnchor
    {
        let resp =
            execute(ctx, &valid, Some(&items), Expected::Success, input).expect("recovery export");
        assert_success(
            &resp,
            &receiver,
            &sender_pub,
            (!generated).then_some(&known_tmk),
        );
    }
    session.close().expect("close export session");
}

fuzz_target!(|bytes: &[u8]| {
    let input = FuzzInput::new(bytes);
    common::common_fuzz_test(&|ctx, _path| run(ctx, &input));
});
