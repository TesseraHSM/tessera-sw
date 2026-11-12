// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Semantic DARC TMK imports through the real TBOR transport. Frequent valid
//! HPKE-Auth imports and isolated mutations reach policy/chain validation,
//! receiver-key unmasking, HPKE opening, and TMK masking. Predictions use inputs
//! and authentic fixture snapshots, never the command's observed result.
//! Successful imports unwrap host-known material to check plaintext semantics.
//! Typed requests cannot exercise malformed framing, partial descriptors, or
//! variable sealed-TMK lengths; the post-open plaintext-length guard, allocator
//! failures, and authenticated malformed receiver scalars are not claimed.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary::*;
use libfuzzer_sys::*;
use tsra_crypto::aead_envelope::AeadAlg as HostAeadAlg;
use tsra_crypto::aead_envelope::*;
use tsra_crypto::*;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_codec::MAX_DATA_SIZE;
use tsra_ddi_tbor_test_harness::assertions::*;
use tsra_ddi_tbor_test_harness::x509_fixture::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;
use tsra_fw_core_crypto_key_masking::aead::*;
use zerocopy::*;

// Wire mirrors of HsmVaultKeyKind::DarcTmk and HsmVaultKeyAttrs in pal/traits.
const DARC_TMK_KIND: u8 = 45;
const SCOPE_SHIFT: u32 = 17;
const GCM_NONCE_LEN: usize = 12;

/// Twelve of the 48 selector values are dedicated deep success lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Valid,
    ArbitrarySession,
    MismatchedSession,
    ClosedSession,
    DefaultCo,
    DefaultCu,
    CryptoUser,
    Uninitialized,
    Initializing,
    NoSecurityDomain,
    MissingOob,
    MaskedKeyFlip,
    RawMaskedKey,
    WrongKind,
    WrongReceiver,
    PolicyFlip,
    RawPolicy,
    PolicyInfo,
    SealedFlip,
    RawSealed,
    CiphertextFlip,
    WrongSender,
    DescriptorCount,
    DescriptorIndex,
    DescriptorLength,
    DescriptorOrder,
    ForeignAnchor,
    RawDer,
    TruncatedDer,
    ReindexedOob,
    ExtraOob,
    PolicyAndSealed,
    EncodeError,
    MaskedKeyScope,
    MissingOobItem,
    IvSuffix,
    SingleCertificate,
}

/// Eight optional control bytes precede at most 1024 payload bytes.
///
/// Layout: scenario, scope, control, session ID (LE), offset (LE), mask,
/// payload. Missing bytes default to zero, including for the empty input.
struct FuzzInput<'a> {
    scenario: Scenario,
    scope: u8,
    control: u8,
    session_id: u16,
    offset: u16,
    mask: u8,
    extra: &'a [u8],
}

impl core::fmt::Debug for FuzzInput<'_> {
    /// Describe controls without exposing fuzz-derived private keys or TMKs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FuzzInput")
            .field("scenario", &self.scenario)
            .field("scope", &self.scope)
            .field("control", &self.control)
            .field("session_id", &self.session_id)
            .field("offset", &self.offset)
            .field("mask", &self.mask)
            .field("payload_len", &self.extra.len())
            .finish()
    }
}

impl<'a> Arbitrary<'a> for FuzzInput<'a> {
    /// Accept short inputs instead of starving expensive semantic scenarios.
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let data = u.bytes(u.len())?;
        let byte = |index| data.get(index).copied().unwrap_or(0);
        let scenario = match byte(0) % 48 {
            0..=11 => Scenario::Valid,
            12 => Scenario::ArbitrarySession,
            13 => Scenario::MismatchedSession,
            14 => Scenario::ClosedSession,
            15 => Scenario::DefaultCo,
            16 => Scenario::DefaultCu,
            17 => Scenario::CryptoUser,
            18 => Scenario::Uninitialized,
            19 => Scenario::Initializing,
            20 => Scenario::NoSecurityDomain,
            21 => Scenario::MissingOob,
            22 => Scenario::MaskedKeyFlip,
            23 => Scenario::RawMaskedKey,
            24 => Scenario::WrongKind,
            25 => Scenario::WrongReceiver,
            26 => Scenario::PolicyFlip,
            27 => Scenario::RawPolicy,
            28 => Scenario::PolicyInfo,
            29 => Scenario::SealedFlip,
            30 => Scenario::RawSealed,
            31 => Scenario::CiphertextFlip,
            32 => Scenario::WrongSender,
            33 => Scenario::DescriptorCount,
            34 => Scenario::DescriptorIndex,
            35 => Scenario::DescriptorLength,
            36 => Scenario::DescriptorOrder,
            37 => Scenario::ForeignAnchor,
            38 => Scenario::RawDer,
            39 => Scenario::TruncatedDer,
            40 => Scenario::ReindexedOob,
            41 => Scenario::ExtraOob,
            42 => Scenario::PolicyAndSealed,
            43 => Scenario::EncodeError,
            44 => Scenario::MaskedKeyScope,
            45 => Scenario::MissingOobItem,
            46 => Scenario::IvSuffix,
            _ => Scenario::SingleCertificate,
        };
        Ok(Self {
            scenario,
            scope: [
                common::KEY_SCOPE_EPHEMERAL,
                common::KEY_SCOPE_LOCAL,
                common::KEY_SCOPE_SECURITY_DOMAIN,
            ][byte(1) as usize % 3],
            control: byte(2),
            session_id: u16::from_le_bytes([byte(3), byte(4)]),
            offset: u16::from_le_bytes([byte(5), byte(6)]),
            mask: byte(7),
            extra: &data[data.len().min(8)..data.len().min(1032)],
        })
    }
}

impl FuzzInput<'_> {
    /// Fill an entire bounded field from fuzz bytes, with useful short defaults.
    fn bytes<const N: usize>(&self) -> [u8; N] {
        core::array::from_fn(|i| {
            self.extra
                .get(i % self.extra.len().max(1))
                .copied()
                .unwrap_or(i as u8 ^ self.mask)
        })
    }

    /// Build a nonzero, at-most-64-bit scalar below either curve's order.
    fn private_key(&self, curve: tsra_crypto::EccCurve, alternate: bool) -> EccPrivateKey {
        let seed = u64::from_le_bytes(self.bytes()) | 1;
        let seed = if alternate { seed ^ 2 } else { seed };
        let mut scalar = vec![0; curve.point_size()];
        let end = scalar.len();
        scalar[end - 8..].copy_from_slice(&seed.to_be_bytes());
        EccPrivateKey::from_scalar(curve, &scalar).expect("bounded nonzero scalar")
    }
}

/// Independent predictions distinguish firmware, host encoding, and transport errors.
#[derive(Clone, Copy, Debug)]
enum Expected {
    Success,
    Reject(TborStatus),
    EncodeError,
    InvalidParameter,
}

/// A request and its owning out-of-band certificate buffers.
struct Import {
    req: TborDarcTmkImportReq,
    items: Vec<Vec<u8>>,
}

/// Construct a decodable request for scenarios that reject before crypto.
fn dummy_request(session_id: u16) -> TborDarcTmkImportReq {
    TborDarcTmkImportReq {
        session_id,
        masked_kex_key: [0; MASKED_KEX_KEY_LEN],
        policy: PartPolicy::zeroed(),
        sealed_tmk: [0; SEALED_TMK_LEN],
        remote_cert_chain: vec![CertDescriptor {
            index: 0,
            length: 1u16.into(),
        }],
    }
}

/// Recover a host public key from independently reversed wire-LE coordinates.
fn receiver_public(wire: &[u8]) -> EccPublicKey {
    assert_eq!(wire.len(), RAW_PUB_LEN);
    let mut be = wire.to_vec();
    be[..common::COORD_LEN].reverse();
    be[common::COORD_LEN..].reverse();
    EccPublicKey::from_hsm_bytes(&be).expect("authentic receiver point")
}

/// Certify a fuzz-derived sender and seal the chosen TMK to a real receiver.
fn valid_import(
    ctx: &TestCtx,
    session_id: u16,
    fixture: &common::SecurityDomainFixture,
    input: &FuzzInput<'_>,
    tmk: &[u8; TMK_LEN],
) -> Import {
    let kex = ctx
        .tbor(&TborDarcKexKeyGenReq {
            session_id,
            scope: input.scope,
        })
        .expect("receiver key generation");
    let recipient = receiver_public(&kex.pub_key);
    let sender = input.private_key(tsra_crypto::EccCurve::P384, false);
    let (x, y) = sender.coord_vec().expect("sender coordinates");
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
    .expect("seal fuzz-derived TMK");
    let (ex, ey) = sealed.enc.coord_vec().expect("encapsulated coordinates");
    let mut sealed_tmk = [0; SEALED_TMK_LEN];
    sealed_tmk[0] = 4;
    sealed_tmk[1..1 + common::COORD_LEN].copy_from_slice(&ex);
    sealed_tmk[1 + common::COORD_LEN..SEC1_PUB_LEN].copy_from_slice(&ey);
    sealed_tmk[SEC1_PUB_LEN..].copy_from_slice(&sealed.ct);
    let mut items = Vec::new();
    let remote_cert_chain = chain
        .der_items()
        .iter()
        .map(|der| common::add_evidence_item(&mut items, der))
        .collect();
    Import {
        req: TborDarcTmkImportReq {
            session_id,
            masked_kex_key: kex.masked_key,
            policy: fixture.policy.clone(),
            sealed_tmk,
            remote_cert_chain,
        },
        items,
    }
}

/// Apply the common fixed-length XOR mutation without changing the array shape.
fn flip(bytes: &mut [u8], offset: u16, mask: u8) {
    let mut changed = bytes.to_vec();
    common::EnvelopeMutation::FlipByte { offset, mask }.apply(&mut changed);
    bytes.copy_from_slice(&changed);
}

/// Inspect unauthenticated framing and metadata without the firmware decoder.
fn masked_key_outcome(original: &[u8], changed: &[u8]) -> Expected {
    let prediction = || -> core::result::Result<(), TborStatus> {
        let env = inspect(changed).map_err(|_| TborStatus::InvalidArg)?;
        let meta = MaskedKeyMetadata::read_from_bytes(env.aad)
            .map_err(|_| TborStatus::MaskedKeyDecodeFailed)?;
        let label_len = usize::from(meta.key_label_len);
        if !env.payload.len().is_multiple_of(16)
            || meta.magic != META_MAGIC
            || meta.version.get() != META_VERSION_V1
            || label_len > KEY_LABEL_MAX
            || meta.data_pad_len > 15
            || meta._reserved.iter().any(|&b| b != 0)
            || meta.key_label[label_len..].iter().any(|&b| b != 0)
        {
            return Err(TborStatus::MaskedKeyDecodeFailed);
        }
        let scope = meta.usage_flags().scope().0;
        if !matches!(
            scope,
            common::KEY_SCOPE_EPHEMERAL
                | common::KEY_SCOPE_LOCAL
                | common::KEY_SCOPE_SECURITY_DOMAIN
        ) {
            return Err(TborStatus::UnsupportedKeyScope);
        }
        let baseline = inspect(original).expect("authentic receiver envelope");
        if env.iv[..GCM_NONCE_LEN] != baseline.iv[..GCM_NONCE_LEN]
            || env.aad != baseline.aad
            || env.payload != baseline.payload
            || env.tag != baseline.tag
        {
            return Err(TborStatus::AesGcmDecryptTagDoesNotMatch);
        }
        Ok(())
    };
    match prediction() {
        Ok(()) => Expected::Success,
        Err(status) => Expected::Reject(status),
    }
}

/// Predict SEC1/point errors before HPKE integrity, retaining byte-identical seals.
fn sealed_outcome(original: &[u8], changed: &[u8]) -> Expected {
    if original == changed {
        return Expected::Success;
    }
    if changed[0] != 4 {
        return Expected::Reject(TborStatus::InvalidArg);
    }
    let x = &changed[1..1 + common::COORD_LEN];
    let y = &changed[1 + common::COORD_LEN..SEC1_PUB_LEN];
    let curve = tsra_crypto::EccCurve::P384;
    if !curve.coordinate_in_range(x) || !curve.coordinate_in_range(y) {
        return Expected::Reject(TborStatus::EccPublicKeyValidationFailed);
    }
    if !EccPublicKey::is_on_curve(curve, x, y).expect("host point validation") {
        return Expected::Reject(TborStatus::EccPointValidationFailed);
    }
    Expected::Reject(TborStatus::AesGcmDecryptTagDoesNotMatch)
}

/// Classify descriptor changes referencing the two authentic baseline certificates.
///
/// Length mismatches fail before DER parsing. Repeating the root can validate
/// as a chain, but recovers the CA rather than the sender and fails HPKE Auth.
fn descriptor_outcome(import: &Import, original_items: &[Vec<u8>]) -> Expected {
    let descriptors = &import.req.remote_cert_chain;
    if !(1..=2).contains(&descriptors.len()) {
        return Expected::Reject(TborStatus::TborInvalidFixedLength);
    }
    let mut roots = Vec::new();
    for desc in descriptors {
        let Some(item) = import.items.get(usize::from(desc.index)) else {
            return Expected::Reject(TborStatus::InvalidArg);
        };
        if usize::from(desc.length.get()) != item.len() {
            return Expected::Reject(TborStatus::InvalidArg);
        }
        if item == &original_items[0] {
            roots.push(true);
        } else {
            assert!(
                item == &original_items[1],
                "descriptor oracle requires authentic DER"
            );
            roots.push(false);
        }
    }
    if !roots[0] {
        return Expected::Reject(TborStatus::X509NotSelfSigned);
    }
    if roots.len() == 1 {
        return Expected::Reject(TborStatus::InvalidArg);
    }
    if roots[1] {
        Expected::Reject(TborStatus::AesGcmDecryptTagDoesNotMatch)
    } else {
        Expected::Success
    }
}

/// Mutate one field while retaining preceding layers, then predict the outcome.
fn mutate(
    ctx: &TestCtx,
    import: &mut Import,
    fixture: &common::SecurityDomainFixture,
    input: &FuzzInput<'_>,
) -> Expected {
    let original = import.req.clone();
    let original_items = import.items.clone();
    let req = &mut import.req;
    match input.scenario {
        Scenario::MaskedKeyFlip | Scenario::IvSuffix => {
            let offset = if input.scenario == Scenario::IvSuffix {
                (HEADER_LEN + GCM_NONCE_LEN + usize::from(input.control % 4)) as u16
            } else {
                input.offset
            };
            flip(&mut req.masked_kex_key, offset, input.mask);
            return masked_key_outcome(&original.masked_kex_key, &req.masked_kex_key);
        }
        Scenario::RawMaskedKey => {
            req.masked_kex_key = input.bytes();
            return masked_key_outcome(&original.masked_kex_key, &req.masked_kex_key);
        }
        Scenario::MaskedKeyScope => {
            let at = HEADER_LEN
                + HostAeadAlg::AesGcm256.iv_len()
                + core::mem::offset_of!(MaskedKeyMetadata, usage_flags);
            let mut attrs =
                u64::from_le_bytes(req.masked_kex_key[at..at + 8].try_into().expect("attrs"));
            attrs = (attrs & !(7 << SCOPE_SHIFT)) | (u64::from(input.control & 7) << SCOPE_SHIFT);
            req.masked_kex_key[at..at + 8].copy_from_slice(&attrs.to_le_bytes());
            return masked_key_outcome(&original.masked_kex_key, &req.masked_kex_key);
        }
        Scenario::WrongKind => {
            req.masked_kex_key = ctx
                .tbor(&TborSdSealingKeyGenReq {
                    session_id: req.session_id,
                    scope: input.scope,
                })
                .expect("authentic wrong-kind key")
                .masked_key;
            return Expected::Reject(TborStatus::UnsupportedKeyType);
        }
        Scenario::WrongReceiver => {
            req.masked_kex_key = ctx
                .tbor(&TborDarcKexKeyGenReq {
                    session_id: req.session_id,
                    scope: input.scope,
                })
                .expect("second receiver key")
                .masked_key;
            return Expected::Reject(TborStatus::AesGcmDecryptTagDoesNotMatch);
        }
        Scenario::PolicyFlip
        | Scenario::PolicyInfo
        | Scenario::RawPolicy
        | Scenario::PolicyAndSealed => {
            let mut bytes = req.policy.as_bytes().to_vec();
            match input.scenario {
                Scenario::RawPolicy => bytes.copy_from_slice(&input.bytes::<PART_POLICY_LEN>()),
                Scenario::PolicyInfo => {
                    req.policy.info[usize::from(input.offset) % POLICY_INFO_LEN] ^=
                        input.mask.max(1);
                    return Expected::Reject(TborStatus::InvalidArg);
                }
                _ => flip(&mut bytes, input.offset, input.mask),
            }
            req.policy =
                PartPolicy::try_read_from_bytes(&bytes).expect("policy has byte-valid fields");
            if input.scenario == Scenario::PolicyAndSealed {
                flip(&mut req.sealed_tmk, input.offset, input.control);
            }
            return if req.policy != original.policy {
                Expected::Reject(TborStatus::InvalidArg)
            } else {
                sealed_outcome(&original.sealed_tmk, &req.sealed_tmk)
            };
        }
        Scenario::SealedFlip | Scenario::CiphertextFlip | Scenario::RawSealed => {
            if input.scenario == Scenario::RawSealed {
                req.sealed_tmk = input.bytes();
            } else {
                let offset = if input.scenario == Scenario::CiphertextFlip {
                    SEC1_PUB_LEN + usize::from(input.offset) % (SEALED_TMK_LEN - SEC1_PUB_LEN)
                } else {
                    usize::from(input.offset) % SEALED_TMK_LEN
                };
                flip(&mut req.sealed_tmk, offset as u16, input.mask);
            }
            return sealed_outcome(&original.sealed_tmk, &req.sealed_tmk);
        }
        Scenario::WrongSender | Scenario::ForeignAnchor => {
            let sender = input.private_key(
                tsra_crypto::EccCurve::P384,
                input.scenario == Scenario::WrongSender,
            );
            let (x, y) = sender.coord_vec().expect("alternate sender coordinates");
            let mut raw = [0; RAW_PUB_LEN];
            raw[..common::COORD_LEN].copy_from_slice(&x);
            raw[common::COORD_LEN..].copy_from_slice(&y);
            let foreign = CaKey::generate();
            let anchor = if input.scenario == Scenario::ForeignAnchor {
                &foreign
            } else {
                &fixture.pota
            };
            let chain = make_chain(anchor, &raw);
            import.items.clear();
            req.remote_cert_chain = chain
                .der_items()
                .iter()
                .map(|der| common::add_evidence_item(&mut import.items, der))
                .collect();
            return Expected::Reject(if input.scenario == Scenario::ForeignAnchor {
                TborStatus::InvalidArg
            } else {
                TborStatus::AesGcmDecryptTagDoesNotMatch
            });
        }
        Scenario::DescriptorCount | Scenario::SingleCertificate => {
            let count = if input.scenario == Scenario::SingleCertificate {
                1
            } else {
                usize::from(input.control % 5)
            };
            req.remote_cert_chain = (0..count)
                .map(|i| original.remote_cert_chain[i % 2])
                .collect();
        }
        Scenario::DescriptorIndex => {
            req.remote_cert_chain[usize::from(input.control % 2)].index = input.mask;
        }
        Scenario::DescriptorLength => {
            let selected = usize::from(input.control % 2);
            let exact = req.remote_cert_chain[selected].length.get();
            let lengths = [0, 1, exact - 1, exact, exact + 1, u16::MAX, input.offset];
            req.remote_cert_chain[selected].length =
                lengths[usize::from(input.control / 2) % lengths.len()].into();
        }
        Scenario::DescriptorOrder => {
            for (i, desc) in req.remote_cert_chain.iter_mut().enumerate() {
                *desc = original.remote_cert_chain[usize::from((input.control >> i) & 1)];
            }
        }
        Scenario::MissingOobItem => {
            import.items.truncate(usize::from(input.control % 2));
        }
        Scenario::ReindexedOob | Scenario::ExtraOob => {
            let padding = usize::from(input.control % 4);
            let mut items = vec![input.bytes::<32>().to_vec(); padding];
            if input.control & 4 != 0 {
                items.push(original_items[1].clone());
                items.push(original_items[0].clone());
                req.remote_cert_chain[0].index = (padding + 1) as u8;
                req.remote_cert_chain[1].index = padding as u8;
            } else {
                items.extend(original_items.iter().cloned());
                for desc in &mut req.remote_cert_chain {
                    desc.index += padding as u8;
                }
            }
            items.push(input.bytes::<32>().to_vec());
            import.items = items;
        }
        Scenario::RawDer | Scenario::TruncatedDer => {
            let index = usize::from(input.control % 2);
            let item = &mut import.items[index];
            if input.scenario == Scenario::RawDer {
                *item = input.bytes::<1024>()[..1 + usize::from(input.offset) % 1024].to_vec();
                item[0] = 0; // Guaranteed malformed Certificate SEQUENCE, not arbitrary harmless edits.
            } else {
                item.truncate(usize::from(input.offset) % item.len());
            }
            req.remote_cert_chain[index].length = (item.len() as u16).into();
            // The socket transport rejects empty OOB buffers before firmware runs.
            if item.is_empty() && tsra_ddi::sock_selected() {
                return Expected::InvalidParameter;
            }
            return Expected::Reject(if item.is_empty() {
                TborStatus::InvalidArg
            } else {
                TborStatus::X509ParseError
            });
        }
        _ => return Expected::Success,
    }
    descriptor_outcome(import, &original_items)
}

/// Inspect output shape and canonical public metadata without logging secrets.
fn assert_envelope(masked: &[u8]) {
    assert_eq!(masked.len(), MASKED_TMK_LEN);
    let env = inspect(masked).expect("TMK envelope framing");
    assert_eq!(env.payload.len(), TMK_LEN);
    let meta = MaskedKeyMetadata::read_from_bytes(env.aad).expect("TMK metadata size");
    assert_eq!(meta.magic, META_MAGIC);
    assert_eq!(meta.version.get(), META_VERSION_V1);
    assert_eq!(meta.key_kind, DARC_TMK_KIND);
    assert_eq!(meta.key_label().expect("TMK label"), b"DarcTmk");
    assert!(
        meta.key_label[usize::from(meta.key_label_len)..]
            .iter()
            .all(|&b| b == 0)
    );
    assert_eq!(meta.data_pad_len, 0);
    assert!(meta._reserved.iter().all(|&b| b == 0));
    let expected_attrs = (1 << 2)
        | (1 << 5)
        | (1 << 7)
        | (1 << 16)
        | (u64::from(common::KEY_SCOPE_SECURITY_DOMAIN) << SCOPE_SHIFT);
    assert_eq!(meta.usage_flags.get(), expected_attrs);
}

/// Unwrap a host-known P-256 key to prove the imported TMK's plaintext value.
fn assert_plaintext(
    ctx: &TestCtx,
    session_id: u16,
    masked: &[u8],
    tmk: &[u8; TMK_LEN],
    input: &FuzzInput<'_>,
) {
    let key = input.private_key(tsra_crypto::EccCurve::P256, false);
    let (x, y) = key.coord_vec().expect("known P-256 coordinates");
    let seed = u64::from_le_bytes(input.bytes()) | 1;
    let mut scalar = [0; 32];
    scalar[24..].copy_from_slice(&seed.to_be_bytes());
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(8).expect("COSE map");
    enc.i8(1).and_then(|e| e.u8(2)).expect("EC2");
    enc.i8(2).and_then(|e| e.bytes(&[])).expect("key ID");
    enc.i8(3).and_then(|e| e.i8(-9)).expect("ESP256");
    enc.i8(4)
        .and_then(|e| e.array(2))
        .and_then(|e| e.u8(1))
        .and_then(|e| e.u8(2))
        .expect("sign/verify operations");
    enc.i8(-1).and_then(|e| e.u8(1)).expect("P-256");
    for (label, bytes) in [
        (-2, x.as_slice()),
        (-3, y.as_slice()),
        (-4, scalar.as_slice()),
    ] {
        enc.i8(label)
            .and_then(|e| e.bytes(bytes))
            .expect("COSE key component");
    }
    let aes = AesKey::from_bytes(tmk).expect("known TMK");
    let wrapped_key =
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &aes, &enc.into_writer())
            .expect("wrap known key under chosen TMK");
    let resp = ctx
        .tbor(&TborDarcKeyUnwrapReq {
            session_id,
            scope: common::KEY_SCOPE_LOCAL,
            key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
            masked_tmk: masked.try_into().expect("TMK envelope length"),
            wrapped_key,
        })
        .expect("imported TMK must unwrap host-known material");
    assert_eq!(resp.key_kind, KEY_KIND_ECC256_PRIVATE);
    let expected_pub = x
        .iter()
        .rev()
        .chain(y.iter().rev())
        .copied()
        .collect::<Vec<_>>();
    assert!(
        resp.pub_key == expected_pub,
        "recovered public key mismatch"
    );
    assert!(!resp.masked_key.is_empty());
}

/// Submit exactly once and compare the result against the precomputed oracle.
fn check(
    ctx: &TestCtx,
    import: &Import,
    expected: Expected,
    input: &FuzzInput<'_>,
    tmk: &[u8; TMK_LEN],
) {
    let oob = import.items.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let result = if input.scenario == Scenario::MissingOob {
        ctx.tbor(&import.req)
    } else {
        ctx.tbor_oob(&import.req, &oob)
    };
    match expected {
        Expected::Success => {
            let resp =
                result.unwrap_or_else(|err| panic!("valid {:?} failed: {err:?}", input.scenario));
            assert_envelope(&resp.masked_tmk);
            assert_plaintext(ctx, import.req.session_id, &resp.masked_tmk, tmk, input);
            if input.control == u8::MAX {
                let again = ctx
                    .tbor_oob(&import.req, &oob)
                    .expect("repeat valid import");
                assert_envelope(&again.masked_tmk);
                assert!(
                    again.masked_tmk != resp.masked_tmk,
                    "masking IV must be fresh"
                );
            }
        }
        Expected::Reject(status) => {
            let err = result.expect_err("invalid import must fail");
            assert_session_rejects(&err, status);
        }
        Expected::EncodeError => {
            assert!(
                matches!(result, Err(DdiError::TborEncodeError)),
                "host encoding must fail"
            );
        }
        Expected::InvalidParameter => {
            assert!(
                matches!(result, Err(DdiError::InvalidParameter)),
                "transport must reject empty OOB buffers"
            );
        }
    }
}

/// Run isolated early gates cheaply; provision real crypto only for deep lanes.
fn run(ctx: &TestCtx, input: &FuzzInput<'_>) {
    let session = match input.scenario {
        Scenario::DefaultCo => ctx
            .open_session(CO_PSK_ID, SessionType::Authenticated)
            .expect("default CO session"),
        Scenario::DefaultCu => ctx
            .open_session(CU_PSK_ID, SessionType::PlainText)
            .expect("default CU session"),
        Scenario::CryptoUser => SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK)),
        _ => SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK)),
    };
    let id = session.session_id();
    let tmk = input.bytes();
    let mut import = Import {
        req: dummy_request(id),
        items: Vec::new(),
    };
    let early = match input.scenario {
        Scenario::DefaultCo | Scenario::DefaultCu => Some(TborStatus::DefaultPskMustRotate),
        Scenario::CryptoUser => Some(TborStatus::InvalidPermissions),
        Scenario::Uninitialized => Some(TborStatus::InvalidArg),
        Scenario::Initializing => {
            let pota = CaKey::generate();
            ctx.part_init(
                session.handshake(),
                &common::mach_seed(),
                &common::known_good_part_policy(pota.raw_pub()),
                &common::pota_thumbprint(),
            )
            .expect("initialize without finalizing");
            Some(TborStatus::InvalidArg)
        }
        Scenario::NoSecurityDomain => {
            common::finalize_partition(ctx, session.handshake());
            Some(TborStatus::InvalidArg)
        }
        Scenario::MismatchedSession => {
            import.req.session_id = id ^ 1;
            Some(TborStatus::FileHandleSessionIdDoesNotMatch)
        }
        Scenario::ArbitrarySession if input.session_id != id => {
            import.req.session_id = input.session_id;
            Some(TborStatus::FileHandleSessionIdDoesNotMatch)
        }
        Scenario::ClosedSession => {
            session.close().expect("close before request");
            check(
                ctx,
                &import,
                Expected::Reject(TborStatus::SessionNotFound),
                input,
                &tmk,
            );
            return;
        }
        Scenario::EncodeError => {
            import.req.remote_cert_chain =
                vec![
                    import.req.remote_cert_chain[0];
                    MAX_DATA_SIZE / core::mem::size_of::<CertDescriptor>() + 1
                ];
            check(ctx, &import, Expected::EncodeError, input, &tmk);
            return;
        }
        _ => None,
    };
    if let Some(status) = early {
        check(ctx, &import, Expected::Reject(status), input, &tmk);
        return;
    }
    let fixture = common::create_test_security_domain_with_policy(ctx, session.handshake());
    import = valid_import(ctx, id, &fixture, input, &tmk);
    let expected = if input.scenario == Scenario::MissingOob {
        Expected::Reject(TborStatus::InvalidArg)
    } else {
        mutate(ctx, &mut import, &fixture, input)
    };
    check(ctx, &import, expected, input, &tmk);
}

fuzz_target!(|input: FuzzInput<'_>| {
    common::common_fuzz_test(&|ctx, _path| run(ctx, &input));
});
