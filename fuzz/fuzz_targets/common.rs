// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared types and helpers for TBOR fuzz targets.

#![allow(dead_code)]

// Starts a private in-process DDI sock server before the fuzzer's `main`;
// libFuzzer `-jobs`/`-fork` workers each get their own.
use ddi_sock_server as _;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use tsra_crypto::AesKey;
use tsra_crypto::aead_envelope::AeadAlg;
use tsra_crypto::aead_envelope::{self};
use tsra_ddi::TsraDdi;
use tsra_ddi_interface::Ddi;
use tsra_ddi_tbor_codec::Encoder;
use tsra_ddi_tbor_codec::Header;
use tsra_ddi_tbor_codec::MAX_DATA_SIZE;
use tsra_ddi_tbor_codec::MAX_TOC_ENTRIES;
use tsra_ddi_tbor_codec::REQ_HEADER_LEN;
use tsra_ddi_tbor_codec::RESP_HEADER_LEN;
use tsra_ddi_tbor_codec::TOC_ENTRY_LEN;
use tsra_ddi_tbor_codec::TocEntry;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::CU_PSK_ID as CU;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::TestPolicy;
use tsra_ddi_tbor_test_harness::coord_sizes;
use tsra_ddi_tbor_test_harness::policy::TestBackupPart;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use tsra_ddi_tbor_test_harness::x509_fixture::make_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::spki_thumbprint;
use tsra_ddi_tbor_types::AES_KEY_SIZE_128;
use tsra_ddi_tbor_types::AES_KEY_SIZE_192;
use tsra_ddi_tbor_types::AES_KEY_SIZE_256;
use tsra_ddi_tbor_types::CertDescriptor;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::ECC_CURVE_P384;
use tsra_ddi_tbor_types::ECC_CURVE_P521;
use tsra_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use tsra_ddi_tbor_types::MACH_SEED_ENVELOPE_MAX_LEN;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_ddi_tbor_types::PART_POLICY_MAX_LEN;
use tsra_ddi_tbor_types::POLICY_BACKUP_PART_ID_LEN;
use tsra_ddi_tbor_types::POLICY_INFO_MAX_LEN;
use tsra_ddi_tbor_types::POLICY_THUMBPRINT_LEN;
use tsra_ddi_tbor_types::POLICY_VERSION;
use tsra_ddi_tbor_types::PolicyFlags;
use tsra_ddi_tbor_types::PolicyKey;
use tsra_ddi_tbor_types::ReportDescriptor;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborKeyReportReq;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use tsra_ddi_tbor_types::TborSdSealingKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;

pub type DdiTest = TsraDdi;

pub const COORD_LEN: usize = RAW_PUB_LEN / 2;

const MACH_SEED_PATTERN_BASE: u8 = 0x40;
const SATA_THUMBPRINT_PATTERN_BASE: u8 = 0x20;
const POLICY_INFO_FILL: u8 = 0xAB;

/// Wire discriminants for the TBOR `KeyScope` enum.
pub const KEY_SCOPE_UNSPECIFIED: u8 = 0b000;
pub const KEY_SCOPE_SESSION: u8 = 0b001;
pub const KEY_SCOPE_EPHEMERAL: u8 = 0b010;
pub const KEY_SCOPE_LOCAL: u8 = 0b011;
pub const KEY_SCOPE_SECURITY_DOMAIN: u8 = 0b100;
pub const KEY_SCOPE_INTERNAL: u8 = 0b101;

/// Map an arbitrary byte to a known TBOR `KeyScope` wire discriminant.
pub fn derive_valid_key_scope(key_scope: u8) -> u8 {
    key_scope % (KEY_SCOPE_INTERNAL + 1)
}

/// TBOR key scopes (wire `KeyScope` discriminants) used by fuzz targets.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScope {
    Unspecified,
    Session,
    Ephemeral,
    Local,
    SecurityDomain,
    Internal,
}

impl KeyScope {
    pub fn to_tbor(self) -> u8 {
        match self {
            Self::Unspecified => KEY_SCOPE_UNSPECIFIED,
            Self::Session => KEY_SCOPE_SESSION,
            Self::Ephemeral => KEY_SCOPE_EPHEMERAL,
            Self::Local => KEY_SCOPE_LOCAL,
            Self::SecurityDomain => KEY_SCOPE_SECURITY_DOMAIN,
            Self::Internal => KEY_SCOPE_INTERNAL,
        }
    }
}

/// Fuzz operations corresponding to the TOC builder methods on
/// [`Encoder`].
#[derive(Arbitrary, Debug)]
pub enum EncoderTOCBuilders {
    SessionId(u16),
    KeyId(u16),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Buffer(Vec<u8>),
    BufferReserve(u16),
    SealedKey(Vec<u8>),
    None,
    Padding(u16),
}

/// Which role's session to open for this iteration.
#[derive(Arbitrary, Debug)]
pub enum FuzzRole {
    /// `psk_id = 0`, `SessionType::Authenticated`
    Co,
    /// `psk_id = 1`, `SessionType::PlainText`
    Cu,
}

impl FuzzRole {
    pub fn psk_id(&self) -> u8 {
        match self {
            FuzzRole::Co => CO,
            FuzzRole::Cu => CU,
        }
    }

    pub fn session_type(&self) -> SessionType {
        match self {
            FuzzRole::Co => SessionType::Authenticated,
            FuzzRole::Cu => SessionType::PlainText,
        }
    }
}

/// TBOR ECC curves (wire `EccCurve` discriminants) for generated keys.
///
/// Shadows the `tsra_crypto::EccCurve` glob import within this module.
#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum EccCurve {
    P256,
    P384,
    P521,
}

impl EccCurve {
    pub fn to_tbor(self) -> u8 {
        match self {
            Self::P256 => ECC_CURVE_P256,
            Self::P384 => ECC_CURVE_P384,
            Self::P521 => ECC_CURVE_P521,
        }
    }

    /// Raw (unpadded) coordinate length in bytes; also the length of an
    /// ECDH shared secret (the X coordinate).
    pub fn coord_len(self) -> usize {
        coord_sizes(self.wire_pub_key_len()).1
    }

    /// Wire coordinate length in bytes, including padding (P-521: 66 -> 68 bytes).
    pub fn wire_coord_len(self) -> usize {
        coord_sizes(self.wire_pub_key_len()).0
    }

    /// Largest digest the firmware zero-extends into the ECDSA field.
    pub fn max_digest_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 64,
        }
    }

    /// Wire `r ‖ s` length, each component padded to the coordinate width.
    pub fn wire_sig_len(self) -> usize {
        coord_sizes(self.wire_pub_key_len()).0 * 2
    }

    /// Wire `x ‖ y` public-key length, each coordinate padded to the wire
    /// coordinate width (P-521: 66 -> 68 bytes).
    pub fn wire_pub_key_len(self) -> usize {
        match self {
            Self::P256 => 64,
            Self::P384 => 96,
            Self::P521 => 136,
        }
    }
}

/// TBOR AES key sizes supported by `AesGenerateKey`.
#[derive(Arbitrary, Debug)]
pub enum AesKeySize {
    Aes128,
    Aes192,
    Aes256,
}

impl AesKeySize {
    pub fn to_tbor(&self) -> u8 {
        match self {
            Self::Aes128 => AES_KEY_SIZE_128,
            Self::Aes192 => AES_KEY_SIZE_192,
            Self::Aes256 => AES_KEY_SIZE_256,
        }
    }
}

fn bounded_appended_bytes(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = usize::arbitrary(u)? % (MACH_SEED_ENVELOPE_MAX_LEN + 1);
    Ok(u.bytes(len)?.to_vec())
}

/// Post-seal mutation applied to a wire-valid `PartInit`
/// `mach_seed_envelope`.
///
/// `None` ships the sealed envelope untouched so the handler advances
/// past AEAD authentication into the policy / thumbprint / seed
/// pipeline. The other variants exercise the envelope parser's header,
/// AAD, ciphertext, tag, and length-reject paths without leaving them
/// buried under negligible-probability arbitrary-byte inputs.
#[derive(Arbitrary, Debug)]
pub enum EnvelopeMutation {
    /// Ship the sealed envelope unchanged.
    None,
    /// XOR a fuzzed mask into a fuzzed offset (offset wrapped modulo
    /// envelope length). Exercises AEAD tag / ciphertext tampering.
    FlipByte { offset: u16, mask: u8 },
    /// Truncate to `len % (envelope.len() + 1)` bytes. Exercises
    /// short-envelope rejects and post-decrypt length checks.
    Truncate { len: u16 },
    /// Append fuzzed trailing bytes (bounded) to exercise over-length
    /// rejects.
    Append(#[arbitrary(with = bounded_appended_bytes)] Vec<u8>),
}

impl EnvelopeMutation {
    pub fn apply(&self, envelope: &mut Vec<u8>) {
        match self {
            EnvelopeMutation::None => {}
            EnvelopeMutation::FlipByte { offset, mask } => {
                if !envelope.is_empty() && *mask != 0 {
                    let idx = (*offset as usize) % envelope.len();
                    envelope[idx] ^= *mask;
                }
            }
            EnvelopeMutation::Truncate { len } => {
                let cap = envelope.len() + 1;
                envelope.truncate((*len as usize) % cap);
            }
            EnvelopeMutation::Append(extra) => {
                envelope.extend_from_slice(extra);
            }
        }
    }

    /// `true` iff this mutation would leave the sealed envelope byte-
    /// identical (matches the `None` variant or a no-op offset/mask/len/
    /// extra choice inside a mutation variant). Drives the "expect
    /// success" classification for the result assertion.
    pub fn is_noop(&self, envelope: &[u8]) -> bool {
        match self {
            EnvelopeMutation::None => true,
            EnvelopeMutation::FlipByte { mask, .. } => *mask == 0 || envelope.is_empty(),
            EnvelopeMutation::Truncate { len } => {
                // `Vec::truncate(new_len)` only shrinks when `new_len <
                // envelope.len()`; `apply` computes
                // `len % (envelope.len() + 1)` so a no-op requires the
                // modulo to land on `envelope.len()`.
                (*len as usize) % (envelope.len() + 1) == envelope.len()
            }
            EnvelopeMutation::Append(extra) => extra.is_empty(),
        }
    }
}

/// Buffer size used by request encoder fuzz targets.
///
/// Sized to hold the worst-case request: a full header, the maximum number
/// of TOC entries (each a 4-byte / `u32` wire word), and the maximum data
/// section.
pub const FUZZ_REQ_BUF_SIZE: usize =
    REQ_HEADER_LEN + MAX_TOC_ENTRIES * TOC_ENTRY_LEN + MAX_DATA_SIZE;

/// Buffer size used by response encoder fuzz targets.
pub const FUZZ_RESP_BUF_SIZE: usize =
    RESP_HEADER_LEN + MAX_TOC_ENTRIES * TOC_ENTRY_LEN + MAX_DATA_SIZE;

static mut DEVICE_DISPLAY: bool = false;

pub fn common_fuzz_test(test: &dyn Fn(&TestCtx, &str)) {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();
    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    let path = match std::env::var("FUZZ_DEVICE") {
        Ok(path) => path,
        Err(_) => dev_infos.first().unwrap().path.clone(),
    };

    // Display all device paths and the selected device path if it hasn't been
    // displayed yet.
    unsafe {
        if !DEVICE_DISPLAY {
            for dev_info in &dev_infos {
                println!("Found device: {}", dev_info.path);
            }
            println!("Selected device: {}", path);
            DEVICE_DISPLAY = true;
        }
    }

    let ctx = TestCtx::new_primary_with_path(&path);

    test(&ctx, &path);
}

/// Two-phase AES-GCM-256 AEAD seal: size-query, allocate, then fill
pub fn seal_aead_envelope(key: &AesKey, iv: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let total = aead_envelope::seal(AeadAlg::AesGcm256, key, iv, aad, pt, None)
        .expect("aead seal size query should succeed");
    let mut buf = vec![0u8; total];
    let written = aead_envelope::seal(AeadAlg::AesGcm256, key, iv, aad, pt, Some(&mut buf))
        .expect("aead seal should succeed");
    buf.truncate(written);
    buf
}

/// Apply a sequence of TOC builder operations to an encoder, returning
/// the encoded bytes on success or `None` if any step (including
/// [`Encoder::finish`]) fails.
pub fn run_encoder<'a, H: Header>(
    mut encoder: Encoder<'a, H>,
    ops: &[EncoderTOCBuilders],
) -> Option<&'a [u8]> {
    for op in ops {
        let result = match op {
            EncoderTOCBuilders::SessionId(id) => encoder.session_id(*id),
            EncoderTOCBuilders::KeyId(id) => encoder.key_id(*id),
            EncoderTOCBuilders::Uint8(v) => encoder.uint8(*v),
            EncoderTOCBuilders::Uint16(v) => encoder.uint16(*v),
            EncoderTOCBuilders::Uint32(v) => encoder.uint32(*v),
            EncoderTOCBuilders::Uint64(v) => encoder.uint64(*v),
            EncoderTOCBuilders::Buffer(data) => encoder.buffer(data),
            EncoderTOCBuilders::BufferReserve(len) => encoder.buffer_reserve(*len as usize),
            EncoderTOCBuilders::SealedKey(data) => encoder.sealed_key(data),
            EncoderTOCBuilders::None => encoder.none(),
            EncoderTOCBuilders::Padding(len) => encoder.padding(*len as usize),
        };
        match result {
            Ok(enc) => encoder = enc,
            Err(_) => return None,
        }
    }

    encoder.finish().ok()
}

pub fn validate_toc_entry(op: &EncoderTOCBuilders, entry: TocEntry<'_>) {
    match (op, entry) {
        (EncoderTOCBuilders::SessionId(expected), TocEntry::SessionId(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::KeyId(expected), TocEntry::KeyId(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint8(expected), TocEntry::Uint8(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint16(expected), TocEntry::Uint16(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint32(expected), TocEntry::Uint32(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint64(expected), TocEntry::Uint64(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Buffer(expected), TocEntry::Buffer(actual)) => {
            assert_eq!(expected, actual);
        }
        (EncoderTOCBuilders::BufferReserve(expected), TocEntry::Buffer(actual)) => {
            assert_eq!(usize::from(*expected), actual.len());
        }
        (EncoderTOCBuilders::SealedKey(expected), TocEntry::SealedKey(actual)) => {
            assert_eq!(expected, actual);
        }
        (EncoderTOCBuilders::None, TocEntry::None) => {}
        (EncoderTOCBuilders::Padding(expected), TocEntry::Padding(actual)) => {
            assert_eq!(usize::from(*expected), actual.len());
            assert!(actual.iter().all(|byte| *byte == 0));
        }
        (expected, actual) => panic!("operation {expected:?} decoded as {actual:?}"),
    }
}

/// Fixed `PartInit` machine seed (`0x40 + i`), mirroring the canonical
/// fixture used by the `PartInit` integration suite.
pub fn mach_seed() -> [u8; MACH_SEED_LEN] {
    core::array::from_fn(|i| MACH_SEED_PATTERN_BASE + i as u8)
}

/// Deterministic synthetic thumbprint `fill + i`, for policy slots whose
/// chain the fuzz target never walks.
pub fn pattern_thumbprint(fill: u8) -> [u8; POLICY_THUMBPRINT_LEN] {
    core::array::from_fn(|i| fill.wrapping_add(i as u8))
}

/// Known-good partition policy: version 1, the given POTA thumbprint, a
/// synthetic SATA thumbprint and a full-length `info` field. SAPOTA, backup
/// partition and DATA are absent.
///
/// `PartFinal` fuzz targets pass the real CA's thumbprint (via
/// `CaKey::spki_thumbprint`) so the cert-chain walk anchors against it;
/// `PartInit`-only fuzz targets may pass [`pattern_thumbprint`].
pub fn known_good_test_policy(pota_spki_thumbprint: [u8; POLICY_THUMBPRINT_LEN]) -> TestPolicy {
    TestPolicy::new(
        pota_spki_thumbprint,
        pattern_thumbprint(SATA_THUMBPRINT_PATTERN_BASE),
    )
    .with_info(&[POLICY_INFO_FILL; POLICY_INFO_MAX_LEN])
}

/// Deterministic CBOR encoding of [`known_good_test_policy`].
pub fn known_good_part_policy(pota_spki_thumbprint: [u8; POLICY_THUMBPRINT_LEN]) -> Vec<u8> {
    known_good_test_policy(pota_spki_thumbprint).encode()
}

/// [`known_good_test_policy`] anchored to `pota` and `sata` and naming the
/// partition (`pid`, raw big-endian `pid_pub`) as its backing partition.
pub fn backup_test_policy(
    pota: &CaKey,
    sata: &CaKey,
    pid: &[u8],
    pid_pub: &[u8; RAW_PUB_LEN],
) -> TestPolicy {
    let pid: [u8; POLICY_BACKUP_PART_ID_LEN] = pid
        .try_into()
        .expect("PartInfo PID should have the policy length");
    let mut policy = known_good_test_policy(pota.spki_thumbprint())
        .with_backup_part(pid, spki_thumbprint(pid_pub));
    policy.sata_spki_thumbprint = sata.spki_thumbprint();
    policy
}

/// Fuzzed field values for [`FuzzPolicy::Structured`]; out-of-range `flags`
/// or `info` lengths yield a schema-invalid document.
#[derive(Arbitrary, Debug)]
pub struct StructuredPolicy {
    pub pota: [u8; POLICY_THUMBPRINT_LEN],
    pub sata: [u8; POLICY_THUMBPRINT_LEN],
    pub sapota: Option<[u8; POLICY_THUMBPRINT_LEN]>,
    pub backup_part: Option<([u8; POLICY_BACKUP_PART_ID_LEN], [u8; POLICY_THUMBPRINT_LEN])>,
    pub flags: u8,
    pub info: Option<Vec<u8>>,
    pub data: Option<[u8; POLICY_THUMBPRINT_LEN]>,
}

/// Fuzzed partition policy document for `PartInit`-style requests.
#[derive(Arbitrary, Debug)]
pub enum FuzzPolicy {
    /// [`known_good_part_policy`] with a synthetic POTA thumbprint.
    KnownGood,
    /// Canonically encoded policy built from fuzzed field values.
    Structured(Box<StructuredPolicy>),
    /// Arbitrary bytes, exercising the firmware CBOR decoder directly.
    Raw(Vec<u8>),
}

impl FuzzPolicy {
    /// Wire bytes of the fuzzed policy document.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::KnownGood => known_good_part_policy(pattern_thumbprint(0x10)),
            Self::Structured(p) => TestPolicy {
                flags: u64::from(p.flags),
                sapota_spki_thumbprint: p.sapota,
                backup_part: p.backup_part.map(|(id, spki_thumbprint)| TestBackupPart {
                    id,
                    spki_thumbprint,
                }),
                info: p.info.clone(),
                data_spki_thumbprint: p.data,
                ..TestPolicy::new(p.pota, p.sata)
            }
            .encode(),
            Self::Raw(bytes) => bytes.clone(),
        }
    }
}

/// XOR `mask` into the final byte of an encoded policy. The last field of
/// every fixture policy is a byte string, so the document stays canonical
/// and schema-valid while its hash no longer matches the bound policy.
pub fn mutate_policy_tail(policy: &mut [u8], mask: u8) {
    *policy.last_mut().expect("encoded policy must be non-empty") ^= mask;
}

/// Host-side mirror of the firmware policy decoder: `bytes` is accepted iff
/// it decodes to a schema-valid policy whose deterministic re-encoding is
/// byte-identical (which rejects non-canonical heads, unordered, duplicate
/// or unknown keys, indefinite lengths and trailing bytes).
pub fn is_valid_part_policy(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= PART_POLICY_MAX_LEN
        && decode_test_policy(bytes).is_some_and(|policy| policy.encode() == bytes)
}

fn decode_test_policy(bytes: &[u8]) -> Option<TestPolicy> {
    fn array<const N: usize>(d: &mut minicbor::Decoder<'_>) -> Option<[u8; N]> {
        d.bytes().ok()?.try_into().ok()
    }

    let mut d = minicbor::Decoder::new(bytes);
    let entries = d.map().ok()??;
    let mut version = None;
    let mut pota = None;
    let mut sata = None;
    let mut sapota = None;
    let mut backup_id = None;
    let mut backup_thumbprint = None;
    let mut flags = None;
    let mut info = None;
    let mut data = None;
    for _ in 0..entries {
        match d.u64().ok()? {
            k if k == PolicyKey::Version as u64 => version = Some(d.u64().ok()?),
            k if k == PolicyKey::PotaSpkiThumbprint as u64 => pota = Some(array(&mut d)?),
            k if k == PolicyKey::SataSpkiThumbprint as u64 => sata = Some(array(&mut d)?),
            k if k == PolicyKey::SapotaSpkiThumbprint as u64 => sapota = Some(array(&mut d)?),
            k if k == PolicyKey::BackupPartId as u64 => backup_id = Some(array(&mut d)?),
            k if k == PolicyKey::BackupPartSpkiThumbprint as u64 => {
                backup_thumbprint = Some(array(&mut d)?)
            }
            k if k == PolicyKey::Flags as u64 => flags = Some(d.u64().ok()?),
            k if k == PolicyKey::Info as u64 => info = Some(d.bytes().ok()?.to_vec()),
            k if k == PolicyKey::DataSpkiThumbprint as u64 => data = Some(array(&mut d)?),
            _ => return None,
        }
    }

    let version = version.filter(|v| *v == u64::from(POLICY_VERSION))?;
    let flags = flags.filter(|f| *f <= u64::from(PolicyFlags::KNOWN_MASK))?;
    if info
        .as_ref()
        .is_some_and(|i| i.is_empty() || i.len() > POLICY_INFO_MAX_LEN)
    {
        return None;
    }
    let backup_part = match (backup_id, backup_thumbprint) {
        (Some(id), Some(spki_thumbprint)) => Some(TestBackupPart {
            id,
            spki_thumbprint,
        }),
        (None, None) => None,
        _ => return None,
    };
    Some(TestPolicy {
        version,
        pota_spki_thumbprint: pota?,
        sata_spki_thumbprint: sata?,
        sapota_spki_thumbprint: sapota,
        backup_part,
        flags,
        info,
        data_spki_thumbprint: data,
    })
}

/// Drive `PartInit` → `PartFinal` so partition-local masking keys are available.
pub fn finalize_partition(ctx: &TestCtx, session: &SessionHandshake) {
    let pota = CaKey::generate();
    let policy = known_good_part_policy(pota.spki_thumbprint());
    let init = ctx
        .part_init(session, &mach_seed(), &policy)
        .expect("PartInit should succeed");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy, &[], &chain.der_items())
        .expect("PartFinal should succeed");
}

pub fn add_evidence_item(oob_items: &mut Vec<Vec<u8>>, der: &[u8]) -> CertDescriptor {
    let index = u8::try_from(oob_items.len()).expect("evidence count fits descriptor index");
    let length = u16::try_from(der.len()).expect("evidence item length fits descriptor");
    oob_items.push(der.to_vec());
    CertDescriptor {
        index,
        length: length.into(),
    }
}

/// Initialize a partition and security domain so security-domain masking is available.
pub fn create_test_security_domain(ctx: &TestCtx, session: &SessionHandshake) {
    let _ = create_test_security_domain_with_policy(ctx, session);
}

/// Retained trust anchor and policy for commands that authenticate DARC imports.
pub struct SecurityDomainFixture {
    pub pota: CaKey,
    pub policy: Vec<u8>,
}

/// Initialize the security domain and retain its exact policy and POTA signer.
pub fn create_test_security_domain_with_policy(
    ctx: &TestCtx,
    session: &SessionHandshake,
) -> SecurityDomainFixture {
    let info = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo should succeed");
    let pid_pub: [u8; RAW_PUB_LEN] = info
        .pid_pub_key
        .as_slice()
        .try_into()
        .expect("PartInfo PID public key should have the expected length");
    let pota = CaKey::generate();
    let sata = CaKey::generate();
    let policy = backup_test_policy(&pota, &sata, &info.pid, &pid_pub).encode();

    let init = ctx
        .part_init(session, &mach_seed(), &policy)
        .expect("PartInit should succeed");
    let pta_chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy, &[], &pta_chain.der_items())
        .expect("PartFinal should succeed");

    let sealing_key = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id: session.session_id,
            scope: KEY_SCOPE_LOCAL,
        })
        .expect("local SD sealing-key generation should succeed");
    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: sealing_key.masked_key.to_vec(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
            auth_envelope: Vec::new(),
        })
        .expect("sealing-key report generation should succeed");

    let mut receiver_pub = [0u8; RAW_PUB_LEN];
    let coord_len = EccCurve::P384.coord_len();
    for (dst, src) in receiver_pub[..coord_len]
        .iter_mut()
        .zip(sealing_key.pub_key[..coord_len].iter().rev())
    {
        *dst = *src;
    }
    for (dst, src) in receiver_pub[coord_len..]
        .iter_mut()
        .zip(sealing_key.pub_key[coord_len..].iter().rev())
    {
        *dst = *src;
    }
    let receiver = make_chain(&sata, &receiver_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let partition_owner = make_chain(&sata, &pid_pub);
    let mut oob_items = Vec::new();
    let receiver_chain = vec![
        add_evidence_item(&mut oob_items, &receiver.root_der),
        add_evidence_item(&mut oob_items, &receiver.leaf_der),
    ];
    let mfgr_chain = vec![
        add_evidence_item(&mut oob_items, &mfgr.root_der),
        add_evidence_item(&mut oob_items, &mfgr.leaf_der),
    ];
    let owner_chain = vec![
        add_evidence_item(&mut oob_items, &owner.root_der),
        add_evidence_item(&mut oob_items, &owner.leaf_der),
    ];
    let partition_owner_chain = vec![
        add_evidence_item(&mut oob_items, &partition_owner.root_der),
        add_evidence_item(&mut oob_items, &partition_owner.leaf_der),
    ];
    let report_descriptor = add_evidence_item(&mut oob_items, &report.report);
    let oob = oob_items.iter().map(Vec::as_slice).collect::<Vec<_>>();

    let req = TborSdCreateRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: sealing_key.masked_key,
        receiver_cert_chain: receiver_chain,
        receiver_mfgr_cert_chain: mfgr_chain,
        receiver_owner_cert_chain: owner_chain,
        receiver_part_owner_cert_chain: partition_owner_chain,
        receiver_report: ReportDescriptor {
            index: report_descriptor.index,
            length: report_descriptor.length,
        },
        policy: policy.clone(),
    };
    ctx.tbor_oob(&req, &oob)
        .expect("test security-domain creation should succeed");
    SecurityDomainFixture { pota, policy }
}

/// Exercise key scopes that cannot be used by the backup fixtures' custom partition.
pub fn exercise_non_partition_key_scope(
    ctx: &TestCtx,
    session: &SessionHandshake,
    scope: KeyScope,
) {
    let req = TborSdSealingKeyGenReq {
        session_id: session.session_id,
        scope: scope.to_tbor(),
    };
    match scope {
        KeyScope::SecurityDomain => {
            create_test_security_domain(ctx, session);
            ctx.tbor(&req)
                .expect("security-domain-scoped sealing-key generation should succeed");
        }
        KeyScope::Unspecified | KeyScope::Session | KeyScope::Internal => {
            finalize_partition(ctx, session);
            ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
        }
        KeyScope::Ephemeral | KeyScope::Local => {
            unreachable!("partition scopes are exercised by the backup fixture");
        }
    }
}
