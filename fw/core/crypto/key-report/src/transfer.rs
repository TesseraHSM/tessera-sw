// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Canonical transfer envelopes and their operation-report bindings.
//!
//! The recipient KEM ([`TransferKem`]) is named by the header's HPKE suite
//! identifiers: P-384, ML-KEM-1024 (HPKE-13) or MLKEM1024-P384 (HPKE-10),
//! for both DARC and SD backup envelopes. Reports are
//! separate from envelopes. The header is used verbatim as both
//! HPKE Base `info` and AEAD AAD. Identifiers and envelope hashes use
//! domain-separated SHA-384. Signer and recipient authorization remains the
//! responsibility of the DARC/SD command, not these crypto helpers.

use tsra_fw_core_crypto_hpke::HpkeOpenConfig;
use tsra_fw_core_crypto_hpke::HpkeSealConfig;
use tsra_fw_core_crypto_hpke::HpkeSuite;
use tsra_fw_hsm_byte_order::pair_from_be;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmCrypto;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::consts::MLDSA87_PUB_KEY_LEN;
use crate::decode::verify_signature;
use crate::decode::CoseReportView;
use crate::parse_report;
use crate::ReportAlg;
use crate::ReportKind;
use crate::ReportParams;
use crate::ReportVerifier;
use crate::ReportView;
use crate::TransferReportParams;

/// Length of a SHA-384 transfer identifier, envelope hash, or policy hash.
pub const TRANSFER_HASH_LEN: usize = 48;
/// P-384/HKDF-SHA384/AES-256-GCM suite used by DARC and P-384 SD envelopes.
pub const TRANSFER_SUITE: HpkeSuite = HpkeSuite::DHKemP384Sha384AesGcm256;

const MAGIC: &[u8; 9] = b"TSRA-XFER";
const VERSION: u8 = 1;
const ENVELOPE_HASH_DOMAIN: &[u8] = b"TSRA-XFER-HASH-v1";
const MLDSA87_KEY_ID_DOMAIN: &[u8] = b"TSRA-MLDSA87-KEY-v1";

/// Largest report-signer public key: an encoded ML-DSA-87 key.
pub const SIGNER_PUBLIC_KEY_MAX_LEN: usize = MLDSA87_PUB_KEY_LEN;
const PREFIX_LEN: usize = MAGIC.len() + 1 + 1 + 6;
const SOURCE_ID_OFFSET: usize = PREFIX_LEN;
const RECIPIENT_ID_OFFSET: usize = SOURCE_ID_OFFSET + TRANSFER_HASH_LEN;
const POLICY_OFFSET: usize = RECIPIENT_ID_OFFSET + TRANSFER_HASH_LEN;
const P384_PUBLIC_LEN: usize = 97;
const MLKEM1024_PUBLIC_LEN: usize = 1568;
const MLKEM1024P384_PUBLIC_LEN: usize = MLKEM1024_PUBLIC_LEN + P384_PUBLIC_LEN;
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// Largest recipient public key (and encapsulation) of any [`TransferKem`].
pub const TRANSFER_PUBLIC_KEY_MAX_LEN: usize = MLKEM1024P384_PUBLIC_LEN;

/// Recipient KEM of a transfer envelope, named by its HPKE suite.
///
/// Public keys use the HPKE `SerializePublicKey` encoding: SEC1
/// uncompressed for P-384, the encapsulation key for ML-KEM-1024 and
/// `ek_PQ ‖ SEC1(ek_T)` for the hybrid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKem {
    /// DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM.
    P384,
    /// HPKE-13: ML-KEM-1024, SHAKE256, AES-256-GCM.
    MlKem1024,
    /// HPKE-10: MLKEM1024-P384, SHAKE256, AES-256-GCM.
    MlKem1024P384,
}

impl TransferKem {
    const ALL: [Self; 3] = [Self::P384, Self::MlKem1024, Self::MlKem1024P384];

    /// HPKE suite sealing to this KEM.
    pub const fn suite(self) -> HpkeSuite {
        match self {
            Self::P384 => TRANSFER_SUITE,
            Self::MlKem1024 => HpkeSuite::MlKem1024Shake256AesGcm256,
            Self::MlKem1024P384 => HpkeSuite::MlKem1024P384Shake256AesGcm256,
        }
    }

    /// Recipient public-key length; equal to the encapsulation length.
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::P384 => P384_PUBLIC_LEN,
            Self::MlKem1024 => MLKEM1024_PUBLIC_LEN,
            Self::MlKem1024P384 => MLKEM1024P384_PUBLIC_LEN,
        }
    }

    const fn key_id_domain(self) -> &'static [u8] {
        match self {
            Self::P384 => b"TSRA-P384-KEY-v1",
            Self::MlKem1024 => b"TSRA-MLKEM1024-KEY-v1",
            Self::MlKem1024P384 => b"TSRA-MLKEM1024-P384-KEY-v1",
        }
    }

    fn suite_bytes(self) -> [u8; 6] {
        let suite = self.suite();
        let [k0, k1] = suite.kem_id().to_be_bytes();
        let [d0, d1] = suite.kdf_id().to_be_bytes();
        let [a0, a1] = suite.aead_id().to_be_bytes();
        [k0, k1, d0, d1, a0, a1]
    }

    fn from_suite_bytes(bytes: &[u8]) -> HsmResult<Self> {
        Self::ALL
            .into_iter()
            .find(|kem| kem.suite_bytes()[..] == *bytes)
            .ok_or(HsmError::InvalidArg)
    }

    /// Identify the KEM of a public key or encapsulation from its length and
    /// SEC1 tag. Point and ML-KEM coefficient validity are checked during
    /// cryptographic use, not here.
    pub fn from_public_key(public_key: &[u8]) -> HsmResult<Self> {
        let kem = match public_key.len() {
            P384_PUBLIC_LEN => Self::P384,
            MLKEM1024_PUBLIC_LEN => Self::MlKem1024,
            MLKEM1024P384_PUBLIC_LEN => Self::MlKem1024P384,
            _ => return Err(HsmError::InvalidArg),
        };
        let tag = match kem {
            Self::P384 => Some(0),
            Self::MlKem1024 => None,
            Self::MlKem1024P384 => Some(MLKEM1024_PUBLIC_LEN),
        };
        if tag.is_some_and(|at| public_key[at] != SEC1_UNCOMPRESSED) {
            return Err(HsmError::InvalidArg);
        }
        Ok(kem)
    }

    /// Check that `public_key` is shaped as a key of this KEM.
    pub fn check_public_key(self, public_key: &[u8]) -> HsmResult<()> {
        if Self::from_public_key(public_key)? != self {
            return Err(HsmError::InvalidArg);
        }
        Ok(())
    }
}

/// Canonical DARC header size, before encapsulation and ciphertext.
pub const DARC_HEADER_LEN: usize = POLICY_OFFSET;
/// Canonical security-domain header size, including its required policy hash.
pub const SD_BACKUP_HEADER_LEN: usize = POLICY_OFFSET + TRANSFER_HASH_LEN;
/// Encrypted P-384 DARC TMK envelope size, excluding its operation report.
pub const DARC_ENVELOPE_LEN: usize = darc_envelope_len(TransferKem::P384);
/// Largest encrypted DARC TMK envelope size (MLKEM1024-P384).
pub const DARC_ENVELOPE_MAX_LEN: usize = darc_envelope_len(TransferKem::MlKem1024P384);
/// Encrypted P-384 BKS3 envelope size, excluding its operation report.
pub const SD_BACKUP_ENVELOPE_LEN: usize = sd_backup_envelope_len(TransferKem::P384);
/// Largest encrypted BKS3 envelope size (MLKEM1024-P384).
pub const SD_BACKUP_ENVELOPE_MAX_LEN: usize = sd_backup_envelope_len(TransferKem::MlKem1024P384);

/// Encrypted DARC TMK envelope size for `kem`, excluding its operation report.
pub const fn darc_envelope_len(kem: TransferKem) -> usize {
    DARC_HEADER_LEN + kem.public_key_len() + 32 + 16
}

/// Encrypted BKS3 envelope size for `kem`, excluding its operation report.
pub const fn sd_backup_envelope_len(kem: TransferKem) -> usize {
    SD_BACKUP_HEADER_LEN + kem.public_key_len() + 48 + 16
}

/// Operation-specific header with fixed-width, canonical SHA-384 identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferHeader<'a> {
    /// Transfer of a 32-byte DARC TMK.
    Darc {
        /// Identifier of the exporting PID public key.
        source_pid_key_id: &'a [u8; TRANSFER_HASH_LEN],
        /// Identifier of the recipient public key.
        recipient_key_id: &'a [u8; TRANSFER_HASH_LEN],
        /// Recipient KEM.
        kem: TransferKem,
    },
    /// Transfer of a 48-byte BKS3, including resealing.
    SdBackup {
        /// Identifier of the exporting PID public key.
        source_pid_key_id: &'a [u8; TRANSFER_HASH_LEN],
        /// Identifier of the recipient public key.
        recipient_key_id: &'a [u8; TRANSFER_HASH_LEN],
        /// Policy enforced by the exporting or resealing command.
        policy_hash: &'a [u8; TRANSFER_HASH_LEN],
        /// Recipient KEM.
        kem: TransferKem,
    },
}

impl TransferHeader<'_> {
    /// Operation report kind required for this envelope.
    pub fn kind(&self) -> ReportKind {
        match self {
            Self::Darc { .. } => ReportKind::Darc,
            Self::SdBackup { .. } => ReportKind::SdBackup,
        }
    }

    /// Header length in its canonical wire encoding.
    pub fn header_len(&self) -> usize {
        match self {
            Self::Darc { .. } => DARC_HEADER_LEN,
            Self::SdBackup { .. } => SD_BACKUP_HEADER_LEN,
        }
    }

    /// Recipient KEM.
    pub fn kem(&self) -> TransferKem {
        match self {
            Self::Darc { kem, .. } | Self::SdBackup { kem, .. } => *kem,
        }
    }

    /// Complete encrypted-envelope length, excluding its signed report.
    pub fn envelope_len(&self) -> usize {
        self.header_len() + self.kem().public_key_len() + self.plaintext_len() + 16
    }

    /// Expected secret length.
    pub fn plaintext_len(&self) -> usize {
        match self {
            Self::Darc { .. } => 32,
            Self::SdBackup { .. } => 48,
        }
    }

    /// Identifier of the reporting PID.
    pub fn source_pid_key_id(&self) -> &[u8; TRANSFER_HASH_LEN] {
        match self {
            Self::Darc {
                source_pid_key_id, ..
            }
            | Self::SdBackup {
                source_pid_key_id, ..
            } => source_pid_key_id,
        }
    }

    /// Identifier of the intended recipient.
    pub fn recipient_key_id(&self) -> &[u8; TRANSFER_HASH_LEN] {
        match self {
            Self::Darc {
                recipient_key_id, ..
            }
            | Self::SdBackup {
                recipient_key_id, ..
            } => recipient_key_id,
        }
    }

    /// Required SD policy binding; DARC headers do not carry this field.
    pub fn policy_hash(&self) -> Option<&[u8; TRANSFER_HASH_LEN]> {
        match self {
            Self::Darc { .. } => None,
            Self::SdBackup { policy_hash, .. } => Some(policy_hash),
        }
    }

    /// Encode the header; reject insufficient output without writing.
    pub fn encode(&self, out: &mut [u8]) -> HsmResult<usize> {
        let len = self.header_len();
        if out.len() < len {
            return Err(HsmError::InvalidArg);
        }
        out[..MAGIC.len()].copy_from_slice(MAGIC);
        out[MAGIC.len()] = VERSION;
        out[MAGIC.len() + 1] = self.kind() as u8;
        out[MAGIC.len() + 2..PREFIX_LEN].copy_from_slice(&self.kem().suite_bytes());
        out[SOURCE_ID_OFFSET..RECIPIENT_ID_OFFSET].copy_from_slice(self.source_pid_key_id());
        out[RECIPIENT_ID_OFFSET..POLICY_OFFSET].copy_from_slice(self.recipient_key_id());
        if let Some(policy) = self.policy_hash() {
            out[POLICY_OFFSET..SD_BACKUP_HEADER_LEN].copy_from_slice(policy);
        }
        Ok(len)
    }
}

/// Structurally validated, zero-copy envelope view. Not authenticated by parsing.
pub struct TransferEnvelopeView<'a> {
    /// Decoded operation and identifiers.
    pub header: TransferHeader<'a>,
    /// Canonical header bytes, used as HPKE info and AAD.
    pub header_bytes: &'a [u8],
    /// HPKE encapsulation, [`TransferKem::public_key_len`] bytes.
    pub enc: &'a [u8],
    /// Ciphertext, including the 16-byte GCM tag.
    pub ciphertext: &'a [u8],
}

/// Parse exactly one transfer envelope, rejecting trailing data.
///
/// Encapsulation shape is checked here; point and ciphertext validation
/// occur during cryptographic use. Parsing does not establish sender authorization or authenticity.
pub fn parse_transfer_envelope(envelope: &[u8]) -> HsmResult<TransferEnvelopeView<'_>> {
    let prefix = envelope.get(..PREFIX_LEN).ok_or(HsmError::InvalidArg)?;
    if &prefix[..MAGIC.len()] != MAGIC || prefix[MAGIC.len()] != VERSION {
        return Err(HsmError::InvalidArg);
    }
    let kem = TransferKem::from_suite_bytes(&prefix[MAGIC.len() + 2..PREFIX_LEN])?;
    let source = envelope
        .get(SOURCE_ID_OFFSET..RECIPIENT_ID_OFFSET)
        .ok_or(HsmError::InvalidArg)?
        .try_into()
        .map_err(|_| HsmError::InvalidArg)?;
    let recipient = envelope
        .get(RECIPIENT_ID_OFFSET..POLICY_OFFSET)
        .ok_or(HsmError::InvalidArg)?
        .try_into()
        .map_err(|_| HsmError::InvalidArg)?;
    let header = match prefix[MAGIC.len() + 1] {
        1 => TransferHeader::Darc {
            source_pid_key_id: source,
            recipient_key_id: recipient,
            kem,
        },
        2 => TransferHeader::SdBackup {
            source_pid_key_id: source,
            recipient_key_id: recipient,
            policy_hash: envelope
                .get(POLICY_OFFSET..SD_BACKUP_HEADER_LEN)
                .ok_or(HsmError::InvalidArg)?
                .try_into()
                .map_err(|_| HsmError::InvalidArg)?,
            kem,
        },
        _ => return Err(HsmError::InvalidArg),
    };
    if envelope.len() != header.envelope_len() {
        return Err(HsmError::InvalidArg);
    }
    let (header_bytes, encrypted) = envelope.split_at(header.header_len());
    let (enc, ciphertext) = encrypted.split_at(kem.public_key_len());
    kem.check_public_key(enc)?;
    Ok(TransferEnvelopeView {
        header,
        header_bytes,
        enc,
        ciphertext,
    })
}

/// Compute a domain-separated SHA-384 identifier of a SEC1 P-384 public key.
///
/// Only point shape is checked. The caller must authorize and validate the
/// key for its role. Output must be exactly 48 bytes.
pub async fn p384_key_id<P: HsmCrypto + HsmAlloc>(
    pal: &P,
    io: &P::Io,
    public_key: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    TransferKem::P384.check_public_key(public_key)?;
    transfer_key_id(pal, io, public_key, out).await
}

/// Algorithm of a report-signer public key: SEC1 uncompressed P-384
/// (ES384) or an encoded ML-DSA-87 key, distinguished by length.
pub fn signer_alg(public_key: &[u8]) -> HsmResult<ReportAlg> {
    match public_key.len() {
        P384_PUBLIC_LEN => {
            TransferKem::P384.check_public_key(public_key)?;
            Ok(ReportAlg::Es384)
        }
        MLDSA87_PUB_KEY_LEN => Ok(ReportAlg::MlDsa87),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Report verifier for a report-signer public key (see [`signer_alg`]).
/// A P-384 key is converted to the PAL operand form in `alloc`; an
/// ML-DSA-87 key is borrowed as is.
pub fn signer_verifier<'a, P: HsmCrypto>(
    alloc: &'a impl HsmScopedAlloc,
    public_key: &'a HsmDmaBuf,
) -> HsmResult<ReportVerifier<'a>> {
    match signer_alg(public_key)? {
        ReportAlg::Es384 => {
            let key = alloc.dma_alloc(P384_PUBLIC_LEN - 1)?;
            key.copy_from_slice(&public_key[1..]);
            pair_from_be(P::BYTE_ORDER, HsmEccCurve::P384, key)?;
            Ok(ReportVerifier::Es384(key))
        }
        ReportAlg::MlDsa87 => Ok(ReportVerifier::MlDsa87(public_key)),
    }
}

/// Compute the domain-separated SHA-384 identifier of a report-signer
/// (PID) public key: [`p384_key_id`] for P-384, a distinct ML-DSA-87
/// domain otherwise. Output must be exactly 48 bytes.
pub async fn signer_key_id<P: HsmCrypto + HsmAlloc>(
    pal: &P,
    io: &P::Io,
    public_key: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    match signer_alg(public_key)? {
        ReportAlg::Es384 => p384_key_id(pal, io, public_key, out).await,
        ReportAlg::MlDsa87 => domain_hash(pal, io, MLDSA87_KEY_ID_DOMAIN, public_key, out).await,
    }
}

/// Compute the domain-separated SHA-384 identifier of a recipient public
/// key of any [`TransferKem`]; each KEM uses its own domain.
///
/// Only key shape is checked. The caller must authorize and validate the
/// key for its role. Output must be exactly 48 bytes.
pub async fn transfer_key_id<P: HsmCrypto + HsmAlloc>(
    pal: &P,
    io: &P::Io,
    public_key: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let kem = TransferKem::from_public_key(public_key)?;
    domain_hash(pal, io, kem.key_id_domain(), public_key, out).await
}

/// Compute the SHA-384 binding of a canonical envelope, excluding its report.
pub async fn transfer_envelope_hash<P: HsmCrypto + HsmAlloc>(
    pal: &P,
    io: &P::Io,
    envelope: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    parse_transfer_envelope(envelope)?;
    domain_hash(pal, io, ENVELOPE_HASH_DOMAIN, envelope, out).await
}

async fn domain_hash<P: HsmCrypto + HsmAlloc>(
    pal: &P,
    io: &P::Io,
    domain: &[u8],
    bytes: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    if out.len() != TRANSFER_HASH_LEN {
        return Err(HsmError::InvalidArg);
    }
    pal.alloc_scoped_async(io, async |alloc| {
        let input = alloc.dma_alloc(domain.len() + bytes.len())?;
        let (tag, body) = input.split_at_mut(domain.len());
        tag.copy_from_slice(domain);
        body.copy_from_slice(bytes);
        pal.hash(io, HsmHashAlgo::Sha384, input, out, HsmDigestForm::Standard)
            .await
    })
    .await
}

/// Select typed report inputs from an envelope and its firmware-computed hash.
///
/// This validates field shape, not the supplied digest. Exporting commands
/// must obtain `envelope_hash` from [`transfer_envelope_hash`] themselves.
pub fn transfer_report_params<'a>(
    envelope: &'a HsmDmaBuf,
    envelope_hash: &'a HsmDmaBuf,
) -> HsmResult<ReportParams<'a>> {
    let view = parse_transfer_envelope(envelope)?;
    if envelope_hash.len() != TRANSFER_HASH_LEN {
        return Err(HsmError::InvalidArg);
    }
    let transfer = TransferReportParams {
        source_pid_key_id: &envelope[SOURCE_ID_OFFSET..RECIPIENT_ID_OFFSET],
        recipient_key_id: &envelope[RECIPIENT_ID_OFFSET..POLICY_OFFSET],
        envelope_hash,
    };
    match view.header {
        TransferHeader::Darc { .. } => Ok(ReportParams::Darc(transfer)),
        TransferHeader::SdBackup { .. } => Ok(ReportParams::SdBackup {
            transfer,
            policy_hash: &envelope[POLICY_OFFSET..SD_BACKUP_HEADER_LEN],
        }),
    }
}

/// Seal a validated TMK/BKS3 into a canonical envelope using HPKE Base.
///
/// The recipient must already be authorized. The helper checks that its
/// key ID matches the header. Outputs must not be published on failure.
pub async fn seal_transfer<P: HsmCrypto + HsmAlloc>(
    pal: &P,
    io: &P::Io,
    header: &TransferHeader<'_>,
    recipient_public_key: &HsmDmaBuf,
    secret: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<usize> {
    if secret.len() != header.plaintext_len() || out.len() < header.envelope_len() {
        return Err(HsmError::InvalidArg);
    }
    let kem = header.kem();
    kem.check_public_key(recipient_public_key)?;
    let recipient_id = alloc.dma_alloc(TRANSFER_HASH_LEN)?;
    transfer_key_id(pal, io, recipient_public_key, recipient_id).await?;
    if &**recipient_id != header.recipient_key_id() {
        return Err(HsmError::InvalidArg);
    }
    let (header_bytes, encrypted) = out[..header.envelope_len()].split_at_mut(header.header_len());
    header.encode(header_bytes)?;
    let (enc, ciphertext) = encrypted.split_at_mut(kem.public_key_len());
    let cfg = HpkeSealConfig::base(
        kem.suite(),
        recipient_public_key,
        header_bytes,
        header_bytes,
    );
    let envelope_len = header.envelope_len();
    tsra_fw_core_crypto_hpke::seal(pal, io, &cfg, secret, Some(enc), Some(ciphertext), alloc)
        .await?;
    Ok(envelope_len)
}

/// Trusted inputs selected by the receiving command's authorization checks.
pub struct TransferVerifyConfig<'a> {
    /// Required operation kind; `PublicKey` is never accepted.
    pub expected_kind: ReportKind,
    /// Authorized source PID public key: SEC1 uncompressed big-endian P-384
    /// or an encoded ML-DSA-87 key (see [`signer_alg`]).
    pub signer_public_key: &'a HsmDmaBuf,
    /// Actual recipient public key in its [`TransferKem`] encoding.
    pub recipient_public_key: &'a HsmDmaBuf,
    /// If set, require this exact SD policy hash. If absent, authenticate the
    /// report/header policy without comparing to the receiver's own policy.
    /// DARC configurations must leave this absent.
    pub expected_policy_hash: Option<&'a [u8; TRANSFER_HASH_LEN]>,
}

/// Authenticate a report and its exact envelope, recipient, and policy.
///
/// The caller must first authorize `signer_public_key`. This function does
/// not validate certificate chains, enforce SD cloning permissions, or
/// establish freshness.
pub async fn verify_transfer<'a, P: HsmCrypto + HsmAlloc>(
    pal: &P,
    io: &P::Io,
    cfg: &TransferVerifyConfig<'_>,
    envelope: &'a HsmDmaBuf,
    signed_report: &HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<VerifiedTransfer<'a>> {
    signer_alg(cfg.signer_public_key)?;
    let cose = {
        let view = parse_transfer_envelope(envelope)?;
        if view.header.kind() != cfg.expected_kind
            || (cfg.expected_kind == ReportKind::Darc && cfg.expected_policy_hash.is_some())
        {
            return Err(HsmError::InvalidArg);
        }
        let parsed = parse_report(signed_report)?;
        if parsed.kind() != cfg.expected_kind {
            return Err(HsmError::InvalidArg);
        }
        let (transfer, policy) = match parsed {
            ReportView::Darc(transfer) => (transfer, None),
            ReportView::SdBackup {
                transfer,
                policy_hash,
            } => (transfer, Some(policy_hash)),
            ReportView::PublicKey(_) => return Err(HsmError::InvalidArg),
        };
        let actual_id = alloc.dma_alloc(TRANSFER_HASH_LEN)?;
        signer_key_id(pal, io, cfg.signer_public_key, actual_id).await?;
        if &**actual_id != view.header.source_pid_key_id()
            || &**transfer.source_pid_key_id != view.header.source_pid_key_id()
            || &**transfer.recipient_key_id != view.header.recipient_key_id()
        {
            return Err(HsmError::InvalidArg);
        }
        view.header
            .kem()
            .check_public_key(cfg.recipient_public_key)?;
        transfer_key_id(pal, io, cfg.recipient_public_key, actual_id).await?;
        if &**actual_id != view.header.recipient_key_id() {
            return Err(HsmError::InvalidArg);
        }
        if let Some(header_policy) = view.header.policy_hash() {
            let report_policy = policy.ok_or(HsmError::InvalidArg)?;
            if &**report_policy != header_policy
                || cfg
                    .expected_policy_hash
                    .is_some_and(|expected| expected != header_policy)
            {
                return Err(HsmError::InvalidArg);
            }
        }
        transfer_envelope_hash(pal, io, envelope, actual_id).await?;
        if **actual_id != **transfer.envelope_hash {
            return Err(HsmError::InvalidArg);
        }
        CoseReportView {
            protected_header: transfer.protected_header,
            payload: transfer.payload,
            signature: transfer.signature,
            alg: transfer.alg,
        }
    };
    let verifier = signer_verifier::<P>(alloc, cfg.signer_public_key)?;
    if !verify_signature(pal, io, alloc, cose, verifier).await? {
        return Err(HsmError::InvalidArg);
    }
    Ok(VerifiedTransfer(parse_transfer_envelope(envelope)?))
}

/// A transfer envelope whose report [`verify_transfer`] authenticated.
///
/// It borrows only the envelope, so verification scratch (signer key,
/// report) can be released before [`open_verified_transfer`].
pub struct VerifiedTransfer<'a>(TransferEnvelopeView<'a>);

impl<'a> VerifiedTransfer<'a> {
    /// The authenticated envelope.
    pub fn view(&self) -> &TransferEnvelopeView<'a> {
        &self.0
    }
}

/// Receiver inputs for verified HPKE opening.
pub struct TransferOpenConfig<'a> {
    /// Authorized signer, recipient, expected kind, and policy comparison.
    pub verification: TransferVerifyConfig<'a>,
    /// Recipient private key: the P-384 scalar in PAL vault format, the
    /// 64-byte ML-KEM-1024 `d ‖ z` seed, or the 32-byte hybrid seed.
    pub recipient_private_key: &'a HsmDmaBuf,
}

/// Verify the transfer before HPKE opening and publish plaintext only on success.
pub async fn open_transfer<P: HsmCrypto + HsmAlloc>(
    pal: &P,
    io: &P::Io,
    cfg: &TransferOpenConfig<'_>,
    envelope: &HsmDmaBuf,
    signed_report: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<usize> {
    // Nested scope: release verification scratch before the (ML-KEM) decap
    // needs its own.
    let verified = pal
        .alloc_scoped_async(io, async |scratch| {
            verify_transfer(pal, io, &cfg.verification, envelope, signed_report, scratch).await
        })
        .await?;
    open_verified_transfer(
        pal,
        io,
        &verified,
        cfg.recipient_private_key,
        cfg.verification.recipient_public_key,
        out,
        alloc,
    )
    .await
}

/// HPKE-open a transfer authenticated by [`verify_transfer`], publishing
/// plaintext only on success.
///
/// `recipient_public_key` must be the key passed to [`verify_transfer`] and
/// `recipient_private_key` its private key (see [`TransferOpenConfig`]).
pub async fn open_verified_transfer<P: HsmCrypto + HsmAlloc>(
    pal: &P,
    io: &P::Io,
    verified: &VerifiedTransfer<'_>,
    recipient_private_key: &HsmDmaBuf,
    recipient_public_key: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<usize> {
    let view = verified.view();
    let expected_len = view.header.plaintext_len();
    if out.len() < expected_len {
        return Err(HsmError::InvalidArg);
    }
    let plaintext = alloc.dma_alloc(view.ciphertext.len())?;
    let hpke = HpkeOpenConfig::base(
        view.header.kem().suite(),
        recipient_private_key,
        recipient_public_key,
        view.header_bytes,
        view.header_bytes,
    );
    let written = tsra_fw_core_crypto_hpke::open(
        pal,
        io,
        &hpke,
        view.enc,
        view.ciphertext,
        Some(plaintext),
        alloc,
    )
    .await?;
    if written != expected_len {
        return Err(HsmError::InvalidArg);
    }
    out[..written].copy_from_slice(&plaintext[..written]);
    Ok(written)
}
