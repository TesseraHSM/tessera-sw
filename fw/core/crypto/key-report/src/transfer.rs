// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Canonical P-384 transfer envelopes and their operation-report bindings.
//!
//! Reports are separate from envelopes. The header is used verbatim as both
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

use crate::decode::verify_signature;
use crate::decode::CoseReportView;
use crate::parse_report;
use crate::ReportKind;
use crate::ReportParams;
use crate::ReportVerifier;
use crate::ReportView;
use crate::TransferReportParams;

/// Length of a SHA-384 transfer identifier, envelope hash, or policy hash.
pub const TRANSFER_HASH_LEN: usize = 48;
/// Fixed P-384/HKDF-SHA384/AES-256-GCM suite used by transfer envelopes.
pub const TRANSFER_SUITE: HpkeSuite = HpkeSuite::DHKemP384Sha384AesGcm256;

const MAGIC: &[u8; 9] = b"TSRA-XFER";
const VERSION: u8 = 1;
const KEY_ID_DOMAIN: &[u8] = b"TSRA-P384-KEY-v1";
const ENVELOPE_HASH_DOMAIN: &[u8] = b"TSRA-XFER-HASH-v1";
const PREFIX_LEN: usize = MAGIC.len() + 1 + 1 + 6;
const SOURCE_ID_OFFSET: usize = PREFIX_LEN;
const RECIPIENT_ID_OFFSET: usize = SOURCE_ID_OFFSET + TRANSFER_HASH_LEN;
const POLICY_OFFSET: usize = RECIPIENT_ID_OFFSET + TRANSFER_HASH_LEN;
const P384_PUBLIC_LEN: usize = 97;

/// Canonical DARC header size, before encapsulation and ciphertext.
pub const DARC_HEADER_LEN: usize = POLICY_OFFSET;
/// Canonical security-domain header size, including its required policy hash.
pub const SD_BACKUP_HEADER_LEN: usize = POLICY_OFFSET + TRANSFER_HASH_LEN;
/// Encrypted DARC TMK envelope size, excluding its operation report.
pub const DARC_ENVELOPE_LEN: usize = DARC_HEADER_LEN + P384_PUBLIC_LEN + 32 + 16;
/// Encrypted BKS3 envelope size, excluding its operation report.
pub const SD_BACKUP_ENVELOPE_LEN: usize = SD_BACKUP_HEADER_LEN + P384_PUBLIC_LEN + 48 + 16;

/// Operation-specific header with fixed-width, canonical SHA-384 identifiers.
pub enum TransferHeader<'a> {
    /// Transfer of a 32-byte DARC TMK.
    Darc {
        /// Identifier of the exporting PID public key.
        source_pid_key_id: &'a [u8; TRANSFER_HASH_LEN],
        /// Identifier of the recipient P-384 public key.
        recipient_key_id: &'a [u8; TRANSFER_HASH_LEN],
    },
    /// Transfer of a 48-byte BKS3, including resealing.
    SdBackup {
        /// Identifier of the exporting PID public key.
        source_pid_key_id: &'a [u8; TRANSFER_HASH_LEN],
        /// Identifier of the recipient P-384 public key.
        recipient_key_id: &'a [u8; TRANSFER_HASH_LEN],
        /// Policy enforced by the exporting or resealing command.
        policy_hash: &'a [u8; TRANSFER_HASH_LEN],
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

    /// Complete encrypted-envelope length, excluding its signed report.
    pub fn envelope_len(&self) -> usize {
        self.header_len() + P384_PUBLIC_LEN + self.plaintext_len() + 16
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
        let suite = &mut out[MAGIC.len() + 2..PREFIX_LEN];
        suite[..2].copy_from_slice(&TRANSFER_SUITE.kem_id().to_be_bytes());
        suite[2..4].copy_from_slice(&TRANSFER_SUITE.kdf_id().to_be_bytes());
        suite[4..].copy_from_slice(&TRANSFER_SUITE.aead_id().to_be_bytes());
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
    /// SEC1 uncompressed P-384 encapsulation.
    pub enc: &'a [u8],
    /// Ciphertext, including the 16-byte GCM tag.
    pub ciphertext: &'a [u8],
}

/// Parse exactly one P-384 transfer envelope, rejecting trailing data.
///
/// Point shape is checked here; ECC validation occurs during cryptographic
/// use. Parsing does not establish sender authorization or authenticity.
pub fn parse_transfer_envelope(envelope: &[u8]) -> HsmResult<TransferEnvelopeView<'_>> {
    let prefix = envelope.get(..PREFIX_LEN).ok_or(HsmError::InvalidArg)?;
    if &prefix[..MAGIC.len()] != MAGIC
        || prefix[MAGIC.len()] != VERSION
        || prefix[MAGIC.len() + 2..PREFIX_LEN] != [0, 0x11, 0, 2, 0, 2]
    {
        return Err(HsmError::InvalidArg);
    }
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
        },
        2 => TransferHeader::SdBackup {
            source_pid_key_id: source,
            recipient_key_id: recipient,
            policy_hash: envelope
                .get(POLICY_OFFSET..SD_BACKUP_HEADER_LEN)
                .ok_or(HsmError::InvalidArg)?
                .try_into()
                .map_err(|_| HsmError::InvalidArg)?,
        },
        _ => return Err(HsmError::InvalidArg),
    };
    if envelope.len() != header.envelope_len() {
        return Err(HsmError::InvalidArg);
    }
    let (header_bytes, encrypted) = envelope.split_at(header.header_len());
    let (enc, ciphertext) = encrypted.split_at(P384_PUBLIC_LEN);
    check_public_key(enc)?;
    Ok(TransferEnvelopeView {
        header,
        header_bytes,
        enc,
        ciphertext,
    })
}

fn check_public_key(public_key: &[u8]) -> HsmResult<()> {
    if public_key.len() != P384_PUBLIC_LEN || public_key[0] != 0x04 {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Compute a domain-separated SHA-384 identifier of a SEC1 P-384 public key.
///
/// Only point shape is checked. The caller must authorize and validate the
/// key for its role. Output must be exactly 48 bytes.
pub async fn p384_key_id<P: HsmCrypto>(
    pal: &P,
    io: &P::Io,
    public_key: &[u8],
    out: &mut HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<()> {
    check_public_key(public_key)?;
    domain_hash(pal, io, KEY_ID_DOMAIN, public_key, out, alloc).await
}

/// Compute the SHA-384 binding of a canonical envelope, excluding its report.
pub async fn transfer_envelope_hash<P: HsmCrypto>(
    pal: &P,
    io: &P::Io,
    envelope: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<()> {
    parse_transfer_envelope(envelope)?;
    domain_hash(pal, io, ENVELOPE_HASH_DOMAIN, envelope, out, alloc).await
}

async fn domain_hash<P: HsmCrypto>(
    pal: &P,
    io: &P::Io,
    domain: &[u8],
    bytes: &[u8],
    out: &mut HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<()> {
    if out.len() != TRANSFER_HASH_LEN {
        return Err(HsmError::InvalidArg);
    }
    let input = alloc.dma_alloc(domain.len() + bytes.len())?;
    input[..domain.len()].copy_from_slice(domain);
    input[domain.len()..].copy_from_slice(bytes);
    pal.hash(io, HsmHashAlgo::Sha384, input, out, HsmDigestForm::Standard)
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
    recipient_public_key: &[u8],
    secret: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<usize> {
    if secret.len() != header.plaintext_len() || out.len() < header.envelope_len() {
        return Err(HsmError::InvalidArg);
    }
    let recipient_id = alloc.dma_alloc(TRANSFER_HASH_LEN)?;
    p384_key_id(pal, io, recipient_public_key, recipient_id, alloc).await?;
    if &**recipient_id != header.recipient_key_id() {
        return Err(HsmError::InvalidArg);
    }
    let (header_bytes, encrypted) = out[..header.envelope_len()].split_at_mut(header.header_len());
    header.encode(header_bytes)?;
    let (enc, ciphertext) = encrypted.split_at_mut(P384_PUBLIC_LEN);
    let cfg = HpkeSealConfig::base(
        TRANSFER_SUITE,
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
    /// Authorized source PID public key, SEC1 uncompressed big-endian.
    pub signer_public_key: &'a [u8],
    /// Actual recipient public key, SEC1 uncompressed big-endian.
    pub recipient_public_key: &'a [u8],
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
pub async fn verify_transfer<'a, P: HsmCrypto>(
    pal: &P,
    io: &P::Io,
    cfg: &TransferVerifyConfig<'_>,
    envelope: &'a HsmDmaBuf,
    signed_report: &HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<TransferEnvelopeView<'a>> {
    check_public_key(cfg.signer_public_key)?;
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
        p384_key_id(pal, io, cfg.signer_public_key, actual_id, alloc).await?;
        if &**actual_id != view.header.source_pid_key_id()
            || &**transfer.source_pid_key_id != view.header.source_pid_key_id()
            || &**transfer.recipient_key_id != view.header.recipient_key_id()
        {
            return Err(HsmError::InvalidArg);
        }
        p384_key_id(pal, io, cfg.recipient_public_key, actual_id, alloc).await?;
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
        transfer_envelope_hash(pal, io, envelope, actual_id, alloc).await?;
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
    let signer = alloc.dma_alloc(P384_PUBLIC_LEN - 1)?;
    signer.copy_from_slice(&cfg.signer_public_key[1..]);
    pair_from_be(P::BYTE_ORDER, HsmEccCurve::P384, signer)?;
    if !verify_signature(pal, io, alloc, cose, ReportVerifier::Es384(signer)).await? {
        return Err(HsmError::InvalidArg);
    }
    parse_transfer_envelope(envelope)
}

/// Receiver inputs for verified HPKE opening.
pub struct TransferOpenConfig<'a> {
    /// Authorized signer, recipient, expected kind, and policy comparison.
    pub verification: TransferVerifyConfig<'a>,
    /// Recipient private key in PAL vault format.
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
    let (info, enc, ciphertext, expected_len) = {
        let view =
            verify_transfer(pal, io, &cfg.verification, envelope, signed_report, alloc).await?;
        (
            view.header_bytes,
            view.enc,
            view.ciphertext,
            view.header.plaintext_len(),
        )
    };
    if out.len() < expected_len {
        return Err(HsmError::InvalidArg);
    }
    let plaintext = alloc.dma_alloc(ciphertext.len())?;
    let hpke = HpkeOpenConfig::base(
        TRANSFER_SUITE,
        cfg.recipient_private_key,
        cfg.verification.recipient_public_key,
        info,
        info,
    );
    let written =
        tsra_fw_core_crypto_hpke::open(pal, io, &hpke, enc, ciphertext, Some(plaintext), alloc)
            .await?;
    if written != expected_len {
        return Err(HsmError::InvalidArg);
    }
    out[..written].copy_from_slice(&plaintext[..written]);
    Ok(written)
}
