// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Canonical P-384 transfer envelopes, signed directly as COSE payloads.
//!
//! The header is HPKE Base `info`; AEAD AAD is empty. Both DARC and SD
//! identify source and recipient keys by canonical SPKI thumbprints.
//! Signer and recipient authorization remains the
//! responsibility of the DARC/SD command, not these crypto helpers.

use tsra_fw_core_crypto_hpke::HpkeOpenConfig;
use tsra_fw_core_crypto_hpke::HpkeSealConfig;
use tsra_fw_core_crypto_hpke::HpkeSuite;
use tsra_fw_core_crypto_x509_chain::p384_spki_thumbprint;
use tsra_fw_core_crypto_x509_chain::P384_SPKI_LEN;
use tsra_fw_hsm_byte_order::pair_from_be;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmCrypto;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::decode::verify_signature;
use crate::decode::CoseReportView;
use crate::parse_report;
use crate::ReportKind;
use crate::ReportView;

/// Length of a SHA-384 key thumbprint or policy hash.
pub const TRANSFER_HASH_LEN: usize = 48;
/// Fixed P-384/HKDF-SHA384/AES-256-GCM suite used by transfer envelopes.
pub const TRANSFER_SUITE: HpkeSuite = HpkeSuite::DHKemP384Sha384AesGcm256;

const MAGIC: &[u8; 9] = b"TSRA-XFER";
const VERSION: u8 = 1;
const PREFIX_LEN: usize = MAGIC.len() + 1 + 1 + 6;
const SOURCE_ID_OFFSET: usize = PREFIX_LEN;
const RECIPIENT_ID_OFFSET: usize = SOURCE_ID_OFFSET + TRANSFER_HASH_LEN;
const POLICY_OFFSET: usize = RECIPIENT_ID_OFFSET + TRANSFER_HASH_LEN;
const P384_PUBLIC_LEN: usize = 97;

/// Canonical DARC header size, before encapsulation and ciphertext.
pub const DARC_HEADER_LEN: usize = POLICY_OFFSET;
/// Canonical security-domain header size, including its required policy hash.
pub const SD_BACKUP_HEADER_LEN: usize = POLICY_OFFSET + TRANSFER_HASH_LEN;
/// Inner encrypted DARC TMK envelope size, excluding COSE framing/signature.
pub const DARC_ENVELOPE_LEN: usize = DARC_HEADER_LEN + P384_PUBLIC_LEN + 32 + 16;
/// Inner encrypted BKS3 envelope size, excluding COSE framing/signature.
pub const SD_BACKUP_ENVELOPE_LEN: usize = SD_BACKUP_HEADER_LEN + P384_PUBLIC_LEN + 48 + 16;
/// ES384 COSE_Sign1 containing the complete DARC envelope.
pub const DARC_SIGNED_ENVELOPE_LEN: usize = DARC_ENVELOPE_LEN + 109;
/// ES384 COSE_Sign1 containing the complete SD envelope.
pub const SD_BACKUP_SIGNED_ENVELOPE_LEN: usize = SD_BACKUP_ENVELOPE_LEN + 109;

/// Operation-specific header with fixed-width, canonical SHA-384 identifiers.
pub enum TransferHeader<'a> {
    /// Transfer of a 32-byte DARC TMK.
    Darc {
        /// SHA-384 of the exporting PID's canonical DER SPKI.
        source_pid_spki_thumbprint: &'a [u8; TRANSFER_HASH_LEN],
        /// SHA-384 of the recipient encryption key's canonical DER SPKI.
        recipient_spki_thumbprint: &'a [u8; TRANSFER_HASH_LEN],
    },
    /// Transfer of a 48-byte BKS3, including resealing.
    SdBackup {
        /// SHA-384 of the exporting PID's canonical DER SPKI.
        source_pid_spki_thumbprint: &'a [u8; TRANSFER_HASH_LEN],
        /// SHA-384 of the recipient encryption key's canonical DER SPKI.
        recipient_spki_thumbprint: &'a [u8; TRANSFER_HASH_LEN],
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

    /// Inner encrypted-envelope length, excluding COSE framing/signature.
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
                source_pid_spki_thumbprint,
                ..
            }
            | Self::SdBackup {
                source_pid_spki_thumbprint,
                ..
            } => source_pid_spki_thumbprint,
        }
    }

    /// Identifier of the intended recipient.
    pub fn recipient_key_id(&self) -> &[u8; TRANSFER_HASH_LEN] {
        match self {
            Self::Darc {
                recipient_spki_thumbprint,
                ..
            }
            | Self::SdBackup {
                recipient_spki_thumbprint,
                ..
            } => recipient_spki_thumbprint,
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
    /// Canonical header bytes, used as HPKE info with empty AAD.
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
            source_pid_spki_thumbprint: source,
            recipient_spki_thumbprint: recipient,
        },
        2 => TransferHeader::SdBackup {
            source_pid_spki_thumbprint: source,
            recipient_spki_thumbprint: recipient,
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

/// Compute the common SD/DARC SHA-384 thumbprint of canonical DER SPKI.
///
/// The caller must authorize and validate the key for its role.
pub async fn transfer_spki_thumbprint<P: HsmCrypto>(
    pal: &P,
    io: &P::Io,
    public_key: &[u8],
    out: &mut HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<()> {
    check_public_key(public_key)?;
    let scratch = alloc.dma_alloc(P384_SPKI_LEN)?;
    p384_spki_thumbprint(pal, io, scratch, &public_key[1..], out).await
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
    transfer_spki_thumbprint(pal, io, recipient_public_key, recipient_id, alloc).await?;
    if &**recipient_id != header.recipient_key_id() {
        return Err(HsmError::InvalidArg);
    }
    let (header_bytes, encrypted) = out[..header.envelope_len()].split_at_mut(header.header_len());
    header.encode(header_bytes)?;
    let (enc, ciphertext) = encrypted.split_at_mut(P384_PUBLIC_LEN);
    let cfg = HpkeSealConfig::base(TRANSFER_SUITE, recipient_public_key, header_bytes, &[]);
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
    /// signed header policy without comparing to the receiver's own policy.
    /// DARC configurations must leave this absent.
    pub expected_policy_hash: Option<&'a [u8; TRANSFER_HASH_LEN]>,
}

/// Authenticate a directly signed envelope, its recipient, and its policy.
///
/// The caller must first authorize `signer_public_key`. This function does
/// not validate certificate chains, enforce SD cloning permissions, or
/// establish freshness.
pub async fn verify_transfer<'a, P: HsmCrypto>(
    pal: &P,
    io: &P::Io,
    cfg: &TransferVerifyConfig<'_>,
    signed_envelope: &'a HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<TransferEnvelopeView<'a>> {
    check_public_key(cfg.signer_public_key)?;
    let parsed = parse_report(signed_envelope)?;
    let transfer = match parsed {
        ReportView::Transfer(transfer) => transfer,
        ReportView::PublicKey(_) => return Err(HsmError::InvalidArg),
    };
    let view = parse_transfer_envelope(transfer.envelope)?;
    if view.header.kind() != cfg.expected_kind
        || (cfg.expected_kind == ReportKind::Darc && cfg.expected_policy_hash.is_some())
    {
        return Err(HsmError::InvalidArg);
    }
    let actual_id = alloc.dma_alloc(TRANSFER_HASH_LEN)?;
    transfer_spki_thumbprint(pal, io, cfg.signer_public_key, actual_id, alloc).await?;
    if &**actual_id != view.header.source_pid_key_id() {
        return Err(HsmError::InvalidArg);
    }
    transfer_spki_thumbprint(pal, io, cfg.recipient_public_key, actual_id, alloc).await?;
    if &**actual_id != view.header.recipient_key_id() {
        return Err(HsmError::InvalidArg);
    }
    if let Some(header_policy) = view.header.policy_hash() {
        if cfg
            .expected_policy_hash
            .is_some_and(|expected| expected != header_policy)
        {
            return Err(HsmError::InvalidArg);
        }
    }
    let cose = CoseReportView {
        protected_header: transfer.protected_header,
        payload: transfer.envelope,
        signature: transfer.signature,
    };
    let signer = alloc.dma_alloc(P384_PUBLIC_LEN - 1)?;
    signer.copy_from_slice(&cfg.signer_public_key[1..]);
    pair_from_be::<P>(HsmEccCurve::P384, signer)?;
    if !verify_signature(pal, io, alloc, cose, signer, view.header.kind()).await? {
        return Err(HsmError::InvalidArg);
    }
    Ok(view)
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
    signed_envelope: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
    alloc: &impl HsmScopedAlloc,
) -> HsmResult<usize> {
    let (info, enc, ciphertext, expected_len) = {
        let view = verify_transfer(pal, io, &cfg.verification, signed_envelope, alloc).await?;
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
        &[],
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
