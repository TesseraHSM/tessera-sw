// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public-key attestations and directly signed transfer envelopes.

use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

use crate::consts::*;
use crate::transfer::TransferHeader;
use crate::KeyReportParams;
use crate::KeyReportView;

/// COSE signature algorithm of a report, carried in its protected header.
///
/// A verifier must check the algorithm against the signer it expects
/// (the PID chain of the requested bank); it is not a negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportAlg {
    /// ECDSA P-384 with SHA-384 (COSE `-35`).
    Es384,
    /// ML-DSA-87, pure mode with an empty context (COSE `-50`).
    MlDsa87,
}

impl ReportAlg {
    /// Encoded protected header naming this algorithm.
    pub(crate) fn protected_header(self) -> &'static [u8; 22] {
        match self {
            Self::Es384 => &PROTECTED_HEADER,
            Self::MlDsa87 => &PROTECTED_HEADER_MLDSA87,
        }
    }

    /// Algorithm named by an encoded protected header.
    pub(crate) fn from_protected_header(header: &[u8]) -> HsmResult<Self> {
        if header == PROTECTED_HEADER || header == TRANSFER_PROTECTED_HEADER {
            Ok(Self::Es384)
        } else if header == PROTECTED_HEADER_MLDSA87 || header == TRANSFER_PROTECTED_HEADER_MLDSA87
        {
            Ok(Self::MlDsa87)
        } else {
            Err(HsmError::InvalidArg)
        }
    }

    /// Signature length for this algorithm.
    pub const fn signature_len(self) -> usize {
        match self {
            Self::Es384 => SIGNATURE_LEN,
            Self::MlDsa87 => MLDSA87_SIGNATURE_LEN,
        }
    }
}

/// Private key that signs a report.
#[derive(Clone, Copy)]
pub enum ReportSigner<'a> {
    /// P-384 private scalar in the PAL's operand order
    /// ([`PRIV_KEY_LEN`] bytes); signs ES384.
    Es384(&'a HsmDmaBuf),
    /// ML-DSA-87 private-key seed ([`MLDSA_SEED_LEN`] bytes); signs
    /// ML-DSA-87 with required hedging.
    MlDsa87Seed(&'a HsmDmaBuf),
}

impl ReportSigner<'_> {
    /// The algorithm this signer produces.
    pub fn alg(&self) -> ReportAlg {
        match self {
            Self::Es384(_) => ReportAlg::Es384,
            Self::MlDsa87Seed(_) => ReportAlg::MlDsa87,
        }
    }

    pub(crate) fn validate(&self) -> HsmResult<()> {
        let ok = match self {
            Self::Es384(key) => key.len() == PRIV_KEY_LEN,
            Self::MlDsa87Seed(seed) => seed.len() == MLDSA_SEED_LEN,
        };
        if ok {
            Ok(())
        } else {
            Err(HsmError::InvalidArg)
        }
    }
}

/// Public key a report must verify under. Its algorithm must equal the
/// report's protected-header algorithm.
#[derive(Clone, Copy)]
pub enum ReportVerifier<'a> {
    /// P-384 public key `x || y`, each coordinate in the PAL's operand
    /// order (the `ecc_verify` wire form).
    Es384(&'a HsmDmaBuf),
    /// Encoded ML-DSA-87 public key ([`MLDSA87_PUB_KEY_LEN`] bytes).
    MlDsa87(&'a HsmDmaBuf),
}

impl ReportVerifier<'_> {
    /// The algorithm this key verifies.
    pub fn alg(&self) -> ReportAlg {
        match self {
            Self::Es384(_) => ReportAlg::Es384,
            Self::MlDsa87(_) => ReportAlg::MlDsa87,
        }
    }
}

/// Operation selected by the signed payload, not a second transfer discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReportKind {
    /// Public-key provenance and attributes.
    PublicKey = 0,
    /// DARC TMK export provenance.
    Darc = 1,
    /// Security-domain BKS3 export provenance, including resealing.
    SdBackup = 2,
}

impl ReportKind {
    pub(crate) fn protected_header(self, alg: ReportAlg) -> &'static [u8] {
        match (self, alg) {
            (Self::PublicKey, _) => alg.protected_header(),
            (Self::Darc | Self::SdBackup, ReportAlg::Es384) => &TRANSFER_PROTECTED_HEADER,
            (Self::Darc | Self::SdBackup, ReportAlg::MlDsa87) => &TRANSFER_PROTECTED_HEADER_MLDSA87,
        }
    }

    pub(crate) fn external_aad(self) -> &'static [u8] {
        match self {
            Self::PublicKey => &[],
            Self::Darc => &DARC_EXTERNAL_AAD,
            Self::SdBackup => &SD_BACKUP_EXTERNAL_AAD,
        }
    }
}

/// Firmware-generated inputs to COSE signing.
///
/// Only exporting commands may sign transfer envelopes, after validating
/// the secret and recipient. Generic `KeyReport` accepts public-key inputs only.
pub enum ReportParams<'a> {
    /// Public-key attestation; only this variant allows caller report data.
    PublicKey(KeyReportParams<'a>),
    /// Complete canonical transfer envelope, used verbatim as the COSE payload.
    Transfer(&'a HsmDmaBuf),
}

/// Zero-copy view of a directly signed transfer envelope.
pub struct TransferReportView<'a> {
    /// The envelope's sole operation discriminator and context fields.
    pub header: TransferHeader<'a>,
    /// Complete envelope: header, encapsulation, ciphertext and tag.
    pub envelope: &'a HsmDmaBuf,
    /// Signed COSE protected header.
    pub protected_header: &'a HsmDmaBuf,
    /// Signature: ES384 big-endian `r || s`, or ML-DSA-87.
    pub signature: &'a HsmDmaBuf,
    /// Signature algorithm named by the protected header.
    pub alg: ReportAlg,
}

/// Disjoint signed payloads: a public-key CBOR map or a binary transfer envelope.
///
/// Parsing does not authenticate signatures or authorize the signer/recipient.
pub enum ReportView<'a> {
    /// Public-key attestation, including existing v1/v2 reports.
    PublicKey(KeyReportView<'a>),
    /// DARC or SD envelope, distinguished by its own signed header.
    Transfer(TransferReportView<'a>),
}

impl ReportView<'_> {
    /// Operation selected by the parsed signed payload.
    pub fn kind(&self) -> ReportKind {
        match self {
            Self::PublicKey(_) => ReportKind::PublicKey,
            Self::Transfer(view) => view.header.kind(),
        }
    }

    /// The report's signature algorithm.
    pub fn alg(&self) -> ReportAlg {
        match self {
            Self::PublicKey(view) => view.alg,
            Self::Transfer(transfer) => transfer.alg,
        }
    }
}
