// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed inputs and views for signed public-key and operation reports.

use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

use crate::consts::*;
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
        if header == PROTECTED_HEADER {
            Ok(Self::Es384)
        } else if header == PROTECTED_HEADER_MLDSA87 {
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
    /// ML-DSA-87 deterministically.
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

/// Signed report discriminator. Operation reports cannot be produced by
/// the generic `KeyReport` command.
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

/// Firmware-derived SHA-384 identifiers and digest for an encrypted transfer.
///
/// Callers must validate the local secret and recipient authorization and
/// compute the envelope digest inside the exporting command. These inputs
/// must not be accepted as caller-supplied claims by a DDI signing command.
pub struct TransferReportParams<'a> {
    /// SHA-384 identifier of the exporting PID public key.
    pub source_pid_key_id: &'a HsmDmaBuf,
    /// SHA-384 identifier of the recipient public key.
    pub recipient_key_id: &'a HsmDmaBuf,
    /// SHA-384 digest of the complete transfer envelope, excluding the report.
    pub envelope_hash: &'a HsmDmaBuf,
}

/// Inputs for the versioned, discriminated report format.
pub enum ReportParams<'a> {
    /// Public-key attestation; only this variant allows caller report data.
    PublicKey(KeyReportParams<'a>),
    /// DARC TMK export.
    Darc(TransferReportParams<'a>),
    /// Security-domain backup export or reseal.
    SdBackup {
        /// Transfer identifiers and envelope digest.
        transfer: TransferReportParams<'a>,
        /// SHA-384 policy digest enforced by the exporting command.
        policy_hash: &'a HsmDmaBuf,
    },
}

/// Zero-copy view of an operation report's transfer fields and signature.
pub struct TransferReportView<'a> {
    /// SHA-384 identifier of the exporting PID public key.
    pub source_pid_key_id: &'a HsmDmaBuf,
    /// SHA-384 identifier of the recipient public key.
    pub recipient_key_id: &'a HsmDmaBuf,
    /// SHA-384 digest of the complete transfer envelope.
    pub envelope_hash: &'a HsmDmaBuf,
    /// Signed COSE protected header.
    pub protected_header: &'a HsmDmaBuf,
    /// Encoded signed payload.
    pub payload: &'a HsmDmaBuf,
    /// Signature: ES384 big-endian `r || s`, or ML-DSA-87.
    pub signature: &'a HsmDmaBuf,
    /// Signature algorithm named by the protected header.
    pub alg: ReportAlg,
}

/// A parsed report with kind-specific required fields.
///
/// Parsing does not authenticate the signature, signer authorization,
/// recipient, or envelope digest. Consumers must verify those separately.
pub enum ReportView<'a> {
    /// Public-key attestation, including legacy v1/v2 reports.
    PublicKey(KeyReportView<'a>),
    /// DARC TMK export.
    Darc(TransferReportView<'a>),
    /// Security-domain backup export or reseal.
    SdBackup {
        /// Transfer identifiers and envelope digest.
        transfer: TransferReportView<'a>,
        /// Required SHA-384 policy digest.
        policy_hash: &'a HsmDmaBuf,
    },
}

impl ReportView<'_> {
    /// The report's kind, validated against its signed payload fields.
    pub fn kind(&self) -> ReportKind {
        match self {
            Self::PublicKey(_) => ReportKind::PublicKey,
            Self::Darc(_) => ReportKind::Darc,
            Self::SdBackup { .. } => ReportKind::SdBackup,
        }
    }

    /// The report's signature algorithm.
    pub fn alg(&self) -> ReportAlg {
        match self {
            Self::PublicKey(view) => view.alg,
            Self::Darc(transfer) | Self::SdBackup { transfer, .. } => transfer.alg,
        }
    }
}
