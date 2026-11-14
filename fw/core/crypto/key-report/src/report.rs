// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed inputs and views for signed public-key and operation reports.

use tsra_fw_hsm_pal_traits::HsmDmaBuf;

use crate::KeyReportParams;
use crate::KeyReportView;

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
    /// ES384 signature in big-endian `r || s` form.
    pub signature: &'a HsmDmaBuf,
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
}
