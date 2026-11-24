// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public-key attestations and directly signed transfer envelopes.

use tsra_fw_hsm_pal_traits::HsmDmaBuf;

use crate::consts::DARC_EXTERNAL_AAD;
use crate::consts::PROTECTED_HEADER;
use crate::consts::SD_BACKUP_EXTERNAL_AAD;
use crate::consts::TRANSFER_PROTECTED_HEADER;
use crate::transfer::TransferHeader;
use crate::KeyReportParams;
use crate::KeyReportView;

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
    pub(crate) fn protected_header(self) -> &'static [u8] {
        match self {
            Self::PublicKey => &PROTECTED_HEADER,
            Self::Darc | Self::SdBackup => &TRANSFER_PROTECTED_HEADER,
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
    /// ES384 signature in big-endian `r || s` form.
    pub signature: &'a HsmDmaBuf,
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
}
