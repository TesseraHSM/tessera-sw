// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for the security-domain backup commands
//! (`SdCreateRemoteBackup`, `SdResealRemoteBackup`).
//!
//! # Out-of-band evidence
//!
//! Bulk attestation evidence (DER cert chains and a COSE_Sign1 report)
//! travels out of band: each [`HsmSdEvidence`] is flattened into
//! `(index, length)` descriptors (via [`super::descriptor_utils`]) and its
//! DER bytes
//! are shipped as `oob_items`, mirroring the `PartFinal` cert-chain
//! transport.

use tsra_ddi_tbor_types::*;

use super::*;

/// Validates the length of a caller-supplied partition policy document
/// (`1..=`[`PART_POLICY_MAX_LEN`] bytes) and returns its wire copy.
///
/// The document's contents are validated by the device.
pub(crate) fn policy_wire(policy: &[u8]) -> HsmResult<Vec<u8>> {
    if policy.is_empty() || policy.len() > PART_POLICY_MAX_LEN {
        return Err(HsmError::InvalidArgument);
    }
    Ok(policy.to_vec())
}

/// Wire descriptors for one attestation party: the three cert-chain
/// lists plus the report descriptor. Produced by [`push_evidence`].
pub(crate) struct EvidenceDescriptors {
    pub(crate) mfgr: Vec<CertDescriptor>,
    pub(crate) owner: Vec<CertDescriptor>,
    pub(crate) part_owner: Vec<CertDescriptor>,
    pub(crate) report: ReportDescriptor,
}

impl EvidenceDescriptors {
    /// Empty evidence: no cert chains and a zero-length report descriptor,
    /// referencing nothing in the out-of-band list.
    ///
    /// Used for `SdCreateRemoteBackup` when the policy's
    /// `require_trusted_sa_key` flag is clear: the firmware ignores the
    /// evidence group entirely in that case, so no DER bytes are shipped.
    pub(crate) fn empty() -> Self {
        Self {
            mfgr: Vec::new(),
            owner: Vec::new(),
            part_owner: Vec::new(),
            report: ReportDescriptor {
                index: 0,
                length: tbor_int::U16::new(0),
            },
        }
    }
}

/// Like [`push_evidence`], but packs [`EvidenceDescriptors::empty`]
/// (shipping no DER bytes) when `evidence` carries nothing.
///
/// The firmware verifies the evidence only when the policy sets
/// `require_trusted_sa_key` and ignores it otherwise. The host does not
/// parse the policy, so callers express the flag-clear case by passing
/// empty evidence.
pub(crate) fn push_evidence_if_present<'a>(
    evidence: &HsmSdEvidence<'a>,
    oob: &mut Vec<&'a [u8]>,
) -> HsmResult<EvidenceDescriptors> {
    let is_empty = evidence.mfgr_cert_chain.is_empty()
        && evidence.owner_cert_chain.is_empty()
        && evidence.part_owner_cert_chain.is_empty()
        && evidence.report.is_empty();
    if is_empty {
        Ok(EvidenceDescriptors::empty())
    } else {
        push_evidence(evidence, oob)
    }
}

/// Flattens one [`HsmSdEvidence`] party into its wire descriptors,
/// appending all referenced DER bytes (the three cert chains, then the
/// report) to the shared `oob` list so their descriptor indices are
/// contiguous.
pub(crate) fn push_evidence<'a>(
    evidence: &HsmSdEvidence<'a>,
    oob: &mut Vec<&'a [u8]>,
) -> HsmResult<EvidenceDescriptors> {
    Ok(EvidenceDescriptors {
        mfgr: push_cert_chain(evidence.mfgr_cert_chain, oob, EVIDENCE_CHAIN_MAX_CERTS)?,
        owner: if evidence.owner_cert_chain.is_empty() {
            Vec::new()
        } else {
            push_cert_chain(evidence.owner_cert_chain, oob, EVIDENCE_CHAIN_MAX_CERTS)?
        },
        part_owner: push_cert_chain(
            evidence.part_owner_cert_chain,
            oob,
            EVIDENCE_CHAIN_MAX_CERTS,
        )?,
        report: push_report(evidence.report, oob)?,
    })
}
