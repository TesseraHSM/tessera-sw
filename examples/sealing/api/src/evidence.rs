// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owned recipient attestation and source identity chains.

use tsra_api::HsmCert;
use tsra_api::HsmSdEvidence;
use tsra_api::HsmSdIdentityEvidence;

/// Certificate chains are DER-encoded, root-first. Recipient PublicKey reports
/// attest sealing keys. Transfer signatures are carried in the signed backup.
#[derive(Clone)]
pub struct Evidence {
    /// Manufacturer chain authenticating the PID.
    pub mfgr_cert_chain: Vec<Vec<u8>>,
    /// Owner chain, or empty when intentionally omitted.
    pub owner_cert_chain: Vec<Vec<u8>>,
    /// POTA/PTA/PID chain authenticating the same PID.
    pub part_owner_cert_chain: Vec<Vec<u8>>,
    /// COSE_Sign1 PublicKey report attesting the recipient sealing key.
    pub report: Vec<u8>,
}

impl Evidence {
    /// Adapt this evidence to the SDK's borrowed view without exposing temporary
    /// certificate-descriptor lifetimes. This is the same attestation material,
    /// not a separate kind of evidence. Empty chains remain empty.
    pub fn with_hsm_evidence<T>(&self, f: impl FnOnce(&HsmSdEvidence<'_>) -> T) -> T {
        let mfgr = certs(&self.mfgr_cert_chain);
        let owner = certs(&self.owner_cert_chain);
        let part_owner = certs(&self.part_owner_cert_chain);
        f(&HsmSdEvidence {
            mfgr_cert_chain: &mfgr,
            owner_cert_chain: &owner,
            part_owner_cert_chain: &part_owner,
            report: &self.report,
        })
    }

    pub fn identity(&self) -> IdentityEvidence {
        IdentityEvidence {
            mfgr_cert_chain: self.mfgr_cert_chain.clone(),
            owner_cert_chain: self.owner_cert_chain.clone(),
            part_owner_cert_chain: self.part_owner_cert_chain.clone(),
        }
    }
}

/// Source PID chains, independent of the signature inside each transfer.
/// Signature-only software authorities leave all chains empty.
#[derive(Clone, Default)]
pub struct IdentityEvidence {
    pub mfgr_cert_chain: Vec<Vec<u8>>,
    pub owner_cert_chain: Vec<Vec<u8>>,
    pub part_owner_cert_chain: Vec<Vec<u8>>,
}

impl IdentityEvidence {
    pub fn with_hsm_identity<T>(&self, f: impl FnOnce(&HsmSdIdentityEvidence<'_>) -> T) -> T {
        let mfgr = certs(&self.mfgr_cert_chain);
        let owner = certs(&self.owner_cert_chain);
        let part_owner = certs(&self.part_owner_cert_chain);
        f(&HsmSdIdentityEvidence {
            mfgr_cert_chain: &mfgr,
            owner_cert_chain: &owner,
            part_owner_cert_chain: &part_owner,
        })
    }
}

fn certs(chain: &[Vec<u8>]) -> Vec<HsmCert<'_>> {
    chain.iter().map(|cert| HsmCert { cert }).collect()
}

impl std::fmt::Debug for IdentityEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityEvidence")
            .field("mfgr_cert_count", &self.mfgr_cert_chain.len())
            .field("owner_cert_count", &self.owner_cert_chain.len())
            .field("part_owner_cert_count", &self.part_owner_cert_chain.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Evidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Evidence")
            .field("mfgr_cert_count", &self.mfgr_cert_chain.len())
            .field("owner_cert_count", &self.owner_cert_chain.len())
            .field("part_owner_cert_count", &self.part_owner_cert_chain.len())
            .field("report_len", &self.report.len())
            .finish_non_exhaustive()
    }
}
