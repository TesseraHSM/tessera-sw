// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owned security-domain attestation evidence.

use tsra_api::HsmCert;
use tsra_api::HsmSdEvidence;

/// Owned attestation for a sender or receiver. Certificate chains are
/// DER-encoded, root-first. The PID-signed report embeds that party's sealing
/// public key.
#[derive(Clone)]
pub struct Evidence {
    /// Manufacturer chain authenticating the PID.
    pub mfgr_cert_chain: Vec<Vec<u8>>,
    /// Owner chain, or empty when intentionally omitted.
    pub owner_cert_chain: Vec<Vec<u8>>,
    /// POTA/PTA/PID chain authenticating the same PID.
    pub part_owner_cert_chain: Vec<Vec<u8>>,
    /// PID-signed COSE_Sign1 key report.
    pub report: Vec<u8>,
}

impl Evidence {
    /// Adapt this evidence to the SDK's borrowed view without exposing temporary
    /// certificate-descriptor lifetimes. This is the same attestation material,
    /// not a separate kind of evidence. Empty chains remain empty.
    pub fn with_hsm_evidence<T>(&self, f: impl FnOnce(&HsmSdEvidence<'_>) -> T) -> T {
        fn certs(chain: &[Vec<u8>]) -> Vec<HsmCert<'_>> {
            chain.iter().map(|cert| HsmCert { cert }).collect()
        }
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
