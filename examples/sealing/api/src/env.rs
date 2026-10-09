// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Domain-lifetime configuration supplied by a sealing service.

use anyhow::Result;
use tsra_api::HsmPartition;
use tsra_api::PartPolicy;

use crate::store::SecurityDomainStore;

/// Domain-lifetime configuration supplied by a sealing service.
///
/// The policy and certificate thumbprints must remain unchanged for the
/// security domain's lifetime. The application constructs the complete
/// policy, including its backing-partition identity, before creating a
/// security domain. Signing keys and per-operation receiver credentials are
/// not part of this interface.
pub trait SecurityDomainEnv {
    /// The application's domain-scoped storage implementation.
    type Store: SecurityDomainStore;

    /// The complete unified partition policy.
    fn policy(&self) -> &PartPolicy;

    /// SHA-384 thumbprint of the POTA DER certificate.
    fn pota_thumbprint(&self) -> &[u8];

    /// SHA-384 thumbprint of the SATA DER certificate.
    fn sata_thumbprint(&self) -> &[u8];

    /// Optional SHA-384 thumbprint of the SAPOTA DER certificate.
    fn sapota_thumbprint(&self) -> Option<&[u8]>;

    /// Root-first DER manufacturer chain cached from the device at startup.
    fn mfgr_cert_chain(&self) -> &[Vec<u8>];

    /// Optional root-first DER device-owner chain. An empty chain omits slot 1;
    /// manufacturer and partition-owner evidence remain required.
    fn owner_cert_chain(&self) -> &[Vec<u8>];

    /// Refresh the partition-owner chain after finalization. The emulator serves
    /// only its PTA-signed PID leaf in slot 2; prepend the supplied
    /// root-first POTA/PTA certificates. Retrieval failures must propagate.
    fn part_owner_cert_chain(
        &self,
        partition: &HsmPartition,
        pta_cert_chain: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>>;

    /// Domain-scoped persistence for partition and local SD recovery state.
    fn store(&self) -> &Self::Store;
}
