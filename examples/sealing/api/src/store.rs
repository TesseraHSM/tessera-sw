// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Domain-scoped persistence for the separate partition and local SD records.

use anyhow::Context;
use anyhow::Result;
use tsra_api::PartPolicy;
use tsra_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use tsra_ddi_tbor_types::MASKED_SD_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;

/// Recovery material captured immediately after partition finalization.
#[derive(Clone, PartialEq, Eq)]
pub struct PartitionState {
    /// The complete, bound partition-policy wire image.
    pub policy: Vec<u8>,
    /// POTA-anchored PTA chain, DER certificates in root-first order.
    pub pta_cert_chain: Vec<Vec<u8>>,
    /// Partition-local masking-key backup envelope from `part_final_ex`.
    pub local_mk_backup: Vec<u8>,
}

/// Local security-domain recovery material. Remote backups are not stored here.
#[derive(Clone, PartialEq, Eq)]
pub struct SecurityDomainState {
    /// Local partition-owner-key backup.
    pub pok_local_backup: Vec<u8>,

    /// Security-domain masking-key backup envelope.
    pub sd_mk_backup: Vec<u8>,
}

/// A store scoped to one domain, provided by its environment.
///
/// Saves must durably publish both records atomically. Loads return `None`
/// only for absent records; read and decoding failures must be returned as
/// errors. Implementations must protect backup material from unauthorized
/// access and must not log it.
pub trait SecurityDomainStore {
    /// Save partition and local SD recovery material together.
    ///
    /// A failure before publication must leave existing records unchanged.
    /// A durability failure after publication may leave both new records
    /// visible; implementations must not remove them in response to that failure.
    fn save_creation(&self, partition: &PartitionState, domain: &SecurityDomainState)
        -> Result<()>;

    /// Read the partition recovery record.
    fn load_partition(&self) -> Result<Option<PartitionState>>;

    /// Read the local SD recovery record.
    fn load_security_domain(&self) -> Result<Option<SecurityDomainState>>;
}

/// Load complete, well-sized local recovery material before touching a device.
///
/// # Errors
/// Returns an error for missing records, malformed policy bytes, empty PTA
/// chains, invalid backup lengths, or storage failures.
pub fn load_local_recovery(
    store: &impl SecurityDomainStore,
) -> Result<(PartitionState, SecurityDomainState)> {
    let partition = load_partition_recovery(store)?;
    let domain = store
        .load_security_domain()?
        .context("local security-domain recovery state is missing")?;
    anyhow::ensure!(
        domain.pok_local_backup.len() == MASKED_SD_LEN,
        "invalid stored local partition-owner-key backup length"
    );
    anyhow::ensure!(
        domain.sd_mk_backup.len() == SD_MK_BACKUP_LEN,
        "invalid stored SD masking-key backup length"
    );
    Ok((partition, domain))
}

/// Load partition recovery material without requiring a local SD backup.
///
/// Validates policy framing, the presence of a PTA chain and the local MK
/// backup length. Remote SD recovery can then use its independent backup.
pub fn load_partition_recovery(store: &impl SecurityDomainStore) -> Result<PartitionState> {
    let partition = store
        .load_partition()?
        .context("partition recovery state is missing")?;
    anyhow::ensure!(
        PartPolicy::ref_from_wire(&partition.policy).is_some(),
        "stored partition policy has an invalid wire format"
    );
    anyhow::ensure!(
        !partition.pta_cert_chain.is_empty(),
        "stored PTA certificate chain is empty"
    );
    anyhow::ensure!(
        partition.local_mk_backup.len() == LOCAL_MK_BACKUP_LEN,
        "invalid stored partition masking-key backup length"
    );
    Ok(partition)
}
