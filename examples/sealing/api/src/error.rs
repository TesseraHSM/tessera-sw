// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured sealing API errors carried by `anyhow::Result`.

use crate::sd::RemoteBackup;
use crate::sd::RemoteRecovery;
use crate::store::PartitionState;
use crate::store::SecurityDomainState;

/// Crate-wide failures requiring specific recovery by the caller.
///
/// API operations return `anyhow::Result` for error propagation and context.
/// Downcast to this type to recover unsaved state after an irreversible
/// device operation. Retry storage, not a successful device creation or restore.
#[derive(thiserror::Error)]
pub enum Error {
    /// The partition finalized, but the domain operation failed before saving.
    #[error("partition finalized, but security-domain operation failed before persistence")]
    PartitionPersistence {
        /// Recovery material to retry saving.
        state: PartitionState,
        /// Creation or restore failure after partition finalization.
        source: anyhow::Error,
    },
    /// The SD was created, but saving its recovery records failed.
    #[error("security domain created, but persistence failed")]
    SecurityDomainPersistence {
        /// Partition recovery material to retry saving alongside local SD state.
        partition: PartitionState,
        /// Local recovery material to retry saving.
        state: SecurityDomainState,
        /// Remote backup and sender attestation still available for delivery.
        result: RemoteBackup,
        /// Storage failure.
        source: anyhow::Error,
    },
    /// The SD restored, but saving its refreshed recovery records failed.
    #[error("security domain restored, but persistence failed")]
    LocalRestorePersistence {
        /// Refreshed partition recovery material to retry saving.
        partition: PartitionState,
        /// Refreshed local SD recovery material to retry saving.
        state: SecurityDomainState,
        /// Storage failure.
        source: anyhow::Error,
    },
    /// External-SA preparation succeeded, but its restore package was not saved.
    #[error("local recovery saved, but external-SA remote backup persistence failed")]
    RemoteBackupPersistence {
        /// Restore-ready ciphertext, certificates and masked receiver key to retry saving.
        result: RemoteRecovery,
        /// Storage failure.
        source: anyhow::Error,
    },
    /// Remote restore succeeded, but saving refreshed local state failed.
    #[error("security domain restored remotely, but persistence failed")]
    RemoteRestorePersistence {
        /// Refreshed partition recovery material.
        partition: PartitionState,
        /// Refreshed local SD recovery material.
        state: SecurityDomainState,
        /// Storage failure.
        source: anyhow::Error,
    },
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
