// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transport-independent peer cloning. Each peer retains its own partition
//! masking key; only the security domain is transferred. Both peers must bind
//! the exact same policy, with peer cloning enabled.

use anyhow::Context;
use anyhow::Result;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;
use zerocopy::IntoBytes;

use crate::hsm::mint_sealing_key;
use crate::hsm::SealingKey;
use crate::Error;
use crate::Evidence;
use crate::PartitionState;
use crate::SealingSession;
use crate::SecurityDomain;
use crate::SecurityDomainEnv;
use crate::SecurityDomainState;
use crate::SecurityDomainStore;

/// Receiver-bound peer backup and the evidence authenticating its sender.
/// Contains no partition-local masking-key backup or authority private key.
pub struct PeerBackup {
    /// HPKE-sealed partition-owner-key backup addressed to the receiver.
    pub pok_peer_backup: Vec<u8>,
    /// The source's associated SD masking-key backup.
    pub sd_mk_backup: Vec<u8>,
    /// All three sender certificate chains and its sealing-key report.
    pub sender_evidence: Evidence,
}

/// A finalized destination partition and its locally masked receiver key.
/// Keep this material on the destination; never send it to the source.
pub struct PreparedPeer {
    /// Fresh destination partition-local recovery material.
    pub partition: PartitionState,
    /// Locally masked receiver key and report to use for peer attestation.
    pub receiver: SealingKey,
}

impl<Env: SecurityDomainEnv> SecurityDomain<Env> {
    /// Finalize a new destination without creating an SD. The POTA signer may
    /// be remote. A fresh local MK is generated; no source local MK is imported.
    pub fn prepare_peer<SignPta>(
        &self,
        session: &SealingSession,
        seed: &[u8],
        sign_pta: SignPta,
    ) -> Result<PreparedPeer>
    where
        SignPta: FnOnce(&[u8], &[u8]) -> Result<Vec<Vec<u8>>>,
    {
        anyhow::ensure!(
            self.env().policy().flags.allow_peer_cloning(),
            "peer cloning is disabled"
        );
        self.ensure_can_create()?;
        let partition = self.init_partition(session, seed, None, sign_pta)?;
        let receiver =
            mint_sealing_key(&session.session).map_err(|source| Error::PartitionPersistence {
                state: partition.clone(),
                source,
            })?;
        Ok(PreparedPeer {
            partition,
            receiver,
        })
    }

    /// Export the live SD to an attested receiver. Firmware verifies receiver
    /// evidence against SATA and the bound policy. `attest` must return the
    /// complete sender evidence for the freshly generated sealing key.
    pub fn create_peer_backup<Attest>(
        &self,
        session: &SealingSession,
        receiver: &Evidence,
        attest: Attest,
    ) -> Result<PeerBackup>
    where
        Attest: FnOnce(&SealingKey) -> Result<Evidence>,
    {
        anyhow::ensure!(
            self.env().policy().flags.allow_peer_cloning(),
            "peer cloning is disabled"
        );
        let (partition, state) = crate::load_local_recovery(self.env().store())?;
        anyhow::ensure!(
            partition.policy == self.env().policy().as_bytes(),
            "peer policy mismatch"
        );
        let sender = mint_sealing_key(&session.session)?;
        let sender_evidence = attest(&sender)?;
        let pok_peer_backup = receiver
            .with_hsm_evidence(|evidence| {
                session.session.sd_create_peer_backup(
                    self.env().policy(),
                    &sender.masked,
                    evidence,
                    &state.pok_local_backup,
                )
            })
            .context("sd_create_peer_backup")?;
        Ok(PeerBackup {
            pok_peer_backup,
            sd_mk_backup: state.sd_mk_backup,
            sender_evidence,
        })
    }

    /// Restore into a prepared destination and atomically persist its local
    /// recovery records. Callers validate sender evidence before invoking this;
    /// firmware also authenticates it and the receiver-bound seal.
    ///
    /// On persistence failure, `Error::LocalRestorePersistence` retains the
    /// refreshed records. Retry storage, not the one-shot device operation.
    pub fn restore_peer(
        &self,
        session: &SealingSession,
        prepared: &PreparedPeer,
        backup: &PeerBackup,
    ) -> Result<()> {
        anyhow::ensure!(
            self.env().policy().flags.allow_peer_cloning(),
            "peer cloning is disabled"
        );
        anyhow::ensure!(
            prepared.partition.policy == self.env().policy().as_bytes(),
            "peer policy mismatch"
        );
        anyhow::ensure!(
            backup.pok_peer_backup.len() == POK_REMOTE_BACKUP_LEN,
            "invalid peer backup length"
        );
        anyhow::ensure!(
            backup.sd_mk_backup.len() == SD_MK_BACKUP_LEN,
            "invalid peer SD masking-key backup length"
        );
        let restored = backup
            .sender_evidence
            .with_hsm_evidence(|evidence| {
                session.session.sd_restore_peer_backup(
                    self.env().policy(),
                    &prepared.receiver.masked,
                    evidence,
                    &backup.pok_peer_backup,
                    &backup.sd_mk_backup,
                )
            })
            .context("sd_restore_peer_backup")?;
        let state = SecurityDomainState {
            pok_local_backup: restored.pok_local_backup,
            sd_mk_backup: restored.sd_mk_backup,
        };
        self.env()
            .store()
            .save_creation(&prepared.partition, &state)
            .map_err(|source| {
                Error::LocalRestorePersistence {
                    partition: prepared.partition.clone(),
                    state,
                    source,
                }
                .into()
            })
    }
}
