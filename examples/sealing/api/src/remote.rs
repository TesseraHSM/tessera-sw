// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Two-phase remote recovery or authorized instance enrollment through an
//! attested sealing authority. No local SD backup is read, and no HPKE plaintext
//! leaves the HSM.

use anyhow::Context;
use anyhow::Result;
use tsra_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::load_partition_recovery;
use crate::mint_sealing_key;
use crate::Error;
use crate::Evidence;
use crate::IdentityEvidence;
use crate::PartPolicy;
use crate::PartitionState;
use crate::RemoteBackup;
use crate::SealingKey;
use crate::SealingSession;
use crate::SecurityDomain;
use crate::SecurityDomainEnv;

/// Finalized recovering or newly enrolled partition and its locally masked receiver.
/// Retain locally before requesting resealing; never send `receiver.masked`.
pub struct PreparedRemoteRestore {
    /// Refreshed partition recovery material.
    pub partition: PartitionState,
    /// Fresh receiver key masked by this partition's restored or newly created local MK.
    pub receiver: SealingKey,
    /// The recovering partition's attestation of that receiver.
    pub evidence: Evidence,
}

/// Backup resealed by an authority to the prepared receiver.
#[derive(Clone)]
pub struct ResealedBackup {
    /// P-384 HPKE Base envelope addressed to the recovering partition.
    pub pok_remote_backup: Vec<u8>,
    /// Original SDMK backup paired with the security-domain seed.
    pub sd_mk_backup: Vec<u8>,
    /// Actual authority PID report signer as DER SPKI (currently P-384).
    pub sender_pid_pub_key: Vec<u8>,
    /// Authority PID chains; the signed backup contains the operation signature.
    pub sender_evidence: IdentityEvidence,
}

impl ResealedBackup {
    /// Check framing before device access. Applications additionally verify
    /// the sender evidence against their trusted authority's policy.
    pub fn validate(&self) -> Result<()> {
        crate::RemoteRecovery::validate_transfer_envelope(&self.pok_remote_backup)?;
        anyhow::ensure!(
            self.pok_remote_backup.len() == POK_REMOTE_BACKUP_LEN,
            "invalid resealed backup length"
        );
        anyhow::ensure!(
            self.sd_mk_backup.len() == SD_MK_BACKUP_LEN,
            "invalid remote SDMK backup length"
        );
        crate::policy::validate_pid_spki(&self.sender_pid_pub_key)?;
        require_identity(&self.sender_evidence)
    }
}

fn require_identity(evidence: &IdentityEvidence) -> Result<()> {
    anyhow::ensure!(
        !evidence.mfgr_cert_chain.is_empty() && !evidence.part_owner_cert_chain.is_empty(),
        "remote resealing requires complete source identity chains"
    );
    Ok(())
}

fn require_evidence(evidence: &Evidence) -> Result<()> {
    anyhow::ensure!(
        !evidence.mfgr_cert_chain.is_empty()
            && !evidence.part_owner_cert_chain.is_empty()
            && !evidence.report.is_empty(),
        "remote resealing requires complete attestation evidence"
    );
    Ok(())
}

/// Open a source backup and reseal it inside the authority's HSM.
///
/// Source PID chains must POTA-authorize the signed backup's signer. Destination
/// evidence must attest an HSM-generated SdSealing key and the requested policy.
/// The outgoing backup is signed by the authority's local PID and binds the
/// requested policy, which need not be the authority's local policy.
pub fn reseal_remote_backup(
    session: &SealingSession,
    policy: &PartPolicy,
    masked_receiver: &[u8],
    source: &RemoteBackup,
    destination: &Evidence,
) -> Result<tsra_api::HsmSdTransferResult> {
    anyhow::ensure!(
        masked_receiver.len() == MASKED_SEALING_KEY_LEN,
        "invalid authority receiver length"
    );
    anyhow::ensure!(
        source.pok_remote_backup.len() == POK_REMOTE_BACKUP_LEN,
        "invalid source backup length"
    );
    require_identity(&source.evidence)?;
    require_evidence(destination)?;
    source
        .evidence
        .with_hsm_identity(|src| {
            destination.with_hsm_evidence(|dst| {
                session.session.sd_reseal_remote_backup(
                    policy.as_bytes(),
                    masked_receiver,
                    src,
                    dst,
                    &source.pok_remote_backup,
                )
            })
        })
        .context("sd_reseal_remote_backup")
}

impl<Env: SecurityDomainEnv> SecurityDomain<Env> {
    /// Prepare a fresh, independently seeded instance of an existing domain.
    ///
    /// The authority must explicitly authorize its PTA and reseal the original
    /// domain to this receiver. Retains the full original policy, including its
    /// backup PID; this is not peer cloning and requires no peer-cloning flag.
    /// No previous local MK is imported. Persist the returned preparation before
    /// requesting resealing, then complete with [`Self::restore_resealed`].
    pub fn prepare_remote_instance<SignPta>(
        &self,
        session: &SealingSession,
        seed: &[u8],
        sign_pta: SignPta,
    ) -> Result<PreparedRemoteRestore>
    where
        SignPta: FnOnce(&[u8], &[u8]) -> Result<Vec<Vec<u8>>>,
    {
        self.ensure_can_create()?;
        let partition = self.init_partition(session, seed, None, sign_pta)?;
        self.prepare_receiver(session, partition)
    }

    /// Restore only the partition, then mint a fresh receiver for remote SD
    /// recovery. Uses saved local MK, policy and original seed; never creates
    /// an SD or reads its local POK/SDMK backup. Persist the returned material
    /// before requesting resealing.
    pub fn prepare_remote_restore<SignPta>(
        &self,
        session: &SealingSession,
        seed: &[u8],
        sign_pta: SignPta,
    ) -> Result<PreparedRemoteRestore>
    where
        SignPta: FnOnce(&[u8], &[u8]) -> Result<Vec<Vec<u8>>>,
    {
        let previous = load_partition_recovery(self.env().store())?;
        anyhow::ensure!(
            previous.policy == self.env().policy().as_bytes(),
            "remote restore policy mismatch"
        );
        let partition =
            self.init_partition(session, seed, Some(&previous.local_mk_backup), sign_pta)?;
        self.prepare_receiver(session, partition)
    }

    fn prepare_receiver(
        &self,
        session: &SealingSession,
        partition: PartitionState,
    ) -> Result<PreparedRemoteRestore> {
        let prepared = (|| {
            let receiver = mint_sealing_key(&session.session)?;
            let evidence = Evidence {
                mfgr_cert_chain: self.env().mfgr_cert_chain().to_vec(),
                owner_cert_chain: self.env().owner_cert_chain().to_vec(),
                part_owner_cert_chain: self
                    .env()
                    .part_owner_cert_chain(&session.partition, &partition.pta_cert_chain)?,
                report: receiver.report.clone(),
            };
            require_evidence(&evidence)?;
            Ok::<_, anyhow::Error>((receiver, evidence))
        })();
        let (receiver, evidence) = prepared.map_err(|source| Error::PartitionPersistence {
            state: partition.clone(),
            source,
        })?;
        Ok(PreparedRemoteRestore {
            partition,
            receiver,
            evidence,
        })
    }

    /// Restore the SD on an already-prepared partition using the authority's
    /// resealed backup, then atomically persist refreshed local recovery.
    ///
    /// Applications validate the signed backup, recipient and response first.
    /// Firmware always verifies the signature against the supplied PID signer.
    /// With trusted-SA enabled it additionally authenticates source PID chains
    /// under SAPOTA; signature-only mode does not establish trusted SA identity.
    pub fn restore_resealed(
        &self,
        session: &SealingSession,
        prepared: &PreparedRemoteRestore,
        backup: &ResealedBackup,
    ) -> Result<()> {
        backup.validate()?;
        anyhow::ensure!(
            prepared.partition.policy == self.env().policy().as_bytes(),
            "prepared remote policy mismatch"
        );
        anyhow::ensure!(
            prepared.receiver.masked.len() == MASKED_SEALING_KEY_LEN,
            "invalid prepared receiver length"
        );
        let result = backup.sender_evidence.with_hsm_identity(|evidence| {
            session.session.sd_restore_remote_backup(
                self.env().policy().as_bytes(),
                &prepared.receiver.masked,
                &backup.sender_pid_pub_key,
                evidence,
                &backup.pok_remote_backup,
                &backup.sd_mk_backup,
            )
        });
        self.finish_remote_restore(prepared.partition.clone(), result)
    }
}
