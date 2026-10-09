// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain creation, local restore and same-partition remote restore.
//!
//! [`SecurityDomain::create`] drives a factory-reset partition through the full
//! provisioning flow — `part_init_ex`, PTA-chain issuance, `part_final_ex`,
//! sealing-key minting, and `sd_create_remote_backup` — and returns the
//! remote backup and sender attestation material. Local recovery records are persisted
//! separately through the environment's store.
//!
//! The caller supplies the receiver certificate chain (containing
//! `RcvrPub`) and receiver attestation evidence. The sender sealing key
//! generated here is distinct from the externally supplied receiver key.
//! Only POTA signing is a callback: it receives the device PTA CSR and
//! PID-signed attestation report and returns the POTA-anchored PTA chain.

use anyhow::Context;
use anyhow::Result;
use tsra_api::HsmCert;
use tsra_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;
use zerocopy::IntoBytes;

pub use crate::env::SecurityDomainEnv;
use crate::error::Error;
pub use crate::evidence::Evidence;
use crate::hsm;
use crate::session::SealingSession;
use crate::store::load_local_recovery;
use crate::store::load_partition_recovery;
use crate::store::PartitionState;
use crate::store::SecurityDomainState;
use crate::store::SecurityDomainStore;

/// Remote backup and owned sender evidence for external delivery.
#[derive(Clone)]
pub struct RemoteBackup {
    /// Remote partition-owner-key backup sealed to the supplied receiver.
    pub pok_remote_backup: Vec<u8>,
    /// Sender identity chains and report. No separate public key is needed.
    pub evidence: Evidence,
}

impl std::fmt::Debug for RemoteBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteBackup")
            .field("pok_remote_backup_len", &self.pok_remote_backup.len())
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

/// Same-partition remote SD recovery data, independent of the local POK backup.
///
/// The receiver key is locally masked, so restoring it still requires the
/// original partition's local MK backup. External-SA recovery carries separate
/// SATA-endorsed sender and receiver HPKE chains; `backup.evidence` retains the
/// original TSRA creation sender evidence, not evidence of the external SA.
/// Legacy recovery instead uses attested sender evidence. The caller validates
/// all material before device access; firmware authenticates the sender and seal.
#[derive(Clone)]
pub struct RemoteRecovery {
    /// Restore-ready HPKE backup and original TSRA creation sender evidence.
    pub backup: RemoteBackup,
    /// Original locally masked receiver sealing key.
    pub masked_receiver_key: Vec<u8>,
    /// SDMK backup paired with the original remote backup.
    pub sd_mk_backup: Vec<u8>,
    /// SATA-endorsed external sender HPKE chain, or empty for legacy attested restore.
    pub sender_cert_chain: Vec<Vec<u8>>,
    /// SATA-endorsed HSM receiver HPKE chain for the external-SA flow.
    pub receiver_cert_chain: Vec<Vec<u8>>,
}

impl RemoteRecovery {
    /// Validate backup lengths and mandatory evidence before device operations.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.masked_receiver_key.len() == MASKED_SEALING_KEY_LEN,
            "invalid remote receiver key length"
        );
        anyhow::ensure!(
            self.backup.pok_remote_backup.len() == POK_REMOTE_BACKUP_LEN,
            "invalid remote POK backup length"
        );
        anyhow::ensure!(
            self.sd_mk_backup.len() == SD_MK_BACKUP_LEN,
            "invalid remote SD masking-key backup length"
        );
        let evidence = &self.backup.evidence;
        anyhow::ensure!(
            !evidence.mfgr_cert_chain.is_empty()
                && !evidence.part_owner_cert_chain.is_empty()
                && !evidence.report.is_empty(),
            "remote recovery requires creation sender evidence"
        );
        anyhow::ensure!(
            self.sender_cert_chain.is_empty() == self.receiver_cert_chain.is_empty(),
            "external-SA recovery requires both sender and receiver HPKE chains"
        );
        Ok(())
    }
}

impl std::fmt::Debug for RemoteRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteRecovery")
            .field("backup", &self.backup)
            .field("masked_receiver_key_len", &self.masked_receiver_key.len())
            .field("sd_mk_backup_len", &self.sd_mk_backup.len())
            .field("sender_cert_chain_len", &self.sender_cert_chain.len())
            .field("receiver_cert_chain_len", &self.receiver_cert_chain.len())
            .finish()
    }
}

/// A security domain with its domain-lifetime environment.
pub struct SecurityDomain<Env: SecurityDomainEnv> {
    env: Env,
}

impl<Env: SecurityDomainEnv> SecurityDomain<Env> {
    /// Retain the application's environment for all domain operations.
    pub fn new(env: Env) -> Self {
        Self { env }
    }

    /// Borrow the retained environment.
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// Provision the security domain on `session`'s partition and seal a
    /// remote backup of it.
    ///
    /// The retained environment supplies the complete policy and anchor
    /// certificate thumbprints. `tee_seed` is the `MACH_SEED_LEN`-byte
    /// machine seed sealed under the session param key at `part_init_ex`.
    ///
    /// # Provisioning flow
    ///
    /// 1. Check that no recovery records exist and manufacturer evidence is present.
    /// 2. Initialize and finalize the partition using the application's PTA signer.
    /// 3. Refresh the sender chain, mint its sealing key, and create the remote backup.
    /// 4. Save partition and local SD recovery records together.
    ///
    /// The signer returns the complete root-first certificate chain, including
    /// any intermediates, with one DER certificate per entry.
    /// Firmware obtains `RcvrPub` from the receiver chain's leaf certificate and
    /// validates it against SATA. Attestation evidence is required when
    /// the policy sets `require_trusted_sa_key`; otherwise its chains and
    /// report may be empty. Receiver and sender attestation both use
    /// [`Evidence`]; the SDK's borrowed view is constructed for the device call.
    ///
    /// # Failure recovery
    ///
    /// Failures after finalization retain partition recovery material in
    /// [`Error`]; storage failures also retain local SD state and the complete
    /// creation result. A storage failure does not roll back device operations.
    /// Existing records are rejected before any
    /// provisioning operation so they cannot be overwritten by create.
    pub fn create<SignPta>(
        &self,
        session: &SealingSession,
        tee_seed: &[u8],
        receiver_cert_chain: &[HsmCert<'_>],
        receiver_evidence: &Evidence,
        sign_pta: SignPta,
    ) -> Result<RemoteBackup>
    where
        SignPta: FnOnce(&[u8], &[u8]) -> Result<Vec<Vec<u8>>>,
    {
        self.ensure_can_create()?;
        let partition_state = self.init_partition(session, tee_seed, None, sign_pta)?;

        let (domain_state, remote_backup) = match self.create_backup(
            session,
            &partition_state,
            receiver_cert_chain,
            receiver_evidence,
        ) {
            Ok(created) => created,
            Err(source) => {
                return Err(Error::PartitionPersistence {
                    state: partition_state,
                    source,
                }
                .into());
            }
        };

        if let Err(source) = self
            .env
            .store()
            .save_creation(&partition_state, &domain_state)
        {
            return Err(Error::SecurityDomainPersistence {
                partition: partition_state,
                state: domain_state,
                result: remote_backup,
                source,
            }
            .into());
        }
        Ok(remote_backup)
    }

    /// Restore a security domain from its saved device-local recovery records.
    ///
    /// The session must be on a factory-state incarnation of the same partition.
    /// Supply the original machine seed, policy, thumbprints and POTA signer.
    /// Reinitializes and finalizes the partition using the previous local MK
    /// backup, then calls `sd_restore_local_backup`. No receiver or attestation
    /// evidence is required. Refreshed partition and SD backups are saved
    /// together, without overwriting the old records on a device failure.
    ///
    /// # Errors
    /// Rejects incomplete recovery state or a changed policy before initialization.
    /// Device errors propagate. If persistence fails after a successful restore,
    /// [`Error::LocalRestorePersistence`] retains the refreshed records for retry.
    pub fn restore_local<SignPta>(
        &self,
        session: &SealingSession,
        tee_seed: &[u8],
        sign_pta: SignPta,
    ) -> Result<()>
    where
        SignPta: FnOnce(&[u8], &[u8]) -> Result<Vec<Vec<u8>>>,
    {
        let (previous_partition, previous_domain) = load_local_recovery(self.env.store())?;
        anyhow::ensure!(
            previous_partition.policy == self.env.policy().as_bytes(),
            "stored partition policy does not match the restore environment",
        );
        let partition = self.init_partition(
            session,
            tee_seed,
            Some(&previous_partition.local_mk_backup),
            sign_pta,
        )?;
        let restored = match session.session.sd_restore_local_backup(
            &previous_domain.pok_local_backup,
            &previous_domain.sd_mk_backup,
        ) {
            Ok(restored) => restored,
            Err(source) => {
                return Err(Error::PartitionPersistence {
                    state: partition,
                    source: anyhow::Error::new(source).context("sd_restore_local_backup"),
                }
                .into());
            }
        };
        let state = SecurityDomainState {
            pok_local_backup: restored.pok_local_backup,
            sd_mk_backup: restored.sd_mk_backup,
        };
        if let Err(source) = self.env.store().save_creation(&partition, &state) {
            return Err(Error::LocalRestorePersistence {
                partition,
                state,
                source,
            }
            .into());
        }
        Ok(())
    }

    /// Restore via `sd_restore_remote_backup`, never via the local SD backup.
    ///
    /// Restores the partition's previous local MK (needed for the receiver key),
    /// then HPKE-opens the remote backup on the device and saves refreshed local
    /// backups. A local POK or current local SDMK record is not required.
    /// Persistence failures retain refreshed state in
    /// [`Error::RemoteRestorePersistence`].
    pub fn restore_remote<SignPta>(
        &self,
        session: &SealingSession,
        tee_seed: &[u8],
        remote: &RemoteRecovery,
        sign_pta: SignPta,
    ) -> Result<()>
    where
        SignPta: FnOnce(&[u8], &[u8]) -> Result<Vec<Vec<u8>>>,
    {
        remote.validate()?;
        anyhow::ensure!(
            remote.sender_cert_chain.is_empty()
                || !self.env.policy().flags.require_trusted_sa_key(),
            "external-SA certificate-only restore cannot satisfy trusted-SA attestation"
        );
        let previous = load_partition_recovery(self.env.store())?;
        anyhow::ensure!(
            previous.policy == self.env.policy().as_bytes(),
            "stored partition policy does not match the restore environment"
        );
        let partition =
            self.init_partition(session, tee_seed, Some(&previous.local_mk_backup), sign_pta)?;
        // Unified `SdRestoreRemoteBackup` (0x0C): the sender certificate
        // chain is always the source of `SndrPub`, and the attestation
        // evidence is optional — the host packs it only when the policy sets
        // `require_trusted_sa_key`, and the firmware ignores it otherwise.
        let certs = remote
            .sender_cert_chain
            .iter()
            .map(|cert| HsmCert { cert })
            .collect::<Vec<_>>();
        let restored = remote.backup.evidence.with_hsm_evidence(|evidence| {
            session.session.sd_restore_remote_backup(
                self.env.policy(),
                &remote.masked_receiver_key,
                &certs,
                evidence,
                &remote.backup.pok_remote_backup,
                &remote.sd_mk_backup,
            )
        });
        self.finish_remote_restore(partition, restored)
    }

    pub(crate) fn finish_remote_restore(
        &self,
        partition: PartitionState,
        restored: tsra_api::HsmResult<tsra_api::HsmSdRestoreResult>,
    ) -> Result<()> {
        let restored = match restored {
            Ok(restored) => restored,
            Err(source) => {
                return Err(Error::PartitionPersistence {
                    state: partition,
                    source: anyhow::Error::new(source).context("sd_restore_remote_backup"),
                }
                .into())
            }
        };
        let state = SecurityDomainState {
            pok_local_backup: restored.pok_local_backup,
            sd_mk_backup: restored.sd_mk_backup,
        };
        if let Err(source) = self.env.store().save_creation(&partition, &state) {
            return Err(Error::RemoteRestorePersistence {
                partition,
                state,
                source,
            }
            .into());
        }
        Ok(())
    }

    pub(crate) fn ensure_can_create(&self) -> Result<()> {
        let store = self.env.store();
        anyhow::ensure!(
            store
                .load_partition()
                .context("read existing partition state")?
                .is_none()
                && store
                    .load_security_domain()
                    .context("read existing SD state")?
                    .is_none(),
            "stored provisioning state already exists; recover it instead of creating again",
        );
        anyhow::ensure!(
            !self.env.mfgr_cert_chain().is_empty(),
            "sender manufacturer certificate chain is required",
        );
        Ok(())
    }

    pub(crate) fn init_partition<SignPta>(
        &self,
        session: &SealingSession,
        tee_seed: &[u8],
        previous_local_mk: Option<&[u8]>,
        sign_pta: SignPta,
    ) -> Result<PartitionState>
    where
        SignPta: FnOnce(&[u8], &[u8]) -> Result<Vec<Vec<u8>>>,
    {
        let policy = self.env.policy();
        let init = session
            .session
            .part_init_ex(
                policy,
                tee_seed,
                self.env.pota_thumbprint(),
                self.env.sata_thumbprint(),
                self.env.sapota_thumbprint(),
            )
            .context("part_init_ex")?;

        let chain = sign_pta(&init.pta_csr, &init.pta_report).context("POTA-sign the PTA chain")?;
        let certs = chain
            .iter()
            .map(|cert| HsmCert { cert })
            .collect::<Vec<_>>();
        let finalized = session
            .session
            .part_final_ex(policy, &certs, previous_local_mk)
            .context("part_final_ex")?;
        Ok(PartitionState {
            policy: policy.as_bytes().to_vec(),
            pta_cert_chain: chain,
            local_mk_backup: finalized.local_mk_backup,
        })
    }

    fn create_backup(
        &self,
        session: &SealingSession,
        partition_state: &PartitionState,
        receiver_cert_chain: &[HsmCert<'_>],
        receiver_evidence: &Evidence,
    ) -> Result<(SecurityDomainState, RemoteBackup)> {
        let part_owner_cert_chain = self
            .env
            .part_owner_cert_chain(&session.partition, &partition_state.pta_cert_chain)
            .context("refresh sender partition-owner chain")?;
        anyhow::ensure!(
            !part_owner_cert_chain.is_empty(),
            "sender partition-owner certificate chain is required",
        );

        let sealing_key = hsm::mint_sealing_key(&session.session)?;
        let sender_evidence = Evidence {
            mfgr_cert_chain: self.env.mfgr_cert_chain().to_vec(),
            owner_cert_chain: self.env.owner_cert_chain().to_vec(),
            part_owner_cert_chain,
            report: sealing_key.report.clone(),
        };
        self.seal_backup(
            session,
            &sealing_key,
            receiver_cert_chain,
            receiver_evidence,
            &sender_evidence,
        )
    }

    fn seal_backup(
        &self,
        session: &SealingSession,
        sealing_key: &hsm::SealingKey,
        receiver_cert_chain: &[HsmCert<'_>],
        receiver_evidence: &Evidence,
        sender_evidence: &Evidence,
    ) -> Result<(SecurityDomainState, RemoteBackup)> {
        let backup = receiver_evidence
            .with_hsm_evidence(|evidence| {
                session.session.sd_create_remote_backup(
                    self.env.policy(),
                    &sealing_key.masked,
                    receiver_cert_chain,
                    evidence,
                )
            })
            .context("sd_create_remote_backup")?;

        let domain_state = SecurityDomainState {
            pok_local_backup: backup.pok_local_backup,
            sd_mk_backup: backup.sd_mk_backup,
        };
        let remote_backup = RemoteBackup {
            pok_remote_backup: backup.pok_remote_backup,
            evidence: sender_evidence.clone(),
        };
        Ok((domain_state, remote_backup))
    }
}
