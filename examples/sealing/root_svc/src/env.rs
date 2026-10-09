// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The root service's self-contained trust authority.
//!
//! [`SelfContainedEnv`] owns the POTA and SATA trust keys in-process and
//! performs the certificate-signing steps locally. This is the demo
//! configuration: a production root service would hold these keys in an HSM
//! or an out-of-process CA and delegate the same signing seams accordingly.
//!
//! It is the application's trust authority, so it lives here in the app
//! rather than in the reusable `tsra_sealing_api` crate. It supplies the
//! complete policy and thumbprints through [`SecurityDomainEnv`],
//! the local POTA signing callback, and the receiver
//! certificate chain supplied to that flow.

use anyhow::Context;
use anyhow::Result;
use tsra_api::HsmPartition;
use tsra_api::PartPolicy;
use tsra_api::PartPolicyBuilder;
use tsra_api::PolicyKeyKind;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPublicKey;
use tsra_crypto::ImportableKey;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_ddi_tbor_types::POLICY_BACKUP_PART_ID_LEN;
use tsra_ddi_tbor_types::POLICY_INFO_LEN;
use tsra_sealing_api::device_cert_chain;
use tsra_sealing_api::load_local_recovery;
use tsra_sealing_api::load_partition_recovery;
use tsra_sealing_api::PartitionState;
use tsra_sealing_api::SealingSession;
use tsra_sealing_api::SecurityDomainEnv;
use tsra_sealing_api::RAW_PUB_LEN;
use tsra_sealing_report::verify_certificate_chain;
use x509::X509Certificate;
use x509::X509CertificateOp;

use crate::pki::make_chain;
use crate::pki::make_pta_chain;
use crate::pki::thumbprint;
use crate::pki::CaKey;
use crate::pki::GeneratedChain;
use crate::store::AuthorityState;
use crate::store::FileStore;
use crate::store::SigningAuthority;

/// A self-contained trust authority that generates fresh POTA and SATA
/// trust anchors in-process and signs locally.
pub struct SelfContainedEnv {
    pota: CaKey,
    pota_certificate: Vec<u8>,
    sata: Option<CaKey>,
    sata_certificate: Option<Vec<u8>>,
    machine_seed: [u8; MACH_SEED_LEN],
    policy: PartPolicy,
    pota_thumbprint: [u8; 48],
    sata_thumbprint: [u8; 48],
    mfgr_cert_chain: Vec<Vec<u8>>,
    store: FileStore,
}

impl SelfContainedEnv {
    /// Generate fresh trust anchors and build the complete domain policy
    /// for the backing partition before provisioning begins.
    pub fn generate(
        session: &SealingSession,
        store: FileStore,
        machine_seed: [u8; MACH_SEED_LEN],
    ) -> Result<Self> {
        let mfgr_cert_chain = device_cert_chain(&session.partition, 0)?;
        let pota = CaKey::generate();
        let sata = CaKey::generate();
        let pid = session.partition.pid().context("read partition id")?;
        anyhow::ensure!(
            pid.len() == POLICY_BACKUP_PART_ID_LEN,
            "partition id must be {POLICY_BACKUP_PART_ID_LEN} bytes, got {}",
            pid.len(),
        );
        let pid_pub = session
            .partition
            .ex_pub_key()
            .context("read partition identity public key")?;
        let pid_pub: [u8; RAW_PUB_LEN] = pid_pub
            .as_slice()
            .try_into()
            .context("partition identity public key must be a raw P-384 point")?;
        let policy = PartPolicyBuilder::new()
            .version(1, 0)
            .pota_key(PolicyKeyKind::Ecc384, &pota.raw_pub())
            .sata_key(PolicyKeyKind::Ecc384, &sata.raw_pub())
            .backup_part_id(&pid)
            .backup_part_pub_key(PolicyKeyKind::Ecc384, &pid_pub)
            .info(&[0xAB; POLICY_INFO_LEN])
            .allow_peer_cloning(true)
            .require_trusted_sa_key(false)
            .build()
            .context("build unified partition policy")?;
        let pota_certificate = pota.self_cert();
        let sata_certificate = sata.self_cert();
        let pota_thumbprint = thumbprint(&pota_certificate);
        let sata_thumbprint = thumbprint(&sata_certificate);
        let store = store.with_authority(AuthorityState {
            pota_private_key: pota.private_key_der()?,
            pota_certificate: pota_certificate.clone(),
            sata_thumbprint,
            machine_seed,
            sata: Some(SigningAuthority {
                private_key: sata.private_key_der()?,
                certificate: sata_certificate.clone(),
            }),
        });
        Ok(Self {
            pota,
            pota_certificate,
            sata: Some(sata),
            sata_certificate: Some(sata_certificate),
            machine_seed,
            policy,
            pota_thumbprint,
            sata_thumbprint,
            mfgr_cert_chain,
            store,
        })
    }

    /// Validate and reopen saved authority/recovery state before opening a device.
    ///
    /// Older records without the POTA signer or original seed cannot be restored
    /// by this self-contained service. SATA's private key is not needed.
    pub fn load(store: FileStore) -> Result<Self> {
        let (partition, _) = load_local_recovery(&store)?;
        Self::load_partition(store, partition)
    }

    /// Remote SD recovery needs partition recovery, not a local SD backup.
    pub fn load_remote(store: FileStore) -> Result<Self> {
        let partition = load_partition_recovery(&store)?;
        Self::load_partition(store, partition)
    }

    fn load_partition(store: FileStore, partition: PartitionState) -> Result<Self> {
        let authority = store.load_authority()?.context(
            "saved state has no POTA signer or machine seed; records from older create commands cannot be restored by this service",
        )?;
        let policy = PartPolicy::ref_from_wire(&partition.policy)
            .context("decode saved partition policy")?
            .clone();
        let pota = CaKey::from_der(&authority.pota_private_key)?;
        anyhow::ensure!(
            policy.pota_pub_key.kind() == PolicyKeyKind::Ecc384
                && policy.pota_pub_key.len() == RAW_PUB_LEN
                && policy.pota_pub_key.data == pota.raw_pub(),
            "saved POTA signing key does not match the partition policy",
        );
        anyhow::ensure!(
            policy.sapota_pub_key.is_empty(),
            "this demo does not support restoring a SAPOTA-bound policy"
        );
        anyhow::ensure!(
            partition.pta_cert_chain.first() == Some(&authority.pota_certificate),
            "saved POTA certificate does not match the partition recovery chain",
        );
        verify_certificate_chain(&partition.pta_cert_chain)
            .context("verify saved POTA/PTA chain")?;
        verify_signing_certificate("POTA", &pota, &authority.pota_certificate)?;
        let (sata, sata_certificate) = match &authority.sata {
            Some(saved) => {
                let sata = CaKey::from_der(&saved.private_key).context("load saved SATA signer")?;
                anyhow::ensure!(
                    policy.sata_pub_key.kind() == PolicyKeyKind::Ecc384
                        && policy.sata_pub_key.len() == RAW_PUB_LEN
                        && policy.sata_pub_key.data == sata.raw_pub(),
                    "saved SATA signing key does not match the partition policy"
                );
                verify_certificate_chain(std::slice::from_ref(&saved.certificate))
                    .context("verify saved SATA certificate")?;
                verify_signing_certificate("SATA", &sata, &saved.certificate)?;
                (Some(sata), Some(saved.certificate.clone()))
            }
            None => (None, None),
        };
        let pota_thumbprint = thumbprint(&authority.pota_certificate);
        Ok(Self {
            pota,
            pota_certificate: authority.pota_certificate.clone(),
            sata,
            sata_certificate,
            machine_seed: authority.machine_seed,
            policy,
            pota_thumbprint,
            sata_thumbprint: authority.sata_thumbprint,
            mfgr_cert_chain: Vec::new(),
            store: store.with_authority(authority),
        })
    }

    pub fn machine_seed(&self) -> &[u8; MACH_SEED_LEN] {
        &self.machine_seed
    }

    /// POTA signer: issue the POTA-anchored PTA chain from the device CSR.
    ///
    /// The local authority trusts the device implicitly, so the
    /// PID-signed attestation `report` is unused here; a remote POTA would
    /// verify it before signing.
    pub fn sign_pta(&self, csr: &[u8], _report: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut chain = make_pta_chain(&self.pota, csr)?;
        *chain
            .first_mut()
            .context("POTA signer returned an empty chain")? = self.pota_certificate.clone();
        Ok(chain)
    }

    /// Certify the externally prepared demo receiver under SATA.
    pub fn receiver_chain(&self, rcvr_pub: &[u8; RAW_PUB_LEN]) -> Result<GeneratedChain> {
        let sata = self
            .sata
            .as_ref()
            .context("SATA signing key is not retained for local restore")?;
        let mut chain = make_chain(sata, rcvr_pub);
        chain.root_der = self
            .sata_certificate
            .as_ref()
            .context("saved SATA certificate is missing")?
            .clone();
        Ok(chain)
    }

    pub(crate) fn peer_authorities(&self) -> Result<(&[u8], &[u8])> {
        anyhow::ensure!(
            self.sata.is_some(),
            "peer serving requires the saved SATA signer"
        );
        Ok((
            &self.pota_certificate,
            self.sata_certificate
                .as_deref()
                .context("peer serving requires the saved SATA certificate")?,
        ))
    }
}

fn verify_signing_certificate(name: &str, key: &CaKey, certificate: &[u8]) -> Result<()> {
    let certificate = X509Certificate::from_der(certificate)?;
    let certificate_key = EccPublicKey::from_bytes(&certificate.get_public_key_der()?)?;
    let (x, y) = certificate_key.coord_vec()?;
    anyhow::ensure!(
        [x, y].concat() == key.raw_pub(),
        "saved {name} certificate does not match its signing key"
    );
    Ok(())
}

impl SecurityDomainEnv for SelfContainedEnv {
    type Store = FileStore;

    fn policy(&self) -> &PartPolicy {
        &self.policy
    }

    fn pota_thumbprint(&self) -> &[u8] {
        &self.pota_thumbprint
    }

    fn sata_thumbprint(&self) -> &[u8] {
        &self.sata_thumbprint
    }

    fn sapota_thumbprint(&self) -> Option<&[u8]> {
        None
    }

    fn mfgr_cert_chain(&self) -> &[Vec<u8>] {
        &self.mfgr_cert_chain
    }

    fn owner_cert_chain(&self) -> &[Vec<u8>] {
        &[]
    }

    fn part_owner_cert_chain(
        &self,
        partition: &HsmPartition,
        pta_cert_chain: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>> {
        let pid = device_cert_chain(partition, 2)?;
        anyhow::ensure!(
            pid.len() == 1,
            "slot 2 must contain only the PID certificate"
        );
        let mut chain = pta_cert_chain.to_vec();
        chain.extend(pid);
        Ok(chain)
    }

    fn store(&self) -> &Self::Store {
        &self.store
    }
}
