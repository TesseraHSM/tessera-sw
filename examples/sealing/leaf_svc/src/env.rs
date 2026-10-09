// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Leaf environment: public authorities and a remote PTA issuer, no signers.

use anyhow::Context;
use anyhow::Result;
use jzon::JsonValue;
use tsra_api::HsmPartition;
use tsra_api::PartPolicy;
use tsra_api::PolicyKeyKind;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_sealing_api::device_cert_chain;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::SecurityDomainEnv;
use tsra_sealing_api::RAW_PUB_LEN;
use tsra_sealing_common::evidence;
use tsra_sealing_common::http::Client;
use tsra_sealing_common::wire;
use tsra_sealing_report::verify_certificate_chain;
use zerocopy::IntoBytes;

use super::validate_name;
use crate::pki;
use crate::store::FileStore;

pub(super) struct LeafEnv {
    pub policy: PartPolicy,
    pub root_policy: PartPolicy,
    pub seed: [u8; MACH_SEED_LEN],
    pub name: String,
    pub instance: String,
    pub root: String,
    pub pota: Vec<u8>,
    pub sata: Vec<u8>,
    pub sapota: Vec<u8>,
    pub manufacturer: Vec<Vec<u8>>,
    pub store: FileStore,
    thumbprints: [[u8; 48]; 3],
}

impl LeafEnv {
    pub fn from_record(store: FileStore, record: &JsonValue) -> Result<Self> {
        anyhow::ensure!(
            record["version"].as_u32() == Some(1),
            "invalid leaf state version"
        );
        let name = validate_name(record["name"].as_str().context("missing leaf name")?)?;
        let instance = if record.has_key("instance") {
            validate_name(record["instance"].as_str().context("invalid instance ID")?)?
        } else {
            "primary".to_owned()
        };
        let root = record["root"]
            .as_str()
            .context("missing root URL")?
            .to_owned();
        Client::new(&root)?;
        let policy_bytes = wire::blob(record, "policy")?;
        let policy = PartPolicy::ref_from_wire(&policy_bytes)
            .context("invalid leaf policy")?
            .clone();
        let root_bytes = wire::blob(record, "root_policy")?;
        let root_policy = PartPolicy::ref_from_wire(&root_bytes)
            .context("invalid root policy")?
            .clone();
        anyhow::ensure!(
            policy.flags.require_trusted_sa_key() && !policy.flags.allow_peer_cloning(),
            "leaf policy must require trusted SA and disable peer cloning"
        );
        let pota = wire::blob(record, "pota")?;
        let sata = wire::blob(record, "sata")?;
        let sapota = wire::blob(record, "sapota")?;
        for (certificate, public) in [
            (&pota, &policy.pota_pub_key),
            (&sata, &policy.sata_pub_key),
            (&sapota, &policy.sapota_pub_key),
            (&sapota, &root_policy.pota_pub_key),
        ] {
            verify_certificate_chain(std::slice::from_ref(certificate))?;
            anyhow::ensure!(
                public.kind() == PolicyKeyKind::Ecc384
                    && public.len() == RAW_PUB_LEN
                    && evidence::cert_public(certificate)? == public.data,
                "leaf authority certificate does not match policy"
            );
        }
        anyhow::ensure!(
            policy.backup_part_pub_key.kind() == PolicyKeyKind::Ecc384
                && policy.backup_part_pub_key.len() == RAW_PUB_LEN,
            "invalid leaf backing partition key"
        );
        Ok(Self {
            policy,
            root_policy,
            name,
            instance,
            root,
            seed: wire::blob(record, "seed")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid leaf seed"))?,
            thumbprints: [
                pki::thumbprint(&pota),
                pki::thumbprint(&sata),
                pki::thumbprint(&sapota),
            ],
            pota,
            sata,
            sapota,
            store,
            manufacturer: Vec::new(),
        })
    }

    pub fn route(&self, operation: &str) -> String {
        format!("/v1/leaves/{}/{operation}", self.name)
    }

    pub fn check_root(&self) -> Result<()> {
        let config = Client::new(&self.root)?.get(&format!("/v1/leaves/{}", self.name))?;
        anyhow::ensure!(
            config["name"].as_str() == Some(self.name.as_str())
                && wire::blob(&config, "policy")? == self.policy.as_bytes()
                && wire::blob(&config, "root_policy")? == self.root_policy.as_bytes()
                && wire::blob(&config, "pota")? == self.pota
                && wire::blob(&config, "sata")? == self.sata
                && wire::blob(&config, "sapota")? == self.sapota,
            "root changed the saved leaf identity or policy"
        );
        Ok(())
    }

    pub fn certify(&self, csr: &[u8], report: &[u8]) -> Result<Vec<Vec<u8>>> {
        let response = Client::new(&self.root)?.post(
            &self.route("pta-cert"),
            &jzon::object! {
                instance: self.instance.as_str(),
                policy: hex::encode(self.policy.as_bytes()),
                csr: hex::encode(csr), report: hex::encode(report),
                manufacturer: wire::encode_chain(&self.manufacturer),
            },
        )?;
        let chain = wire::chain(&response, "pta")?;
        verify_certificate_chain(&chain)?;
        anyhow::ensure!(chain.first() == Some(&self.pota), "root changed leaf POTA");
        anyhow::ensure!(
            evidence::cert_public(chain.last().context("missing PTA")?)?
                == pki::pta_pub_from_csr(csr)?[1..],
            "PTA certificate does not match CSR"
        );
        Ok(chain)
    }

    pub fn validate_receiver(&self, receiver: &JsonValue) -> Result<(Vec<Vec<u8>>, Evidence)> {
        let chain = wire::chain(receiver, "chain")?;
        verify_certificate_chain(&chain)?;
        anyhow::ensure!(
            chain.first() == Some(&self.sata),
            "receiver is not endorsed by leaf SATA"
        );
        let attestation = wire::evidence(&receiver["evidence"])?;
        let (_, public) = evidence::verify_attested_key(
            &attestation,
            &self.root_policy,
            &self.policy.sapota_pub_key.data,
        )?;
        anyhow::ensure!(
            attestation.part_owner_cert_chain.first() == Some(&self.sapota),
            "receiver evidence does not use the saved SAPOTA certificate"
        );
        anyhow::ensure!(
            evidence::cert_public(chain.last().context("missing receiver certificate")?)? == public,
            "receiver report and SATA certificate attest different keys"
        );
        Ok((chain, attestation))
    }
}

impl SecurityDomainEnv for LeafEnv {
    type Store = FileStore;
    fn policy(&self) -> &PartPolicy {
        &self.policy
    }
    fn pota_thumbprint(&self) -> &[u8] {
        &self.thumbprints[0]
    }
    fn sata_thumbprint(&self) -> &[u8] {
        &self.thumbprints[1]
    }
    fn sapota_thumbprint(&self) -> Option<&[u8]> {
        Some(&self.thumbprints[2])
    }
    fn mfgr_cert_chain(&self) -> &[Vec<u8>] {
        &self.manufacturer
    }
    fn owner_cert_chain(&self) -> &[Vec<u8>] {
        &[]
    }
    fn part_owner_cert_chain(
        &self,
        partition: &HsmPartition,
        pta: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>> {
        let mut chain = pta.to_vec();
        chain.extend(device_cert_chain(partition, 2)?);
        Ok(chain)
    }
    fn store(&self) -> &FileStore {
        &self.store
    }
}
