// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A joining peer keeps public authority certificates, its own machine seed
//! and the issuer URL, never the primary's software signing keys. Subsequent
//! local recovery uses that issuer to certify the new PTA.

use anyhow::Context;
use anyhow::Result;
use jzon::JsonValue;
use tsra_api::HsmPartition;
use tsra_api::PartPolicy;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_sealing_api::device_cert_chain;
use tsra_sealing_api::SecurityDomainEnv;
use tsra_sealing_report::verify_certificate_chain;
use zerocopy::IntoBytes;

use super::evidence;
use super::http::Client;
use super::wire;
use crate::pki;
use crate::store::FileStore;

pub struct PeerEnv {
    pub policy: PartPolicy,
    pub seed: [u8; MACH_SEED_LEN],
    pub primary: String,
    pub pota: Vec<u8>,
    pub sata: Vec<u8>,
    pub manufacturer: Vec<Vec<u8>>,
    pub store: FileStore,
    pota_thumbprint: [u8; 48],
    sata_thumbprint: [u8; 48],
}

impl PeerEnv {
    pub fn from_record(store: FileStore, record: &JsonValue) -> Result<Self> {
        anyhow::ensure!(
            record["version"].as_u32() == Some(1),
            "invalid peer state version"
        );
        let bytes = wire::blob(record, "policy")?;
        let policy = PartPolicy::ref_from_wire(&bytes)
            .context("invalid peer policy")?
            .clone();
        anyhow::ensure!(
            policy.flags.allow_peer_cloning(),
            "peer cloning is disabled"
        );
        anyhow::ensure!(
            policy.sapota_pub_key.is_empty(),
            "demo peer does not support SAPOTA"
        );
        let primary = record["primary"]
            .as_str()
            .context("missing peer issuer URL")?
            .to_owned();
        Client::new(&primary)?;
        let pota = wire::blob(record, "pota")?;
        let sata = wire::blob(record, "sata")?;
        for (certificate, public) in [
            (&pota, &policy.pota_pub_key.data),
            (&sata, &policy.sata_pub_key.data),
        ] {
            verify_certificate_chain(std::slice::from_ref(certificate))?;
            anyhow::ensure!(
                evidence::cert_public(certificate)? == *public,
                "authority certificate does not match policy"
            );
        }
        Ok(Self {
            policy,
            primary,
            seed: wire::blob(record, "seed")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid peer machine seed"))?,
            pota_thumbprint: pki::thumbprint(&pota),
            sata_thumbprint: pki::thumbprint(&sata),
            pota,
            sata,
            manufacturer: Vec::new(),
            store,
        })
    }

    pub fn record(&self) -> JsonValue {
        jzon::object! {
            version: 1, primary: self.primary.as_str(),
            seed: hex::encode(self.seed), policy: hex::encode(self.policy.as_bytes()),
            pota: hex::encode(&self.pota), sata: hex::encode(&self.sata),
        }
    }

    pub fn certify(&self, csr: &[u8], report: &[u8]) -> Result<JsonValue> {
        let response = Client::new(&self.primary)?.post(
            "/v1/pta-cert",
            &jzon::object! {
                csr: hex::encode(csr), report: hex::encode(report),
                manufacturer: wire::encode_chain(&self.manufacturer),
            },
        )?;
        let chain = wire::chain(&response, "pta")?;
        verify_certificate_chain(&chain)?;
        anyhow::ensure!(
            chain.first() == Some(&self.pota),
            "issuer changed the POTA certificate"
        );
        let leaf = chain.last().context("missing PTA certificate")?;
        anyhow::ensure!(
            evidence::cert_public(leaf)? == pki::pta_pub_from_csr(csr)?[1..],
            "issued PTA does not match CSR"
        );
        Ok(response)
    }
}

impl SecurityDomainEnv for PeerEnv {
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
