// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Root-owned leaf identities. Registration, binding and remote backup are
//! separate immutable records, atomically published by the shared file store.
//!
//! `POST /v1/leaves/NAME/instances {"instance":"ID"}` is the controller's
//! explicit enrollment authority gate. `GET .../instances/ID` returns
//! `authorized` before issuance and `enrolled` after the first verified PTA
//! is pinned. Primary uses the original creation binding; missing instance
//! fields in legacy PTA/reseal requests mean primary. No join may self-approve.
//! `POST`/`GET .../catalog` publishes/fetches one immutable, metadata-validated
//! SD-masked key and public identity; local and session keys are never shared.
//! These control/catalog endpoints are unauthenticated loopback demo APIs,
//! not production authentication or hardware-admission boundaries.

use anyhow::Context;
use anyhow::Result;
use tsra_api::HsmKeyManager;
use tsra_api::HsmSealingKey;
use tsra_api::PartPolicy;
use tsra_api::PartPolicyBuilder;
use tsra_api::PolicyKeyKind;
use tsra_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;
use tsra_sealing_api::device_cert_chain;
use tsra_sealing_api::load_local_recovery;
use tsra_sealing_api::mint_sealing_key;
use tsra_sealing_api::reseal_remote_backup;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::RemoteBackup;
use tsra_sealing_api::SecurityDomainEnv;
use tsra_sealing_common::key_check;
use tsra_sealing_report::verify_certificate_chain;
use zerocopy::IntoBytes;

use super::validate_name;
use super::JsonValue;
use super::RootDomain;
use super::SealingSession;
use crate::peer::evidence;
use crate::peer::wire;
use crate::pki;
use crate::pki::CaKey;
use crate::store::FileStore;

struct Registration {
    name: String,
    pota: CaKey,
    sata: CaKey,
    pota_cert: Vec<u8>,
    sata_cert: Vec<u8>,
    sapota: Vec<u8>,
    masked_receiver: Vec<u8>,
    receiver_chain: Vec<Vec<u8>>,
}

impl Registration {
    fn load(domain: &RootDomain, name: &str) -> Result<Self> {
        let saved = domain
            .env()
            .store()
            .load(&filename("registration", name)?)?
            .context("unknown leaf name")?;
        anyhow::ensure!(
            saved["name"].as_str() == Some(name),
            "leaf registration name mismatch"
        );
        let registration = Self {
            name: name.to_owned(),
            pota: CaKey::from_der(&wire::blob(&saved, "pota_private")?)?,
            sata: CaKey::from_der(&wire::blob(&saved, "sata_private")?)?,
            pota_cert: wire::blob(&saved, "pota")?,
            sata_cert: wire::blob(&saved, "sata")?,
            sapota: wire::blob(&saved, "sapota")?,
            masked_receiver: wire::blob(&saved, "masked_receiver")?,
            receiver_chain: wire::chain(&saved, "receiver_chain")?,
        };
        for (certificate, key) in [
            (&registration.pota_cert, &registration.pota),
            (&registration.sata_cert, &registration.sata),
        ] {
            verify_certificate_chain(std::slice::from_ref(certificate))?;
            anyhow::ensure!(
                evidence::cert_public(certificate)? == key.raw_pub(),
                "leaf signer mismatch"
            );
        }
        anyhow::ensure!(
            registration.sapota == domain.env().peer_authorities()?.0,
            "leaf registration belongs to another root POTA"
        );
        verify_certificate_chain(&registration.receiver_chain)?;
        anyhow::ensure!(
            registration.receiver_chain.first() == Some(&registration.sata_cert),
            "leaf receiver is not endorsed by its SATA"
        );
        Ok(registration)
    }

    fn policy(&self, pid: &[u8], public: &[u8]) -> Result<PartPolicy> {
        PartPolicyBuilder::new()
            .version(1, 0)
            .pota_key(PolicyKeyKind::Ecc384, &self.pota.raw_pub())
            .sata_key(PolicyKeyKind::Ecc384, &self.sata.raw_pub())
            .sapota_key(PolicyKeyKind::Ecc384, &evidence::cert_public(&self.sapota)?)
            .backup_part_id(pid)
            .backup_part_pub_key(PolicyKeyKind::Ecc384, public)
            .require_trusted_sa_key(true)
            .allow_peer_cloning(false)
            .build()
            .context("build leaf policy")
    }

    fn binding(&self, store: &FileStore) -> Result<Option<Vec<u8>>> {
        store
            .load(&filename("binding", &self.name)?)?
            .map(|record| wire::blob(&record, "policy"))
            .transpose()
    }

    fn check_binding(&self, store: &FileStore, policy: &[u8]) -> Result<()> {
        if let Some(bound) = self.binding(store)? {
            anyhow::ensure!(
                bound == policy,
                "leaf is already bound to another partition or policy"
            );
        }
        Ok(())
    }

    fn receiver(&self, domain: &RootDomain, session: &SealingSession) -> Result<JsonValue> {
        let mut key = HsmSealingKey::from_masked_key(&session.session, &self.masked_receiver)?;
        let report = HsmKeyManager::generate_key_report_vec(&mut key, &[0; KEY_REPORT_DATA_LEN])?;
        let manufacturer = device_cert_chain(&session.partition, 0)?;
        let (partition, _) = load_local_recovery(domain.env().store())?;
        let part_owner = domain
            .env()
            .part_owner_cert_chain(&session.partition, &partition.pta_cert_chain)?;
        let evidence = Evidence {
            owner_cert_chain: Vec::new(),
            mfgr_cert_chain: manufacturer,
            part_owner_cert_chain: part_owner,
            report,
        };
        let (_, public) = evidence::verify_attested_key(
            &evidence,
            domain.env().policy(),
            &domain.env().policy().pota_pub_key.data,
        )?;
        anyhow::ensure!(
            evidence::cert_public(
                self.receiver_chain
                    .last()
                    .context("missing receiver certificate")?
            )? == public,
            "saved masked receiver does not match its SATA certificate"
        );
        Ok(jzon::object! {
            chain: wire::encode_chain(&self.receiver_chain),
            evidence: wire::encode_evidence(&evidence),
        })
    }

    fn saved_backup(&self, store: &FileStore) -> Result<(PartPolicy, JsonValue)> {
        let bound = self.binding(store)?.context("leaf has not enrolled")?;
        let policy = PartPolicy::ref_from_wire(&bound)
            .context("invalid bound policy")?
            .clone();
        let record = store
            .load(&filename("remote", &self.name)?)?
            .context("root has no saved remote backup for this leaf")?;
        anyhow::ensure!(
            wire::blob(&record, "policy")? == bound,
            "saved backup policy mismatch"
        );
        anyhow::ensure!(
            wire::blob(&record, "pok_remote_backup")?.len() == POK_REMOTE_BACKUP_LEN
                && wire::blob(&record, "sd_mk_backup")?.len() == SD_MK_BACKUP_LEN,
            "invalid saved remote backup lengths"
        );
        anyhow::ensure!(
            wire::chain(&record["receiver"], "chain")? == self.receiver_chain,
            "saved backup receiver does not match registration"
        );
        Ok((policy, record))
    }

    fn endorse_for_reseal(
        &self,
        store: &FileStore,
        evidence: &Evidence,
        policy: &PartPolicy,
        binding: &JsonValue,
    ) -> Result<Evidence> {
        let (pid, _) = evidence::verify_attested_key(evidence, policy, &policy.pota_pub_key.data)?;
        self.check_binding(store, policy.as_bytes())?;
        let pta = evidence
            .part_owner_cert_chain
            .get(1)
            .context("missing leaf PTA certificate")?;
        anyhow::ensure!(
            evidence.part_owner_cert_chain.first() == Some(&self.pota_cert)
                && evidence::cert_public(pta)? == wire::blob(binding, "pta_public")?
                && wire::blob(binding, "policy")? == policy.as_bytes(),
            "reseal evidence belongs to another leaf PTA"
        );
        // Reseal requires SATA-anchored PID evidence. Endorse only after
        // verifying the original POTA/PTA chain and this name's pinned PTA.
        let chain = pki::make_chain(&self.sata, &pid);
        let mut endorsed = evidence.clone();
        endorsed.part_owner_cert_chain = vec![self.sata_cert.clone(), chain.leaf_der];
        Ok(endorsed)
    }

    fn reseal(
        &self,
        domain: &RootDomain,
        session: &SealingSession,
        request: &JsonValue,
    ) -> Result<JsonValue> {
        let store = domain.env().store();
        let instance = request_instance(request)?;
        let target_binding = self
            .instance_binding(store, &instance)?
            .context("instance has not enrolled")?;
        let (policy, saved) = self.saved_backup(store)?;
        anyhow::ensure!(
            wire::blob(request, "policy")? == policy.as_bytes(),
            "reseal request policy mismatch"
        );
        let original = wire::evidence(&saved["sender"])?;
        // Never use the target's pin to validate the original creation source.
        let original_binding = store
            .load(&filename("binding", &self.name)?)?
            .context("missing original creation binding")?;
        let source = RemoteBackup {
            pok_remote_backup: wire::blob(&saved, "pok_remote_backup")?,
            evidence: self.endorse_for_reseal(store, &original, &policy, &original_binding)?,
        };
        let destination = self.endorse_for_reseal(
            store,
            &wire::evidence(&request["receiver"])?,
            &policy,
            &target_binding,
        )?;
        let sender = self.receiver(domain, session)?;
        let resealed = reseal_remote_backup(
            session,
            &policy,
            &self.masked_receiver,
            &source,
            &destination,
        )?;
        Ok(jzon::object! {
            version: 1, policy: hex::encode(policy.as_bytes()),
            pok_remote_backup: hex::encode(resealed),
            sd_mk_backup: saved["sd_mk_backup"].clone(),
            sender: sender,
        })
    }

    fn instance_binding(&self, store: &FileStore, instance: &str) -> Result<Option<JsonValue>> {
        if instance == "primary" {
            return store.load(&filename("binding", &self.name)?);
        }
        let authorization = store
            .load(&instance_filename("authorization", &self.name, instance)?)?
            .context("instance is not authorized; controller must register it with root")?;
        anyhow::ensure!(
            authorization["name"].as_str() == Some(self.name.as_str())
                && authorization["instance"].as_str() == Some(instance),
            "instance authorization service or instance mismatch"
        );
        anyhow::ensure!(
            Some(wire::blob(&authorization, "policy")?) == self.binding(store)?,
            "instance authorization policy mismatch"
        );
        store.load(&instance_filename("binding", &self.name, instance)?)
    }
}

fn request_instance(request: &JsonValue) -> Result<String> {
    if request.has_key("instance") {
        validate_name(
            request["instance"]
                .as_str()
                .context("invalid instance ID")?,
        )
    } else {
        Ok("primary".to_owned())
    }
}

fn instance_filename(kind: &str, name: &str, instance: &str) -> Result<String> {
    validate_name(name)?;
    validate_name(instance)?;
    // Length prefix avoids ambiguity when both names contain hyphens.
    Ok(format!(
        "leaf-instance-{kind}-{}-{name}-{instance}.json",
        name.len()
    ))
}

fn filename(kind: &str, name: &str) -> Result<String> {
    validate_name(name)?;
    Ok(format!("leaf-{kind}-{name}.json"))
}

fn register(
    domain: &RootDomain,
    session: &SealingSession,
    request: &JsonValue,
) -> Result<JsonValue> {
    let name = request["name"].as_str().context("missing leaf name")?;
    let file = filename("registration", name)?;
    let store = domain.env().store();
    if store.load(&file)?.is_some() {
        Registration::load(domain, name)?;
        return Ok(jzon::object! { name: name, status: "registered" });
    }
    let pota = CaKey::generate();
    let sata = CaKey::generate();
    let key = mint_sealing_key(&session.session)?;
    let manufacturer = device_cert_chain(&session.partition, 0)?;
    let (_, public) = evidence::verify_report(&manufacturer, &key.report, domain.env().policy())?;
    let public = public
        .try_into()
        .map_err(|_| anyhow::anyhow!("sealing key must be P-384"))?;
    let chain = pki::make_chain(&sata, &public);
    let record = jzon::object! {
        version: 1, name: name,
        pota_private: hex::encode(pota.private_key_der()?),
        sata_private: hex::encode(sata.private_key_der()?),
        pota: hex::encode(pota.self_cert()),
        sata: hex::encode(&chain.root_der),
        sapota: hex::encode(domain.env().peer_authorities()?.0),
        masked_receiver: hex::encode(key.masked),
        receiver_chain: wire::encode_chain(&[chain.root_der, chain.leaf_der]),
    };
    store.write_record(&file, &record, true)?;
    Ok(jzon::object! { name: name, status: "registered" })
}

pub(crate) fn handle(
    domain: &RootDomain,
    session: &SealingSession,
    method: &str,
    path: &str,
    request: &JsonValue,
) -> Result<JsonValue> {
    if method == "POST" && path == "/v1/leaves" {
        return register(domain, session, request);
    }
    let suffix = path
        .strip_prefix("/v1/leaves/")
        .context("unsupported leaf route")?;
    let (name, operation) = suffix.split_once('/').unwrap_or((suffix, ""));
    let registration = Registration::load(domain, name)?;
    let store = domain.env().store();
    match (method, operation) {
        ("GET", "") => Ok(jzon::object! {
            version: 1, name: name,
            pota: hex::encode(&registration.pota_cert),
            sata: hex::encode(&registration.sata_cert),
            sapota: hex::encode(&registration.sapota),
            root_policy: hex::encode(domain.env().policy().as_bytes()),
            policy: registration.binding(store)?.map(hex::encode),
        }),
        ("POST", "policy") => {
            let policy = registration.policy(
                &wire::blob(request, "pid")?,
                &wire::blob(request, "public")?,
            )?;
            registration.check_binding(store, policy.as_bytes())?;
            Ok(jzon::object! { policy: hex::encode(policy.as_bytes()) })
        }
        ("POST", "pta-cert") => {
            let instance = request_instance(request)?;
            let binding = registration.instance_binding(store, &instance)?;
            let bytes = wire::blob(request, "policy")?;
            let policy = PartPolicy::ref_from_wire(&bytes).context("invalid leaf policy")?;
            let expected =
                registration.policy(&policy.backup_part_id, &policy.backup_part_pub_key.data)?;
            anyhow::ensure!(
                policy.as_bytes() == expected.as_bytes(),
                "unexpected leaf policy"
            );
            registration.check_binding(store, &bytes)?;
            let csr = wire::blob(request, "csr")?;
            let (pid, public) = evidence::verify_report(
                &wire::chain(request, "manufacturer")?,
                &wire::blob(request, "report")?,
                policy,
            )?;
            anyhow::ensure!(
                pki::pta_pub_from_csr(&csr)?[1..] == public,
                "CSR does not match attested PTA"
            );
            if let Some(binding) = binding {
                // PID rotates across reset; the UDS/seed/policy-derived PTA is
                // the durable identity proved by the signed CSR during recovery.
                anyhow::ensure!(
                    wire::blob(&binding, "pta_public")? == public,
                    "leaf PTA identity changed"
                );
            } else if instance == "primary" {
                anyhow::ensure!(
                    pid == policy.backup_part_pub_key.data,
                    "enrollment PID does not match leaf policy"
                );
            }
            let mut pta = pki::make_pta_chain(&registration.pota, &csr)?;
            *pta.first_mut().context("empty PTA chain")? = registration.pota_cert;
            store.write_immutable(
                &if instance == "primary" {
                    filename("binding", name)?
                } else {
                    instance_filename("binding", name, &instance)?
                },
                &jzon::object! { version: 1, policy: hex::encode(bytes), pta_public: hex::encode(public) },
            )?;
            Ok(jzon::object! { pta: wire::encode_chain(&pta) })
        }
        ("POST", "instances") => {
            let instance = validate_name(
                request["instance"]
                    .as_str()
                    .context("missing instance ID")?,
            )?;
            let policy = registration
                .binding(store)?
                .context("service has not enrolled")?;
            if instance != "primary" {
                store.write_immutable(
                    &instance_filename("authorization", name, &instance)?,
                    &jzon::object! {
                        version: 1, name: name, instance: instance.as_str(), policy: hex::encode(policy),
                    },
                )?;
            }
            Ok(jzon::object! { name: name, instance: instance, status: "authorized" })
        }
        ("GET", op) if op.starts_with("instances/") => {
            let instance = validate_name(op.trim_start_matches("instances/"))?;
            let binding = registration.instance_binding(store, &instance)?;
            Ok(jzon::object! {
                name: name, instance: instance,
                status: if binding.is_some() { "enrolled" } else { "authorized" },
            })
        }
        ("POST", "catalog") => {
            let (policy, _) = registration.saved_backup(store)?;
            key_check::validate_domain_catalog(request, name, policy.as_bytes())?;
            store.write_immutable(&filename("catalog", name)?, request)?;
            Ok(jzon::object! { status: "stored" })
        }
        ("GET", "catalog") => {
            let policy = registration
                .binding(store)?
                .context("service has not enrolled")?;
            let catalog = store
                .load(&filename("catalog", name)?)?
                .context("service has no domain key catalog")?;
            key_check::validate_domain_catalog(&catalog, name, &policy)?;
            Ok(catalog)
        }
        ("GET", "receiver") => registration.receiver(domain, session),
        ("GET", "recovery") => {
            let (policy, _) = registration.saved_backup(store)?;
            Ok(jzon::object! { status: "available", policy: hex::encode(policy.as_bytes()) })
        }
        ("POST", "reseal") => registration.reseal(domain, session, request),
        ("POST", "backup") => {
            let bound = registration
                .binding(store)?
                .context("leaf has not enrolled")?;
            anyhow::ensure!(
                wire::blob(request, "policy")? == bound,
                "backup policy mismatch"
            );
            let policy = PartPolicy::ref_from_wire(&bound).context("invalid bound policy")?;
            let sender = wire::evidence(&request["sender"])?;
            let original_binding = registration
                .instance_binding(store, "primary")?
                .context("missing original creation binding")?;
            registration.endorse_for_reseal(store, &sender, policy, &original_binding)?;
            let (pid, _) =
                evidence::verify_attested_key(&sender, policy, &policy.pota_pub_key.data)?;
            anyhow::ensure!(
                pid == policy.backup_part_pub_key.data,
                "backup belongs to another partition"
            );
            anyhow::ensure!(
                wire::blob(request, "pok_remote_backup")?.len() == POK_REMOTE_BACKUP_LEN
                    && wire::blob(request, "sd_mk_backup")?.len() == SD_MK_BACKUP_LEN,
                "invalid leaf backup lengths"
            );
            anyhow::ensure!(
                wire::chain(&request["receiver"], "chain")? == registration.receiver_chain,
                "backup names a different root receiver"
            );
            let receiver = wire::evidence(&request["receiver"]["evidence"])?;
            let (_, public) = evidence::verify_attested_key(
                &receiver,
                domain.env().policy(),
                &domain.env().policy().pota_pub_key.data,
            )?;
            anyhow::ensure!(
                evidence::cert_public(
                    registration
                        .receiver_chain
                        .last()
                        .context("missing receiver")?
                )? == public,
                "backup receiver evidence mismatch"
            );
            anyhow::ensure!(
                request["version"].as_u32() == Some(1),
                "invalid backup version"
            );
            store.write_immutable(&filename("remote", name)?, request)?;
            Ok(jzon::object! { status: "stored" })
        }
        _ => anyhow::bail!("unsupported leaf route"),
    }
}
