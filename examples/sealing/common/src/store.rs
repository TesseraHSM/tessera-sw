// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Atomic recovery backups with separately stored demo signers and ECC keys.
//!
//! Private key material is stored unencrypted in this example, with mode 0600
//! on Unix. Production services should keep authority signers in an HSM or CA.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use anyhow::Context;
use anyhow::Result;
use jzon::JsonValue;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_sealing_api::PartitionState;
use tsra_sealing_api::RemoteRecovery;
use tsra_sealing_api::SecurityDomainState;
use tsra_sealing_api::SecurityDomainStore;

use crate::key_check;
use crate::key_check::SavedKey;

const VERSION: u32 = 1;
const RECOVERY_VERSION: u32 = 2;
const PARTITION_FILE: &str = "partition-state.json";
const DOMAIN_FILE: &str = "security-domain-state.json";
const RECOVERY_FILE: &str = "recovery-state.json";
const POTA_FILE: &str = "pota.json";
const SATA_FILE: &str = "sata.json";
const KEYS_FILE: &str = "keys.json";
const REMOTE_FILE: &str = "remote-backup.json";
const PEER_FILE: &str = "peer.json";
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, PartialEq, Eq)]
pub struct AuthorityState {
    pub pota_private_key: Vec<u8>,
    pub pota_certificate: Vec<u8>,
    pub sata_thumbprint: [u8; 48],
    pub machine_seed: [u8; MACH_SEED_LEN],
    pub sata: Option<SigningAuthority>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SigningAuthority {
    pub private_key: Vec<u8>,
    pub certificate: Vec<u8>,
}

pub struct FileStore {
    dir: PathBuf,
    authority: Option<AuthorityState>,
}

impl FileStore {
    pub fn new(dir: &Path) -> Result<Self> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(dir)
            .context("create recovery state directory")?;
        let dir = dir
            .canonicalize()
            .context("resolve recovery state directory")?;
        #[cfg(unix)]
        if let Some(parent) = dir.parent() {
            fs::File::open(parent)?
                .sync_all()
                .context("sync state directory parent")?;
        }
        Ok(Self {
            dir,
            authority: None,
        })
    }

    pub fn with_authority(mut self, authority: AuthorityState) -> Self {
        self.authority = Some(authority);
        self
    }

    pub fn ensure_new_creation(&self) -> Result<()> {
        for name in [
            RECOVERY_FILE,
            PARTITION_FILE,
            DOMAIN_FILE,
            POTA_FILE,
            SATA_FILE,
            KEYS_FILE,
            REMOTE_FILE,
            PEER_FILE,
            "peer-prepared.json",
            "leaf.json",
            "leaf-backup.json",
            "leaf-remote-prepared.json",
            "leaf-resealed.json",
        ] {
            match fs::symlink_metadata(self.dir.join(name)) {
                Ok(_) => anyhow::bail!(
                    "recovery state already exists in {}; refusing to reset the partition",
                    self.dir.display()
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).with_context(|| format!("inspect saved {name}")),
            }
        }
        Ok(())
    }

    pub fn load_peer(&self) -> Result<Option<JsonValue>> {
        self.load(PEER_FILE)
    }

    pub fn save_peer(&self, record: &JsonValue) -> Result<()> {
        self.write_immutable(PEER_FILE, record)
    }

    pub fn save_prepared_peer(&self, peer: &tsra_sealing_api::PreparedPeer) -> Result<()> {
        self.write_immutable(
            "peer-prepared.json",
            &jzon::object! {
                version: VERSION,
                policy: hex::encode(&peer.partition.policy),
                pta: crate::wire::encode_chain(&peer.partition.pta_cert_chain),
                local_mk_backup: hex::encode(&peer.partition.local_mk_backup),
                masked_receiver: hex::encode(&peer.receiver.masked),
                report: hex::encode(&peer.receiver.report),
            },
        )
    }

    pub fn load_authority(&self) -> Result<Option<AuthorityState>> {
        let bundle = self.load_bundle()?;
        if bundle["version"].as_u32() == Some(RECOVERY_VERSION) {
            if bundle["pota_file"].is_null() {
                return Ok(None);
            }
            let pota = self.load_signer(POTA_FILE)?;
            anyhow::ensure!(
                blob(&bundle, "pota_thumbprint")? == crate::pki::thumbprint(&pota.certificate),
                "saved POTA certificate thumbprint mismatch"
            );
            let sata_thumbprint = blob(&bundle, "sata_thumbprint")?
                .as_slice()
                .try_into()
                .context("saved SATA thumbprint must be 48 bytes")?;
            let sata = if bundle["sata_file"].is_null() {
                None
            } else {
                let sata = self.load_signer(SATA_FILE)?;
                anyhow::ensure!(
                    crate::pki::thumbprint(&sata.certificate) == sata_thumbprint,
                    "saved SATA certificate thumbprint mismatch"
                );
                Some(sata)
            };
            return Ok(Some(AuthorityState {
                pota_private_key: pota.private_key,
                pota_certificate: pota.certificate,
                sata_thumbprint,
                machine_seed: blob(&bundle, "machine_seed")?
                    .as_slice()
                    .try_into()
                    .context("saved machine seed has an invalid length")?,
                sata,
            }));
        }
        let authority = &bundle["authority"];
        if authority.is_null() {
            return Ok(None);
        }
        anyhow::ensure!(authority.is_object(), "invalid saved trust authority");
        Ok(Some(AuthorityState {
            pota_private_key: blob(authority, "pota_private_key")?,
            pota_certificate: blob(authority, "pota_certificate")?,
            sata_thumbprint: blob(authority, "sata_thumbprint")?
                .as_slice()
                .try_into()
                .context("saved SATA thumbprint must be 48 bytes")?,
            machine_seed: blob(authority, "machine_seed")?
                .as_slice()
                .try_into()
                .context("saved machine seed has an invalid length")?,
            sata: None,
        }))
    }

    fn load_signer(&self, name: &str) -> Result<SigningAuthority> {
        let record = self
            .load(name)?
            .with_context(|| format!("saved {name} is missing"))?;
        Ok(SigningAuthority {
            private_key: blob(&record, "private_key")?,
            certificate: blob(&record, "certificate")?,
        })
    }

    pub fn load_ecc_keys(&self) -> Result<Option<Vec<SavedKey>>> {
        let mut record = self.load_bundle()?;
        if record["version"].as_u32() == Some(RECOVERY_VERSION) {
            if record["keys_file"].is_null() {
                return Ok(None);
            }
            record = self
                .load(KEYS_FILE)?
                .context("saved keys.json is missing")?;
            return key_check::decode(&record["ecc_keys"]).map(Some);
        }
        if !record.has_key("ecc_keys") || record["ecc_keys"].is_null() {
            return Ok(None);
        }
        key_check::decode(&record["ecc_keys"]).map(Some)
    }

    pub fn save_ecc_keys(&self, keys: &[SavedKey]) -> Result<()> {
        let mut record = self.load_bundle()?;
        anyhow::ensure!(
            record["partition"].is_object() && record["security_domain"].is_object(),
            "save recovery backups before saving ECC scope check keys"
        );
        anyhow::ensure!(
            record["version"].as_u32() == Some(RECOVERY_VERSION),
            "save split recovery state before saving ECC keys"
        );
        self.write_immutable(
            KEYS_FILE,
            &jzon::object! {
                version: VERSION,
                ecc_keys: key_check::encode(keys)?,
            },
        )?;
        record["keys_file"] = KEYS_FILE.into();
        self.write_record(RECOVERY_FILE, &record, false)
    }

    pub fn save_remote(&self, remote: &RemoteRecovery) -> Result<()> {
        let mut record = self.load_bundle()?;
        anyhow::ensure!(
            record["version"].as_u32() == Some(RECOVERY_VERSION)
                && record["partition"].is_object()
                && record["security_domain"].is_object(),
            "save local recovery state before the remote backup"
        );
        self.write_immutable(REMOTE_FILE, &crate::recovery_wire::encode(remote)?)?;
        record["remote_file"] = REMOTE_FILE.into();
        self.write_record(RECOVERY_FILE, &record, false)
    }

    pub fn load_remote(&self) -> Result<RemoteRecovery> {
        let record = self.load_bundle()?;
        anyhow::ensure!(
            record["remote_file"].as_str() == Some(REMOTE_FILE),
            "no saved remote backup; create with --remote-restorable"
        );
        let remote = self
            .load(REMOTE_FILE)?
            .context("saved remote-backup.json is missing")?;
        crate::recovery_wire::decode(&remote)
    }

    pub fn write_immutable(&self, name: &str, record: &JsonValue) -> Result<()> {
        if let Some(existing) = self.load(name)? {
            anyhow::ensure!(
                existing == *record,
                "refusing to overwrite different saved {name}"
            );
            return Ok(());
        }
        self.write_record(name, record, true)
    }

    pub fn write_record(&self, name: &str, record: &JsonValue, immutable: bool) -> Result<()> {
        let mut temporary = TemporaryFile::new(&self.dir, name)?;
        let file = temporary
            .file
            .as_mut()
            .context("missing temporary recovery file")?;
        file.write_all(record.dump().as_bytes())
            .context("write recovery record")?;
        file.sync_all().context("sync recovery record")?;
        drop(temporary.file.take());
        if immutable {
            fs::hard_link(&temporary.path, self.dir.join(name))
                .with_context(|| format!("publish {name} without overwriting existing state"))?;
        } else {
            fs::rename(&temporary.path, self.dir.join(name))
                .with_context(|| format!("publish {name}"))?;
        }
        // Publication cannot be undone if the directory sync then fails.
        #[cfg(unix)]
        fs::File::open(&self.dir)?
            .sync_all()
            .context("recovery record published, but directory sync failed")?;
        Ok(())
    }

    pub fn load(&self, name: &str) -> Result<Option<JsonValue>> {
        let path = self.dir.join(name);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let record = jzon::parse(&text).with_context(|| format!("parse {}", path.display()))?;
        anyhow::ensure!(
            record["version"].as_u32() == Some(VERSION)
                || ((name == RECOVERY_FILE || name == REMOTE_FILE)
                    && record["version"].as_u32() == Some(RECOVERY_VERSION)),
            "unsupported or missing recovery record version in {}",
            path.display(),
        );
        Ok(Some(record))
    }

    fn load_bundle(&self) -> Result<JsonValue> {
        if let Some(record) = self.load(RECOVERY_FILE)? {
            for field in ["partition", "security_domain"] {
                anyhow::ensure!(
                    record[field].is_null() || record[field].is_object(),
                    "invalid {field} recovery record",
                );
            }
            if record["version"].as_u32() == Some(RECOVERY_VERSION) {
                for (field, name) in [
                    ("pota_file", POTA_FILE),
                    ("sata_file", SATA_FILE),
                    ("keys_file", KEYS_FILE),
                    ("remote_file", REMOTE_FILE),
                ] {
                    anyhow::ensure!(
                        record[field].is_null() || record[field].as_str() == Some(name),
                        "invalid saved {field} reference"
                    );
                }
            }
            return Ok(record);
        }
        Ok(jzon::object! {
            version: VERSION,
            partition: self.load(PARTITION_FILE)?.unwrap_or(JsonValue::Null),
            security_domain: self.load(DOMAIN_FILE)?.unwrap_or(JsonValue::Null),
        })
    }
}

struct TemporaryFile {
    path: PathBuf,
    file: Option<fs::File>,
}

impl TemporaryFile {
    fn new(dir: &Path, name: &str) -> Result<Self> {
        let path = dir.join(format!(
            ".{name}.tmp.{}.{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed),
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .context("create temporary recovery record")?;
        Ok(Self {
            path,
            file: Some(file),
        })
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        drop(self.file.take());
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => eprintln!("failed to remove temporary recovery record: {error}"),
        }
    }
}

fn blob(record: &JsonValue, field: &str) -> Result<Vec<u8>> {
    let encoded = record[field]
        .as_str()
        .with_context(|| format!("missing or invalid {field}"))?;
    hex::decode(encoded).with_context(|| format!("invalid hex in {field}"))
}

impl SecurityDomainStore for FileStore {
    fn save_creation(
        &self,
        partition: &PartitionState,
        domain: &SecurityDomainState,
    ) -> Result<()> {
        let mut chain = jzon::array![];
        for cert in &partition.pta_cert_chain {
            chain.push(hex::encode(cert))?;
        }
        let previous = self.load_bundle()?;
        let saved_authority = self.load_authority()?;
        let authority = self.authority.clone().or_else(|| saved_authority.clone());
        if previous["version"].as_u32() == Some(RECOVERY_VERSION)
            && !previous["pota_file"].is_null()
        {
            anyhow::ensure!(
                authority == saved_authority,
                "provided authority does not match the saved signer and recovery state"
            );
        } else if let Some(authority) = &authority {
            if let Some(sata) = &authority.sata {
                anyhow::ensure!(
                    crate::pki::thumbprint(&sata.certificate) == authority.sata_thumbprint,
                    "SATA certificate does not match the supplied thumbprint"
                );
            }
            self.write_immutable(
                POTA_FILE,
                &signer_record(&authority.pota_private_key, &authority.pota_certificate),
            )?;
            if let Some(sata) = &authority.sata {
                self.write_immutable(
                    SATA_FILE,
                    &signer_record(&sata.private_key, &sata.certificate),
                )?;
            }
        }
        let keys_file = if previous["version"].as_u32() == Some(RECOVERY_VERSION) {
            self.load_ecc_keys()?;
            previous["keys_file"].clone()
        } else if !previous["ecc_keys"].is_null() {
            key_check::decode(&previous["ecc_keys"])?;
            self.write_immutable(
                KEYS_FILE,
                &jzon::object! {
                    version: VERSION,
                    ecc_keys: previous["ecc_keys"].clone(),
                },
            )?;
            KEYS_FILE.into()
        } else {
            JsonValue::Null
        };
        let record = jzon::object! {
            version: RECOVERY_VERSION,
            pota_file: authority.as_ref().map(|_| POTA_FILE),
            sata_file: authority.as_ref().and_then(|authority| authority.sata.as_ref()).map(|_| SATA_FILE),
            keys_file: keys_file,
            remote_file: previous["remote_file"].clone(),
            machine_seed: authority.as_ref().map(|authority| hex::encode(authority.machine_seed)),
            pota_thumbprint: authority.as_ref().map(|authority| hex::encode(crate::pki::thumbprint(&authority.pota_certificate))),
            sata_thumbprint: authority.as_ref().map(|authority| hex::encode(authority.sata_thumbprint)),
            partition: jzon::object! {
                version: VERSION,
                policy: hex::encode(&partition.policy),
                pta_cert_chain: chain,
                local_mk_backup: hex::encode(&partition.local_mk_backup),
            },
            security_domain: jzon::object! {
                version: VERSION,
                pok_local_backup: hex::encode(&domain.pok_local_backup),
                sd_mk_backup: hex::encode(&domain.sd_mk_backup),
            },
        };

        self.write_record(RECOVERY_FILE, &record, false)
    }

    fn load_partition(&self) -> Result<Option<PartitionState>> {
        let bundle = self.load_bundle()?;
        let record = &bundle["partition"];
        if record.is_null() {
            return Ok(None);
        }
        anyhow::ensure!(
            record["pta_cert_chain"].is_array(),
            "missing or invalid PTA chain"
        );
        let pta_cert_chain = record["pta_cert_chain"]
            .members()
            .map(|cert| {
                hex::decode(
                    cert.as_str()
                        .context("PTA certificate must be a hex string")?,
                )
                .context("invalid hex in PTA certificate")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(PartitionState {
            policy: blob(record, "policy")?,
            pta_cert_chain,
            local_mk_backup: blob(record, "local_mk_backup")?,
        }))
    }

    fn load_security_domain(&self) -> Result<Option<SecurityDomainState>> {
        let bundle = self.load_bundle()?;
        let record = &bundle["security_domain"];
        if record.is_null() {
            return Ok(None);
        }
        Ok(Some(SecurityDomainState {
            pok_local_backup: blob(record, "pok_local_backup")?,
            sd_mk_backup: blob(record, "sd_mk_backup")?,
        }))
    }
}

fn signer_record(private_key: &[u8], certificate: &[u8]) -> JsonValue {
    jzon::object! {
        version: VERSION,
        private_key: hex::encode(private_key),
        certificate: hex::encode(certificate),
    }
}
