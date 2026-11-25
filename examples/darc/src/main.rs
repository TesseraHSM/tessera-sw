// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DARC TMK transfer between two partitions for every recipient KEM:
//! P-384, ML-KEM-1024 (HPKE-13) and MLKEM1024-P384 (HPKE-10).
//!
//! Each subcommand talks to the one partition selected by `TSRA_DDI_ARGS`
//! and exchanges artifacts with the other party through `--state-dir`:
//!
//! 1. `provision --name N` (both parties): factory-reset, bind a policy
//!    anchored to the shared POTA/SATA/DATA demo authorities, finalize and
//!    initialize the security domain. Saves the POTA- and DATA-anchored
//!    PID chains.
//! 2. `kex --name TARGET --kem K`: mint a DARC key-exchange key and the
//!    target PID's key report attesting it.
//! 3. `export --name SOURCE --target TARGET`: mint a TMK and seal it to the
//!    attested KEX key; the target is authorized by its DATA-anchored PID
//!    chain. Saves one complete source-PID-signed encrypted artifact.
//! 4. `import --name TARGET --source SOURCE`: verify that artifact under the
//!    source's POTA-anchored PID chain, open it and re-mask the TMK
//!    under the target security domain.
//!
//! `run_all_kems.sh` drives the flow against two `ddi_sock_server`
//! simulators. The demo authorities' private keys are stored in the state
//! directory: development use only.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use tsra_api::*;
use tsra_crypto::HashAlgo;
use tsra_crypto::Hasher;
use tsra_sealing_api::device_cert_chain;
use tsra_sealing_api::spki_thumbprint;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::PartPolicy;
use tsra_sealing_api::PolicyFields;
use tsra_sealing_api::SealingSession;
use tsra_sealing_common::pki::make_chain;
use tsra_sealing_common::pki::make_pta_chain;
use tsra_sealing_common::pki::CaKey;
use x509::X509Certificate;
use x509::X509CertificateOp;

/// `KeyScope::Local`: the KEX key is masked under the partition-local
/// masking key, so it survives across sessions.
const KEX_SCOPE_LOCAL: u8 = 3;
/// Fixed demo machine seed bound at `part_init_ex`.
const MACHINE_SEED: [u8; 32] = [0x5D; 32];
/// Caller data bound into the KEX key report.
const REPORT_DATA: [u8; 128] = [0xDA; 128];

#[derive(Parser)]
#[command(about = "DARC TMK transfer example")]
struct Cli {
    /// Directory shared by both parties.
    #[arg(long, global = true, default_value = "darc-state")]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect an unauthenticated root hash for a locally owned simulator fixture.
    SimulatorRootPin,
    /// Factory-reset and provision this partition.
    Provision {
        #[arg(long)]
        name: String,
    },
    /// Mint the target's DARC KEX key and its key report.
    Kex {
        #[arg(long)]
        name: String,
        #[arg(long, value_enum)]
        kem: Kem,
    },
    /// Mint a TMK on the source and seal it to the target's KEX key.
    Export {
        #[arg(long)]
        name: String,
        #[arg(long)]
        target: String,
    },
    /// Open the sealed TMK on the target.
    Import {
        #[arg(long)]
        name: String,
        #[arg(long)]
        source: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Kem {
    P384,
    Mlkem1024,
    #[value(name = "mlkem1024-p384")]
    Mlkem1024P384,
}

impl From<Kem> for HsmTransferKem {
    fn from(kem: Kem) -> Self {
        match kem {
            Kem::P384 => Self::P384,
            Kem::Mlkem1024 => Self::MlKem1024,
            Kem::Mlkem1024P384 => Self::MlKem1024P384,
        }
    }
}

/// Party artifacts under `<state-dir>/<name>/`.
struct Party {
    dir: PathBuf,
}

impl Party {
    fn new(state_dir: &Path, name: &str) -> Result<Self> {
        let dir = state_dir.join(name);
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Self { dir })
    }

    fn write(&self, file: &str, bytes: &[u8]) -> Result<()> {
        let path = self.dir.join(file);
        fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))
    }

    fn read(&self, file: &str) -> Result<Vec<u8>> {
        let path = self.dir.join(file);
        fs::read(&path).with_context(|| format!("read {}", path.display()))
    }

    /// Root-first DER chain, one hex certificate per line.
    fn write_chain(&self, file: &str, chain: &[Vec<u8>]) -> Result<()> {
        let text: String = chain.iter().map(|der| hex::encode(der) + "\n").collect();
        self.write(file, text.as_bytes())
    }

    fn read_chain(&self, file: &str) -> Result<Vec<Vec<u8>>> {
        let text = String::from_utf8(self.read(file)?).context("chain file is not UTF-8")?;
        text.lines()
            .map(|line| hex::decode(line).context("chain file is not hex"))
            .collect()
    }
}

/// Shared demo trust anchors: POTA authorizes PIDs as report signers, SATA
/// authorizes SD receivers, DATA authorizes DARC recipients.
struct Authorities {
    pota: CaKey,
    sata: CaKey,
    data: CaKey,
}

impl Authorities {
    fn load_or_create(state_dir: &Path) -> Result<Self> {
        let dir = Party::new(state_dir, "authorities")?;
        let load = |name: &str| -> Result<CaKey> {
            let path = dir.dir.join(name);
            match fs::read(&path) {
                Ok(der) => CaKey::from_der(&der),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let key = CaKey::generate();
                    dir.write(name, &key.private_key_der()?)?;
                    Ok(key)
                }
                Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
            }
        };
        Ok(Self {
            pota: load("pota.der")?,
            sata: load("sata.der")?,
            data: load("data.der")?,
        })
    }
}

fn certs(chain: &[Vec<u8>]) -> Vec<HsmCert<'_>> {
    chain.iter().map(|cert| HsmCert { cert }).collect()
}

fn open_partition() -> Result<HsmPartition> {
    let info = HsmPartitionManager::partition_info_list()
        .into_iter()
        .next()
        .context("no partition; set TSRA_DDI_ARGS")?;
    let rev = info.api_rev_range.context("partition API revision")?.max();
    HsmPartitionManager::open_partition(&info.path, rev).context("open partition")
}

/// Open the configured partition on the CO session rotated by `provision`.
fn open_session() -> Result<(HsmPartition, HsmSession)> {
    let partition = open_partition()?;
    let session = SealingSession::open_co_session(&partition, partition.api_rev())?;
    Ok((partition, session))
}

fn simulator_root_pin() -> Result<()> {
    let partition = open_partition()?;
    let pem = partition
        .cert_chain(0)
        .context("simulator certificate chain")?;
    let chain = X509Certificate::from_pem_stack(pem.as_bytes()).context("certificates")?;
    let spki = chain
        .last()
        .context("simulator root")?
        .subject_public_key_info_der()
        .context("root SPKI")?;
    let pin = Hasher::hash_vec(&mut HashAlgo::sha384(), spki).context("root hash")?;
    println!("{}", hex::encode(pin));
    Ok(())
}

fn provision(state_dir: &Path, name: &str) -> Result<()> {
    let party = Party::new(state_dir, name)?;
    let ca = Authorities::load_or_create(state_dir)?;
    let session = SealingSession::open_reset()?;
    let partition = &session.partition;

    let pid = partition.pid().context("partition id")?;
    let pid_pub = partition.ex_pub_key().context("PID public key")?;
    let policy = PartPolicy::new(PolicyFields {
        pota_spki_thumbprint: spki_thumbprint(&ca.pota.raw_pub())?,
        sata_spki_thumbprint: spki_thumbprint(&ca.sata.raw_pub())?,
        sapota_spki_thumbprint: None,
        backup_part: Some((
            pid.as_slice().try_into().context("partition id length")?,
            spki_thumbprint(&pid_pub)?,
        )),
        flags: PolicyFlags::new(),
        info: None,
        data_spki_thumbprint: Some(spki_thumbprint(&ca.data.raw_pub())?),
    })?;

    let init = session
        .session
        .part_init_ex(policy.as_bytes(), &MACHINE_SEED)
        .context("part_init_ex")?;
    let pta_chain = make_pta_chain(&ca.pota, &init.pta_csr)?;
    session
        .session
        .part_final_ex(policy.as_bytes(), &certs(&pta_chain), None)
        .context("part_final_ex")?;

    // DARC needs an initialized security domain (its masking key protects
    // the TMK). Seal the SD backup to a throwaway SATA-certified receiver.
    let receiver = make_chain(&ca.sata, &CaKey::generate().raw_pub());
    let no_evidence = Evidence {
        mfgr_cert_chain: Vec::new(),
        owner_cert_chain: Vec::new(),
        part_owner_cert_chain: Vec::new(),
        report: Vec::new(),
    };
    no_evidence
        .with_hsm_evidence(|evidence| {
            session
                .session
                .sd_create_remote_backup(policy.as_bytes(), &receiver.certs(), evidence)
        })
        .context("initialize security domain")?;

    // Slot 2 holds only the PTA-issued PID leaf. Prefix it with the POTA
    // chain (import: authorizes the report signer) and with the same PTA
    // re-certified under DATA (export: authorizes the recipient).
    let pid_leaf = device_cert_chain(partition, 2)?;
    anyhow::ensure!(pid_leaf.len() == 1, "slot 2 must hold only the PID leaf");
    let data_chain = make_pta_chain(&ca.data, &init.pta_csr)?;
    party.write("policy.cbor", policy.as_bytes())?;
    party.write_chain(
        "pota_pid_chain.txt",
        &[pta_chain, pid_leaf.clone()].concat(),
    )?;
    party.write_chain("data_pid_chain.txt", &[data_chain, pid_leaf].concat())?;
    println!("[{name}] provisioned: SD initialized, POTA and DATA PID chains saved");
    Ok(())
}

fn kex(state_dir: &Path, name: &str, kem: HsmTransferKem) -> Result<()> {
    let party = Party::new(state_dir, name)?;
    let (_partition, session) = open_session()?;
    let (masked, public) = session
        .darc_kex_key_gen(KEX_SCOPE_LOCAL, kem)
        .context("darc_kex_key_gen")?;
    let mut report = vec![0u8; session.darc_kex_key_report(&masked, &REPORT_DATA, None)?];
    let len = session
        .darc_kex_key_report(&masked, &REPORT_DATA, Some(&mut report))
        .context("darc_kex_key_report")?;
    report.truncate(len);

    party.write("kex.masked", &masked)?;
    party.write("kex.report", &report)?;
    println!(
        "[{name}] {kem:?} KEX key: masked {} B, public {} B, key report {} B",
        masked.len(),
        public.len(),
        report.len()
    );
    Ok(())
}

fn export(state_dir: &Path, name: &str, target: &str) -> Result<()> {
    let source = Party::new(state_dir, name)?;
    let target = Party::new(state_dir, target)?;
    let (_partition, session) = open_session()?;
    let masked_tmk = session.darc_tmk_gen().context("darc_tmk_gen")?;
    let target_chain = target.read_chain("data_pid_chain.txt")?;
    let exported = session
        .darc_tmk_export(
            &masked_tmk,
            &source.read("policy.cbor")?,
            &certs(&target_chain),
            &target.read("kex.report")?,
        )
        .context("darc_tmk_export")?;

    source.write("tmk.sealed", &exported.sealed_tmk)?;
    println!(
        "[{name}] exported TMK: complete signed artifact {} B",
        exported.sealed_tmk.len()
    );
    Ok(())
}

fn import(state_dir: &Path, name: &str, source: &str) -> Result<()> {
    let target = Party::new(state_dir, name)?;
    let source = Party::new(state_dir, source)?;
    let (_partition, session) = open_session()?;
    let source_chain = source.read_chain("pota_pid_chain.txt")?;
    let masked_tmk = session
        .darc_tmk_import(
            &target.read("kex.masked")?,
            &target.read("policy.cbor")?,
            &source.read("tmk.sealed")?,
            &certs(&source_chain),
        )
        .context("darc_tmk_import")?;

    target.write("tmk.masked", &masked_tmk)?;
    println!(
        "[{name}] imported TMK: re-masked under the target SD ({} B)",
        masked_tmk.len()
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::SimulatorRootPin => simulator_root_pin(),
        Command::Provision { name } => provision(&cli.state_dir, &name),
        Command::Kex { name, kem } => kex(&cli.state_dir, &name, kem.into()),
        Command::Export { name, target } => export(&cli.state_dir, &name, &target),
        Command::Import { name, source } => import(&cli.state_dir, &name, &source),
    }
}
