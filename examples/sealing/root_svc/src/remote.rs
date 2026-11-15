// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! External-SA HPKE open/reseal, recovery validation and file encoding.

use anyhow::Context;
use anyhow::Result;
use tsra_crypto as hpke;
use tsra_crypto::aead_envelope;
use tsra_crypto::EccCurve;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EccPublicKey;
use tsra_crypto::HpkeKeyPair;
use tsra_crypto::HpkeOpenConfig;
use tsra_crypto::HpkePrivateKey;
use tsra_crypto::HpkeSealConfig;
use tsra_crypto::ImportableKey;
use tsra_sealing_api::mint_sealing_key;
use tsra_sealing_api::spki_thumbprint;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::PartPolicy;
use tsra_sealing_api::RemoteBackup;
use tsra_sealing_api::RemoteRecovery;
use tsra_sealing_api::SealingSession;
use tsra_sealing_api::SecurityDomain;
use tsra_sealing_api::SecurityDomainEnv;
use tsra_sealing_api::SecurityDomainStore;
use tsra_sealing_api::TransferKem;
use tsra_sealing_api::RAW_PUB_LEN;
use tsra_sealing_common::evidence;
use tsra_sealing_common::pki::GeneratedChain;
use tsra_sealing_report::attested_recipient;
use tsra_sealing_report::parse_key_report_bytes;
use tsra_sealing_report::sd_header;
use tsra_sealing_report::sign_software_key_report;
use tsra_sealing_report::sign_software_sd_transfer;
use tsra_sealing_report::validate_sd_envelope;
use tsra_sealing_report::verify_certificate_chain;
use tsra_sealing_report::verify_key_report_bytes;
use tsra_sealing_report::verify_sd_transfer_report;
use tsra_sealing_report::SD_HEADER_LEN;
use x509::X509Certificate;
use x509::X509CertificateOp;
use zeroize::Zeroizing;

use crate::env::SelfContainedEnv;

/// External software HPKE receiver certified under SATA. Its P-384 leaf key
/// is the P-384 KEM key, or signs a key report delegating to a post-quantum
/// key pair. The leaf also signs the authority's software operation reports.
pub(crate) struct SoftwareReceiver {
    leaf: EccPrivateKey,
    leaf_raw: [u8; RAW_PUB_LEN],
    pq: Option<HpkeKeyPair>,
    /// Transfer recipient key: raw P-384 `X || Y` or the PQ public key.
    pub recipient: Vec<u8>,
    pub chain: GeneratedChain,
    pub key_report: Option<Vec<u8>>,
}

impl SoftwareReceiver {
    pub fn generate(env: &SelfContainedEnv, kem: TransferKem) -> Result<Self> {
        let leaf = EccPrivateKey::from_curve(EccCurve::P384)?;
        let leaf_raw = raw_public(&leaf)?;
        let pq = (kem != TransferKem::P384)
            .then(|| kem.suite().generate_keypair())
            .transpose()?;
        let recipient = match &pq {
            Some(pair) => pair.public_key().to_vec()?,
            None => leaf_raw.to_vec(),
        };
        let (chain, key_report) = endorse(env, &leaf, &recipient)?;
        Ok(Self {
            leaf,
            leaf_raw,
            pq,
            recipient,
            chain,
            key_report,
        })
    }

    pub fn chain_der(&self) -> Vec<Vec<u8>> {
        vec![self.chain.root_der.clone(), self.chain.leaf_der.clone()]
    }

    /// HPKE-open an SD envelope addressed to this receiver.
    pub fn open(&self, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let kem = validate_sd_envelope(envelope)?;
        anyhow::ensure!(
            kem == TransferKem::from_recipient(&self.recipient)?,
            "SD envelope is not addressed to this receiver's KEM"
        );
        let header = &envelope[..SD_HEADER_LEN];
        let (enc, ct) = envelope[SD_HEADER_LEN..].split_at(kem.enc_len());
        let mut plaintext = Zeroizing::new(vec![0u8; ct.len()]);
        let length = TransferKem::with_hpke_public(&self.recipient, |_, public| {
            let private = match &self.pq {
                Some(pair) => pair.private_key(),
                None => HpkePrivateKey::Ecc(&self.leaf),
            };
            let open = HpkeOpenConfig::base(kem.suite(), private, public, header, header);
            Ok(hpke::open(&open, enc, ct, Some(&mut plaintext[..]))?)
        })?;
        anyhow::ensure!(length == 48, "SD envelope did not contain a 48-byte BKS3");
        plaintext.truncate(length);
        Ok(plaintext)
    }
}

fn raw_public(key: &EccPrivateKey) -> Result<[u8; RAW_PUB_LEN]> {
    let (x, y) = key.coord_vec()?;
    [x, y]
        .concat()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid P-384 public coordinates"))
}

/// Certify `leaf` under SATA. A P-384 `recipient` must be the leaf key
/// itself; any other recipient gets a leaf-signed key report.
fn endorse(
    env: &SelfContainedEnv,
    leaf: &EccPrivateKey,
    recipient: &[u8],
) -> Result<(GeneratedChain, Option<Vec<u8>>)> {
    let leaf_raw = raw_public(leaf)?;
    let chain = env.receiver_chain(&leaf_raw)?;
    if TransferKem::from_recipient(recipient)? == TransferKem::P384 {
        anyhow::ensure!(
            recipient == leaf_raw,
            "P-384 recipient must be the leaf key"
        );
        return Ok((chain, None));
    }
    Ok((chain, Some(sign_software_key_report(leaf, recipient)?)))
}

/// Certify an HSM receiver under SATA: directly for P-384, otherwise through
/// a fresh demo leaf that signs a key report attesting it.
fn endorse_hsm_receiver(
    env: &SelfContainedEnv,
    recipient: &[u8],
) -> Result<(GeneratedChain, Vec<u8>)> {
    if TransferKem::from_recipient(recipient)? == TransferKem::P384 {
        let raw = recipient
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid HSM receiver coordinates"))?;
        return Ok((env.receiver_chain(&raw)?, Vec::new()));
    }
    let leaf = EccPrivateKey::from_curve(EccCurve::P384)?;
    let (chain, report) = endorse(env, &leaf, recipient)?;
    Ok((chain, report.context("missing receiver key report")?))
}

/// Prepare a restore-ready backup through an external software SA.
///
/// The SA private key is needed only while opening/resealing here. The saved
/// package is already addressed to the HSM, so that key need not be exported.
/// Both the SA and the HSM receiver use `kem`.
pub fn create(
    domain: &SecurityDomain<SelfContainedEnv>,
    session: &SealingSession,
    seed: &[u8],
    kem: TransferKem,
) -> Result<RemoteRecovery> {
    let env = domain.env();
    anyhow::ensure!(
        !env.policy().flags.require_trusted_sa_key(),
        "software SA cannot satisfy trusted-SA attestation"
    );
    let sa = SoftwareReceiver::generate(env, kem)?;
    let no_attestation = Evidence {
        mfgr_cert_chain: Vec::new(),
        owner_cert_chain: Vec::new(),
        part_owner_cert_chain: Vec::new(),
        report: Vec::new(),
    };
    let created = domain.create(
        session,
        seed,
        &sa.chain.certs(),
        sa.key_report.as_deref(),
        &no_attestation,
        |csr, report| env.sign_pta(csr, report),
    )?;
    let source_pid = evidence::verify_transfer_source(
        &created.evidence,
        env.policy(),
        &env.policy().pota_spki_thumbprint,
        &created.pok_remote_backup,
        Some(&sa.recipient),
    )?;
    anyhow::ensure!(
        spki_thumbprint(&source_pid)?
            == env
                .policy()
                .backup_part
                .context("policy has no backing partition")?
                .1,
        "creation source PID mismatch"
    );
    let receiver = mint_sealing_key(&session.session, kem)
        .context("local recovery saved, but HSM remote receiver generation failed")?;
    let mut receiver_evidence = created.evidence.clone();
    receiver_evidence.report = receiver.report.clone();
    evidence::verify_peer(&receiver_evidence, env.policy())?;
    let receiver_recipient = attested_recipient(&parse_key_report_bytes(&receiver.report)?)?;
    let (receiver_chain, receiver_key_report) = endorse_hsm_receiver(env, &receiver_recipient)?;
    let header = sd_header(&sa.leaf_raw, &receiver_recipient, env.policy().as_bytes())?;

    let remote_backup = sa
        .open(&created.pok_remote_backup)
        .and_then(|bks3| seal(&header, &receiver_recipient, &bks3))
        .context("local recovery saved, but external-SA HPKE open/reseal failed")?;
    let state = env
        .store()
        .load_security_domain()?
        .context("saved local SD recovery state is missing after creation")?;
    let report = sign_software_sd_transfer(
        &sa.leaf,
        &sa.leaf_raw,
        &receiver_recipient,
        env.policy().as_bytes(),
        &remote_backup,
    )?;
    let remote = RemoteRecovery {
        backup: RemoteBackup {
            pok_remote_backup: remote_backup,
            evidence: Evidence {
                mfgr_cert_chain: Vec::new(),
                owner_cert_chain: Vec::new(),
                part_owner_cert_chain: Vec::new(),
                report,
            },
        },
        masked_receiver_key: receiver.masked,
        sd_mk_backup: state.sd_mk_backup,
        sender_pid_pub_key: sa.leaf_raw.to_vec(),
        receiver_cert_chain: vec![receiver_chain.root_der, receiver_chain.leaf_der],
        receiver_key_report,
    };
    validate(&remote, env.policy())?;
    Ok(remote)
}

/// HPKE Base seal `plaintext` to `recipient`, using `header` as info and AAD.
fn seal(header: &[u8], recipient: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    TransferKem::with_hpke_public(recipient, |kem, public| {
        let sealed = hpke::seal_vec(
            &HpkeSealConfig::base(kem.suite(), public, header, header),
            plaintext,
        )?;
        Ok([header, &sealed.enc, &sealed.ct].concat())
    })
}

pub fn validate(remote: &RemoteRecovery, policy: &PartPolicy) -> Result<()> {
    remote.validate()?;
    let envelope = aead_envelope::inspect(&remote.masked_receiver_key)
        .context("decode remote receiver envelope")?;
    let kem = TransferKem::from_masked_key_len(remote.masked_receiver_key.len())?;
    anyhow::ensure!(
        envelope.aad.len() == 192 && envelope.payload.len() == kem.seed_len(),
        "invalid remote receiver envelope shape"
    );
    let external = remote.backup.evidence.mfgr_cert_chain.is_empty();
    if external {
        anyhow::ensure!(
            !policy.flags.require_trusted_sa_key(),
            "software SA cannot satisfy trusted-SA attestation"
        );
        validate_hpke_chain(&remote.receiver_cert_chain, policy)
            .context("verify HSM receiver HPKE chain")?;
        let leaf = remote
            .receiver_cert_chain
            .last()
            .context("missing receiver certificate")?;
        let recipient = if remote.receiver_key_report.is_empty() {
            public_key(leaf)?
        } else {
            attested_recipient(
                &verify_key_report_bytes(&remote.receiver_key_report, leaf)
                    .context("verify receiver key report against the SATA leaf")?,
            )?
        };
        verify_sd_transfer_report(
            &remote.backup.evidence.report,
            &remote.sender_pid_pub_key,
            &remote.backup.pok_remote_backup,
            policy.as_bytes(),
            Some(&recipient),
        )?;
        anyhow::ensure!(
            remote.backup.evidence.owner_cert_chain.is_empty()
                && remote.backup.evidence.part_owner_cert_chain.is_empty(),
            "software authority must not assert hardware provenance"
        );
    } else {
        let anchor = if policy.flags.require_trusted_sa_key() {
            policy
                .sapota_spki_thumbprint
                .as_ref()
                .context("policy has no SAPOTA")?
        } else {
            &policy.pota_spki_thumbprint
        };
        let pid = evidence::verify_transfer_source(
            &remote.backup.evidence,
            policy,
            anchor,
            &remote.backup.pok_remote_backup,
            None,
        )?;
        anyhow::ensure!(
            pid.as_slice() == remote.sender_pid_pub_key,
            "restore source PID mismatch"
        );
    }
    Ok(())
}

fn validate_hpke_chain(chain: &[Vec<u8>], policy: &PartPolicy) -> Result<()> {
    verify_certificate_chain(chain)?;
    let anchored = chain_has_anchor(chain, &policy.sata_spki_thumbprint)?;
    anyhow::ensure!(anchored, "HPKE chain is not endorsed by policy SATA");
    let leaf = chain.last().context("HPKE certificate chain is empty")?;
    anyhow::ensure!(
        public_key(leaf)?.len() == RAW_PUB_LEN,
        "HPKE key must be P-384"
    );
    Ok(())
}

fn chain_has_anchor(chain: &[Vec<u8>], anchor: &[u8; 48]) -> Result<bool> {
    let mut anchored = false;
    for certificate in chain.iter().take(chain.len().saturating_sub(1)) {
        let public = public_key(certificate)?;
        if public.len() == RAW_PUB_LEN {
            anchored |= spki_thumbprint(&public)? == *anchor;
        }
    }
    Ok(anchored)
}

fn public_key(certificate: &[u8]) -> Result<Vec<u8>> {
    let certificate = X509Certificate::from_der(certificate)?;
    let key = EccPublicKey::from_bytes(&certificate.get_public_key_der()?)?;
    let (x, y) = key.coord_vec()?;
    Ok([x, y].concat())
}
