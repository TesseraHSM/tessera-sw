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
use tsra_crypto::HpkeOpenConfig;
use tsra_crypto::HpkeSealConfig;
use tsra_crypto::HpkeSuite;
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
use tsra_sealing_api::RAW_PUB_LEN;
use tsra_sealing_common::evidence;
use tsra_sealing_report::parse_ec2_cose_key_bytes;
use tsra_sealing_report::parse_key_report_bytes;
use tsra_sealing_report::sd_header;
use tsra_sealing_report::sign_software_sd_transfer;
use tsra_sealing_report::validate_sd_envelope;
use tsra_sealing_report::verify_certificate_chain;
use tsra_sealing_report::verify_sd_transfer_report;
use tsra_sealing_report::Curve;
use tsra_sealing_report::SD_HEADER_LEN;
use x509::X509Certificate;
use x509::X509CertificateOp;
use zeroize::Zeroizing;

use crate::env::SelfContainedEnv;

/// Prepare a restore-ready backup through an external software SA.
///
/// The SA private key is needed only while opening/resealing here. The saved
/// package is already addressed to the HSM, so that key need not be exported.
pub fn create(
    domain: &SecurityDomain<SelfContainedEnv>,
    session: &SealingSession,
    seed: &[u8],
) -> Result<RemoteRecovery> {
    let env = domain.env();
    anyhow::ensure!(
        !env.policy().flags.require_trusted_sa_key(),
        "software SA cannot satisfy trusted-SA attestation"
    );
    let sa_key = EccPrivateKey::from_curve(EccCurve::P384)?;
    let (x, y) = sa_key.coord_vec()?;
    let sa_public = EccPublicKey::from_coordinates(EccCurve::P384, &x, &y)?;
    let raw: [u8; RAW_PUB_LEN] = [x, y]
        .concat()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid SA public coordinates"))?;
    let chain = env.receiver_chain(&raw)?;
    let no_attestation = Evidence {
        mfgr_cert_chain: Vec::new(),
        owner_cert_chain: Vec::new(),
        part_owner_cert_chain: Vec::new(),
        report: Vec::new(),
    };
    let created = domain.create(
        session,
        seed,
        &chain.certs(),
        &no_attestation,
        |csr, report| env.sign_pta(csr, report),
    )?;
    let source_pid = evidence::verify_transfer_source(
        &created.evidence,
        env.policy(),
        &env.policy().pota_spki_thumbprint,
        &created.pok_remote_backup,
        Some(&raw),
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
    let receiver = mint_sealing_key(&session.session)
        .context("local recovery saved, but HSM remote receiver generation failed")?;
    let mut receiver_evidence = created.evidence.clone();
    receiver_evidence.report = receiver.report.clone();
    evidence::verify_peer(&receiver_evidence, env.policy())?;
    let receiver_public = reported_public_key(&receiver.report)?;
    let (x, y) = receiver_public.coord_vec()?;
    let receiver_raw: [u8; RAW_PUB_LEN] = [x, y]
        .concat()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid HSM receiver coordinates"))?;
    let receiver_chain = env.receiver_chain(&receiver_raw)?;
    let header = sd_header(&raw, &receiver_raw, env.policy().as_bytes())?;

    let remote_backup = reseal(
        &created.pok_remote_backup,
        &sa_key,
        &sa_public,
        &receiver_public,
        &header,
    )
    .context("local recovery saved, but external-SA HPKE open/reseal failed")?;
    let state = env
        .store()
        .load_security_domain()?
        .context("saved local SD recovery state is missing after creation")?;
    let report = sign_software_sd_transfer(
        &sa_key,
        &raw,
        &receiver_raw,
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
        sender_pid_pub_key: [&[4][..], raw.as_slice()].concat(),
        receiver_cert_chain: vec![receiver_chain.root_der, receiver_chain.leaf_der],
    };
    validate(&remote, env.policy())?;
    Ok(remote)
}

fn reported_public_key(bytes: &[u8]) -> Result<EccPublicKey> {
    let report = parse_key_report_bytes(bytes)?;
    let public = parse_ec2_cose_key_bytes(
        report
            .public_key
            .get(..usize::from(report.public_key_size))
            .context("invalid sealing public key length")?,
    )?;
    anyhow::ensure!(public.curve == Curve::P384, "remote HPKE key must be P-384");
    Ok(EccPublicKey::from_coordinates(
        EccCurve::P384,
        public.x,
        public.y,
    )?)
}

fn reseal(
    original: &[u8],
    sa_private: &EccPrivateKey,
    sa_public: &EccPublicKey,
    receiver: &EccPublicKey,
    header: &[u8],
) -> Result<Vec<u8>> {
    validate_sd_envelope(original)?;
    let enc =
        EccPublicKey::from_coordinates(EccCurve::P384, &original[162..210], &original[210..258])?;
    let suite = HpkeSuite::DHKemP384Sha384AesGcm256;
    let open = HpkeOpenConfig::base(
        suite,
        sa_private,
        sa_public,
        &original[..SD_HEADER_LEN],
        &original[..SD_HEADER_LEN],
    );
    let mut plaintext = Zeroizing::new([0u8; 64]);
    let length = hpke::open(&open, &enc, &original[258..], Some(&mut plaintext[..]))?;
    anyhow::ensure!(length == 48, "remote backup did not contain a 48-byte BKS3");
    let seal = HpkeSealConfig::base(suite, receiver, header, header);
    let sealed = hpke::seal_vec(&seal, &plaintext[..length])?;
    let (x, y) = sealed.enc.coord_vec()?;
    Ok([header, &[4], &x, &y, &sealed.ct].concat())
}

pub fn validate(remote: &RemoteRecovery, policy: &PartPolicy) -> Result<()> {
    remote.validate()?;
    let envelope = aead_envelope::inspect(&remote.masked_receiver_key)
        .context("decode remote receiver envelope")?;
    anyhow::ensure!(
        envelope.aad.len() == 192 && envelope.payload.len() == 48,
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
        let recipient = public_key(
            remote
                .receiver_cert_chain
                .last()
                .context("missing receiver certificate")?,
        )?;
        verify_sd_transfer_report(
            &remote.backup.evidence.report,
            &remote.sender_pid_pub_key[1..],
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
            pid.as_slice() == &remote.sender_pid_pub_key[1..],
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
