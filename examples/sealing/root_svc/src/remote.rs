// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! External-SA HPKE open/reseal, recovery validation and file encoding.

use anyhow::Context;
use anyhow::Result;
use tsra_api::PartPolicy;
use tsra_crypto as hpke;
use tsra_crypto::aead_envelope;
use tsra_crypto::EccCurve;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EccPublicKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_crypto::HpkeOpenConfig;
use tsra_crypto::HpkeSealConfig;
use tsra_crypto::HpkeSuite;
use tsra_crypto::ImportableKey;
use tsra_sealing_api::mint_sealing_key;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::RemoteBackup;
use tsra_sealing_api::RemoteRecovery;
use tsra_sealing_api::SealingSession;
use tsra_sealing_api::SecurityDomain;
use tsra_sealing_api::SecurityDomainEnv;
use tsra_sealing_api::SecurityDomainStore;
use tsra_sealing_api::RAW_PUB_LEN;
use tsra_sealing_report::parse_ec2_cose_key_bytes;
use tsra_sealing_report::parse_key_report_bytes;
use tsra_sealing_report::verify_certificate_chain;
use tsra_sealing_report::verify_key_report_bytes;
use tsra_sealing_report::Curve;
use x509::X509Certificate;
use x509::X509CertificateOp;
use zerocopy::IntoBytes;
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
    let sender_cert_chain = vec![chain.root_der.clone(), chain.leaf_der.clone()];
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
    validate_evidence(&created.evidence, env.policy(), false)?;
    let sender_public = reported_public_key(&created.evidence.report)?;
    let receiver = mint_sealing_key(&session.session)
        .context("local recovery saved, but HSM remote receiver generation failed")?;
    let mut receiver_evidence = created.evidence.clone();
    receiver_evidence.report = receiver.report.clone();
    validate_evidence(&receiver_evidence, env.policy(), false)?;
    let receiver_public = reported_public_key(&receiver.report)?;
    let (x, y) = receiver_public.coord_vec()?;
    let raw: [u8; RAW_PUB_LEN] = [x, y]
        .concat()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid HSM receiver coordinates"))?;
    let receiver_chain = env.receiver_chain(&raw)?;

    let remote_backup = reseal(
        &created.pok_remote_backup,
        &sa_key,
        &sa_public,
        &sender_public,
        &receiver_public,
    )
    .context("local recovery saved, but external-SA HPKE open/reseal failed")?;
    let state = env
        .store()
        .load_security_domain()?
        .context("saved local SD recovery state is missing after creation")?;
    let remote = RemoteRecovery {
        backup: RemoteBackup {
            pok_remote_backup: remote_backup,
            evidence: created.evidence,
        },
        masked_receiver_key: receiver.masked,
        sd_mk_backup: state.sd_mk_backup,
        sender_cert_chain,
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
    original_sender: &EccPublicKey,
    receiver: &EccPublicKey,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        original.len() == 161 && original[0] == 4,
        "invalid remote HPKE seal"
    );
    let enc = EccPublicKey::from_coordinates(EccCurve::P384, &original[1..49], &original[49..97])?;
    let suite = HpkeSuite::DHKemP384Sha384AesGcm256;
    let open = HpkeOpenConfig::auth(suite, sa_private, sa_public, &[], &[], original_sender);
    let mut plaintext = Zeroizing::new([0u8; 64]);
    let length = hpke::open(&open, &enc, &original[97..], Some(&mut plaintext[..]))?;
    anyhow::ensure!(length == 48, "remote backup did not contain a 48-byte BKS3");
    let seal = HpkeSealConfig::auth(suite, receiver, &[], &[], sa_private);
    let sealed = hpke::seal_vec(&seal, &plaintext[..length])?;
    let (x, y) = sealed.enc.coord_vec()?;
    Ok([vec![4], x, y, sealed.ct].concat())
}

pub fn validate(remote: &RemoteRecovery, policy: &PartPolicy) -> Result<()> {
    remote.validate()?;
    let envelope = aead_envelope::inspect(&remote.masked_receiver_key)
        .context("decode remote receiver envelope")?;
    anyhow::ensure!(
        envelope.aad.len() == 192 && envelope.payload.len() == 48,
        "invalid remote receiver envelope shape"
    );
    let external = !remote.sender_cert_chain.is_empty();
    if external {
        anyhow::ensure!(
            !policy.flags.require_trusted_sa_key(),
            "software SA cannot satisfy trusted-SA attestation"
        );
        validate_hpke_chain(&remote.sender_cert_chain, policy)
            .context("verify external-SA sender HPKE chain")?;
        validate_hpke_chain(&remote.receiver_cert_chain, policy)
            .context("verify HSM receiver HPKE chain")?;
    }
    validate_evidence(&remote.backup.evidence, policy, !external)
}

fn validate_hpke_chain(chain: &[Vec<u8>], policy: &PartPolicy) -> Result<()> {
    verify_certificate_chain(chain)?;
    let mut anchored = false;
    for cert in chain.iter().take(chain.len().saturating_sub(1)) {
        anchored |= public_key(cert)? == policy.sata_pub_key.data;
    }
    anyhow::ensure!(anchored, "HPKE chain is not endorsed by policy SATA");
    let leaf = chain.last().context("HPKE certificate chain is empty")?;
    anyhow::ensure!(
        public_key(leaf)?.len() == RAW_PUB_LEN,
        "HPKE key must be P-384"
    );
    Ok(())
}

fn public_key(certificate: &[u8]) -> Result<Vec<u8>> {
    let certificate = X509Certificate::from_der(certificate)?;
    let key = EccPublicKey::from_bytes(&certificate.get_public_key_der()?)?;
    let (x, y) = key.coord_vec()?;
    Ok([x, y].concat())
}

fn validate_evidence(evidence: &Evidence, policy: &PartPolicy, legacy: bool) -> Result<()> {
    let mut digest = [0u8; 48];
    HashAlgo::sha384().hash(policy.as_bytes(), Some(&mut digest))?;
    for (name, chain) in [
        ("manufacturer", &evidence.mfgr_cert_chain),
        ("owner", &evidence.owner_cert_chain),
        ("partition-owner", &evidence.part_owner_cert_chain),
    ] {
        if name == "owner" && chain.is_empty() {
            continue;
        }
        verify_certificate_chain(chain)
            .with_context(|| format!("verify remote sender {name} chain"))?;
        let leaf = chain.last().context("remote sender chain is empty")?;
        anyhow::ensure!(
            public_key(leaf)? == policy.backup_part_pub_key.data,
            "remote sender {name} leaf does not match the backing partition PID"
        );
        let report = verify_key_report_bytes(&evidence.report, leaf)
            .with_context(|| format!("verify remote sender report against {name} leaf"))?;
        anyhow::ensure!(
            report.policy_hash == Some(digest.as_slice()),
            "remote sender report policy binding mismatch"
        );
        let key = parse_ec2_cose_key_bytes(
            report
                .public_key
                .get(..usize::from(report.public_key_size))
                .context("invalid reported public key size")?,
        )?;
        anyhow::ensure!(key.curve == Curve::P384, "remote sender key must be P-384");
    }
    let chain = &evidence.part_owner_cert_chain;
    let anchor = if legacy {
        &policy.sata_pub_key
    } else {
        &policy.pota_pub_key
    };
    let mut anchored = false;
    for certificate in chain.iter().take(chain.len().saturating_sub(1)) {
        if public_key(certificate)? == anchor.data {
            anchored = true;
        }
    }
    anyhow::ensure!(
        anchored,
        "creation sender partition-owner chain does not match its policy anchor"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use tsra_api::PartPolicyBuilder;
    use tsra_api::PolicyKeyKind;

    use super::*;
    use crate::pki::make_chain;
    use crate::pki::CaKey;

    fn wire_seal(config: &HpkeSealConfig<'_>, plaintext: &[u8]) -> Result<Vec<u8>> {
        let sealed = hpke::seal_vec(config, plaintext)?;
        let (x, y) = sealed.enc.coord_vec()?;
        Ok([vec![4], x, y, sealed.ct].concat())
    }

    fn public(private: &EccPrivateKey) -> Result<EccPublicKey> {
        let (x, y) = private.coord_vec()?;
        Ok(EccPublicKey::from_coordinates(EccCurve::P384, &x, &y)?)
    }

    #[test]
    fn external_hpke_chain_requires_policy_sata_not_just_valid_signatures() -> Result<()> {
        let sata = CaKey::generate();
        let other = CaKey::generate();
        let key = CaKey::generate();
        let policy = PartPolicyBuilder::new()
            .version(1, 0)
            .pota_key(PolicyKeyKind::Ecc384, &other.raw_pub())
            .sata_key(PolicyKeyKind::Ecc384, &sata.raw_pub())
            .require_trusted_sa_key(false)
            .build()?;
        let chain = make_chain(&sata, &key.raw_pub());
        validate_hpke_chain(&[chain.root_der, chain.leaf_der], &policy)?;
        let wrong = make_chain(&other, &key.raw_pub());
        let chain = vec![wrong.root_der, wrong.leaf_der];
        verify_certificate_chain(&chain)?;
        assert!(validate_hpke_chain(&chain, &policy)
            .expect_err("valid signatures do not establish SATA authorization")
            .to_string()
            .contains("not endorsed by policy SATA"));
        assert!(validate_hpke_chain(&[], &policy).is_err());
        Ok(())
    }

    #[test]
    fn external_sa_reseal_changes_authenticated_sender_and_recipient() -> Result<()> {
        let original_sender = EccPrivateKey::from_curve(EccCurve::P384)?;
        let original_public = public(&original_sender)?;
        let sa = EccPrivateKey::from_curve(EccCurve::P384)?;
        let sa_public = public(&sa)?;
        let receiver = EccPrivateKey::from_curve(EccCurve::P384)?;
        let receiver_public = public(&receiver)?;
        let suite = HpkeSuite::DHKemP384Sha384AesGcm256;
        let plaintext = [0x42; 48];
        let original = wire_seal(
            &HpkeSealConfig::auth(suite, &sa_public, &[], &[], &original_sender),
            &plaintext,
        )?;
        let sealed = reseal(
            &original,
            &sa,
            &sa_public,
            &original_public,
            &receiver_public,
        )?;
        assert_eq!(sealed.len(), 161);
        assert_ne!(sealed, original);
        let enc = EccPublicKey::from_coordinates(EccCurve::P384, &sealed[1..49], &sealed[49..97])?;
        let mut output = Zeroizing::new([0u8; 64]);
        let length = hpke::open(
            &HpkeOpenConfig::auth(suite, &receiver, &receiver_public, &[], &[], &sa_public),
            &enc,
            &sealed[97..],
            Some(&mut output[..]),
        )?;
        assert_eq!(&output[..length], plaintext);
        assert!(hpke::open(
            &HpkeOpenConfig::auth(
                suite,
                &receiver,
                &receiver_public,
                &[],
                &[],
                &original_public
            ),
            &enc,
            &sealed[97..],
            Some(&mut output[..]),
        )
        .is_err());
        assert!(reseal(
            &original,
            &sa,
            &sa_public,
            &receiver_public,
            &receiver_public
        )
        .is_err());
        let mut tampered = original;
        *tampered.last_mut().context("HPKE tag")? ^= 1;
        assert!(reseal(
            &tampered,
            &sa,
            &sa_public,
            &original_public,
            &receiver_public
        )
        .is_err());
        assert!(reseal(
            &[0; 160],
            &sa,
            &sa_public,
            &original_public,
            &receiver_public
        )
        .is_err());
        Ok(())
    }
}
