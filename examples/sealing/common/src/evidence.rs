// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Consistency checks for the loopback demo. Emulator manufacturer roots are
//! generated per process: supplied roots are NOT trusted hardware identities.
//! Any local caller can request admission. SATA endorses a PID only after its
//! report signature, policy and CSR binding have been checked.

use anyhow::Context;
use anyhow::Result;
use tsra_api::PartPolicy;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPublicKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_crypto::ImportableKey;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::RAW_PUB_LEN;
use tsra_sealing_report::parse_ec2_cose_key_bytes;
use tsra_sealing_report::verify_certificate_chain;
use tsra_sealing_report::verify_key_report_bytes;
use tsra_sealing_report::Curve;
use x509::X509Certificate;
use x509::X509CertificateOp;
use zerocopy::IntoBytes;

pub fn cert_public(cert: &[u8]) -> Result<Vec<u8>> {
    let cert = X509Certificate::from_der(cert)?;
    let key = EccPublicKey::from_bytes(&cert.get_public_key_der()?)?;
    let (x, y) = key.coord_vec()?;
    Ok([x, y].concat())
}

/// Verify the PID-signed report and full policy binding. Returns the PID and
/// attested public key separately so CSR ownership can be checked.
pub fn verify_report(
    chain: &[Vec<u8>],
    report: &[u8],
    policy: &PartPolicy,
) -> Result<([u8; RAW_PUB_LEN], Vec<u8>)> {
    verify_certificate_chain(chain)?;
    let leaf = chain.last().context("missing manufacturer leaf")?;
    let report = verify_key_report_bytes(report, leaf)?;
    let mut digest = [0; 48];
    HashAlgo::sha384().hash(policy.as_bytes(), Some(&mut digest))?;
    anyhow::ensure!(
        report.policy_hash == Some(digest.as_slice()),
        "peer policy binding mismatch"
    );
    let public = report
        .public_key
        .get(..usize::from(report.public_key_size))
        .context("invalid attested public key size")?;
    let public = parse_ec2_cose_key_bytes(public)?;
    anyhow::ensure!(public.curve == Curve::P384, "peer key must be P-384");
    let pid = cert_public(leaf)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("PID must be P-384"))?;
    Ok((pid, [public.x, public.y].concat()))
}

pub fn verify_peer(evidence: &Evidence, policy: &PartPolicy) -> Result<()> {
    verify_attested_key(evidence, policy, &policy.sata_pub_key.data)?;
    Ok(())
}

/// Check required manufacturer/partition-owner and optional device-owner chains,
/// a caller-selected partition-owner anchor,
/// and the report's policy. Return the PID and attested key independently.
pub fn verify_attested_key(
    evidence: &Evidence,
    policy: &PartPolicy,
    part_owner_anchor: &[u8],
) -> Result<([u8; RAW_PUB_LEN], Vec<u8>)> {
    let (pid, public) = verify_report(&evidence.mfgr_cert_chain, &evidence.report, policy)?;
    let owner = (!evidence.owner_cert_chain.is_empty()).then_some(&evidence.owner_cert_chain);
    for chain in std::iter::once(&evidence.part_owner_cert_chain).chain(owner) {
        verify_certificate_chain(chain)?;
        let leaf = chain.last().context("missing peer evidence leaf")?;
        anyhow::ensure!(
            cert_public(leaf)? == pid,
            "peer evidence chains name different PIDs"
        );
        verify_key_report_bytes(&evidence.report, leaf)?;
    }
    let root = evidence
        .part_owner_cert_chain
        .first()
        .context("missing partition-owner root")?;
    anyhow::ensure!(
        cert_public(root)? == part_owner_anchor,
        "evidence not anchored to the required partition-owner authority"
    );
    Ok((pid, public))
}
