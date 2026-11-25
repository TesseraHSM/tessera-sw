// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Consistency checks for the loopback demo. Emulator manufacturer roots are
//! generated per process: supplied roots are NOT trusted hardware identities.
//! Any local caller can request admission. POTA signs a PTA only after its
//! report signature, policy and CSR binding have been checked.

use anyhow::Context;
use anyhow::Result;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPublicKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_crypto::ImportableKey;
use tsra_sealing_api::spki_thumbprint;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::IdentityEvidence;
use tsra_sealing_api::PartPolicy;
use tsra_sealing_api::Thumbprint;
use tsra_sealing_api::RAW_PUB_LEN;
use tsra_sealing_report::attested_recipient;
use tsra_sealing_report::verify_certificate_chain;
use tsra_sealing_report::verify_key_report_bytes;
use tsra_sealing_report::verify_sd_transfer_report;
use tsra_sealing_report::KeyFlags;
use x509::X509Certificate;
use x509::X509CertificateOp;

pub fn cert_public(cert: &[u8]) -> Result<Vec<u8>> {
    let cert = X509Certificate::from_der(cert)?;
    let key = EccPublicKey::from_bytes(&cert.get_public_key_der()?)?;
    let (x, y) = key.coord_vec()?;
    Ok([x, y].concat())
}

/// Verify the PID-signed report and full policy binding. Returns the PID and
/// attested public key separately so CSR ownership can be checked. The key is
/// raw P-384 `X || Y` or an ML-KEM-1024 / MLKEM1024-P384 public key.
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
    let public = attested_recipient(&report)?;
    let pid = cert_public(leaf)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("PID must be P-384"))?;
    Ok((pid, public))
}

/// Check peer evidence whose partition-owner chain is anchored to the policy
/// POTA thumbprint, matching the firmware peer-clone check.
pub fn verify_peer(evidence: &Evidence, policy: &PartPolicy) -> Result<()> {
    verify_attested_key(evidence, policy, &policy.pota_spki_thumbprint)?;
    let report = verify_key_report_bytes(
        &evidence.report,
        evidence
            .mfgr_cert_chain
            .last()
            .context("missing manufacturer leaf")?,
    )?;
    let flags = KeyFlags::from(report.flags);
    anyhow::ensure!(
        flags.is_generated() && !flags.is_imported() && flags.is_sd_sealing(),
        "recipient must attest an HSM-generated SdSealing key"
    );
    Ok(())
}

/// Authenticate source PID chains separately from the mandatory operation signature.
pub fn verify_transfer_source(
    evidence: &IdentityEvidence,
    policy: &PartPolicy,
    anchor: &Thumbprint,
    envelope: &[u8],
    recipient: Option<&[u8]>,
) -> Result<[u8; RAW_PUB_LEN]> {
    let mut pid = None;
    for (name, chain) in [
        ("manufacturer", &evidence.mfgr_cert_chain),
        ("partition-owner", &evidence.part_owner_cert_chain),
        ("owner", &evidence.owner_cert_chain),
    ] {
        if name == "owner" && chain.is_empty() {
            continue;
        }
        verify_certificate_chain(chain)?;
        let public = cert_public(chain.last().context("missing source PID leaf")?)?;
        if let Some(pid) = &pid {
            anyhow::ensure!(*pid == public, "source chains name different PIDs");
        } else {
            pid = Some(public);
        }
    }
    let pid: [u8; RAW_PUB_LEN] = pid
        .context("missing source PID")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("source PID must be P-384"))?;
    anyhow::ensure!(
        spki_thumbprint(&cert_public(
            evidence
                .part_owner_cert_chain
                .first()
                .context("missing source authority")?
        )?)? == *anchor,
        "source PID not anchored to required authority"
    );
    verify_sd_transfer_report(envelope, &pid, policy.as_bytes(), recipient)?;
    Ok(pid)
}

/// Check required manufacturer/partition-owner and optional device-owner chains,
/// a caller-selected partition-owner anchor (an SPKI key thumbprint),
/// and the report's policy. Return the PID and attested key independently.
pub fn verify_attested_key(
    evidence: &Evidence,
    policy: &PartPolicy,
    part_owner_anchor: &Thumbprint,
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
        spki_thumbprint(&cert_public(root)?)? == *part_owner_anchor,
        "evidence not anchored to the required partition-owner authority"
    );
    Ok((pid, public))
}
