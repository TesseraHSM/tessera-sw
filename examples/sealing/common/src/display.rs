// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Verified, readable certificate and attestation output.
//!
//! Display verification uses supplied roots and checks report signatures;
//! it does not establish policy binding, freshness, or revocation status.

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::RemoteBackup;
use tsra_sealing_api::RemoteRecovery;
use tsra_sealing_report::parse_ec2_cose_key_bytes;
use tsra_sealing_report::parse_key_report_bytes;
use tsra_sealing_report::verify_certificate_chain;
use tsra_sealing_report::verify_key_report_bytes;
use tsra_sealing_report::KeyFlags;

pub fn write_leaf_receiver(
    output: &mut impl Write,
    chain: &[Vec<u8>],
    evidence: &Evidence,
) -> Result<()> {
    writeln!(
        output,
        "\nLeaf creation: root-HSM receiver endorsed by leaf SATA"
    )?;
    writeln!(
        output,
        "  Trusted-SA evidence anchored to root POTA (leaf SAPOTA)."
    )?;
    write_certificate_chain(output, chain, "Root receiver", "leaf SATA/sealing key")?;
    write_evidence(output, evidence, "Root receiver")
}

pub fn write_peer_authorities(output: &mut impl Write, pota: &[u8], sata: &[u8]) -> Result<()> {
    writeln!(
        output,
        "\nPeer cloning: authority certificates received from primary"
    )?;
    writeln!(
        output,
        "  Demo trust: supplied roots, not trusted manufacturer admission."
    )?;
    for (name, certificate) in [("POTA", pota), ("SATA", sata)] {
        write_certificate_chain(output, &[certificate.to_vec()], "Primary", name)?;
    }
    Ok(())
}

pub fn write_peer_enrollment(
    output: &mut impl Write,
    manufacturer: &[Vec<u8>],
    csr: &[u8],
    report: &[u8],
) -> Result<()> {
    writeln!(output, "\nPeer cloning: PTA enrollment request to primary")?;
    writeln!(
        output,
        "  PTA CSR: {} bytes; SHA-384 {}",
        csr.len(),
        fingerprint(csr)?
    )?;
    let evidence = Evidence {
        mfgr_cert_chain: manufacturer.to_vec(),
        owner_cert_chain: Vec::new(),
        part_owner_cert_chain: Vec::new(),
        report: report.to_vec(),
    };
    write_evidence(output, &evidence, "Joining PTA")
}

pub fn write_peer_enrollment_response(
    output: &mut impl Write,
    pta: &[Vec<u8>],
    pid: &[Vec<u8>],
) -> Result<()> {
    writeln!(
        output,
        "\nPeer cloning: issued certificate chains received from primary"
    )?;
    write_certificate_chain(output, pta, "Joining peer", "POTA/PTA")?;
    write_certificate_chain(output, pid, "Joining peer", "SATA/PID")
}

/// The caller validates policy and SATA binding before displaying peer evidence.
pub fn write_peer_evidence(output: &mut impl Write, evidence: &Evidence, role: &str) -> Result<()> {
    writeln!(output, "\nPeer cloning: {role} sealing-key evidence")?;
    write_evidence(output, evidence, role)
}

pub fn write_remote_creation(
    output: &mut impl Write,
    recovery: &RemoteRecovery,
    state_dir: &Path,
) -> Result<()> {
    writeln!(output, "Security domain created.")?;
    writeln!(
        output,
        "  creation receiver:    external software sealing authority"
    )?;
    writeln!(
        output,
        "  restore sender:       external SA, SATA-endorsed HPKE key"
    )?;
    writeln!(
        output,
        "  restore receiver:     HSM local-scoped sealing key"
    )?;
    writeln!(
        output,
        "  remote backup saved:  {}",
        state_dir.join("remote-backup.json").display()
    )?;
    write_backup_summary(output, &recovery.backup, state_dir)?;
    writeln!(
        output,
        "\nOriginal TSRA creation sender evidence (before external-SA reseal):"
    )?;
    write_sender_evidence(output, &recovery.backup.evidence)
        .context("print sender certificate chains and attestation report")?;
    write_remote_parties(output, recovery)
}

pub fn write_temporary_creation(
    output: &mut impl Write,
    backup: &RemoteBackup,
    receiver_pub: &[u8],
    receiver_chain: &[Vec<u8>],
    state_dir: &Path,
) -> Result<()> {
    writeln!(output, "Security domain created.")?;
    writeln!(
        output,
        "  receiver public key:  {}",
        hex::encode(receiver_pub)
    )?;
    write_backup_summary(output, backup, state_dir)?;
    write_sender_evidence(output, &backup.evidence)
        .context("print sender certificate chains and attestation report")?;
    writeln!(output, "\nReceiver attestation omitted: temporary host receiver; trusted-SA evidence is not required by this demo.")?;
    write_certificate_chain(output, receiver_chain, "Receiver", "SATA-authorized HPKE")
}

fn write_backup_summary(
    output: &mut impl Write,
    backup: &RemoteBackup,
    state_dir: &Path,
) -> Result<()> {
    writeln!(
        output,
        "  pok_remote_backup:    {} bytes",
        backup.pok_remote_backup.len()
    )?;
    writeln!(
        output,
        "  sender report:        {} bytes",
        backup.evidence.report.len()
    )?;
    writeln!(output, "  local recovery state: {}", state_dir.display())?;
    Ok(())
}

/// Call only after remote recovery validation, before opening the partition.
pub fn write_validated_remote(output: &mut impl Write, recovery: &RemoteRecovery) -> Result<()> {
    if recovery.sender_cert_chain.is_empty() {
        writeln!(output, "Legacy remote sender evidence verified (required chains, optional device-owner chain, ES384 report and policy binding).")?;
        write_sender_evidence(output, &recovery.backup.evidence)
    } else {
        writeln!(
            output,
            "External-SA sender and HSM receiver HPKE chains verified against policy SATA."
        )?;
        write_remote_parties(output, recovery)
    }
}

fn write_sender_evidence(output: &mut impl Write, evidence: &Evidence) -> Result<()> {
    write_evidence(output, evidence, "Sender")
}

fn write_remote_parties(output: &mut impl Write, remote: &RemoteRecovery) -> Result<()> {
    writeln!(
        output,
        "\nRemote restore parties (saved certificates, not fresh attestation):"
    )?;
    writeln!(output, "  Sender: external software SA; receiver: TSRA")?;
    for (role, chain) in [
        ("Sender", &remote.sender_cert_chain),
        ("Receiver", &remote.receiver_cert_chain),
    ] {
        write_certificate_chain(output, chain, role, "SATA-authorized HPKE")?;
    }
    writeln!(
        output,
        "  SA attestation: omitted; require_trusted_sa_key = false"
    )?;
    Ok(())
}

fn write_evidence(output: &mut impl Write, evidence: &Evidence, role: &str) -> Result<()> {
    let context_role = role.to_ascii_lowercase();
    for (name, chain) in [
        ("manufacturer", &evidence.mfgr_cert_chain),
        ("owner", &evidence.owner_cert_chain),
        ("partition-owner", &evidence.part_owner_cert_chain),
    ] {
        if name == "owner" && chain.is_empty() {
            writeln!(output, "\n{role} device-owner evidence: omitted (optional)")?;
            continue;
        }
        write_certificate_chain(output, chain, role, name)?;
    }
    writeln!(output, "\n{role} attestation report:")?;
    if evidence.report.is_empty() {
        writeln!(output, "  (empty)")?;
    } else {
        write_key_report(output, evidence, &context_role)?;
    }
    Ok(())
}

fn write_certificate_chain(
    output: &mut impl Write,
    chain: &[Vec<u8>],
    role: &str,
    name: &str,
) -> Result<()> {
    writeln!(
        output,
        "\n{role} {name} certificate chain (root-first; {} certificates):",
        chain.len()
    )?;
    if chain.is_empty() {
        writeln!(output, "  (empty)")?;
        writeln!(output, "  Verification: not applicable; chain omitted")?;
        return Ok(());
    }
    let certificates = verify_certificate_chain(chain).with_context(|| {
        format!(
            "verify {} {name} certificate chain",
            role.to_ascii_lowercase()
        )
    })?;
    writeln!(
        output,
        "  Verification: valid path to supplied root; currently within validity dates"
    )?;
    writeln!(
        output,
        "  Trust: supplied root only; root self-signature and revocation not checked"
    )?;
    for (index, cert) in certificates.iter().enumerate() {
        let position = if index == 0 {
            "root"
        } else if index + 1 == certificates.len() {
            "leaf"
        } else {
            "intermediate"
        };
        writeln!(output, "  Certificate {} ({position}):", index + 1)?;
        writeln!(output, "    Subject:     {}", cert.subject)?;
        writeln!(output, "    Issuer:      {}", cert.issuer)?;
        writeln!(output, "    Serial:      {}", cert.serial_number)?;
        writeln!(output, "    Valid from:  {}", cert.not_before)?;
        writeln!(output, "    Valid until: {}", cert.not_after)?;
        writeln!(output, "    Public key:  {}", cert.public_key)?;
        writeln!(output, "    Signature:   {}", cert.signature_algorithm)?;
        writeln!(output, "    Fingerprint: SHA-384 {}", cert.fingerprint)?;
    }
    Ok(())
}

fn write_key_report(output: &mut impl Write, evidence: &Evidence, role: &str) -> Result<()> {
    let report = parse_key_report_bytes(&evidence.report)
        .with_context(|| format!("decode {role} attestation report"))?;
    let mut verified_leaves = Vec::new();
    for (name, chain) in [
        ("manufacturer", &evidence.mfgr_cert_chain),
        ("partition-owner", &evidence.part_owner_cert_chain),
    ] {
        if let Some(leaf) = chain.last() {
            verify_key_report_bytes(&evidence.report, leaf)
                .with_context(|| format!("verify {role} attestation report against {name} leaf"))?;
            verified_leaves.push(name);
        }
    }
    anyhow::ensure!(
        !verified_leaves.is_empty(),
        "{role} attestation report has no manufacturer or partition-owner signing certificate",
    );
    let public_key = report
        .public_key
        .get(..usize::from(report.public_key_size))
        .context("attested public-key length exceeds the report field")?;
    let key = parse_ec2_cose_key_bytes(public_key)
        .with_context(|| format!("decode {role} EC2 public key"))?;
    let flags = KeyFlags::from(report.flags);
    writeln!(output, "  Format:              COSE_Sign1 key attestation")?;
    writeln!(output, "  Version:             {}", report.version)?;
    writeln!(output, "  Public key:          EC2 / {:?}", key.curve)?;
    writeln!(
        output,
        "  Key fingerprint:     SHA-384 {}",
        fingerprint(public_key)?
    )?;
    writeln!(output, "  Generated on device: {}", flags.is_generated())?;
    writeln!(output, "  Imported:            {}", flags.is_imported())?;
    writeln!(output, "  Session-only:        {}", flags.is_session_key())?;
    let capabilities = [
        ("encrypt", flags.can_encrypt()),
        ("decrypt", flags.can_decrypt()),
        ("sign", flags.can_sign()),
        ("verify", flags.can_verify()),
        ("wrap", flags.can_wrap()),
        ("unwrap", flags.can_unwrap()),
        ("derive", flags.can_derive()),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
    .collect::<Vec<_>>();
    writeln!(
        output,
        "  Capabilities:        {}",
        if capabilities.is_empty() {
            "none".to_owned()
        } else {
            capabilities.join(", ")
        },
    )?;
    let unknown_flags = report.flags & !0x3ff;
    if unknown_flags != 0 {
        writeln!(output, "  Unknown flags:       0x{unknown_flags:08x}")?;
    }
    writeln!(
        output,
        "  Application UUID:    {}",
        format_uuid(report.app_uuid)?
    )?;
    writeln!(
        output,
        "  VM launch ID:        {}",
        format_uuid(report.vm_launch_id)?
    )?;
    if report.report_data.iter().all(|&byte| byte == 0) {
        writeln!(
            output,
            "  Report data:         {} bytes (all zero)",
            report.report_data.len()
        )?;
    } else {
        writeln!(
            output,
            "  Report data:         {} bytes; SHA-384 {}",
            report.report_data.len(),
            fingerprint(report.report_data)?,
        )?;
    }
    match report.policy_hash {
        Some(hash) => writeln!(
            output,
            "  Policy digest:       SHA-384 {}",
            hex::encode(hash)
        )?,
        None => writeln!(output, "  Policy digest:       not present (version 1)")?,
    }
    writeln!(
        output,
        "  Signature:           ES384 (ECDSA P-384 / SHA-384), {} bytes",
        report.signature.len()
    )?;
    writeln!(
        output,
        "  Verification:        valid ES384 signature against {} leaf certificate(s)",
        verified_leaves.join(" and "),
    )?;
    Ok(())
}

fn fingerprint(bytes: &[u8]) -> Result<String> {
    let mut digest = [0u8; 48];
    HashAlgo::sha384()
        .hash(bytes, Some(&mut digest))
        .context("compute display fingerprint")?;
    Ok(hex::encode(digest))
}

fn format_uuid(bytes: &[u8]) -> Result<String> {
    anyhow::ensure!(bytes.len() == 16, "attested identifier must be 16 bytes");
    Ok(format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&bytes[..4]),
        hex::encode(&bytes[4..6]),
        hex::encode(&bytes[6..8]),
        hex::encode(&bytes[8..10]),
        hex::encode(&bytes[10..]),
    ))
}

#[cfg(test)]
mod tests {
    use tsra_crypto::EccCurve;
    use tsra_crypto::EccKeyOp;
    use tsra_crypto::EccPrivateKey;
    use tsra_crypto::EcdsaAlgo;
    use tsra_crypto::SignOp;

    use super::*;
    use crate::pki;
    use crate::pki::CaKey;

    #[test]
    fn sender_evidence_output_preserves_certificates_order_and_report() -> Result<()> {
        let signer = EccPrivateKey::from_curve(EccCurve::P384)?;
        let evidence = example_evidence(true, &signer)?;
        let mut output = Vec::new();
        write_sender_evidence(&mut output, &evidence)?;
        let output = String::from_utf8(output)?;
        assert!(
            output.contains("Sender manufacturer certificate chain (root-first; 2 certificates):")
        );
        assert!(output.contains("Sender device-owner evidence: omitted (optional)"));
        assert!(output
            .contains("Sender partition-owner certificate chain (root-first; 2 certificates):"));
        assert!(output.contains("Certificate 1 (root):\n    Subject:     CN=TSRA POTA Root CA"));
        assert!(output.contains("Certificate 2 (leaf):\n    Subject:     CN=TSRA Evidence Leaf"));
        assert_eq!(
            output
                .matches("Verification: valid path to supplied root")
                .count(),
            2
        );
        assert_eq!(output.matches("Public key:  EC / NIST P-384").count(), 4);
        assert!(output.contains("Signature:   ECDSA / SHA-384"));
        assert!(output.contains("Valid from:  2025-01-01T00:00:00Z"));
        assert!(output.contains("Valid until: 2035-01-01T00:00:00Z"));
        assert!(!output.contains("-----BEGIN CERTIFICATE-----"));
        assert!(output.contains("Sender attestation report:\n"));
        assert!(output.contains("Version:             2"));
        assert!(output.contains("Public key:          EC2 / P384"));
        assert!(output.contains("Capabilities:        derive"));
        assert!(output.contains("Application UUID:    a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1"));
        assert!(output.contains("VM launch ID:        c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3"));
        assert!(output.contains("Report data:         128 bytes (all zero)"));
        assert!(output.contains(&format!("Policy digest:       SHA-384 {}", "ab".repeat(48))));
        assert!(output.ends_with(
            "Verification:        valid ES384 signature against manufacturer and partition-owner leaf certificate(s)\n"
        ));
        assert!(!output.contains(&hex::encode(&evidence.report)));
        Ok(())
    }

    #[test]
    fn receiver_evidence_uses_same_verified_readable_output() -> Result<()> {
        let signer = EccPrivateKey::from_curve(EccCurve::P384)?;
        let mut evidence = example_evidence(true, &signer)?;
        let mut sender = Vec::new();
        let mut receiver = Vec::new();
        write_sender_evidence(&mut sender, &evidence)?;
        write_evidence(&mut receiver, &evidence, "Receiver")?;
        assert_eq!(
            String::from_utf8(receiver)?,
            String::from_utf8(sender)?.replace("Sender", "Receiver"),
        );
        *evidence.report.last_mut().context("report signature")? ^= 1;
        let mut output = Vec::new();
        let error = write_evidence(&mut output, &evidence, "Receiver")
            .expect_err("invalid receiver signature must fail");
        assert!(error
            .to_string()
            .contains("verify receiver attestation report against manufacturer leaf"));
        let output = String::from_utf8(output)?;
        assert!(!output.contains("Verification:        valid ES384 signature"));
        assert!(!output.contains("Application UUID:"));
        Ok(())
    }

    #[test]
    fn sender_evidence_output_labels_empty_chains_and_report() -> Result<()> {
        let evidence = Evidence {
            mfgr_cert_chain: Vec::new(),
            owner_cert_chain: Vec::new(),
            part_owner_cert_chain: Vec::new(),
            report: Vec::new(),
        };
        let mut output = Vec::new();
        write_sender_evidence(&mut output, &evidence)?;
        let output = String::from_utf8(output)?;
        assert_eq!(output.matches("(empty)").count(), 3);
        assert!(output.contains("device-owner evidence: omitted (optional)"));
        assert!(!output.contains("Sender owner certificate chain"));
        assert!(!output.contains("-----BEGIN CERTIFICATE-----"));
        assert!(output.ends_with("Sender attestation report:\n  (empty)\n"));
        Ok(())
    }

    #[test]
    fn invalid_report_signatures_never_produce_verified_claims() -> Result<()> {
        for with_policy in [false, true] {
            let signer = EccPrivateKey::from_curve(EccCurve::P384)?;
            let evidence = example_evidence(with_policy, &signer)?;
            let other_signer = EccPrivateKey::from_curve(EccCurve::P384)?;
            let other = example_evidence(with_policy, &other_signer)?;
            let mut signature = evidence.clone();
            *signature.report.last_mut().context("report signature")? ^= 1;
            let mut payload = evidence.clone();
            let offset = payload
                .report
                .windows(16)
                .position(|bytes| bytes == [0xa1; 16])
                .context("report application UUID")?;
            payload.report[offset] ^= 1;
            parse_key_report_bytes(&payload.report)?;
            let mut manufacturer = evidence.clone();
            manufacturer.mfgr_cert_chain = other.mfgr_cert_chain;
            let mut partition_owner = evidence.clone();
            partition_owner.part_owner_cert_chain = other.part_owner_cert_chain;
            for (invalid, name) in [
                (signature, "manufacturer"),
                (payload, "manufacturer"),
                (manufacturer, "manufacturer"),
                (partition_owner, "partition-owner"),
            ] {
                let mut output = Vec::new();
                let error = write_sender_evidence(&mut output, &invalid)
                    .expect_err("invalid report signature must fail");
                assert!(error.to_string().contains(&format!(
                    "verify sender attestation report against {name} leaf"
                )));
                let output = String::from_utf8(output)?;
                assert!(!output.contains("Verification:        valid ES384 signature"));
                assert!(!output.contains("Application UUID:"));
            }
        }
        Ok(())
    }

    #[test]
    fn report_requires_at_least_one_signing_chain() -> Result<()> {
        let signer = EccPrivateKey::from_curve(EccCurve::P384)?;
        let evidence = example_evidence(true, &signer)?;
        for name in ["manufacturer", "partition-owner"] {
            let mut partial = evidence.clone();
            if name == "manufacturer" {
                partial.part_owner_cert_chain.clear();
            } else {
                partial.mfgr_cert_chain.clear();
            }
            let mut output = Vec::new();
            write_sender_evidence(&mut output, &partial)?;
            assert!(String::from_utf8(output)?.contains(&format!(
                "valid ES384 signature against {name} leaf certificate(s)"
            )));
        }
        let mut missing = evidence;
        missing.mfgr_cert_chain.clear();
        missing.part_owner_cert_chain.clear();
        let mut output = Vec::new();
        let error = write_sender_evidence(&mut output, &missing)
            .expect_err("report without a signing certificate must fail");
        assert!(error
            .to_string()
            .contains("no manufacturer or partition-owner signing certificate"));
        assert!(!String::from_utf8(output)?.contains("Verification:        valid"));
        Ok(())
    }

    #[test]
    fn report_verification_covers_original_payload_and_empty_external_aad() -> Result<()> {
        let signer = EccPrivateKey::from_curve(EccCurve::P384)?;
        let evidence = example_evidence(true, &signer)?;
        let leaf = evidence
            .mfgr_cert_chain
            .last()
            .context("manufacturer leaf")?;
        let mut envelope = minicbor::Decoder::new(&evidence.report);
        envelope.tag()?;
        envelope.array()?;
        envelope.bytes()?;
        envelope.map()?;
        let mut payload = envelope.bytes()?.to_vec();
        assert_eq!(&payload[..3], &[0xa8, 0x00, 0x02]);
        // An equivalent, non-minimal integer encoding must be verified as signed.
        payload.splice(2..3, [0x18, 0x02]);
        let signed = signed_report(&payload, &signer, &[])?;
        assert_eq!(verify_key_report_bytes(&signed, leaf)?.version, 2);
        assert!(verify_key_report_bytes(&signed, &[0x30, 0x00]).is_err());
        let with_aad = signed_report(&payload, &signer, b"unexpected external AAD")?;
        assert!(verify_key_report_bytes(&with_aad, leaf).is_err());
        Ok(())
    }

    #[test]
    fn invalid_certificate_chains_are_errors_not_verified_summaries() -> Result<()> {
        assert!(verify_certificate_chain(&[]).is_err());
        let issuer = CaKey::generate();
        let leaf = CaKey::generate();
        let chain = pki::make_chain(&issuer, &leaf.raw_pub());
        let valid = chain
            .certs()
            .iter()
            .map(|cert| cert.cert.to_vec())
            .collect::<Vec<_>>();
        let mut wrong_root = valid.clone();
        wrong_root[0] = CaKey::generate().self_cert();
        let mut tampered = valid.clone();
        *tampered[1].last_mut().context("leaf signature")? ^= 1;
        let mut reversed = valid.clone();
        reversed.reverse();
        let mut unused_issuer = valid.clone();
        unused_issuer.insert(1, CaKey::generate().self_cert());
        for invalid in [
            wrong_root,
            tampered,
            reversed,
            unused_issuer,
            vec![vec![0x30, 0x00]],
        ] {
            let evidence = Evidence {
                mfgr_cert_chain: invalid,
                owner_cert_chain: Vec::new(),
                part_owner_cert_chain: Vec::new(),
                report: Vec::new(),
            };
            let mut output = Vec::new();
            let error = write_sender_evidence(&mut output, &evidence)
                .expect_err("invalid certificate chain must fail");
            assert!(error
                .to_string()
                .contains("verify sender manufacturer certificate chain"));
            assert!(!String::from_utf8(output)?.contains("Verification: valid"));
        }
        Ok(())
    }

    #[test]
    fn expired_certificates_are_rejected_before_display() -> Result<()> {
        let mut certificate = CaKey::generate().self_cert();
        for (original, expired) in [
            (b"20250101000000Z", b"20000101000000Z"),
            (b"20350101000000Z", b"20010101000000Z"),
        ] {
            let offset = certificate
                .windows(original.len())
                .position(|bytes| bytes == original)
                .context("certificate validity timestamp")?;
            certificate[offset..offset + expired.len()].copy_from_slice(expired);
        }
        let error = verify_certificate_chain(&[certificate])
            .err()
            .context("expired certificate must fail")?;
        assert!(error.to_string().contains("expired or not yet valid"));
        Ok(())
    }

    #[test]
    fn sender_evidence_output_propagates_write_errors() {
        struct BrokenWriter;

        impl Write for BrokenWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed output",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let evidence = Evidence {
            mfgr_cert_chain: Vec::new(),
            owner_cert_chain: Vec::new(),
            part_owner_cert_chain: Vec::new(),
            report: Vec::new(),
        };
        let error = write_sender_evidence(&mut BrokenWriter, &evidence)
            .expect_err("output failure must propagate");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .expect("I/O error")
                .kind(),
            std::io::ErrorKind::BrokenPipe,
        );
    }

    fn example_evidence(with_policy: bool, signer: &EccPrivateKey) -> Result<Evidence> {
        let (x, y) = signer.coord_vec()?;
        let mut public_key = [0u8; 96];
        public_key[..48].copy_from_slice(&x);
        public_key[48..].copy_from_slice(&y);
        let chain = |issuer: &CaKey| {
            pki::make_chain(issuer, &public_key)
                .certs()
                .iter()
                .map(|cert| cert.cert.to_vec())
                .collect()
        };
        Ok(Evidence {
            mfgr_cert_chain: chain(&CaKey::generate()),
            owner_cert_chain: Vec::new(),
            part_owner_cert_chain: chain(&CaKey::generate()),
            report: example_report(with_policy, signer)?,
        })
    }

    fn example_report(with_policy: bool, signer: &EccPrivateKey) -> Result<Vec<u8>> {
        use minicbor::Encoder;
        use tsra_sealing_report::PUBLIC_KEY_MAX_SIZE;

        let mut key = Encoder::new(Vec::new());
        key.map(4)?
            .u8(1)?
            .u8(2)?
            .i8(-1)?
            .u8(2)?
            .i8(-2)?
            .bytes(&[0x11; 48])?
            .i8(-3)?
            .bytes(&[0x22; 48])?;
        let key = key.into_writer();
        let mut public_key = [0u8; PUBLIC_KEY_MAX_SIZE];
        public_key[..key.len()].copy_from_slice(&key);
        let mut payload = Encoder::new(Vec::new());
        payload
            .map(if with_policy { 8 } else { 7 })?
            .u8(0)?
            .u16(if with_policy { 2 } else { 1 })?
            .u8(1)?
            .bytes(&public_key)?
            .u8(2)?
            .u16(u16::try_from(key.len())?)?
            .u8(3)?
            .u32(
                KeyFlags::new()
                    .with_is_generated(true)
                    .with_can_derive(true)
                    .into(),
            )?
            .u8(4)?
            .bytes(&[0xa1; 16])?
            .u8(5)?
            .bytes(&[0; 128])?
            .u8(6)?
            .bytes(&[0xc3; 16])?;
        if with_policy {
            payload.u8(7)?.bytes(&[0xab; 48])?;
        }
        signed_report(&payload.into_writer(), signer, &[])
    }

    fn signed_report(
        payload: &[u8],
        signer: &EccPrivateKey,
        external_aad: &[u8],
    ) -> Result<Vec<u8>> {
        use minicbor::Encoder;

        let mut protected = Encoder::new(Vec::new());
        protected
            .map(2)?
            .u8(1)?
            .i8(-35)?
            .u8(3)?
            .str("application/cbor")?;
        let protected = protected.into_writer();
        let mut signature_input = Encoder::new(Vec::new());
        signature_input
            .array(4)?
            .str("Signature1")?
            .bytes(&protected)?
            .bytes(external_aad)?
            .bytes(payload)?;
        let mut signature = [0u8; 96];
        let written = EcdsaAlgo::new(HashAlgo::sha384()).sign(
            signer,
            &signature_input.into_writer(),
            Some(&mut signature),
        )?;
        anyhow::ensure!(written == signature.len(), "fixture signature length");
        let mut envelope = Encoder::new(Vec::new());
        envelope
            .tag(minicbor::data::Tag::Unassigned(18))?
            .array(4)?
            .bytes(&protected)?
            .map(0)?
            .bytes(payload)?
            .bytes(&signature)?;
        Ok(envelope.into_writer())
    }

    #[test]
    fn version_one_report_has_no_policy_digest() -> Result<()> {
        let signer = EccPrivateKey::from_curve(EccCurve::P384)?;
        let evidence = example_evidence(false, &signer)?;
        let mut output = Vec::new();
        write_sender_evidence(&mut output, &evidence)?;
        let output = String::from_utf8(output)?;
        assert!(output.contains("Version:             1"));
        assert!(output.contains("Policy digest:       not present (version 1)"));
        assert!(output.contains("Key fingerprint:     SHA-384 "));
        assert!(output.contains("Verification:        valid ES384 signature"));
        Ok(())
    }

    #[test]
    fn malformed_report_is_an_error_not_a_summary() {
        for report in [Vec::new(), vec![0xd2, 0x84, 0x01, 0xab]] {
            let evidence = Evidence {
                mfgr_cert_chain: Vec::new(),
                owner_cert_chain: Vec::new(),
                part_owner_cert_chain: Vec::new(),
                report,
            };
            let mut output = Vec::new();
            let error =
                write_key_report(&mut output, &evidence, "sender").expect_err("malformed report");
            assert!(error
                .to_string()
                .contains("decode sender attestation report"));
            assert!(output.is_empty());
        }
    }
}
