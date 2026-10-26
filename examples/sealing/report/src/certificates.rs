// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate display metadata and chain verification using SDK crypto helpers.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
use anyhow::Result;
use der::asn1::AnyRef;
use der::asn1::BitStringRef;
use der::asn1::GeneralizedTime;
use der::asn1::ObjectIdentifier;
use der::asn1::UintRef;
use der::asn1::UtcTime;
use der::DateTime;
use der::Decode;
use der::Reader;
use der::SliceReader;
use der::Tag;
use der::TagMode;
use der::TagNumber;
use der::Tagged;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use x509::X509Certificate;
use x509::X509CertificateOp;

/// Readable metadata for a certificate in a verified chain.
pub struct CertificateSummary {
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Certificate serial number in hexadecimal.
    pub serial_number: String,
    /// Start of validity, in UTC.
    pub not_before: String,
    /// End of validity, in UTC.
    pub not_after: String,
    /// Public-key algorithm and named curve, when applicable.
    pub public_key: String,
    /// Certificate-signature algorithm.
    pub signature_algorithm: String,
    /// SHA-384 fingerprint of the complete DER certificate.
    pub fingerprint: String,
}

struct ParsedCertificate<'a> {
    summary: CertificateSummary,
    issuer: AnyRef<'a>,
    subject: AnyRef<'a>,
    not_before: DateTime,
    not_after: DateTime,
}

/// Verify a non-empty root-first DER chain and return certificate summaries.
///
/// Checks each adjacent signature, supplied order, validity at the current time, and
/// the certificate path using the repository's cross-platform X.509 verifier.
/// The first certificate is the caller-supplied trust anchor; this does not
/// independently establish its trust, verify its self-signature, or check
/// revocation. This does not verify an accompanying attestation report.
///
/// # Errors
/// Returns an error for malformed, out-of-order, expired, not-yet-valid, or
/// invalid chains. No success summary is returned for a failed verification.
pub fn verify_certificate_chain(chain: &[Vec<u8>]) -> Result<Vec<CertificateSummary>> {
    anyhow::ensure!(!chain.is_empty(), "certificate chain is empty");
    let now = DateTime::from_unix_duration(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("read verification time")?,
    )?;
    let parsed = chain
        .iter()
        .enumerate()
        .map(|(index, der)| {
            parse_certificate(der).with_context(|| format!("parse certificate {}", index + 1))
        })
        .collect::<Result<Vec<_>>>()?;
    let root = parsed.first().context("certificate chain has no root")?;
    anyhow::ensure!(
        root.issuer == root.subject,
        "first certificate is not a self-issued root"
    );
    for (index, certificate) in parsed.iter().enumerate() {
        anyhow::ensure!(
            certificate.not_before <= now && now <= certificate.not_after,
            "certificate {} is expired or not yet valid",
            index + 1,
        );
    }
    for (index, pair) in parsed.windows(2).enumerate() {
        anyhow::ensure!(
            pair[1].issuer == pair[0].subject,
            "certificate {} is not issued by the preceding certificate",
            index + 2,
        );
    }

    let certificates = chain
        .iter()
        .enumerate()
        .map(|(index, der)| {
            X509Certificate::from_der(der)
                .with_context(|| format!("load certificate {}", index + 1))
        })
        .collect::<Result<Vec<_>>>()?;
    for (index, pair) in certificates.windows(2).enumerate() {
        anyhow::ensure!(
            pair[1]
                .verify_signature(&pair[0])
                .with_context(|| format!("verify certificate {} signature", index + 2))?,
            "certificate {} signature does not match the preceding certificate",
            index + 2,
        );
    }
    // Path builders can skip unused issuers, so verify every supplied certificate.
    for (index, certificate) in certificates.iter().enumerate() {
        let issuers = if index == 0 {
            vec![certificate.clone()]
        } else {
            certificates[..index].iter().rev().cloned().collect()
        };
        anyhow::ensure!(
            certificate
                .validate_chain(&issuers)
                .with_context(|| format!("verify certificate {} path", index + 1))?,
            "certificate {} verification failed against its supplied root",
            index + 1,
        );
    }
    Ok(parsed
        .into_iter()
        .map(|certificate| certificate.summary)
        .collect())
}

fn parse_certificate(bytes: &[u8]) -> Result<ParsedCertificate<'_>> {
    let certificate = AnyRef::from_der(bytes)?;
    let (tbs, signature_algorithm, _signature) = certificate.sequence(|reader| {
        Ok((
            reader.decode::<AnyRef<'_>>()?,
            reader.decode::<AnyRef<'_>>()?,
            reader.decode::<BitStringRef<'_>>()?,
        ))
    })?;
    let (serial, tbs_algorithm, issuer, validity, subject, spki) = tbs.sequence(|reader| {
        reader.context_specific::<u8>(TagNumber::N0, TagMode::Explicit)?;
        let fields = (
            reader.decode::<UintRef<'_>>()?,
            reader.decode::<AnyRef<'_>>()?,
            reader.decode::<AnyRef<'_>>()?,
            reader.decode::<AnyRef<'_>>()?,
            reader.decode::<AnyRef<'_>>()?,
            reader.decode::<AnyRef<'_>>()?,
        );
        while !reader.is_finished() {
            reader.decode::<AnyRef<'_>>()?;
        }
        Ok(fields)
    })?;
    anyhow::ensure!(
        tbs_algorithm == signature_algorithm,
        "certificate signature algorithms differ"
    );
    let (not_before, not_after) = validity.sequence(|reader| {
        Ok((
            reader.decode::<AnyRef<'_>>()?,
            reader.decode::<AnyRef<'_>>()?,
        ))
    })?;
    let not_before = certificate_time(not_before)?;
    let not_after = certificate_time(not_after)?;
    let mut digest = [0u8; 48];
    HashAlgo::sha384()
        .hash(bytes, Some(&mut digest))
        .context("hash certificate")?;
    Ok(ParsedCertificate {
        summary: CertificateSummary {
            subject: distinguished_name(subject)?,
            issuer: distinguished_name(issuer)?,
            serial_number: hex::encode(serial.as_bytes()),
            not_before: not_before.to_string(),
            not_after: not_after.to_string(),
            public_key: public_key_description(spki)?,
            signature_algorithm: signature_description(signature_algorithm)?,
            fingerprint: hex::encode(digest),
        },
        issuer,
        subject,
        not_before,
        not_after,
    })
}

fn certificate_time(value: AnyRef<'_>) -> Result<DateTime> {
    match value.tag() {
        Tag::UtcTime => Ok(value.decode_as::<UtcTime>()?.to_date_time()),
        Tag::GeneralizedTime => Ok(value.decode_as::<GeneralizedTime>()?.to_date_time()),
        tag => anyhow::bail!("unsupported certificate time encoding {tag:?}"),
    }
}

fn distinguished_name(name: AnyRef<'_>) -> Result<String> {
    anyhow::ensure!(
        name.tag() == Tag::Sequence,
        "certificate name is not a sequence"
    );
    let mut reader = SliceReader::new(name.value())?;
    let mut attributes = Vec::new();
    while !reader.is_finished() {
        let set = reader.decode::<AnyRef<'_>>()?;
        anyhow::ensure!(set.tag() == Tag::Set, "name attribute is not a set");
        let mut set_reader = SliceReader::new(set.value())?;
        while !set_reader.is_finished() {
            let attribute = set_reader.decode::<AnyRef<'_>>()?;
            let (oid, value) = attribute.sequence(|reader| {
                Ok((
                    reader.decode::<ObjectIdentifier>()?,
                    reader.decode::<AnyRef<'_>>()?,
                ))
            })?;
            let label = match oid.to_string().as_str() {
                "2.5.4.3" => "CN".to_owned(),
                "2.5.4.5" => "serialNumber".to_owned(),
                "2.5.4.6" => "C".to_owned(),
                "2.5.4.7" => "L".to_owned(),
                "2.5.4.8" => "ST".to_owned(),
                "2.5.4.10" => "O".to_owned(),
                "2.5.4.11" => "OU".to_owned(),
                _ => oid.to_string(),
            };
            let text = match value.tag() {
                Tag::Utf8String | Tag::PrintableString | Tag::Ia5String => {
                    std::str::from_utf8(value.value())
                        .context("decode name attribute")?
                        .trim_end()
                        .escape_default()
                        .to_string()
                }
                _ => format!("DER {}", hex::encode(value.value())),
            };
            attributes.push(format!("{label}={text}"));
        }
    }
    Ok(if attributes.is_empty() {
        "(empty name)".to_owned()
    } else {
        attributes.join(", ")
    })
}

fn algorithm_identifier(algorithm: AnyRef<'_>) -> Result<(ObjectIdentifier, Option<AnyRef<'_>>)> {
    Ok(algorithm.sequence(|reader| {
        let oid = reader.decode::<ObjectIdentifier>()?;
        let parameters = if reader.is_finished() {
            None
        } else {
            Some(reader.decode::<AnyRef<'_>>()?)
        };
        Ok((oid, parameters))
    })?)
}

fn public_key_description(spki: AnyRef<'_>) -> Result<String> {
    let algorithm = spki.sequence(|reader| {
        let algorithm = reader.decode::<AnyRef<'_>>()?;
        reader.decode::<BitStringRef<'_>>()?;
        Ok(algorithm)
    })?;
    let (oid, parameters) = algorithm_identifier(algorithm)?;
    match oid.to_string().as_str() {
        "1.2.840.10045.2.1" => {
            let curve = parameters
                .context("EC public key has no named curve")?
                .decode_as::<ObjectIdentifier>()?
                .to_string();
            let name = match curve.as_str() {
                "1.2.840.10045.3.1.7" => "NIST P-256",
                "1.3.132.0.34" => "NIST P-384",
                "1.3.132.0.35" => "NIST P-521",
                _ => curve.as_str(),
            };
            Ok(format!("EC / {name}"))
        }
        "1.2.840.113549.1.1.1" => Ok("RSA".to_owned()),
        _ => Ok(format!("algorithm {oid}")),
    }
}

fn signature_description(algorithm: AnyRef<'_>) -> Result<String> {
    let (oid, _) = algorithm_identifier(algorithm)?;
    Ok(match oid.to_string().as_str() {
        "1.2.840.10045.4.3.2" => "ECDSA / SHA-256".to_owned(),
        "1.2.840.10045.4.3.3" => "ECDSA / SHA-384".to_owned(),
        "1.2.840.10045.4.3.4" => "ECDSA / SHA-512".to_owned(),
        "1.2.840.113549.1.1.11" => "RSA / SHA-256".to_owned(),
        "1.2.840.113549.1.1.12" => "RSA / SHA-384".to_owned(),
        "1.2.840.113549.1.1.13" => "RSA / SHA-512".to_owned(),
        _ => format!("algorithm {oid}"),
    })
}
