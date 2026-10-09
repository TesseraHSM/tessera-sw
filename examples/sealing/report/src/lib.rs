// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side decoding and signature verification of sealing key-attestation reports.
//!
//! Supports the version 1 and 2 COSE_Sign1 formats emitted by the SDK.
//! Decoding validates the encoding, not the signature, certificate chains,
//! policy binding, or trustworthiness of the claims. All byte fields borrow
//! the input; no DMA buffers or firmware APIs are required.
//!
//! [`verify_certificate_chain`] checks a root-first chain against its supplied
//! root and returns readable certificate summaries. This does not independently
//! establish trust in that root or check revocation.
//! [`verify_key_report_bytes`] additionally checks the report's ES384 signature
//! against a supplied certificate's public key. Its chain must be verified
//! separately; policy binding and freshness are not checked.

mod certificates;

use anyhow::Context;
use anyhow::Result;
use bitfield_struct::bitfield;
pub use certificates::verify_certificate_chain;
pub use certificates::CertificateSummary;
use minicbor::Decoder;
use minicbor::Encoder;
use tsra_crypto::EccCurve;
use tsra_crypto::EccPublicKey;
use tsra_crypto::EcdsaAlgo;
use tsra_crypto::HashAlgo;
use tsra_crypto::ImportableKey;
use tsra_crypto::VerifyOp;
use x509::X509Certificate;
use x509::X509CertificateOp;

/// Fixed padded COSE public-key field size in an TSRA key report.
pub const PUBLIC_KEY_MAX_SIZE: usize = 525;

const PROTECTED_HEADER: &[u8] = &[
    0xa2, 0x01, 0x38, 0x22, 0x03, 0x70, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x2f, 0x63, 0x62, 0x6f, 0x72,
];

/// Attested key attributes and capabilities, using the TSRA wire bit layout.
#[bitfield(u32)]
pub struct KeyFlags {
    /// Key imported from outside the device.
    pub is_imported: bool,
    /// Key scoped to the current session.
    pub is_session_key: bool,
    /// Key generated on the device.
    pub is_generated: bool,
    /// Encryption capability.
    pub can_encrypt: bool,
    /// Decryption capability.
    pub can_decrypt: bool,
    /// Signing capability.
    pub can_sign: bool,
    /// Signature-verification capability.
    pub can_verify: bool,
    /// Key-wrapping capability.
    pub can_wrap: bool,
    /// Key-unwrapping capability.
    pub can_unwrap: bool,
    /// Key-derivation capability.
    pub can_derive: bool,
    #[bits(22)]
    _reserved: u32,
}

/// Decoded claims and signature from a key-attestation report.
///
/// Parsing alone does not authenticate these claims; use
/// [`verify_key_report_bytes`] to check their signature.
pub struct KeyReport<'a> {
    payload: &'a [u8],
    /// Report version: 1, or 2 when a policy digest is present.
    pub version: u16,
    /// Padded COSE_Key field.
    pub public_key: &'a [u8],
    /// Actual COSE_Key length within the padded field.
    pub public_key_size: u16,
    /// Key attributes and capabilities.
    pub flags: u32,
    /// Owning application's 16-byte identifier.
    pub app_uuid: &'a [u8],
    /// Caller-supplied 128-byte report data.
    pub report_data: &'a [u8],
    /// VM's 16-byte launch identifier.
    pub vm_launch_id: &'a [u8],
    /// Optional SHA-384 partition-policy digest, present in version 2.
    pub policy_hash: Option<&'a [u8]>,
    /// ES384 signature; parsing does not verify it.
    pub signature: &'a [u8],
}

/// Decode an TSRA COSE_Sign1 report without copying its byte fields.
///
/// # Errors
/// Rejects malformed CBOR, unsupported formats, duplicate or missing claims,
/// invalid field lengths, and trailing bytes. Does not verify the signature.
pub fn parse_key_report_bytes(bytes: &[u8]) -> Result<KeyReport<'_>> {
    let mut envelope = Decoder::new(bytes);
    anyhow::ensure!(
        envelope.tag().context("COSE tag")? == minicbor::data::Tag::Unassigned(18),
        "expected a COSE_Sign1 report",
    );
    anyhow::ensure!(
        envelope.array()? == Some(4),
        "COSE_Sign1 must contain four fields"
    );
    anyhow::ensure!(
        envelope.bytes()? == PROTECTED_HEADER,
        "unsupported COSE protected header"
    );
    anyhow::ensure!(
        envelope.map()? == Some(0),
        "expected an empty unprotected header"
    );
    let payload = envelope.bytes().context("COSE payload")?;
    let signature = envelope.bytes().context("COSE signature")?;
    anyhow::ensure!(signature.len() == 96, "ES384 signature must be 96 bytes");
    anyhow::ensure!(
        envelope.position() == bytes.len(),
        "trailing bytes after COSE_Sign1"
    );

    let mut decoder = Decoder::new(payload);
    let entries = decoder
        .map()?
        .context("report must use a definite-length map")?;
    anyhow::ensure!(
        entries == 7 || entries == 8,
        "unsupported report claim count"
    );
    let mut version = None;
    let mut public_key = None;
    let mut public_key_size = None;
    let mut flags = None;
    let mut app_uuid = None;
    let mut report_data = None;
    let mut vm_launch_id = None;
    let mut policy_hash = None;
    let mut seen = 0u8;
    for _ in 0..entries {
        let label = decoder.u8().context("report claim label")?;
        anyhow::ensure!(label <= 7, "unsupported report claim {label}");
        anyhow::ensure!(seen & (1 << label) == 0, "duplicate report claim {label}");
        seen |= 1 << label;
        match label {
            0 => version = Some(decoder.u16()?),
            1 => public_key = Some(decoder.bytes()?),
            2 => public_key_size = Some(decoder.u16()?),
            3 => flags = Some(decoder.u32()?),
            4 => app_uuid = Some(decoder.bytes()?),
            5 => report_data = Some(decoder.bytes()?),
            6 => vm_launch_id = Some(decoder.bytes()?),
            7 => policy_hash = Some(decoder.bytes()?),
            _ => anyhow::bail!("unsupported report claim {label}"),
        }
    }
    anyhow::ensure!(
        decoder.position() == payload.len(),
        "trailing bytes in report payload"
    );
    let report = KeyReport {
        payload,
        version: version.context("missing report version")?,
        public_key: public_key.context("missing public key")?,
        public_key_size: public_key_size.context("missing public-key size")?,
        flags: flags.context("missing key flags")?,
        app_uuid: app_uuid.context("missing application UUID")?,
        report_data: report_data.context("missing report data")?,
        vm_launch_id: vm_launch_id.context("missing VM launch ID")?,
        policy_hash,
        signature,
    };
    let expected_version = if report.policy_hash.is_some() { 2 } else { 1 };
    anyhow::ensure!(
        report.version == expected_version,
        "report version does not match its claims"
    );
    anyhow::ensure!(
        report.public_key.len() == PUBLIC_KEY_MAX_SIZE,
        "invalid padded public-key size"
    );
    anyhow::ensure!(
        report.public_key_size > 0 && usize::from(report.public_key_size) <= PUBLIC_KEY_MAX_SIZE,
        "invalid COSE public-key length",
    );
    anyhow::ensure!(
        report.app_uuid.len() == 16,
        "invalid application UUID length"
    );
    anyhow::ensure!(
        report.vm_launch_id.len() == 16,
        "invalid VM launch ID length"
    );
    anyhow::ensure!(
        report.report_data.len() == 128,
        "invalid report-data length"
    );
    if let Some(hash) = report.policy_hash {
        anyhow::ensure!(hash.len() == 48, "invalid SHA-384 policy-digest length");
    }
    Ok(report)
}

/// Decode a report and verify its ES384 signature against a leaf certificate.
///
/// Uses the certificate's P-384 public key, not the attested key in the report.
/// The COSE Sig_structure covers the original encoded payload and protected
/// header with empty external AAD. Certificate-chain trust and validity must
/// be checked separately with [`verify_certificate_chain`]; this does not
/// validate policy binding or freshness.
///
/// # Errors
/// Rejects malformed reports or certificates, non-P-384 signing keys, and
/// signatures that do not match the report and certificate.
pub fn verify_key_report_bytes<'a>(
    bytes: &'a [u8],
    leaf_certificate: &[u8],
) -> Result<KeyReport<'a>> {
    let report = parse_key_report_bytes(bytes)?;
    let certificate =
        X509Certificate::from_der(leaf_certificate).context("load report signing certificate")?;
    let public_key_der = certificate
        .get_public_key_der()
        .context("extract report signing public key")?;
    let public_key =
        EccPublicKey::from_bytes(&public_key_der).context("import report signing public key")?;
    anyhow::ensure!(
        public_key.curve() == EccCurve::P384,
        "ES384 requires a P-384 signing certificate"
    );
    let mut signature_input = Encoder::new(Vec::new());
    signature_input
        .array(4)?
        .str("Signature1")?
        .bytes(PROTECTED_HEADER)?
        .bytes(&[])?
        .bytes(report.payload)?;
    anyhow::ensure!(
        EcdsaAlgo::new(HashAlgo::sha384())
            .verify(
                &public_key,
                &signature_input.into_writer(),
                report.signature
            )
            .context("verify ES384 report signature")?,
        "report signature does not match the leaf certificate",
    );
    Ok(report)
}

/// Supported elliptic curves in a COSE EC2 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// NIST P-521.
    P521,
}

/// Unverified EC2 public key with borrowed big-endian coordinates.
pub struct Ec2PublicKey<'a> {
    /// NIST curve.
    pub curve: Curve,
    /// Affine X coordinate.
    pub x: &'a [u8],
    /// Affine Y coordinate.
    pub y: &'a [u8],
}

/// Decode the canonical EC2 COSE_Key used by sealing-key reports.
///
/// # Errors
/// Rejects unsupported key types or curves, malformed or duplicate fields,
/// invalid coordinate lengths, and trailing bytes. Does not check that the
/// point lies on the curve.
pub fn parse_ec2_cose_key_bytes(bytes: &[u8]) -> Result<Ec2PublicKey<'_>> {
    let mut decoder = Decoder::new(bytes);
    anyhow::ensure!(
        decoder.map()? == Some(4),
        "EC2 key must contain four fields"
    );
    let mut key_type = None;
    let mut curve = None;
    let mut x = None;
    let mut y = None;
    let mut seen = 0u8;
    for _ in 0..4 {
        let label = decoder.i8()?;
        let bit = match label {
            1 => 1,
            -1 => 2,
            -2 => 4,
            -3 => 8,
            _ => anyhow::bail!("unsupported EC2 key label {label}"),
        };
        anyhow::ensure!(seen & bit == 0, "duplicate EC2 key label {label}");
        seen |= bit;
        match label {
            1 => key_type = Some(decoder.u8()?),
            -1 => curve = Some(decoder.i8()?),
            -2 => x = Some(decoder.bytes()?),
            -3 => y = Some(decoder.bytes()?),
            _ => anyhow::bail!("unsupported EC2 key label {label}"),
        }
    }
    anyhow::ensure!(
        decoder.position() == bytes.len(),
        "trailing bytes after EC2 key"
    );
    anyhow::ensure!(key_type == Some(2), "expected an EC2 public key");
    let (curve, coordinate_size) = match curve.context("missing EC2 curve")? {
        1 => (Curve::P256, 32),
        2 => (Curve::P384, 48),
        3 => (Curve::P521, 66),
        value => anyhow::bail!("unsupported EC2 curve {value}"),
    };
    let x = x.context("missing EC2 X coordinate")?;
    let y = y.context("missing EC2 Y coordinate")?;
    anyhow::ensure!(
        x.len() == coordinate_size && y.len() == coordinate_size,
        "invalid EC2 coordinate lengths",
    );
    Ok(Ec2PublicKey { curve, x, y })
}
