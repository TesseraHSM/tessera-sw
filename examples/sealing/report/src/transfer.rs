// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host operation-report verification and explicitly software-authority signing.

use anyhow::Context;
use anyhow::Result;
use minicbor::Decoder;
use minicbor::Encoder;
use tsra_crypto::EccCurve;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EccPublicKey;
use tsra_crypto::EcdsaAlgo;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_crypto::ImportableKey;
use tsra_crypto::Signer;
use tsra_crypto::VerifyOp;

use crate::PROTECTED_HEADER;

pub const SD_HEADER_LEN: usize = 161;
pub const SD_ENVELOPE_LEN: usize = 322;
const PREFIX: &[u8] = b"TSRA-XFER\x01\x02\x00\x11\x00\x02\x00\x02";

pub struct SdTransferReport<'a> {
    pub source_pid_spki_thumbprint: &'a [u8],
    pub recipient_spki_thumbprint: &'a [u8],
    pub envelope_hash: &'a [u8],
    pub policy_hash: &'a [u8],
    payload: &'a [u8],
    signature: &'a [u8],
}

pub fn sha384(bytes: &[u8]) -> Result<[u8; 48]> {
    let mut digest = [0; 48];
    HashAlgo::sha384().hash(bytes, Some(&mut digest))?;
    Ok(digest)
}

pub fn p384_spki_from_raw(raw: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(raw.len() == 96, "signer/recipient must be raw P-384 X||Y");
    Ok(EccPublicKey::from_coordinates(EccCurve::P384, &raw[..48], &raw[48..])?.to_vec()?)
}

pub fn p384_raw_from_spki(spki: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(spki.len() == 120, "expected canonical P-384 DER SPKI");
    let public = EccPublicKey::from_bytes(spki)?;
    anyhow::ensure!(public.curve() == EccCurve::P384, "expected P-384");
    let (x, y) = public.coord_vec()?;
    let raw = [x, y].concat();
    anyhow::ensure!(p384_spki_from_raw(&raw)? == spki, "noncanonical P-384 SPKI");
    Ok(raw)
}

pub fn sd_spki_thumbprint(raw: &[u8]) -> Result<[u8; 48]> {
    sha384(&p384_spki_from_raw(raw)?)
}

pub fn sd_header(signer: &[u8], recipient: &[u8], policy: &[u8]) -> Result<Vec<u8>> {
    Ok([
        PREFIX,
        &sd_spki_thumbprint(signer)?,
        &sd_spki_thumbprint(recipient)?,
        &sha384(policy)?,
    ]
    .concat())
}

pub fn validate_sd_envelope(envelope: &[u8]) -> Result<()> {
    anyhow::ensure!(
        envelope.len() == SD_ENVELOPE_LEN
            && envelope.starts_with(PREFIX)
            && envelope[SD_HEADER_LEN] == 4,
        "invalid P-384 HPKE Base SD envelope (legacy Auth backups are unsupported)"
    );
    EccPublicKey::from_coordinates(EccCurve::P384, &envelope[162..210], &envelope[210..258])?;
    Ok(())
}

pub fn parse_sd_transfer_report(bytes: &[u8]) -> Result<SdTransferReport<'_>> {
    let mut outer = Decoder::new(bytes);
    anyhow::ensure!(
        outer.tag()? == minicbor::data::Tag::Unassigned(18),
        "expected COSE_Sign1"
    );
    anyhow::ensure!(outer.array()? == Some(4), "invalid COSE array");
    anyhow::ensure!(
        outer.bytes()? == PROTECTED_HEADER,
        "unsupported protected header"
    );
    anyhow::ensure!(outer.map()? == Some(0), "unexpected unprotected claims");
    let payload = outer.bytes()?;
    let signature = outer.bytes()?;
    anyhow::ensure!(
        signature.len() == 96 && outer.position() == bytes.len(),
        "invalid COSE signature or trailing data"
    );
    let mut claims = Decoder::new(payload);
    anyhow::ensure!(
        claims.map()? == Some(6),
        "expected SdBackup operation claims"
    );
    let mut seen = 0u16;
    let mut source = None;
    let mut recipient = None;
    let mut envelope_hash = None;
    let mut policy_hash = None;
    for _ in 0..6 {
        let label = claims.u8()?;
        anyhow::ensure!(matches!(label, 0 | 7..=11), "unexpected operation claim");
        anyhow::ensure!(seen & (1 << label) == 0, "duplicate operation claim");
        seen |= 1 << label;
        match label {
            0 => anyhow::ensure!(claims.u16()? == 2, "operation report must be v2"),
            7 => policy_hash = Some(claims.bytes()?),
            8 => anyhow::ensure!(claims.u8()? == 2, "expected SdBackup report"),
            9 => source = Some(claims.bytes()?),
            10 => recipient = Some(claims.bytes()?),
            11 => envelope_hash = Some(claims.bytes()?),
            _ => anyhow::bail!("unexpected operation claim"),
        }
    }
    anyhow::ensure!(
        seen == 0xf81 && claims.position() == payload.len(),
        "missing operation claims or trailing data"
    );
    let report = SdTransferReport {
        source_pid_spki_thumbprint: source.context("missing source ID")?,
        recipient_spki_thumbprint: recipient.context("missing recipient ID")?,
        envelope_hash: envelope_hash.context("missing envelope hash")?,
        policy_hash: policy_hash.context("missing SD policy hash")?,
        payload,
        signature,
    };
    anyhow::ensure!(
        [
            report.source_pid_spki_thumbprint,
            report.recipient_spki_thumbprint,
            report.envelope_hash,
            report.policy_hash
        ]
        .iter()
        .all(|field| field.len() == 48),
        "operation digests must be SHA-384"
    );
    Ok(report)
}

fn signature_input(payload: &[u8]) -> Result<Vec<u8>> {
    let mut input = Encoder::new(Vec::new());
    input
        .array(4)?
        .str("Signature1")?
        .bytes(PROTECTED_HEADER)?
        .bytes(&[])?
        .bytes(payload)?;
    Ok(input.into_writer())
}

pub fn verify_sd_report_signature<'a>(
    bytes: &'a [u8],
    signer: &[u8],
) -> Result<SdTransferReport<'a>> {
    let report = parse_sd_transfer_report(bytes)?;
    anyhow::ensure!(
        report.source_pid_spki_thumbprint == sd_spki_thumbprint(signer)?,
        "operation signer mismatch"
    );
    let key = EccPublicKey::from_coordinates(EccCurve::P384, &signer[..48], &signer[48..])?;
    anyhow::ensure!(
        EcdsaAlgo::new(HashAlgo::sha384()).verify(
            &key,
            &signature_input(report.payload)?,
            report.signature
        )?,
        "invalid operation report signature"
    );
    Ok(report)
}

/// Signature and transfer binding only; this does not authenticate SA identity
/// or assert trusted HSM provenance. Callers authenticate PID chains separately.
pub fn verify_sd_transfer_report<'a>(
    bytes: &'a [u8],
    signer: &[u8],
    envelope: &[u8],
    policy: &[u8],
    recipient: Option<&[u8]>,
) -> Result<SdTransferReport<'a>> {
    validate_sd_envelope(envelope)?;
    let report = verify_sd_report_signature(bytes, signer)?;
    anyhow::ensure!(
        report.source_pid_spki_thumbprint == &envelope[17..65]
            && report.recipient_spki_thumbprint == &envelope[65..113],
        "operation/header key IDs mismatch"
    );
    anyhow::ensure!(
        report.policy_hash == sha384(policy)? && report.policy_hash == &envelope[113..161],
        "transferred SD policy mismatch"
    );
    if let Some(recipient) = recipient {
        anyhow::ensure!(
            report.recipient_spki_thumbprint == sd_spki_thumbprint(recipient)?,
            "operation recipient mismatch"
        );
    }
    anyhow::ensure!(
        report.envelope_hash == sha384(&[b"TSRA-XFER-HASH-v1".as_slice(), envelope].concat())?,
        "operation envelope hash mismatch"
    );
    Ok(report)
}

/// Software authority signature-only report; never supplies hardware identity chains.
pub fn sign_software_sd_transfer(
    key: &EccPrivateKey,
    signer: &[u8],
    recipient: &[u8],
    policy: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>> {
    validate_sd_envelope(envelope)?;
    anyhow::ensure!(
        envelope[..SD_HEADER_LEN] == sd_header(signer, recipient, policy)?,
        "software report header mismatch"
    );
    let mut payload = Encoder::new(Vec::new());
    payload
        .map(6)?
        .u8(0)?
        .u16(2)?
        .u8(7)?
        .bytes(&sha384(policy)?)?
        .u8(8)?
        .u8(2)?
        .u8(9)?
        .bytes(&sd_spki_thumbprint(signer)?)?
        .u8(10)?
        .bytes(&sd_spki_thumbprint(recipient)?)?
        .u8(11)?
        .bytes(&sha384(
            &[b"TSRA-XFER-HASH-v1".as_slice(), envelope].concat(),
        )?)?;
    let payload = payload.into_writer();
    let signature = Signer::sign_vec(
        &mut EcdsaAlgo::new(HashAlgo::sha384()),
        key,
        &signature_input(&payload)?,
    )?;
    let mut report = Encoder::new(Vec::new());
    report
        .tag(minicbor::data::Tag::Unassigned(18))?
        .array(4)?
        .bytes(PROTECTED_HEADER)?
        .map(0)?
        .bytes(&payload)?
        .bytes(&signature)?;
    let report = report.into_writer();
    verify_sd_transfer_report(&report, signer, envelope, policy, Some(recipient))?;
    Ok(report)
}
