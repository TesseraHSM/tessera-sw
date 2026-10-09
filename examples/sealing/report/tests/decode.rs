// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::Result;
use minicbor::Decoder;
use minicbor::Encoder;
use tsra_sealing_report::parse_ec2_cose_key_bytes;
use tsra_sealing_report::parse_key_report_bytes;
use tsra_sealing_report::Curve;
use tsra_sealing_report::KeyFlags;
use tsra_sealing_report::PUBLIC_KEY_MAX_SIZE;

fn ec2_key(curve: i8, coordinate_size: usize) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(4)?
        .u8(1)?
        .u8(2)?
        .i8(-1)?
        .i8(curve)?
        .i8(-2)?
        .bytes(&vec![0x11; coordinate_size])?
        .i8(-3)?
        .bytes(&vec![0x22; coordinate_size])?;
    Ok(encoder.into_writer())
}

fn payload(version: u16, key_size: u16, policy: Option<&[u8]>) -> Result<Vec<u8>> {
    let key = ec2_key(2, 48)?;
    let mut public_key = [0u8; PUBLIC_KEY_MAX_SIZE];
    public_key[..key.len()].copy_from_slice(&key);
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(if policy.is_some() { 8 } else { 7 })?
        .u8(0)?
        .u16(version)?
        .u8(1)?
        .bytes(&public_key)?
        .u8(2)?
        .u16(key_size)?
        .u8(3)?
        .u32(0x204)?
        .u8(4)?
        .bytes(&[0xa1; 16])?
        .u8(5)?
        .bytes(&[0xb2; 128])?
        .u8(6)?
        .bytes(&[0xc3; 16])?;
    if let Some(hash) = policy {
        encoder.u8(7)?.bytes(hash)?;
    }
    Ok(encoder.into_writer())
}

fn envelope(payload: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    let mut protected = Encoder::new(Vec::new());
    protected
        .map(2)?
        .u8(1)?
        .i8(-35)?
        .u8(3)?
        .str("application/cbor")?;
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .tag(minicbor::data::Tag::Unassigned(18))?
        .array(4)?
        .bytes(&protected.into_writer())?
        .map(0)?
        .bytes(payload)?
        .bytes(signature)?;
    Ok(encoder.into_writer())
}

#[test]
fn decodes_v1_and_v2_without_copying_byte_fields() -> Result<()> {
    let key_size = u16::try_from(ec2_key(2, 48)?.len())?;
    for (version, policy) in [(1, None), (2, Some(&[0xab; 48][..]))] {
        let bytes = envelope(&payload(version, key_size, policy)?, &[0xd4; 96])?;
        let report = parse_key_report_bytes(&bytes)?;
        assert_eq!(report.version, version);
        assert_eq!(report.public_key_size, key_size);
        assert_eq!(report.public_key.len(), PUBLIC_KEY_MAX_SIZE);
        assert_eq!(report.flags, 0x204);
        assert_eq!(report.app_uuid, &[0xa1; 16]);
        assert_eq!(report.report_data, &[0xb2; 128]);
        assert_eq!(report.vm_launch_id, &[0xc3; 16]);
        assert_eq!(report.policy_hash, policy);
        assert_eq!(report.signature, &[0xd4; 96]);
        let base = bytes.as_ptr() as usize;
        let end = base + bytes.len();
        for field in [
            report.public_key,
            report.app_uuid,
            report.report_data,
            report.vm_launch_id,
            report.signature,
        ] {
            let start = field.as_ptr() as usize;
            assert!(start >= base && start + field.len() <= end);
        }
        let flags = KeyFlags::from(report.flags);
        assert!(flags.is_generated());
        assert!(flags.can_derive());
        assert!(!flags.is_imported());
    }
    Ok(())
}

#[test]
fn rejects_every_truncated_report_and_trailing_bytes() -> Result<()> {
    let key_size = u16::try_from(ec2_key(2, 48)?.len())?;
    let mut report = envelope(&payload(2, key_size, Some(&[0xab; 48]))?, &[0; 96])?;
    for length in 0..report.len() {
        assert!(
            parse_key_report_bytes(&report[..length]).is_err(),
            "length {length}"
        );
    }
    report.push(0);
    assert!(parse_key_report_bytes(&report).is_err());
    let mut claims = payload(1, key_size, None)?;
    claims.push(0);
    assert!(parse_key_report_bytes(&envelope(&claims, &[0; 96])?).is_err());
    Ok(())
}

#[test]
fn rejects_duplicate_missing_and_unknown_claims() -> Result<()> {
    let key_size = u16::try_from(ec2_key(2, 48)?.len())?;
    let original = payload(1, key_size, None)?;
    let mut decoder = Decoder::new(&original);
    decoder.map()?;
    let mut last_label = 0;
    for _ in 0..7 {
        last_label = decoder.position();
        decoder.u8()?;
        decoder.skip()?;
    }
    for label in [0, 8] {
        let mut claims = original.clone();
        claims[last_label] = label;
        assert!(parse_key_report_bytes(&envelope(&claims, &[0; 96])?).is_err());
    }
    let mut missing = original[..last_label].to_vec();
    missing[0] = 0xa6;
    assert!(parse_key_report_bytes(&envelope(&missing, &[0; 96])?).is_err());
    Ok(())
}

#[test]
fn rejects_unsupported_versions_and_invalid_lengths() -> Result<()> {
    let key_size = u16::try_from(ec2_key(2, 48)?.len())?;
    for claims in [
        payload(2, key_size, None)?,
        payload(1, key_size, Some(&[0xab; 48]))?,
        payload(3, key_size, Some(&[0xab; 48]))?,
        payload(1, 0, None)?,
        payload(1, 526, None)?,
        payload(2, key_size, Some(&[0xab; 47]))?,
    ] {
        assert!(parse_key_report_bytes(&envelope(&claims, &[0; 96])?).is_err());
    }
    let claims = payload(1, key_size, None)?;
    assert!(parse_key_report_bytes(&envelope(&claims, &[0; 95])?).is_err());
    let mut bytes = envelope(&claims, &[0; 96])?;
    bytes[3] ^= 1;
    assert!(parse_key_report_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn decodes_all_ec2_curves_and_rejects_invalid_coordinates() -> Result<()> {
    for (identifier, curve, size) in [
        (1, Curve::P256, 32),
        (2, Curve::P384, 48),
        (3, Curve::P521, 66),
    ] {
        let bytes = ec2_key(identifier, size)?;
        let key = parse_ec2_cose_key_bytes(&bytes)?;
        assert_eq!(key.curve, curve);
        assert_eq!(key.x, vec![0x11; size]);
        assert_eq!(key.y, vec![0x22; size]);
        for length in 0..bytes.len() {
            assert!(parse_ec2_cose_key_bytes(&bytes[..length]).is_err());
        }
        assert!(parse_ec2_cose_key_bytes(&ec2_key(identifier, size - 1)?).is_err());
    }
    assert!(parse_ec2_cose_key_bytes(&ec2_key(4, 48)?).is_err());
    let mut bytes = ec2_key(2, 48)?;
    bytes.push(0);
    assert!(parse_ec2_cose_key_bytes(&bytes).is_err());
    Ok(())
}
