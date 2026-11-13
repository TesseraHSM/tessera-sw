// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition policy document for the sealing examples.
//!
//! The device takes the policy as a deterministically-encoded CBOR map
//! (RFC 8949 §4.2.1): definite length, unsigned keys in strictly ascending
//! order, shortest-form heads, absent optional fields omitted and no trailing
//! bytes. [`PartPolicy`] keeps the exact wire bytes together with their typed
//! fields, so the bytes bound into the device never drift from the fields the
//! application reads back.

use std::ops::Deref;

use anyhow::Context;
use anyhow::Result;
use minicbor::Decoder;
use minicbor::Encoder;
use tsra_api::PolicyFlags;
use tsra_api::PolicyKey;
use tsra_api::PART_POLICY_MAX_LEN;
use tsra_api::POLICY_BACKUP_PART_ID_LEN;
use tsra_api::POLICY_INFO_MAX_LEN;
use tsra_api::POLICY_THUMBPRINT_LEN;
use tsra_api::POLICY_VERSION;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;

use crate::RAW_PUB_LEN;

/// A public-key thumbprint stored in the policy.
pub type Thumbprint = [u8; POLICY_THUMBPRINT_LEN];

/// DER prefix of a P-384 SubjectPublicKeyInfo carrying an uncompressed point;
/// the raw `X ‖ Y` coordinates follow it.
const P384_SPKI_PREFIX: [u8; 24] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
];

/// SHA-384 thumbprint of a raw P-384 `X ‖ Y` public key, taken over its
/// canonical SubjectPublicKeyInfo DER — the form firmware rebuilds from a
/// certificate key before comparing it with a policy thumbprint.
pub fn spki_thumbprint(raw_pub: &[u8]) -> Result<Thumbprint> {
    anyhow::ensure!(
        raw_pub.len() == RAW_PUB_LEN,
        "policy keys must be raw P-384 points"
    );
    let spki = [P384_SPKI_PREFIX.as_slice(), raw_pub].concat();
    let mut out = [0u8; POLICY_THUMBPRINT_LEN];
    HashAlgo::sha384()
        .hash(&spki, Some(&mut out))
        .context("hash SubjectPublicKeyInfo")?;
    Ok(out)
}

/// Typed fields of a partition policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyFields {
    /// Partition-owner trust anchor thumbprint.
    pub pota_spki_thumbprint: Thumbprint,
    /// Sealing-authority trust anchor thumbprint.
    pub sata_spki_thumbprint: Thumbprint,
    /// Optional sealing-authority partition-owner anchor thumbprint.
    pub sapota_spki_thumbprint: Option<Thumbprint>,
    /// Optional backing partition: its ID and identity-key thumbprint.
    pub backup_part: Option<([u8; POLICY_BACKUP_PART_ID_LEN], Thumbprint)>,
    /// Boolean policy flags.
    pub flags: PolicyFlags,
    /// Optional opaque application information (1..=64 bytes).
    pub info: Option<Vec<u8>>,
    /// Optional data-key thumbprint.
    pub data_spki_thumbprint: Option<Thumbprint>,
}

/// A validated policy: deterministic CBOR wire bytes and their typed fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartPolicy {
    fields: PolicyFields,
    bytes: Vec<u8>,
}

impl PartPolicy {
    /// Encode `fields` as a deterministic CBOR policy.
    pub fn new(fields: PolicyFields) -> Result<Self> {
        let bytes = encode(&fields)?;
        Ok(Self { fields, bytes })
    }

    /// Decode `bytes`, rejecting any non-deterministic or invalid document.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let fields = decode(bytes).context("invalid partition policy")?;
        let policy = Self::new(fields)?;
        anyhow::ensure!(
            policy.bytes == bytes,
            "partition policy is not deterministically encoded"
        );
        Ok(policy)
    }

    /// The exact wire bytes handed to the device.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Deref for PartPolicy {
    type Target = PolicyFields;

    fn deref(&self) -> &PolicyFields {
        &self.fields
    }
}

fn encode(fields: &PolicyFields) -> Result<Vec<u8>> {
    let flags = fields.flags.into_bits();
    anyhow::ensure!(
        flags & !PolicyFlags::KNOWN_MASK == 0,
        "policy sets reserved flag bits"
    );
    if let Some(info) = &fields.info {
        anyhow::ensure!(
            (1..=POLICY_INFO_MAX_LEN).contains(&info.len()),
            "policy info must be 1..={POLICY_INFO_MAX_LEN} bytes"
        );
    }
    let entries = 4
        + u64::from(fields.sapota_spki_thumbprint.is_some())
        + 2 * u64::from(fields.backup_part.is_some())
        + u64::from(fields.info.is_some())
        + u64::from(fields.data_spki_thumbprint.is_some());

    let mut enc = Encoder::new(Vec::new());
    enc.map(entries)?
        .u8(PolicyKey::Version as u8)?
        .u8(POLICY_VERSION)?
        .u8(PolicyKey::PotaSpkiThumbprint as u8)?
        .bytes(&fields.pota_spki_thumbprint)?
        .u8(PolicyKey::SataSpkiThumbprint as u8)?
        .bytes(&fields.sata_spki_thumbprint)?;
    if let Some(sapota) = &fields.sapota_spki_thumbprint {
        enc.u8(PolicyKey::SapotaSpkiThumbprint as u8)?
            .bytes(sapota)?;
    }
    if let Some((part_id, thumbprint)) = &fields.backup_part {
        enc.u8(PolicyKey::BackupPartId as u8)?
            .bytes(part_id)?
            .u8(PolicyKey::BackupPartSpkiThumbprint as u8)?
            .bytes(thumbprint)?;
    }
    enc.u8(PolicyKey::Flags as u8)?.u8(flags)?;
    if let Some(info) = &fields.info {
        enc.u8(PolicyKey::Info as u8)?.bytes(info)?;
    }
    if let Some(data) = &fields.data_spki_thumbprint {
        enc.u8(PolicyKey::DataSpkiThumbprint as u8)?.bytes(data)?;
    }
    let bytes = enc.into_writer();
    anyhow::ensure!(
        bytes.len() <= PART_POLICY_MAX_LEN,
        "encoded policy exceeds {PART_POLICY_MAX_LEN} bytes"
    );
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<PolicyFields> {
    anyhow::ensure!(
        (1..=PART_POLICY_MAX_LEN).contains(&bytes.len()),
        "policy must be 1..={PART_POLICY_MAX_LEN} bytes"
    );
    let mut dec = Decoder::new(bytes);
    let entries = dec.map()?.context("policy map must have definite length")?;
    let mut version = None;
    let mut pota = None;
    let mut sata = None;
    let mut sapota = None;
    let mut backup_id = None;
    let mut backup_pub = None;
    let mut flags = None;
    let mut info = None;
    let mut data = None;
    let mut last_key = 0u8;
    for _ in 0..entries {
        let key = dec.u8()?;
        anyhow::ensure!(key > last_key, "policy keys must be strictly ascending");
        last_key = key;
        match key {
            k if k == PolicyKey::Version as u8 => version = Some(dec.u8()?),
            k if k == PolicyKey::PotaSpkiThumbprint as u8 => pota = Some(fixed(&mut dec)?),
            k if k == PolicyKey::SataSpkiThumbprint as u8 => sata = Some(fixed(&mut dec)?),
            k if k == PolicyKey::SapotaSpkiThumbprint as u8 => sapota = Some(fixed(&mut dec)?),
            k if k == PolicyKey::BackupPartId as u8 => backup_id = Some(fixed(&mut dec)?),
            k if k == PolicyKey::BackupPartSpkiThumbprint as u8 => {
                backup_pub = Some(fixed(&mut dec)?)
            }
            k if k == PolicyKey::Flags as u8 => flags = Some(dec.u8()?),
            k if k == PolicyKey::Info as u8 => info = Some(dec.bytes()?.to_vec()),
            k if k == PolicyKey::DataSpkiThumbprint as u8 => data = Some(fixed(&mut dec)?),
            _ => anyhow::bail!("unknown policy key {key}"),
        }
    }
    anyhow::ensure!(dec.position() == bytes.len(), "trailing bytes after policy");
    anyhow::ensure!(
        version == Some(POLICY_VERSION),
        "unsupported policy version"
    );
    let backup_part = match (backup_id, backup_pub) {
        (Some(id), Some(thumbprint)) => Some((id, thumbprint)),
        (None, None) => None,
        _ => anyhow::bail!("policy backup partition ID and thumbprint must be paired"),
    };
    Ok(PolicyFields {
        pota_spki_thumbprint: pota.context("policy has no POTA thumbprint")?,
        sata_spki_thumbprint: sata.context("policy has no SATA thumbprint")?,
        sapota_spki_thumbprint: sapota,
        backup_part,
        flags: PolicyFlags::from_bits(flags.context("policy has no flags")?),
        info,
        data_spki_thumbprint: data,
    })
}

fn fixed<const N: usize>(dec: &mut Decoder<'_>) -> Result<[u8; N]> {
    dec.bytes()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("policy field must be {N} bytes"))
}
