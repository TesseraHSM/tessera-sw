// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition policy ([`PartPolicy`]) schema and strict CBOR decoder.
//!
//! The policy is a deterministic CBOR map with unsigned-integer keys
//! (see `docs/tbor-ddi/part_policy.md`).  Its exact bytes are hashed into
//! the partition's attested state, so [`PartPolicy::decode`] accepts only
//! the single canonical encoding of each policy (RFC 8949 §4.2.1 core
//! deterministic encoding) and rejects everything else.
//!
//! The decoder is split into three layers so the schema stays in one
//! place:
//!
//! * [`CborReader`] reads CBOR item heads and enforces shortest-form,
//!   definite-length encoding.
//! * [`FIELDS`] is the schema table: one row per map key with its
//!   expected type, size bounds and presence.  Adding a field means
//!   adding a row (and a [`PartPolicy`] member).
//! * [`PartPolicy::decode`] walks the map against the table, then
//!   assembles the typed view and checks cross-field rules.
//!
//! The policy carries no public keys: each trust anchor is identified by
//! its public-key thumbprint, `SHA-384(DER(SubjectPublicKeyInfo))` of the
//! canonical P-384 key (see [`POLICY_THUMBPRINT_LEN`]).

use bitfield_struct::bitfield;

/// Maximum encoded size of a [`PartPolicy`] (bytes).
pub const PART_POLICY_MAX_LEN: usize = 384;

/// Length of a public-key thumbprint (SHA-384 of the canonical
/// SubjectPublicKeyInfo DER).
pub const POLICY_THUMBPRINT_LEN: usize = 48;

/// Maximum length of [`PartPolicy::info`] (bytes).
pub const POLICY_INFO_MAX_LEN: usize = 64;

/// Length of [`PolicyBackupPart::id`] (bytes).
pub const POLICY_BACKUP_PART_ID_LEN: usize = 16;

/// The only supported policy format version.
pub const POLICY_VERSION: u8 = 1;

/// A public-key thumbprint (see [`POLICY_THUMBPRINT_LEN`]).
pub type PolicyThumbprint = [u8; POLICY_THUMBPRINT_LEN];

/// CBOR map keys of the policy document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyKey {
    /// `version` (uint).
    Version = 1,
    /// `pota_spki_thumbprint` (bstr 48).
    PotaSpkiThumbprint = 2,
    /// `sata_spki_thumbprint` (bstr 48).
    SataSpkiThumbprint = 3,
    /// `sapota_spki_thumbprint` (bstr 48, optional).
    SapotaSpkiThumbprint = 4,
    /// `backup_part_id` (bstr 16, optional, paired with key 6).
    BackupPartId = 5,
    /// `backup_part_spki_thumbprint` (bstr 48, optional, paired with key 5).
    BackupPartSpkiThumbprint = 6,
    /// `flags` (uint).
    Flags = 7,
    /// `info` (bstr 1..=64, optional).
    Info = 8,
    /// `data_spki_thumbprint` (bstr 48, optional).
    DataSpkiThumbprint = 9,
}

/// Boolean policy flags (CBOR key [`PolicyKey::Flags`]).
///
/// Bits 3..8 are reserved and must be zero ([`PolicyFlags::is_valid`]).
#[bitfield(u8)]
#[derive(PartialEq, Eq)]
pub struct PolicyFlags {
    /// Bit 0: include the First Mutable Composite Device Identity
    /// (CDI-FMC) in key derivations.
    pub include_fmc_cdi: bool,

    /// Bit 1: require the remote sealing key to be anchored in a
    /// trusted (TSRA-based) Sealing Authority key.
    pub require_trusted_sa_key: bool,

    /// Bit 2: allow cloning of the security domain to a peer partition
    /// endorsed by the same POTA.
    pub allow_peer_cloning: bool,

    /// Bits 3..8: reserved, must be zero.
    #[bits(5)]
    __: u8,
}

impl PolicyFlags {
    /// Bit 0: see [`PolicyFlags::include_fmc_cdi`].
    pub const INCLUDE_FMC_CDI: u8 = 1 << 0;

    /// Bit 1: see [`PolicyFlags::require_trusted_sa_key`].
    pub const REQUIRE_TRUSTED_SA_KEY: u8 = 1 << 1;

    /// Bit 2: see [`PolicyFlags::allow_peer_cloning`].
    pub const ALLOW_PEER_CLONING: u8 = 1 << 2;

    /// Mask of all defined flag bits.
    pub const KNOWN_MASK: u8 =
        Self::INCLUDE_FMC_CDI | Self::REQUIRE_TRUSTED_SA_KEY | Self::ALLOW_PEER_CLONING;

    /// `true` iff only known flag bits are set.
    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.into_bits() & !Self::KNOWN_MASK == 0
    }
}

/// Backing-partition identity (CBOR keys 5 and 6, present together).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyBackupPart<'a> {
    /// Partition ID of the backing partition.
    pub id: &'a [u8; POLICY_BACKUP_PART_ID_LEN],

    /// Thumbprint of the backing partition's PID public key.
    pub spki_thumbprint: &'a PolicyThumbprint,
}

/// Decoded partition policy, borrowing the encoded document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartPolicy<'a> {
    /// POTA (Partition Owner Trust Anchor) key thumbprint.
    pub pota_spki_thumbprint: &'a PolicyThumbprint,

    /// SATA (Sealing Authority Trust Anchor) key thumbprint.
    pub sata_spki_thumbprint: &'a PolicyThumbprint,

    /// SAPOTA (Sealing Authority's POTA) key thumbprint, if provisioned.
    pub sapota_spki_thumbprint: Option<&'a PolicyThumbprint>,

    /// Backing partition identity, if provisioned.
    pub backup_part: Option<PolicyBackupPart<'a>>,

    /// Boolean policy flags.
    pub flags: PolicyFlags,

    /// Opaque caller data; empty when absent.
    pub info: &'a [u8],

    /// DATA (DARC Trust Anchor) key thumbprint, if provisioned.  Anchors
    /// the target chain verified by `DarcTmkExport`.
    pub data_spki_thumbprint: Option<&'a PolicyThumbprint>,
}

/// Why a policy document was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// Empty or larger than [`PART_POLICY_MAX_LEN`].
    InvalidSize,
    /// The document ends inside an item.
    Truncated,
    /// Bytes follow the top-level map.
    TrailingBytes,
    /// Not the shortest-form, definite-length encoding.
    NonCanonical,
    /// An item has the wrong CBOR major type.
    UnexpectedType,
    /// Map keys are not strictly ascending (includes duplicates).
    KeyOrder,
    /// A map key is not part of the schema.
    UnknownKey,
    /// A required field is absent.
    MissingField,
    /// A value is outside its schema bounds.
    InvalidValue,
}

/// Result type of the policy decoder.
pub type PolicyResult<T> = Result<T, PolicyError>;

/// CBOR major types used by the policy schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Major {
    Uint = 0,
    Bstr = 2,
    Map = 5,
}

/// Minimal CBOR reader that enforces deterministic encoding.
struct CborReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> PolicyResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(PolicyError::Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(PolicyError::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    /// Read an item head of the `expected` major type and return its
    /// argument.  Rejects non-shortest arguments, indefinite lengths and
    /// reserved additional-info values.
    fn head(&mut self, expected: Major) -> PolicyResult<u64> {
        let initial = self.take(1)?[0];
        if initial >> 5 != expected as u8 {
            return Err(PolicyError::UnexpectedType);
        }
        let (width, min) = match initial & 0x1f {
            ai @ 0..=23 => return Ok(u64::from(ai)),
            24 => (1, 24),
            25 => (2, 1 << 8),
            26 => (4, 1 << 16),
            27 => (8, 1 << 32),
            _ => return Err(PolicyError::NonCanonical),
        };
        let arg = self
            .take(width)?
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        if arg < min {
            return Err(PolicyError::NonCanonical);
        }
        Ok(arg)
    }

    fn bstr(&mut self) -> PolicyResult<&'a [u8]> {
        let len = self.head(Major::Bstr)?;
        let len = usize::try_from(len).map_err(|_| PolicyError::Truncated)?;
        self.take(len)
    }

    fn finish(&self) -> PolicyResult<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(PolicyError::TrailingBytes)
        }
    }
}

/// Expected value type and bounds of one schema field.
#[derive(Clone, Copy)]
enum FieldKind {
    /// Unsigned integer in `min..=max`.
    Uint { min: u64, max: u64 },
    /// Byte string whose length is in `min..=max`.
    Bstr { min: usize, max: usize },
}

impl FieldKind {
    const fn thumbprint() -> Self {
        Self::Bstr {
            min: POLICY_THUMBPRINT_LEN,
            max: POLICY_THUMBPRINT_LEN,
        }
    }
}

/// One row of the policy schema.
struct FieldSpec {
    key: PolicyKey,
    kind: FieldKind,
    required: bool,
}

/// The policy schema, in ascending key order.
const FIELDS: [FieldSpec; 9] = [
    FieldSpec {
        key: PolicyKey::Version,
        kind: FieldKind::Uint {
            min: POLICY_VERSION as u64,
            max: POLICY_VERSION as u64,
        },
        required: true,
    },
    FieldSpec {
        key: PolicyKey::PotaSpkiThumbprint,
        kind: FieldKind::thumbprint(),
        required: true,
    },
    FieldSpec {
        key: PolicyKey::SataSpkiThumbprint,
        kind: FieldKind::thumbprint(),
        required: true,
    },
    FieldSpec {
        key: PolicyKey::SapotaSpkiThumbprint,
        kind: FieldKind::thumbprint(),
        required: false,
    },
    FieldSpec {
        key: PolicyKey::BackupPartId,
        kind: FieldKind::Bstr {
            min: POLICY_BACKUP_PART_ID_LEN,
            max: POLICY_BACKUP_PART_ID_LEN,
        },
        required: false,
    },
    FieldSpec {
        key: PolicyKey::BackupPartSpkiThumbprint,
        kind: FieldKind::thumbprint(),
        required: false,
    },
    FieldSpec {
        key: PolicyKey::Flags,
        kind: FieldKind::Uint {
            min: 0,
            max: PolicyFlags::KNOWN_MASK as u64,
        },
        required: true,
    },
    FieldSpec {
        key: PolicyKey::Info,
        kind: FieldKind::Bstr {
            min: 1,
            max: POLICY_INFO_MAX_LEN,
        },
        required: false,
    },
    FieldSpec {
        key: PolicyKey::DataSpkiThumbprint,
        kind: FieldKind::thumbprint(),
        required: false,
    },
];

/// Index of `key` in [`FIELDS`] (keys are dense, starting at 1).
const fn field_index(key: PolicyKey) -> usize {
    key as usize - 1
}

// Every row's key must match its index so `field_index` is valid.
const _: () = {
    let mut i = 0;
    while i < FIELDS.len() {
        assert!(field_index(FIELDS[i].key) == i);
        i += 1;
    }
};

/// A decoded field value.
#[derive(Clone, Copy)]
enum FieldValue<'a> {
    Uint(u64),
    Bstr(&'a [u8]),
}

impl FieldSpec {
    fn read<'a>(&self, r: &mut CborReader<'a>) -> PolicyResult<FieldValue<'a>> {
        match self.kind {
            FieldKind::Uint { min, max } => {
                let v = r.head(Major::Uint)?;
                if !(min..=max).contains(&v) {
                    return Err(PolicyError::InvalidValue);
                }
                Ok(FieldValue::Uint(v))
            }
            FieldKind::Bstr { min, max } => {
                let v = r.bstr()?;
                if !(min..=max).contains(&v.len()) {
                    return Err(PolicyError::InvalidValue);
                }
                Ok(FieldValue::Bstr(v))
            }
        }
    }
}

/// Field values collected from the map, indexed by [`field_index`].
struct Fields<'a>([Option<FieldValue<'a>>; FIELDS.len()]);

impl<'a> Fields<'a> {
    fn uint(&self, key: PolicyKey) -> Option<u64> {
        match self.0[field_index(key)] {
            Some(FieldValue::Uint(v)) => Some(v),
            _ => None,
        }
    }

    fn bstr(&self, key: PolicyKey) -> Option<&'a [u8]> {
        match self.0[field_index(key)] {
            Some(FieldValue::Bstr(v)) => Some(v),
            _ => None,
        }
    }

    fn array<const N: usize>(&self, key: PolicyKey) -> PolicyResult<Option<&'a [u8; N]>> {
        self.bstr(key)
            .map(|v| v.try_into().map_err(|_| PolicyError::InvalidValue))
            .transpose()
    }

    fn required_array<const N: usize>(&self, key: PolicyKey) -> PolicyResult<&'a [u8; N]> {
        self.array(key)?.ok_or(PolicyError::MissingField)
    }
}

impl<'a> PartPolicy<'a> {
    /// Decode and validate a policy document.
    ///
    /// Accepts only the canonical encoding; see the module docs.
    pub fn decode(bytes: &'a [u8]) -> PolicyResult<Self> {
        if bytes.is_empty() || bytes.len() > PART_POLICY_MAX_LEN {
            return Err(PolicyError::InvalidSize);
        }
        let fields = Self::read_fields(bytes)?;
        Self::assemble(&fields)
    }

    /// Walk the top-level map, checking each entry against [`FIELDS`].
    fn read_fields(bytes: &'a [u8]) -> PolicyResult<Fields<'a>> {
        let mut r = CborReader::new(bytes);
        let mut fields = Fields([None; FIELDS.len()]);
        let entries = r.head(Major::Map)?;
        let mut prev_key = 0;
        for _ in 0..entries {
            let key = r.head(Major::Uint)?;
            if key <= prev_key {
                return Err(PolicyError::KeyOrder);
            }
            prev_key = key;
            let spec = usize::try_from(key)
                .ok()
                .and_then(|k| FIELDS.get(k.wrapping_sub(1)))
                .ok_or(PolicyError::UnknownKey)?;
            fields.0[field_index(spec.key)] = Some(spec.read(&mut r)?);
        }
        r.finish()?;
        if FIELDS
            .iter()
            .any(|spec| spec.required && fields.0[field_index(spec.key)].is_none())
        {
            return Err(PolicyError::MissingField);
        }
        Ok(fields)
    }

    /// Build the typed view and check cross-field rules.
    fn assemble(fields: &Fields<'a>) -> PolicyResult<Self> {
        let backup_id = fields.array(PolicyKey::BackupPartId)?;
        let backup_thumbprint = fields.array(PolicyKey::BackupPartSpkiThumbprint)?;
        let backup_part = match (backup_id, backup_thumbprint) {
            (Some(id), Some(spki_thumbprint)) => Some(PolicyBackupPart {
                id,
                spki_thumbprint,
            }),
            (None, None) => None,
            _ => return Err(PolicyError::MissingField),
        };

        let flags = fields
            .uint(PolicyKey::Flags)
            .and_then(|v| u8::try_from(v).ok())
            .map(PolicyFlags::from_bits)
            .ok_or(PolicyError::MissingField)?;
        if !flags.is_valid() {
            return Err(PolicyError::InvalidValue);
        }

        Ok(Self {
            pota_spki_thumbprint: fields.required_array(PolicyKey::PotaSpkiThumbprint)?,
            sata_spki_thumbprint: fields.required_array(PolicyKey::SataSpkiThumbprint)?,
            sapota_spki_thumbprint: fields.array(PolicyKey::SapotaSpkiThumbprint)?,
            backup_part,
            flags,
            info: fields.bstr(PolicyKey::Info).unwrap_or(&[]),
            data_spki_thumbprint: fields.array(PolicyKey::DataSpkiThumbprint)?,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;

    /// Test-only deterministic encoder for one map entry.
    fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
        let m = major << 5;
        match arg {
            0..=23 => out.push(m | arg as u8),
            24..=0xff => out.extend_from_slice(&[m | 24, arg as u8]),
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend_from_slice(&(arg as u16).to_be_bytes());
            }
            _ => {
                out.push(m | 26);
                out.extend_from_slice(&(arg as u32).to_be_bytes());
            }
        }
    }

    enum V<'a> {
        U(u64),
        B(&'a [u8]),
    }

    fn encode(entries: &[(u64, V<'_>)]) -> Vec<u8> {
        let mut out = Vec::new();
        head(&mut out, 5, entries.len() as u64);
        for (k, v) in entries {
            head(&mut out, 0, *k);
            match v {
                V::U(u) => head(&mut out, 0, *u),
                V::B(b) => {
                    head(&mut out, 2, b.len() as u64);
                    out.extend_from_slice(b);
                }
            }
        }
        out
    }

    const POTA: [u8; 48] = [0x11; 48];
    const SATA: [u8; 48] = [0x22; 48];

    fn minimal() -> Vec<u8> {
        encode(&[
            (1, V::U(1)),
            (2, V::B(&POTA)),
            (3, V::B(&SATA)),
            (7, V::U(0)),
        ])
    }

    fn full() -> Vec<u8> {
        encode(&[
            (1, V::U(1)),
            (2, V::B(&POTA)),
            (3, V::B(&SATA)),
            (4, V::B(&[0x33; 48])),
            (5, V::B(&[0xCD; 16])),
            (6, V::B(&[0x44; 48])),
            (7, V::U(u64::from(PolicyFlags::KNOWN_MASK))),
            (8, V::B(&[0xAB; 64])),
            (9, V::B(&[0x55; 48])),
        ])
    }

    #[test]
    fn decodes_minimal_policy() {
        let bytes = minimal();
        let p = PartPolicy::decode(&bytes).expect("decode");
        assert_eq!(p.pota_spki_thumbprint, &POTA);
        assert_eq!(p.sata_spki_thumbprint, &SATA);
        assert_eq!(p.sapota_spki_thumbprint, None);
        assert_eq!(p.backup_part, None);
        assert_eq!(p.flags, PolicyFlags::new());
        assert!(p.info.is_empty());
        assert_eq!(p.data_spki_thumbprint, None);
    }

    #[test]
    fn decodes_full_policy_within_max_len() {
        let bytes = full();
        assert!(bytes.len() <= PART_POLICY_MAX_LEN);
        let p = PartPolicy::decode(&bytes).expect("decode");
        assert_eq!(p.sapota_spki_thumbprint, Some(&[0x33; 48]));
        let backup = p.backup_part.expect("backup part");
        assert_eq!(backup.id, &[0xCD; 16]);
        assert_eq!(backup.spki_thumbprint, &[0x44; 48]);
        assert!(p.flags.include_fmc_cdi());
        assert!(p.flags.require_trusted_sa_key());
        assert!(p.flags.allow_peer_cloning());
        assert_eq!(p.info, &[0xAB; 64]);
        assert_eq!(p.data_spki_thumbprint, Some(&[0x55; 48]));
    }

    #[test]
    fn rejects_invalid_documents() {
        let with_trailing = {
            let mut b = minimal();
            b.push(0);
            b
        };
        let non_shortest_flags = {
            // flags 0 encoded as 0x18 0x00 instead of 0x00.
            let mut b = minimal();
            let last = b.len() - 1;
            b[last] = 0x18;
            b.push(0x00);
            b
        };
        let indefinite_map = {
            let mut b = minimal();
            b[0] = 0xbf;
            b.push(0xff);
            b
        };
        let cases: [(&str, Vec<u8>, PolicyError); 16] = [
            ("empty", Vec::new(), PolicyError::InvalidSize),
            (
                "oversize",
                std::vec![0; PART_POLICY_MAX_LEN + 1],
                PolicyError::InvalidSize,
            ),
            ("not a map", std::vec![0x80], PolicyError::UnexpectedType),
            (
                "truncated",
                minimal()[..20].to_vec(),
                PolicyError::Truncated,
            ),
            ("trailing bytes", with_trailing, PolicyError::TrailingBytes),
            (
                "non-shortest",
                non_shortest_flags,
                PolicyError::NonCanonical,
            ),
            ("indefinite map", indefinite_map, PolicyError::NonCanonical),
            (
                "unsorted keys",
                encode(&[
                    (2, V::B(&POTA)),
                    (1, V::U(1)),
                    (3, V::B(&SATA)),
                    (7, V::U(0)),
                ]),
                PolicyError::KeyOrder,
            ),
            (
                "duplicate key",
                encode(&[
                    (1, V::U(1)),
                    (2, V::B(&POTA)),
                    (2, V::B(&POTA)),
                    (3, V::B(&SATA)),
                    (7, V::U(0)),
                ]),
                PolicyError::KeyOrder,
            ),
            (
                "unknown key",
                encode(&[
                    (1, V::U(1)),
                    (2, V::B(&POTA)),
                    (3, V::B(&SATA)),
                    (7, V::U(0)),
                    (10, V::U(0)),
                ]),
                PolicyError::UnknownKey,
            ),
            (
                "missing sata",
                encode(&[(1, V::U(1)), (2, V::B(&POTA)), (7, V::U(0))]),
                PolicyError::MissingField,
            ),
            (
                "bad version",
                encode(&[
                    (1, V::U(2)),
                    (2, V::B(&POTA)),
                    (3, V::B(&SATA)),
                    (7, V::U(0)),
                ]),
                PolicyError::InvalidValue,
            ),
            (
                "short thumbprint",
                encode(&[
                    (1, V::U(1)),
                    (2, V::B(&POTA[..47])),
                    (3, V::B(&SATA)),
                    (7, V::U(0)),
                ]),
                PolicyError::InvalidValue,
            ),
            (
                "reserved flag bit",
                encode(&[
                    (1, V::U(1)),
                    (2, V::B(&POTA)),
                    (3, V::B(&SATA)),
                    (7, V::U(1 << 3)),
                ]),
                PolicyError::InvalidValue,
            ),
            (
                "empty info",
                encode(&[
                    (1, V::U(1)),
                    (2, V::B(&POTA)),
                    (3, V::B(&SATA)),
                    (7, V::U(0)),
                    (8, V::B(&[])),
                ]),
                PolicyError::InvalidValue,
            ),
            (
                "backup id without thumbprint",
                encode(&[
                    (1, V::U(1)),
                    (2, V::B(&POTA)),
                    (3, V::B(&SATA)),
                    (5, V::B(&[0; 16])),
                    (7, V::U(0)),
                ]),
                PolicyError::MissingField,
            ),
        ];
        for (name, bytes, want) in cases {
            assert_eq!(PartPolicy::decode(&bytes), Err(want), "{name}");
        }
    }

    #[test]
    fn rejects_wrong_value_type() {
        let bytes = encode(&[
            (1, V::B(&[1])),
            (2, V::B(&POTA)),
            (3, V::B(&SATA)),
            (7, V::U(0)),
        ]);
        assert_eq!(PartPolicy::decode(&bytes), Err(PolicyError::UnexpectedType));
    }
}
