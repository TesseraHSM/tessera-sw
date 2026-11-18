// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test-only deterministic CBOR encoder for the partition policy.
//!
//! [`TestPolicy`] mirrors the policy schema (see
//! `docs/tbor-ddi/part_policy.md`) and [`TestPolicy::encode`] emits the
//! canonical encoding the firmware accepts via the shared
//! [`PartPolicyFields::encode`]; unlike the SDK builder it accepts
//! out-of-range values. The low-level [`CborWriter`] lets negative tests
//! hand-craft non-canonical or malformed documents.

use tsra_ddi_tbor_types::PartPolicyFields;
use tsra_ddi_tbor_types::POLICY_BACKUP_PART_ID_LEN;
use tsra_ddi_tbor_types::POLICY_VERSION;

/// A public-key thumbprint (see [`tsra_ddi_tbor_types::POLICY_THUMBPRINT_LEN`]).
pub type Thumbprint = tsra_ddi_tbor_types::PolicyThumbprint;

/// CBOR major type 0: unsigned integer.
pub const MAJOR_UINT: u8 = 0;
/// CBOR major type 2: byte string.
pub const MAJOR_BSTR: u8 = 2;
/// CBOR major type 5: map.
pub const MAJOR_MAP: u8 = 5;

/// Minimal CBOR writer emitting shortest-form heads.
#[derive(Debug, Default, Clone)]
pub struct CborWriter {
    buf: Vec<u8>,
}

impl CborWriter {
    /// Create an empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a shortest-form head for `major` with argument `arg`.
    pub fn head(&mut self, major: u8, arg: u64) -> &mut Self {
        let mt = major << 5;
        match arg {
            0..=23 => self.buf.push(mt | arg as u8),
            24..=0xFF => self.buf.extend_from_slice(&[mt | 24, arg as u8]),
            0x100..=0xFFFF => {
                self.buf.push(mt | 25);
                self.buf.extend_from_slice(&(arg as u16).to_be_bytes());
            }
            0x1_0000..=0xFFFF_FFFF => {
                self.buf.push(mt | 26);
                self.buf.extend_from_slice(&(arg as u32).to_be_bytes());
            }
            _ => {
                self.buf.push(mt | 27);
                self.buf.extend_from_slice(&arg.to_be_bytes());
            }
        }
        self
    }

    /// Append an unsigned integer.
    pub fn uint(&mut self, v: u64) -> &mut Self {
        self.head(MAJOR_UINT, v)
    }

    /// Append a byte string.
    pub fn bstr(&mut self, b: &[u8]) -> &mut Self {
        self.head(MAJOR_BSTR, b.len() as u64);
        self.buf.extend_from_slice(b);
        self
    }

    /// Append a map header for `n` entries.
    pub fn map(&mut self, n: u64) -> &mut Self {
        self.head(MAJOR_MAP, n)
    }

    /// Append raw bytes verbatim.
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Consume the writer, returning the encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Backing-partition identity (policy keys 5 and 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestBackupPart {
    /// Partition ID of the backing partition.
    pub id: [u8; POLICY_BACKUP_PART_ID_LEN],
    /// Thumbprint of the backing partition's PID public key.
    pub spki_thumbprint: Thumbprint,
}

/// Owned partition policy for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestPolicy {
    /// Format version (key 1).
    pub version: u64,
    /// POTA public-key thumbprint (key 2).
    pub pota_spki_thumbprint: Thumbprint,
    /// SATA public-key thumbprint (key 3).
    pub sata_spki_thumbprint: Thumbprint,
    /// Optional SAPOTA public-key thumbprint (key 4).
    pub sapota_spki_thumbprint: Option<Thumbprint>,
    /// Optional backing partition (keys 5 and 6).
    pub backup_part: Option<TestBackupPart>,
    /// Flag bits (key 7); see `PolicyFlags`.
    pub flags: u64,
    /// Optional opaque info (key 8).
    pub info: Option<Vec<u8>>,
    /// Optional DATA public-key thumbprint (key 9).
    pub data_spki_thumbprint: Option<Thumbprint>,
}

impl TestPolicy {
    /// Minimal valid policy: version 1, the given POTA/SATA thumbprints,
    /// no flags and no optional fields.
    pub fn new(pota_spki_thumbprint: Thumbprint, sata_spki_thumbprint: Thumbprint) -> Self {
        Self {
            version: POLICY_VERSION.into(),
            pota_spki_thumbprint,
            sata_spki_thumbprint,
            sapota_spki_thumbprint: None,
            backup_part: None,
            flags: 0,
            info: None,
            data_spki_thumbprint: None,
        }
    }

    /// Set the SAPOTA thumbprint.
    pub fn with_sapota(mut self, t: Thumbprint) -> Self {
        self.sapota_spki_thumbprint = Some(t);
        self
    }

    /// Set the backing partition.
    pub fn with_backup_part(
        mut self,
        id: [u8; POLICY_BACKUP_PART_ID_LEN],
        spki_thumbprint: Thumbprint,
    ) -> Self {
        self.backup_part = Some(TestBackupPart {
            id,
            spki_thumbprint,
        });
        self
    }

    /// Set the flag bits.
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags.into();
        self
    }

    /// Set the info bytes.
    pub fn with_info(mut self, info: &[u8]) -> Self {
        self.info = Some(info.to_vec());
        self
    }

    /// Set the DATA thumbprint.
    pub fn with_data(mut self, t: Thumbprint) -> Self {
        self.data_spki_thumbprint = Some(t);
        self
    }

    /// Deterministic CBOR encoding (via the shared
    /// [`PartPolicyFields::encode`]).
    pub fn encode(&self) -> Vec<u8> {
        PartPolicyFields {
            version: self.version,
            pota_spki_thumbprint: &self.pota_spki_thumbprint,
            sata_spki_thumbprint: &self.sata_spki_thumbprint,
            sapota_spki_thumbprint: self.sapota_spki_thumbprint.as_ref(),
            backup_part: self
                .backup_part
                .as_ref()
                .map(|b| (&b.id, &b.spki_thumbprint)),
            flags: self.flags,
            info: self.info.as_deref(),
            data_spki_thumbprint: self.data_spki_thumbprint.as_ref(),
        }
        .encode()
    }
}
