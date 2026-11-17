// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side constants for the partition policy document.
//!
//! The policy is a deterministically-encoded CBOR map (see
//! `docs/tbor-ddi/part_policy.md`); the firmware decoder lives in
//! `tsra_fw_ddi_tbor_types::policy`.  The host carries the policy as
//! opaque bytes; this module mirrors the constants, map keys and flag
//! bits of the schema and provides [`PartPolicyFields::encode`], the
//! deterministic encoder shared by the SDK policy builder and the test
//! harness.  Public keys are referenced by [`POLICY_THUMBPRINT_LEN`]-byte
//! SHA-384 thumbprints of their DER SubjectPublicKeyInfo.

use alloc::vec::Vec;
use core::convert::Infallible;

use bitfield_struct::bitfield;
use minicbor::encode;
use minicbor::Encoder;

/// Maximum encoded size of a partition policy (bytes).
pub const PART_POLICY_MAX_LEN: usize = 384;

/// Length of a public-key thumbprint (SHA-384 of the canonical
/// SubjectPublicKeyInfo DER).
pub const POLICY_THUMBPRINT_LEN: usize = 48;

/// Maximum length of the `info` field (bytes).
pub const POLICY_INFO_MAX_LEN: usize = 64;

/// Length of the `backup_part_id` field (bytes).
pub const POLICY_BACKUP_PART_ID_LEN: usize = 16;

/// The only supported policy format version.
pub const POLICY_VERSION: u8 = 1;

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
/// Bits 3..8 are reserved and must be zero.
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
}

/// A public-key thumbprint: SHA-384 of the key's DER SubjectPublicKeyInfo.
pub type PolicyThumbprint = [u8; POLICY_THUMBPRINT_LEN];

/// Field values of a partition policy document, borrowed for encoding.
///
/// [`encode`](Self::encode) performs no schema validation (version,
/// flag bits and `info` length are emitted as given) so tests can produce
/// documents the firmware rejects; SDK callers should use the validating
/// `PartPolicyBuilder` in `tsra_api` instead.
#[derive(Debug, Clone, Copy)]
pub struct PartPolicyFields<'a> {
    /// `version` (key 1).
    pub version: u64,
    /// `pota_spki_thumbprint` (key 2).
    pub pota_spki_thumbprint: &'a PolicyThumbprint,
    /// `sata_spki_thumbprint` (key 3).
    pub sata_spki_thumbprint: &'a PolicyThumbprint,
    /// `sapota_spki_thumbprint` (key 4).
    pub sapota_spki_thumbprint: Option<&'a PolicyThumbprint>,
    /// `backup_part_id` and `backup_part_spki_thumbprint` (keys 5 and 6).
    pub backup_part: Option<(&'a [u8; POLICY_BACKUP_PART_ID_LEN], &'a PolicyThumbprint)>,
    /// `flags` (key 7).
    pub flags: u64,
    /// `info` (key 8).
    pub info: Option<&'a [u8]>,
    /// `data_spki_thumbprint` (key 9).
    pub data_spki_thumbprint: Option<&'a PolicyThumbprint>,
}

impl PartPolicyFields<'_> {
    /// Encode the document deterministically (RFC 8949 section 4.2.1):
    /// a definite-length map with uint keys in ascending order,
    /// shortest-form heads, and absent optional fields omitted.
    pub fn encode(&self) -> Vec<u8> {
        enum Val<'v> {
            Uint(u64),
            Bstr(&'v [u8]),
        }
        let entries = [
            (PolicyKey::Version, Some(Val::Uint(self.version))),
            (
                PolicyKey::PotaSpkiThumbprint,
                Some(Val::Bstr(self.pota_spki_thumbprint)),
            ),
            (
                PolicyKey::SataSpkiThumbprint,
                Some(Val::Bstr(self.sata_spki_thumbprint)),
            ),
            (
                PolicyKey::SapotaSpkiThumbprint,
                self.sapota_spki_thumbprint.map(|t| Val::Bstr(t)),
            ),
            (
                PolicyKey::BackupPartId,
                self.backup_part.map(|(id, _)| Val::Bstr(id)),
            ),
            (
                PolicyKey::BackupPartSpkiThumbprint,
                self.backup_part.map(|(_, t)| Val::Bstr(t)),
            ),
            (PolicyKey::Flags, Some(Val::Uint(self.flags))),
            (PolicyKey::Info, self.info.map(Val::Bstr)),
            (
                PolicyKey::DataSpkiThumbprint,
                self.data_spki_thumbprint.map(|t| Val::Bstr(t)),
            ),
        ];

        let count = entries.iter().filter(|(_, v)| v.is_some()).count();
        let mut enc = Encoder::new(Vec::with_capacity(PART_POLICY_MAX_LEN));
        // minicbor emits shortest-form heads, so this is deterministic.
        // Writing into a `Vec` cannot fail, and primitive encoders never
        // produce custom errors.
        let result: Result<(), encode::Error<Infallible>> = (|| {
            enc.map(count as u64)?;
            for (key, val) in entries {
                let Some(val) = val else { continue };
                enc.u8(key as u8)?;
                match val {
                    Val::Uint(v) => enc.u64(v)?,
                    Val::Bstr(b) => enc.bytes(b)?,
                };
            }
            Ok(())
        })();
        result.expect("encoding into a Vec cannot fail");
        enc.into_writer()
    }
}
