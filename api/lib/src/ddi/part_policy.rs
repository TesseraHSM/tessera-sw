// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fluent builder for the partition policy CBOR document.
//!
//! The partition policy is a deterministically-encoded CBOR map (schema
//! in `docs/tbor-ddi/part_policy.md`) that names its trust anchors by
//! SPKI thumbprint. [`PartPolicyBuilder`] validates typed fields and
//! emits the canonical encoding the firmware accepts. The SDK entry
//! points take the policy as plain bytes, so a policy produced by any
//! other conforming encoder works equally well.
//!
//! Public keys are supplied as a [`PolicyKeyFormat`] plus bytes, so new
//! key algorithms (for example ML-DSA or composite keys) can be added as
//! formats without changing the builder or the document schema.

use tsra_crypto as crypto;
use tsra_ddi_tbor_types::PART_POLICY_MAX_LEN;
use tsra_ddi_tbor_types::POLICY_BACKUP_PART_ID_LEN;
use tsra_ddi_tbor_types::POLICY_INFO_MAX_LEN;
use tsra_ddi_tbor_types::POLICY_VERSION;
use tsra_ddi_tbor_types::PartPolicyFields;
use tsra_ddi_tbor_types::PolicyFlags;
use tsra_ddi_tbor_types::PolicyThumbprint;

use super::*;

/// Length of a raw ECC P-384 public key (`X || Y`).
const ECC_P384_RAW_LEN: usize = 96;

/// DER SubjectPublicKeyInfo prefix of an uncompressed P-384 key
/// (`id-ecPublicKey`, `secp384r1`, BIT STRING, `0x04`), followed by
/// `X || Y`.
const ECC_P384_SPKI_PREFIX: [u8; 24] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
];

/// Encoding of a public key supplied to [`PartPolicyBuilder`] or
/// [`policy_key_thumbprint`].
///
/// Every format resolves to the key's SPKI thumbprint: SHA-384 of its
/// DER SubjectPublicKeyInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyKeyFormat {
    /// A precomputed
    /// [`POLICY_THUMBPRINT_LEN`](tsra_ddi_tbor_types::POLICY_THUMBPRINT_LEN)-byte
    /// SPKI thumbprint.
    Thumbprint,
    /// A DER SubjectPublicKeyInfo of any key algorithm; it is hashed
    /// as given, so it must be the key's DER (canonical) encoding.
    SpkiDer,
    /// A raw uncompressed ECC P-384 public key, `X || Y` (96 bytes).
    EccP384,
}

/// Compute the SPKI thumbprint of `key` given in `format`.
///
/// # Errors
///
/// [`HsmError::InvalidArgument`] if `key` does not have the length or
/// structure `format` requires. Curve membership of an
/// [`EccP384`](PolicyKeyFormat::EccP384) key is not checked.
pub fn policy_key_thumbprint(format: PolicyKeyFormat, key: &[u8]) -> HsmResult<PolicyThumbprint> {
    match format {
        PolicyKeyFormat::Thumbprint => key.try_into().map_err(|_| HsmError::InvalidArgument),
        PolicyKeyFormat::SpkiDer => {
            if !is_der_sequence(key) {
                return Err(HsmError::InvalidArgument);
            }
            sha384(key)
        }
        PolicyKeyFormat::EccP384 => {
            if key.len() != ECC_P384_RAW_LEN {
                return Err(HsmError::InvalidArgument);
            }
            let mut spki = [0u8; ECC_P384_SPKI_PREFIX.len() + ECC_P384_RAW_LEN];
            spki[..ECC_P384_SPKI_PREFIX.len()].copy_from_slice(&ECC_P384_SPKI_PREFIX);
            spki[ECC_P384_SPKI_PREFIX.len()..].copy_from_slice(key);
            sha384(&spki)
        }
    }
}

fn sha384(data: &[u8]) -> HsmResult<PolicyThumbprint> {
    let digest = crypto::Hasher::hash_vec(&mut crypto::HashAlgo::sha384(), data)
        .map_err(|_| HsmError::InternalError)?;
    digest.try_into().map_err(|_| HsmError::InternalError)
}

/// Whether `der` is exactly one DER SEQUENCE with a minimally-encoded
/// definite length of at most 0xFFFF bytes.
fn is_der_sequence(der: &[u8]) -> bool {
    let [0x30, len_byte, rest @ ..] = der else {
        return false;
    };
    let (len, body) = match *len_byte {
        n @ 0..=0x7F => (usize::from(n), rest),
        0x81 => match rest {
            [n @ 0x80..=0xFF, body @ ..] => (usize::from(*n), body),
            _ => return false,
        },
        0x82 => match rest {
            [hi @ 0x01..=0xFF, lo, body @ ..] => {
                (usize::from(u16::from_be_bytes([*hi, *lo])), body)
            }
            _ => return false,
        },
        _ => return false,
    };
    len == body.len()
}

/// Fluent builder for the partition policy CBOR document.
///
/// Create one with [`new`](Self::new), set the required POTA and SATA
/// keys and any optional fields, then call [`build`](Self::build). Setters
/// never fail; the first invalid input is recorded and reported by
/// [`build`](Self::build) as [`HsmError::InvalidArgument`].
#[derive(Debug, Clone, Default)]
pub struct PartPolicyBuilder {
    pota: Option<PolicyThumbprint>,
    sata: Option<PolicyThumbprint>,
    sapota: Option<PolicyThumbprint>,
    backup_part_id: Option<[u8; POLICY_BACKUP_PART_ID_LEN]>,
    backup_part: Option<PolicyThumbprint>,
    data: Option<PolicyThumbprint>,
    info: Option<Vec<u8>>,
    flags: PolicyFlags,
    error: Option<HsmError>,
}

impl PartPolicyBuilder {
    /// Start an empty builder (no keys, no flags, no optional fields).
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&mut self, err: HsmError) {
        self.error.get_or_insert(err);
    }

    fn key(&mut self, format: PolicyKeyFormat, key: &[u8]) -> Option<PolicyThumbprint> {
        policy_key_thumbprint(format, key)
            .map_err(|err| self.record(err))
            .ok()
    }

    /// Set the POTA (Partition Owner Trust Anchor) key. Required.
    pub fn pota_key(mut self, format: PolicyKeyFormat, key: &[u8]) -> Self {
        self.pota = self.key(format, key);
        self
    }

    /// Set the SATA (Sealing Authority Trust Anchor) key. Required.
    pub fn sata_key(mut self, format: PolicyKeyFormat, key: &[u8]) -> Self {
        self.sata = self.key(format, key);
        self
    }

    /// Set the SAPOTA (Sealing Authority's POTA) key.
    pub fn sapota_key(mut self, format: PolicyKeyFormat, key: &[u8]) -> Self {
        self.sapota = self.key(format, key);
        self
    }

    /// Set the backing-partition identifier (exactly
    /// [`POLICY_BACKUP_PART_ID_LEN`] bytes). Must be set together with
    /// [`backup_part_key`](Self::backup_part_key).
    pub fn backup_part_id(mut self, id: &[u8]) -> Self {
        match id.try_into() {
            Ok(id) => self.backup_part_id = Some(id),
            Err(_) => self.record(HsmError::InvalidArgument),
        }
        self
    }

    /// Set the backing partition's PID public key. Must be set together
    /// with [`backup_part_id`](Self::backup_part_id).
    pub fn backup_part_key(mut self, format: PolicyKeyFormat, key: &[u8]) -> Self {
        self.backup_part = self.key(format, key);
        self
    }

    /// Set the DATA (DARC TMK authority) key.
    pub fn data_key(mut self, format: PolicyKeyFormat, key: &[u8]) -> Self {
        self.data = self.key(format, key);
        self
    }

    /// Set the opaque `info` field (at most [`POLICY_INFO_MAX_LEN`]
    /// bytes). An empty slice omits the field.
    pub fn info(mut self, info: &[u8]) -> Self {
        if info.len() > POLICY_INFO_MAX_LEN {
            self.record(HsmError::InvalidArgument);
        } else {
            self.info = (!info.is_empty()).then(|| info.to_vec());
        }
        self
    }

    /// Replace the policy flags wholesale. Reserved bits are rejected by
    /// [`build`](Self::build).
    pub fn flags(mut self, flags: PolicyFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Set the `include_fmc_cdi` flag.
    pub fn include_fmc_cdi(mut self, value: bool) -> Self {
        self.flags.set_include_fmc_cdi(value);
        self
    }

    /// Set the `require_trusted_sa_key` flag.
    pub fn require_trusted_sa_key(mut self, value: bool) -> Self {
        self.flags.set_require_trusted_sa_key(value);
        self
    }

    /// Set the `allow_peer_cloning` flag.
    pub fn allow_peer_cloning(mut self, value: bool) -> Self {
        self.flags.set_allow_peer_cloning(value);
        self
    }

    /// Validate the fields and return the encoded policy document.
    ///
    /// # Errors
    ///
    /// [`HsmError::InvalidArgument`] if a setter received invalid input,
    /// the POTA or SATA key is missing, only one of the backup-partition
    /// ID and key is set, or a reserved flag bit is set.
    pub fn build(&self) -> HsmResult<Vec<u8>> {
        if let Some(err) = self.error {
            return Err(err);
        }
        let (Some(pota), Some(sata)) = (&self.pota, &self.sata) else {
            return Err(HsmError::InvalidArgument);
        };
        let backup_part = match (&self.backup_part_id, &self.backup_part) {
            (Some(id), Some(key)) => Some((id, key)),
            (None, None) => None,
            _ => return Err(HsmError::InvalidArgument),
        };
        let flags = self.flags.into_bits();
        if flags & !PolicyFlags::KNOWN_MASK != 0 {
            return Err(HsmError::InvalidArgument);
        }

        let doc = PartPolicyFields {
            version: POLICY_VERSION.into(),
            pota_spki_thumbprint: pota,
            sata_spki_thumbprint: sata,
            sapota_spki_thumbprint: self.sapota.as_ref(),
            backup_part,
            flags: flags.into(),
            info: self.info.as_deref(),
            data_spki_thumbprint: self.data.as_ref(),
        }
        .encode();
        if doc.len() > PART_POLICY_MAX_LEN {
            return Err(HsmError::InvalidArgument);
        }
        Ok(doc)
    }
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::POLICY_THUMBPRINT_LEN;

    use super::*;

    const T1: [u8; POLICY_THUMBPRINT_LEN] = [0x11; POLICY_THUMBPRINT_LEN];
    const T2: [u8; POLICY_THUMBPRINT_LEN] = [0x22; POLICY_THUMBPRINT_LEN];

    /// P-384 generator point `G` as `X || Y`.
    const P384_G: &str = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
    /// SHA-384 of the DER SPKI of [`P384_G`].
    const P384_G_THUMBPRINT: &str = "9b816e622b2e1a95723958091bfa35d774110a7475ec59c9425e007a8a84e0ebaabef67249e6a0fe621ae4f4d30b0cc8";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn minimal() -> PartPolicyBuilder {
        PartPolicyBuilder::new()
            .pota_key(PolicyKeyFormat::Thumbprint, &T1)
            .sata_key(PolicyKeyFormat::Thumbprint, &T2)
    }

    /// CBOR encoding of a 48-byte bstr filled with `fill`.
    fn bstr48(fill: u8) -> Vec<u8> {
        let mut v = vec![0x58, 0x30];
        v.extend([fill; 48]);
        v
    }

    #[test]
    fn minimal_policy_matches_vector() {
        let mut expected = vec![0xA4, 0x01, 0x01, 0x02];
        expected.extend(bstr48(0x11));
        expected.push(0x03);
        expected.extend(bstr48(0x22));
        expected.extend([0x07, 0x00]);

        assert_eq!(minimal().build().expect("valid"), expected);
    }

    #[test]
    fn full_policy_matches_vector() {
        let policy = minimal()
            .sapota_key(PolicyKeyFormat::Thumbprint, &[0x33; 48])
            .backup_part_id(&[0x44; 16])
            .backup_part_key(PolicyKeyFormat::Thumbprint, &[0x55; 48])
            .data_key(PolicyKeyFormat::Thumbprint, &[0x66; 48])
            .info(&[0x77; 64])
            .include_fmc_cdi(true)
            .require_trusted_sa_key(true)
            .allow_peer_cloning(true)
            .build()
            .expect("valid");

        let mut expected = vec![0xA9, 0x01, 0x01, 0x02];
        expected.extend(bstr48(0x11));
        expected.push(0x03);
        expected.extend(bstr48(0x22));
        expected.push(0x04);
        expected.extend(bstr48(0x33));
        expected.extend([0x05, 0x50]);
        expected.extend([0x44; 16]);
        expected.push(0x06);
        expected.extend(bstr48(0x55));
        expected.extend([0x07, 0x07, 0x08, 0x58, 0x40]);
        expected.extend([0x77; 64]);
        expected.push(0x09);
        expected.extend(bstr48(0x66));

        assert_eq!(policy, expected);
        assert_eq!(policy.len(), 345);
    }

    #[test]
    fn key_formats_resolve_to_the_same_thumbprint() {
        let raw = unhex(P384_G);
        let mut spki = ECC_P384_SPKI_PREFIX.to_vec();
        spki.extend(&raw);
        let expected = unhex(P384_G_THUMBPRINT);

        for (format, key) in [
            (PolicyKeyFormat::EccP384, raw.as_slice()),
            (PolicyKeyFormat::SpkiDer, spki.as_slice()),
            (PolicyKeyFormat::Thumbprint, expected.as_slice()),
        ] {
            assert_eq!(
                policy_key_thumbprint(format, key).expect("valid key"),
                expected.as_slice(),
                "{format:?}"
            );
        }
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let raw = unhex(P384_G);
        let mut spki = ECC_P384_SPKI_PREFIX.to_vec();
        spki.extend(&raw);
        let mut trailing = spki.clone();
        trailing.push(0);
        let mut long_form = vec![0x30, 0x81, 0x76];
        long_form.extend(&spki[2..]);

        let cases: [(PolicyKeyFormat, &[u8]); 8] = [
            (PolicyKeyFormat::Thumbprint, &T1[..47]),
            (PolicyKeyFormat::Thumbprint, &[0; 49]),
            (PolicyKeyFormat::EccP384, &raw[..95]),
            (PolicyKeyFormat::EccP384, &spki),
            (PolicyKeyFormat::SpkiDer, &[]),
            (PolicyKeyFormat::SpkiDer, &raw),
            (PolicyKeyFormat::SpkiDer, &trailing),
            // Non-minimal long-form length.
            (PolicyKeyFormat::SpkiDer, &long_form),
        ];
        for (format, key) in cases {
            assert_eq!(
                policy_key_thumbprint(format, key),
                Err(HsmError::InvalidArgument),
                "{format:?} len {}",
                key.len()
            );
            assert_eq!(
                minimal().pota_key(format, key).build(),
                Err(HsmError::InvalidArgument)
            );
        }
    }

    #[test]
    fn missing_or_unpaired_fields_are_rejected() {
        let only_pota = PartPolicyBuilder::new().pota_key(PolicyKeyFormat::Thumbprint, &T1);
        let only_sata = PartPolicyBuilder::new().sata_key(PolicyKeyFormat::Thumbprint, &T2);
        for builder in [
            PartPolicyBuilder::new(),
            only_pota,
            only_sata,
            minimal().backup_part_id(&[0x44; 16]),
            minimal().backup_part_key(PolicyKeyFormat::Thumbprint, &T1),
        ] {
            assert_eq!(builder.build(), Err(HsmError::InvalidArgument));
        }
    }

    #[test]
    fn field_bounds_are_enforced() {
        for len in [15, 17] {
            assert_eq!(
                minimal()
                    .backup_part_id(&vec![0; len])
                    .backup_part_key(PolicyKeyFormat::Thumbprint, &T1)
                    .build(),
                Err(HsmError::InvalidArgument)
            );
        }
        assert_eq!(
            minimal().info(&[0; POLICY_INFO_MAX_LEN + 1]).build(),
            Err(HsmError::InvalidArgument)
        );
        assert_eq!(
            minimal().info(&[]).build(),
            minimal().build(),
            "empty info omits the field"
        );
        for bits in 0..=u8::MAX {
            let result = minimal().flags(PolicyFlags::from_bits(bits)).build();
            assert_eq!(
                result.is_ok(),
                bits & !PolicyFlags::KNOWN_MASK == 0,
                "{bits:#x}"
            );
        }
    }

    #[test]
    fn first_error_is_sticky() {
        let builder = minimal()
            .pota_key(PolicyKeyFormat::EccP384, &[0; 1])
            .pota_key(PolicyKeyFormat::Thumbprint, &T1);
        assert_eq!(builder.build(), Err(HsmError::InvalidArgument));
    }
}
