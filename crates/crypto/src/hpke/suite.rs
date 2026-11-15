// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE ciphersuite definitions and per-suite constants.
//!
//! Eight ciphersuites are exposed via [`HpkeSuite`]:
//!
//! * Three RFC 9180 combinations: DHKEM(P-N) + HKDF + AES-256-GCM.
//! * Three that substitute AES-256-CBC + HMAC for the AEAD step under a
//!   private-use AEAD identifier (`0xFFFF`) with a FIPS-compliant key
//!   sizing scheme. The same private-use ID is used by the firmware
//!   HPKE implementation in `fw/core/crypto/hpke`.
//! * Two post-quantum suites (draft-ietf-hpke-pq) with the one-stage
//!   SHAKE256 KDF (draft-ietf-hpke-hpke §7.2): HPKE-10
//!   (MLKEM1024-P384) and HPKE-13 (ML-KEM-1024). They support the
//!   Base and PSK modes only.
//!
//! # Wire formats (host)
//!
//! DHKEM public keys and the encapsulated key (`enc`) are SEC1
//! uncompressed (`0x04 ‖ x ‖ y`) for RFC 9180 interoperability; private
//! keys are raw big-endian scalars (no PKCS#8 wrapping). ML-KEM keys
//! are the FIPS 203 encapsulation key and the 64-byte `d ‖ z` seed;
//! hybrid keys are `ek_PQ ‖ SEC1(ek_T)` and a 32-byte seed.
//!
//! | KEM                         | `Npk = Nenc` | `Nsk` | `Nsecret` | `Ndh` |
//! |-----------------------------|--------------|-------|-----------|-------|
//! | DHKEM(P-256, HKDF-SHA-256)  | 65           | 32    | 32        | 32    |
//! | DHKEM(P-384, HKDF-SHA-384)  | 97           | 48    | 48        | 48    |
//! | DHKEM(P-521, HKDF-SHA-512)  | 133          | 66    | 64        | 66    |
//! | ML-KEM-1024                 | 1568         | 64    | 32        | —     |
//! | MLKEM1024-P384              | 1665         | 32    | 32        | 48    |
//!
//! `Ndh` is the raw ECDH x-coordinate (RFC 9180 §7.1.1) — note that for
//! P-521 it is 66, not 64.
//!
//! # CBC-HMAC AEAD key layout
//!
//! The CBC variants use the FIPS-compliant key sizing scheme defined
//! by the firmware HPKE crate:
//!
//! ```text
//! key       = MAC_KEY[Nh] ‖ ENC_KEY[32]
//! tag_len   = Nh             (full HMAC output, no truncation)
//! mac_input = aad ‖ iv ‖ ciphertext ‖ I2OSP(aad.len() * 8, 8)
//! ```

use crate::EccCurve;
use crate::HashAlgo;

// =============================================================================
// HpkeSuite enum
// =============================================================================

/// HPKE ciphersuite.
///
/// All suites use AES-256. The CBC variants use AES-256-CBC + HMAC
/// with FIPS-compliant MAC key lengths (= full hash output, per
/// SP 800-107).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum HpkeSuite {
    /// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
    DHKemP256Sha256AesGcm256,

    /// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-CBC-HMAC-SHA256.
    DHKemP256Sha256Aes256Cbc,

    /// DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM.
    DHKemP384Sha384AesGcm256,

    /// DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-CBC-HMAC-SHA384.
    DHKemP384Sha384Aes256Cbc,

    /// DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM.
    DHKemP521Sha512AesGcm256,

    /// DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-CBC-HMAC-SHA512.
    DHKemP521Sha512Aes256Cbc,

    /// HPKE-10: MLKEM1024-P384, SHAKE256, AES-256-GCM.
    ///
    /// The recipient private key is the 32-byte hybrid seed.
    MlKem1024P384Shake256AesGcm256,

    /// HPKE-13: ML-KEM-1024, SHAKE256, AES-256-GCM.
    ///
    /// The recipient private key is the 64-byte `d ‖ z` seed.
    MlKem1024Shake256AesGcm256,
}

// =============================================================================
// Internal KEM / KDF tables
// =============================================================================

/// KEM family selector. The integer value is the index into
/// [`KEM_TABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KemKind {
    DhP256 = 0,
    DhP384 = 1,
    DhP521 = 2,
    MlKem1024 = 3,
    MlKem1024P384 = 4,
}

/// KDF selector. The integer value is the index into [`KDF_TABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KdfKind {
    HkdfSha256 = 0,
    HkdfSha384 = 1,
    HkdfSha512 = 2,
    Shake256 = 3,
}

#[derive(Clone, Copy)]
struct KemEntry {
    kem_id: u16,
    /// DHKEM curve, or the hybrid's traditional curve.
    curve: Option<EccCurve>,
    npk: usize,
    nsk: usize,
    nsecret: usize,
    ndh: usize,
    auth: bool,
}

const KEM_TABLE: [KemEntry; 5] = [
    KemEntry {
        kem_id: 0x0010,
        curve: Some(EccCurve::P256),
        npk: 65,
        nsk: 32,
        nsecret: 32,
        ndh: 32,
        auth: true,
    },
    KemEntry {
        kem_id: 0x0011,
        curve: Some(EccCurve::P384),
        npk: 97,
        nsk: 48,
        nsecret: 48,
        ndh: 48,
        auth: true,
    },
    KemEntry {
        kem_id: 0x0012,
        curve: Some(EccCurve::P521),
        npk: 133,
        nsk: 66,
        nsecret: 64,
        ndh: 66,
        auth: true,
    },
    KemEntry {
        kem_id: 0x0042,
        curve: None,
        npk: 1568,
        nsk: 64,
        nsecret: 32,
        ndh: 0,
        auth: false,
    },
    KemEntry {
        kem_id: 0x0051,
        curve: Some(EccCurve::P384),
        npk: 1568 + 97,
        nsk: 32,
        nsecret: 32,
        ndh: 48,
        auth: false,
    },
];

#[derive(Clone, Copy)]
struct KdfEntry {
    kdf_id: u16,
    nh: usize,
}

const KDF_TABLE: [KdfEntry; 4] = [
    KdfEntry {
        kdf_id: 0x0001,
        nh: 32,
    },
    KdfEntry {
        kdf_id: 0x0002,
        nh: 48,
    },
    KdfEntry {
        kdf_id: 0x0003,
        nh: 64,
    },
    KdfEntry {
        kdf_id: 0x0011,
        nh: 64,
    },
];

const AEAD_ID_GCM: u16 = 0x0002;
const AEAD_ID_CBC: u16 = 0xFFFF;
const AES256_KEY_LEN: usize = 32;
const CBC_IV_LEN: usize = 16;
const GCM_NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

// =============================================================================
// HpkeSuite accessors
// =============================================================================

impl HpkeSuite {
    const fn parts(&self) -> (KemKind, KdfKind, bool) {
        match self {
            Self::DHKemP256Sha256AesGcm256 => (KemKind::DhP256, KdfKind::HkdfSha256, false),
            Self::DHKemP256Sha256Aes256Cbc => (KemKind::DhP256, KdfKind::HkdfSha256, true),
            Self::DHKemP384Sha384AesGcm256 => (KemKind::DhP384, KdfKind::HkdfSha384, false),
            Self::DHKemP384Sha384Aes256Cbc => (KemKind::DhP384, KdfKind::HkdfSha384, true),
            Self::DHKemP521Sha512AesGcm256 => (KemKind::DhP521, KdfKind::HkdfSha512, false),
            Self::DHKemP521Sha512Aes256Cbc => (KemKind::DhP521, KdfKind::HkdfSha512, true),
            Self::MlKem1024P384Shake256AesGcm256 => {
                (KemKind::MlKem1024P384, KdfKind::Shake256, false)
            }
            Self::MlKem1024Shake256AesGcm256 => (KemKind::MlKem1024, KdfKind::Shake256, false),
        }
    }

    pub(crate) const fn kem(&self) -> KemKind {
        self.parts().0
    }

    const fn kdf(&self) -> KdfKind {
        self.parts().1
    }

    const fn kem_entry(&self) -> &'static KemEntry {
        &KEM_TABLE[self.kem() as usize]
    }

    const fn kdf_entry(&self) -> &'static KdfEntry {
        &KDF_TABLE[self.kdf() as usize]
    }

    /// Returns the IANA KEM identifier (RFC 9180 §7.1).
    pub const fn kem_id(&self) -> u16 {
        self.kem_entry().kem_id
    }

    /// Returns the IANA KDF identifier (RFC 9180 §7.2).
    pub const fn kdf_id(&self) -> u16 {
        self.kdf_entry().kdf_id
    }

    /// Returns the IANA AEAD identifier (RFC 9180 §7.3, plus the
    /// private-use value for the CBC variants).
    pub const fn aead_id(&self) -> u16 {
        if self.is_cbc() {
            AEAD_ID_CBC
        } else {
            AEAD_ID_GCM
        }
    }

    /// `true` for the AES-256-CBC + HMAC variants, `false` for GCM.
    pub const fn is_cbc(&self) -> bool {
        self.parts().2
    }

    /// `true` for suites whose KDF is one-stage (SHAKE256).
    pub const fn is_one_stage(&self) -> bool {
        matches!(self.kdf(), KdfKind::Shake256)
    }

    /// `true` if the KEM supports the Auth and AuthPSK modes. The
    /// post-quantum KEMs do not.
    pub const fn supports_auth(&self) -> bool {
        self.kem_entry().auth
    }

    /// NIST curve used by the DHKEM, or by the traditional component
    /// of the hybrid KEM. `None` for ML-KEM-1024.
    pub const fn kem_curve(&self) -> Option<EccCurve> {
        self.kem_entry().curve
    }

    /// HKDF hash used by the two-stage KDF, the DHKEM and the CBC-HMAC
    /// AEAD. `None` for the one-stage (SHAKE256) suites.
    pub fn kdf_hash(&self) -> Option<HashAlgo> {
        match self.kdf() {
            KdfKind::HkdfSha256 => Some(HashAlgo::sha256()),
            KdfKind::HkdfSha384 => Some(HashAlgo::sha384()),
            KdfKind::HkdfSha512 => Some(HashAlgo::sha512()),
            KdfKind::Shake256 => None,
        }
    }

    /// AEAD key length in bytes (`Nk`).
    ///
    /// * GCM: 32 bytes (AES-256 key).
    /// * CBC: `mac_key_len + 32` bytes (`MAC_KEY ‖ ENC_KEY`).
    pub const fn nk(&self) -> usize {
        if self.is_cbc() {
            self.cbc_mac_key_len() + AES256_KEY_LEN
        } else {
            AES256_KEY_LEN
        }
    }

    /// AEAD nonce / IV length in bytes (`Nn`).
    pub const fn nn(&self) -> usize {
        if self.is_cbc() {
            CBC_IV_LEN
        } else {
            GCM_NONCE_LEN
        }
    }

    /// KDF output length in bytes (`Nh`); 64 for SHAKE256.
    pub const fn nh(&self) -> usize {
        self.kdf_entry().nh
    }

    /// AEAD tag length in bytes (`Nt`).
    ///
    /// * GCM: always 16.
    /// * CBC: full HMAC output (`Nh`) — wire-compatible with the
    ///   firmware HPKE crate.
    pub const fn nt(&self) -> usize {
        if self.is_cbc() {
            self.nh()
        } else {
            GCM_TAG_LEN
        }
    }

    /// KEM public-key length in bytes (`Npk`).
    pub const fn npk(&self) -> usize {
        self.kem_entry().npk
    }

    /// KEM encapsulated-key length in bytes (`Nenc = Npk` for every
    /// suite here).
    pub const fn nenc(&self) -> usize {
        self.npk()
    }

    /// KEM private-key length in bytes (`Nsk`): the raw scalar for
    /// DHKEM, the seed for the post-quantum KEMs.
    pub const fn nsk(&self) -> usize {
        self.kem_entry().nsk
    }

    /// KEM shared-secret length in bytes (`Nsecret`).
    pub const fn nsecret(&self) -> usize {
        self.kem_entry().nsecret
    }

    /// Raw ECDH shared-secret length in bytes (`Ndh`, curve byte
    /// size — note 66 for P-521, not 64); 0 for ML-KEM-1024.
    pub const fn ndh(&self) -> usize {
        self.kem_entry().ndh
    }

    /// CBC-HMAC MAC key length = full hash output length.
    pub const fn cbc_mac_key_len(&self) -> usize {
        self.nh()
    }

    /// CBC-HMAC encryption-key length (always 32 for AES-256).
    pub const fn cbc_enc_key_len(&self) -> usize {
        AES256_KEY_LEN
    }

    /// KEM suite identifier: `concat("KEM", I2OSP(kem_id, 2))` = 5 bytes.
    pub const fn kem_suite_id(&self) -> [u8; 5] {
        let id = self.kem_id().to_be_bytes();
        [b'K', b'E', b'M', id[0], id[1]]
    }

    /// HPKE suite identifier: `concat("HPKE", kem_id, kdf_id, aead_id)`
    /// = 10 bytes.
    pub const fn hpke_suite_id(&self) -> [u8; 10] {
        let kem = self.kem_id().to_be_bytes();
        let kdf = self.kdf_id().to_be_bytes();
        let aead = self.aead_id().to_be_bytes();
        [
            b'H', b'P', b'K', b'E', kem[0], kem[1], kdf[0], kdf[1], aead[0], aead[1],
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sizes() {
        let s = HpkeSuite::DHKemP256Sha256AesGcm256;
        assert_eq!(s.npk(), 65);
        assert_eq!(s.nsk(), 32);
        assert_eq!(s.nh(), 32);
        assert_eq!(s.nk(), 32);
        assert_eq!(s.nn(), 12);
        assert_eq!(s.nt(), 16);
        assert_eq!(s.ndh(), 32);
        assert_eq!(s.nsecret(), 32);

        let s = HpkeSuite::DHKemP521Sha512AesGcm256;
        assert_eq!(s.npk(), 133);
        assert_eq!(s.nsk(), 66);
        assert_eq!(s.nh(), 64);
        assert_eq!(s.nsecret(), 64);
        assert_eq!(s.ndh(), 66);

        let s = HpkeSuite::DHKemP384Sha384Aes256Cbc;
        assert_eq!(s.nk(), 48 + 32);
        assert_eq!(s.nn(), 16);
        assert_eq!(s.nt(), 48); // full HMAC-SHA-384 output
        assert_eq!(s.aead_id(), 0xFFFF);
    }

    #[test]
    fn suite_ids() {
        let s = HpkeSuite::DHKemP256Sha256AesGcm256;
        assert_eq!(s.kem_suite_id(), *b"KEM\x00\x10");
        assert_eq!(s.hpke_suite_id(), *b"HPKE\x00\x10\x00\x01\x00\x02");

        let s = HpkeSuite::MlKem1024P384Shake256AesGcm256;
        assert_eq!(s.kem_suite_id(), *b"KEM\x00\x51");
        assert_eq!(s.hpke_suite_id(), *b"HPKE\x00\x51\x00\x11\x00\x02");

        let s = HpkeSuite::MlKem1024Shake256AesGcm256;
        assert_eq!(s.kem_suite_id(), *b"KEM\x00\x42");
        assert_eq!(s.hpke_suite_id(), *b"HPKE\x00\x42\x00\x11\x00\x02");
    }

    #[test]
    fn pq_suites() {
        let s = HpkeSuite::MlKem1024Shake256AesGcm256;
        assert_eq!(
            (s.npk(), s.nenc(), s.nsk(), s.nsecret()),
            (1568, 1568, 64, 32)
        );
        let s = HpkeSuite::MlKem1024P384Shake256AesGcm256;
        assert_eq!(
            (s.npk(), s.nenc(), s.nsk(), s.nsecret()),
            (1665, 1665, 32, 32)
        );

        for s in [
            HpkeSuite::MlKem1024Shake256AesGcm256,
            HpkeSuite::MlKem1024P384Shake256AesGcm256,
        ] {
            assert!(s.is_one_stage());
            assert!(!s.supports_auth());
            assert!(!s.is_cbc());
            assert!(s.kdf_hash().is_none());
            assert_eq!((s.nh(), s.nk(), s.nn(), s.nt()), (64, 32, 12, 16));
        }

        assert_eq!(HpkeSuite::MlKem1024Shake256AesGcm256.kem_curve(), None);
        assert_eq!(
            HpkeSuite::MlKem1024P384Shake256AesGcm256.kem_curve(),
            Some(EccCurve::P384)
        );

        let s = HpkeSuite::DHKemP384Sha384AesGcm256;
        assert!(!s.is_one_stage());
        assert!(s.supports_auth());
    }
}
