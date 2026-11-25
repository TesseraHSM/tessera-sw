// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE ciphersuite definitions and per-suite size constants.
//!
//! Eight ciphersuites are exposed as a single [`HpkeSuite`] enum:
//!
//! * Three RFC 9180 combinations (DHKEM(P-N) + HKDF + AES-256-GCM).
//! * Three that substitute AES-256-CBC + HMAC for the AEAD step using a
//!   private-use AEAD identifier (`0xFFFF`) and a FIPS-compliant key
//!   sizing scheme.
//! * Two post-quantum suites from draft-ietf-hpke-pq, both using the
//!   one-stage SHAKE256 KDF (`0x0011`) of draft-ietf-hpke-hpke and
//!   AES-256-GCM:
//!   * HPKE-10: MLKEM1024-P384 hybrid KEM (`0x0051`).
//!   * HPKE-13: ML-KEM-1024 KEM (`0x0042`).
//!
//! The post-quantum KEMs do not support the Auth / AuthPSK modes.
//!
//! ## CBC-HMAC key layout
//!
//! For the CBC variants the AEAD key concatenates the MAC key (size =
//! hash output length per SP 800-107) and the AES encryption key
//! (always 32 bytes for AES-256):
//!
//! | Suite      | `MAC_KEY` | `ENC_KEY` | Total `Nk` | Tag `Nt` |
//! |------------|-----------|-----------|------------|----------|
//! | P-256/CBC  | 32        | 32        | 64         | 32       |
//! | P-384/CBC  | 48        | 32        | 80         | 48       |
//! | P-521/CBC  | 64        | 32        | 96         | 64       |
//!
//! The tag is the full HMAC output (no truncation).
//!
//! ## Internal representation
//!
//! Every per-suite quantity is derived from three orthogonal selectors —
//! the [`KemKind`], the [`KdfKind`] and an `is_cbc` flag. The per-KEM
//! and per-KDF constants live in [`KEM_TABLE`] and [`KDF_TABLE`].

use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;

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
pub(crate) enum KdfKind {
    HkdfSha256 = 0,
    HkdfSha384 = 1,
    HkdfSha512 = 2,
    Shake256 = 3,
}

/// Per-KEM parameters.
#[derive(Clone, Copy)]
struct KemEntry {
    /// IANA KEM identifier.
    kem_id: u16,
    /// NIST curve of the DH KEM, or of the hybrid's traditional part.
    curve: Option<HsmEccCurve>,
    /// HKDF hash of the DHKEM `ExtractAndExpand`; `None` for PQ KEMs.
    hash: Option<HsmHashAlgo>,
    /// Serialized public-key length in bytes (`Npk`).
    npk: usize,
    /// PAL-native ECC public-key length (`x ‖ y`) of the DH KEM or of
    /// the hybrid's traditional part; 0 for ML-KEM.
    npk_pal: usize,
    /// Encapsulated-key length in bytes (`Nenc`).
    nenc: usize,
    /// Private-key length in bytes (`Nsk`).
    nsk: usize,
    /// KEM shared-secret length in bytes (`Nsecret`).
    nsecret: usize,
    /// Raw ECDH shared-secret length in bytes (`Ndh`); 0 for ML-KEM.
    ndh: usize,
    /// Whether the KEM supports AuthEncap / AuthDecap.
    auth: bool,
}

/// One entry per [`KemKind`].
///
/// For DHKEM `npk` is the SEC1 uncompressed wire size (`1 + 2 * Nsk`
/// per RFC 9180 §7.1.1) used in `kem_context` and on the wire.
///
/// P-521 entry is left at the legacy PAL-padded value and is not
/// RFC 9180 compliant — that suite is not currently supported.
const KEM_TABLE: [KemEntry; 5] = [
    KemEntry {
        kem_id: 0x0010,
        curve: Some(HsmEccCurve::P256),
        hash: Some(HsmHashAlgo::Sha256),
        npk: 65,
        npk_pal: 64,
        nenc: 65,
        nsk: 32,
        nsecret: 32,
        ndh: 32,
        auth: true,
    },
    KemEntry {
        kem_id: 0x0011,
        curve: Some(HsmEccCurve::P384),
        hash: Some(HsmHashAlgo::Sha384),
        npk: 97,
        npk_pal: 96,
        nenc: 97,
        nsk: 48,
        nsecret: 48,
        ndh: 48,
        auth: true,
    },
    KemEntry {
        kem_id: 0x0012,
        curve: Some(HsmEccCurve::P521),
        hash: Some(HsmHashAlgo::Sha512),
        // P-521 is unsupported: PAL uses 4-byte aligned coords (68 B
        // each) which conflicts with RFC 9180 P-521 (66 B each).
        npk: 136,
        npk_pal: 136,
        nenc: 136,
        nsk: 68,
        nsecret: 64,
        ndh: 66,
        auth: true,
    },
    // ML-KEM-1024 (draft-ietf-hpke-pq §3): `Nsk` is the `d ‖ z` seed.
    KemEntry {
        kem_id: 0x0042,
        curve: None,
        hash: None,
        npk: 1568,
        npk_pal: 0,
        nenc: 1568,
        nsk: 64,
        nsecret: 32,
        ndh: 0,
        auth: false,
    },
    // MLKEM1024-P384 (draft-ietf-hpke-pq §4, draft-irtf-cfrg-concrete-
    // hybrid-kems): `ek_PQ ‖ SEC1(ek_T)`, `Nsk` is the 32-byte seed.
    KemEntry {
        kem_id: 0x0051,
        curve: Some(HsmEccCurve::P384),
        hash: None,
        npk: 1568 + 97,
        npk_pal: 96,
        nenc: 1568 + 97,
        nsk: 32,
        nsecret: 32,
        ndh: 48,
        auth: false,
    },
];

/// Per-KDF parameters.
#[derive(Clone, Copy)]
struct KdfEntry {
    /// IANA KDF identifier.
    kdf_id: u16,
    /// HKDF hash; `None` for one-stage KDFs.
    hash: Option<HsmHashAlgo>,
    /// `Nh` in bytes.
    nh: usize,
}

/// One entry per [`KdfKind`].
const KDF_TABLE: [KdfEntry; 4] = [
    KdfEntry {
        kdf_id: 0x0001,
        hash: Some(HsmHashAlgo::Sha256),
        nh: 32,
    },
    KdfEntry {
        kdf_id: 0x0002,
        hash: Some(HsmHashAlgo::Sha384),
        nh: 48,
    },
    KdfEntry {
        kdf_id: 0x0003,
        hash: Some(HsmHashAlgo::Sha512),
        nh: 64,
    },
    KdfEntry {
        kdf_id: 0x0011,
        hash: None,
        nh: 64,
    },
];

/// IANA AEAD identifier for AES-256-GCM (RFC 9180 §7.3).
const AEAD_ID_GCM: u16 = 0x0002;

/// Private-use AEAD identifier this crate assigns to AES-256-CBC + HMAC.
const AEAD_ID_CBC: u16 = 0xFFFF;

/// AES-256 encryption key length used by every CBC suite.
const AES256_KEY_LEN: usize = 32;

/// AES-CBC IV / GCM nonce sizes.
const CBC_IV_LEN: usize = 16;
const GCM_NONCE_LEN: usize = 12;

/// AES-256-GCM tag size.
const GCM_TAG_LEN: usize = 16;

// =============================================================================
// HpkeSuite accessors
// =============================================================================

impl HpkeSuite {
    /// Decompose the suite into its `(KemKind, KdfKind, is_cbc)`
    /// selectors.
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

    /// KEM family of this suite.
    pub(crate) const fn kem(&self) -> KemKind {
        self.parts().0
    }

    /// KDF of this suite.
    pub(crate) const fn kdf(&self) -> KdfKind {
        self.parts().1
    }

    const fn kem_entry(&self) -> &'static KemEntry {
        &KEM_TABLE[self.kem() as usize]
    }

    const fn kdf_entry(&self) -> &'static KdfEntry {
        &KDF_TABLE[self.kdf() as usize]
    }

    /// `true` when the KDF is one-stage (`LabeledDerive`), `false` for
    /// the two-stage HKDF (`LabeledExtract` / `LabeledExpand`).
    pub const fn is_one_stage(&self) -> bool {
        self.kdf_entry().hash.is_none()
    }

    /// `true` when the KEM supports the Auth / AuthPSK modes.
    pub const fn supports_auth(&self) -> bool {
        self.kem_entry().auth
    }

    // ── IANA identifiers ──────────────────────────────────────────

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

    // ── Crypto algorithm selectors ────────────────────────────────

    /// NIST curve used by the DH KEM or by the hybrid KEM's
    /// traditional part; `None` for ML-KEM.
    pub const fn kem_curve(&self) -> Option<HsmEccCurve> {
        self.kem_entry().curve
    }

    /// HKDF hash of the two-stage KDF; `None` for one-stage KDFs.
    pub const fn kdf_hash(&self) -> Option<HsmHashAlgo> {
        self.kdf_entry().hash
    }

    /// HKDF hash of the DHKEM `ExtractAndExpand`; `None` for PQ KEMs.
    pub const fn kem_hash(&self) -> Option<HsmHashAlgo> {
        self.kem_entry().hash
    }

    /// Hash algorithm used by the CBC-HMAC AEAD (equal to
    /// [`Self::kdf_hash`]; CBC suites always use HKDF).
    pub const fn aead_hash(&self) -> Option<HsmHashAlgo> {
        self.kdf_hash()
    }

    // ── Size constants ────────────────────────────────────────────

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
    ///
    /// * GCM: 12 (96-bit IV).
    /// * CBC: 16 (one AES block).
    pub const fn nn(&self) -> usize {
        if self.is_cbc() {
            CBC_IV_LEN
        } else {
            GCM_NONCE_LEN
        }
    }

    /// KDF hash output length in bytes (`Nh`).
    pub const fn nh(&self) -> usize {
        self.kdf_entry().nh
    }

    /// AEAD tag length in bytes (`Nt`).
    ///
    /// * GCM: always 16.
    /// * CBC: full HMAC output (`Nh`), no truncation.
    pub const fn nt(&self) -> usize {
        if self.is_cbc() {
            self.nh()
        } else {
            GCM_TAG_LEN
        }
    }

    /// KEM public-key length in bytes (`Npk`).
    ///
    /// For DHKEM, SEC1 uncompressed (`0x04 ‖ X ‖ Y`, big-endian) per
    /// RFC 9180 §7.1.1. The on-the-wire / `kem_context` encoding.
    /// For ML-KEM, the encapsulation key; for the hybrid,
    /// `ek_PQ ‖ SEC1(ek_T)`.
    ///
    /// **P-521 unsupported.** The HSM PAL pads P-521 coords to 4-byte
    /// alignment (68 B each) which conflicts with the RFC 9180 P-521
    /// encoding (66 B each). P-521 HPKE is not currently usable; the
    /// per-suite constant below is left at the legacy padded value
    /// so callers that don't exercise P-521 keep compiling.
    pub const fn npk(&self) -> usize {
        self.kem_entry().npk
    }

    /// PAL-native ECC public-key length in bytes (`x ‖ y`, no SEC1
    /// prefix, operand-order coords) of the DH KEM or of the hybrid's
    /// traditional part; 0 for ML-KEM.
    ///
    /// Used only inside this crate to size buffers passed to / from
    /// the [`HsmCrypto::ecc_gen_keypair`] / [`HsmCrypto::ecdh_derive`]
    /// PAL entry points, which traffic in the HSM-native LE coord
    /// format throughout. See [`Self::npk`] for the wire-format size.
    pub const fn npk_pal(&self) -> usize {
        self.kem_entry().npk_pal
    }

    /// KEM encapsulated-key length in bytes (`Nenc`). Same as
    /// [`Self::npk`] for every supported KEM.
    pub const fn nenc(&self) -> usize {
        self.kem_entry().nenc
    }

    /// KEM private-key length in bytes (`Nsk`). P-521 uses 68 bytes
    /// (4-byte aligned HSM wire format); ML-KEM-1024 the 64-byte
    /// `d ‖ z` seed; MLKEM1024-P384 the 32-byte hybrid seed.
    pub const fn nsk(&self) -> usize {
        self.kem_entry().nsk
    }

    /// KEM shared-secret length in bytes (`Nsecret`): the DHKEM's
    /// HKDF `Nh`, or 32 for the PQ KEMs.
    pub const fn nsecret(&self) -> usize {
        self.kem_entry().nsecret
    }

    /// Raw ECDH shared-secret length in bytes (`Ndh`).
    ///
    /// This is the curve byte size, NOT the HSM-padded size. P-521
    /// raw x-coordinate is 66 bytes. 0 for ML-KEM.
    pub const fn ndh(&self) -> usize {
        self.kem_entry().ndh
    }

    /// CBC-HMAC MAC key length = full hash output length (FIPS
    /// SP 800-107 compliant).
    pub const fn cbc_mac_key_len(&self) -> usize {
        self.nh()
    }

    /// CBC-HMAC encryption-key length (always 32 for AES-256).
    pub const fn cbc_enc_key_len(&self) -> usize {
        AES256_KEY_LEN
    }

    // ── Suite-id construction ─────────────────────────────────────

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
