// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA (FIPS 204) digital signatures.
//!
//! This module provides the lattice-based signature scheme standardised by NIST
//! in FIPS 204, in the seed-and-expanded-key forms the HSM wire protocol
//! carries.
//!
//! # Supported Parameter Sets
//!
//! - **ML-DSA-44**: 1312-byte public key, 2420-byte signature
//! - **ML-DSA-65**: 1952-byte public key, 3309-byte signature
//! - **ML-DSA-87**: 2592-byte public key, 4627-byte signature
//!
//! # Architecture
//!
//! The module is structured around several key components:
//!
//! - [`MlDsaVariant`]: Enumeration of the three parameter sets
//! - [`MlDsaPrivateKey`]: Expanded signing key
//! - [`MlDsaPublicKey`]: Encoded verifying key
//! - [`MlDsaAlgo`]: Signing and verification operations
//! - [`HashAlgo::mldsa_mu`]: The external-`μ` hash of a message, as OpenSSL's
//!   `ML-DSA-MU` digest computes it
//!
//! # Platform Support
//!
//! Linux uses OpenSSL 3.5+ in the crate-private default-provider libctx.
//! Windows uses the Microsoft CNG provider on PQC-capable systems (updated
//! Windows Server 2025 or Windows 11 24H2 and newer). CNG supports hedged
//! signing, but an explicit deterministic signing request returns
//! [`CryptoError::MlDsaDeterministicUnsupported`]; it is never silently hedged.
//! Older OpenSSL builds retain classical crypto support but return
//! [`CryptoError::PqcUnavailable`] for PQC operations.
//!
//! # Randomness
//!
//! Signing randomness is drawn from the platform generator by default; see
//! [`MlDsaAlgo::deterministic`] for FIPS 204's deterministic variant, which
//! fixes it at zero instead.
//!
//! The key-generation seed is different: it cannot be drawn here, because the
//! seed *is* the private key. It is what the HSM stores in the masked blob and
//! returns to the caller, so it has to come from outside — which is also why
//! there is no [`KeyGenerationOp`] implementation, that trait yielding only a
//! key and no way to surface the seed alongside it.
//!
//! # Key Encodings
//!
//! Generation starts from a 32-byte seed, but signing takes the *expanded* key:
//! that is what the masked key blob stores, so the expansion happens once at
//! generation rather than on every use. Because the three parameter sets have
//! distinct encoded lengths, [`ImportableKey::from_bytes`] recovers the variant
//! from the length rather than needing it passed alongside.
//!
//! # Security Considerations
//!
//! - Signing is *hedged* by default: the same message signed twice under
//!   different randomness yields different, equally valid signatures
//! - The signing randomness must come from a cryptographically secure generator
//! - Expanded signing keys must be protected as private key material
//! - The FIPS 204 context string is bound into the signature, so verification
//!   must use the same context that signing did

mod key;
mod sign;

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod key_ossl;
        mod sign_ossl;
        use key_ossl as platform;
    } else if #[cfg(target_os = "windows")] {
        mod key_cng;
        mod sign_cng;
        use key_cng as platform;
    } else {
        compile_error!("Unsupported target OS for ML-DSA");
    }
}

pub use key::MlDsaPrivateKey;
pub use key::MlDsaPublicKey;
pub use sign::MlDsaAlgo;

use super::*;

/// Length of the ML-DSA key-generation seed, FIPS 204 `xi`.
pub const MLDSA_SEED_LEN: usize = 32;

/// Length of the per-signature randomness for hedged signing, FIPS 204 `rnd`.
pub const MLDSA_RND_LEN: usize = 32;

/// Maximum length of the FIPS 204 signing context string.
pub const MLDSA_CTX_MAX_LEN: usize = 255;

/// Length of the FIPS 204 message representative `μ`, which an
/// [external-μ](MlDsaAlgo::external_mu) engine takes in place of the message.
pub const MLDSA_MU_LEN: usize = 64;

/// ML-DSA parameter sets.
///
/// Each variant fixes the lattice dimensions and therefore every encoded
/// length. The three sets are distinct types in the underlying implementation,
/// so this enum is what selects between them at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    /// ML-DSA-44, NIST security category 2.
    MlDsa44,
    /// ML-DSA-65, NIST security category 3.
    MlDsa65,
    /// ML-DSA-87, NIST security category 5.
    MlDsa87,
}

impl MlDsaVariant {
    /// Returns the encoded public-key length in bytes.
    pub fn pub_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Returns the expanded secret-key length in bytes.
    pub fn sec_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// Returns the signature length in bytes.
    pub fn sig_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// Recovers the variant from an encoded public-key length.
    ///
    /// The three lengths are distinct, so a well-formed key identifies its own
    /// parameter set and callers need not track it alongside the bytes.
    pub fn from_pub_key_len(len: usize) -> Option<Self> {
        [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87]
            .into_iter()
            .find(|v| v.pub_key_len() == len)
    }

    /// Recovers the variant from an expanded secret-key length.
    ///
    /// See [`from_pub_key_len`](Self::from_pub_key_len).
    pub fn from_sec_key_len(len: usize) -> Option<Self> {
        [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87]
            .into_iter()
            .find(|v| v.sec_key_len() == len)
    }

    #[cfg(target_os = "windows")]
    pub(super) fn parameter_name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "44",
            Self::MlDsa65 => "65",
            Self::MlDsa87 => "87",
        }
    }

    #[cfg(all(target_os = "linux", ossl350))]
    pub(super) fn name(self) -> &'static std::ffi::CStr {
        match self {
            Self::MlDsa44 => c"ML-DSA-44",
            Self::MlDsa65 => c"ML-DSA-65",
            Self::MlDsa87 => c"ML-DSA-87",
        }
    }
}

#[cfg(all(test, any(target_os = "windows", ossl350)))]
mod tests;
