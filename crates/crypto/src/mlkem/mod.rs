// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-KEM (FIPS 203) key encapsulation.
//!
//! This module provides the lattice-based key encapsulation mechanism
//! standardised by NIST in FIPS 203, in the seed-and-expanded-key forms the HSM
//! wire protocol carries.
//!
//! # Supported Parameter Sets
//!
//! - **ML-KEM-512**: 800-byte encapsulation key, 768-byte ciphertext
//! - **ML-KEM-768**: 1184-byte encapsulation key, 1088-byte ciphertext
//! - **ML-KEM-1024**: 1568-byte encapsulation key, 1568-byte ciphertext
//!
//! Every parameter set produces the same 32-byte shared secret.
//!
//! # Architecture
//!
//! The module is structured around several key components:
//!
//! - [`MlKemVariant`]: Enumeration of the three parameter sets
//! - [`MlKemPrivateKey`]: Expanded decapsulation key
//! - [`MlKemPublicKey`]: Encoded encapsulation key
//! - [`MlKemAlgo`]: Encapsulation and decapsulation operations
//!
//! # Platform Support
//!
//! Linux uses OpenSSL 3.5+ in the crate-private default-provider libctx.
//! Windows uses the Microsoft CNG provider on PQC-capable systems (updated
//! Windows Server 2025 or Windows 11 24H2 and newer). Both backends draw
//! fresh encapsulation entropy internally and implement implicit rejection.
//! Older OpenSSL builds retain classical crypto support but return
//! [`CryptoError::PqcUnavailable`] for PQC operations.
//!
//! # Randomness
//!
//! Each encapsulation draws a fresh message from the platform generator.
//!
//! The key-generation seed is different: it cannot be drawn here, because the
//! seed *is* the private key. It is what the HSM stores in the masked blob and
//! returns to the caller, so it has to come from outside — which is also why
//! there is no [`KeyGenerationOp`] implementation, that trait yielding only a
//! key and no way to surface the seed alongside it.
//!
//! # Key Encodings
//!
//! Generation starts from a 64-byte seed, but decapsulation takes the *expanded*
//! key: that is what the masked key blob stores, so the expansion happens once at
//! generation rather than on every use. Because the three parameter sets have
//! distinct encoded lengths, [`ImportableKey::from_bytes`] recovers the variant
//! from the length rather than needing it passed alongside.
//!
//! # Security Considerations
//!
//! - The encapsulation message must come from a cryptographically secure
//!   generator: it fully determines both the ciphertext and the shared secret
//! - Shared secrets should be fed to a KDF rather than used directly as keys
//! - Decapsulation is *implicitly rejecting*: a ciphertext that does not decrypt
//!   yields a pseudo-random secret rather than an error, so a caller cannot use
//!   the outcome as a decryption oracle
//! - Expanded decapsulation keys must be protected as private key material

mod kem;
mod key;

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod key_ossl;
        mod kem_ossl;
        use key_ossl as platform;
    } else if #[cfg(target_os = "windows")] {
        mod key_cng;
        mod kem_cng;
        use key_cng as platform;
    } else {
        compile_error!("Unsupported target OS for ML-KEM");
    }
}

pub use kem::MlKemAlgo;
pub use key::MlKemPrivateKey;
pub use key::MlKemPublicKey;

use super::*;

/// Length of the ML-KEM key-generation seed, FIPS 203 `d ‖ z`.
pub const MLKEM_SEED_LEN: usize = 64;

/// Length of the encapsulation randomness, FIPS 203 `m`.
pub const MLKEM_M_LEN: usize = 32;

/// Length of the derived shared secret, identical for every parameter set.
pub const MLKEM_SHARED_SECRET_LEN: usize = 32;

/// ML-KEM parameter sets.
///
/// Each variant fixes the lattice dimensions and therefore every encoded
/// length. The three sets are distinct types in the underlying implementation,
/// so this enum is what selects between them at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    /// ML-KEM-512, NIST security category 1.
    MlKem512,
    /// ML-KEM-768, NIST security category 3.
    MlKem768,
    /// ML-KEM-1024, NIST security category 5.
    MlKem1024,
}

impl MlKemVariant {
    /// Returns the encapsulation-key length in bytes.
    pub fn pub_key_len(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Returns the expanded decapsulation-key length in bytes.
    pub fn sec_key_len(self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// Returns the ciphertext length in bytes.
    pub fn ciphertext_len(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Recovers the variant from an encapsulation-key length.
    ///
    /// The three lengths are distinct, so a well-formed key identifies its own
    /// parameter set and callers need not track it alongside the bytes.
    pub fn from_pub_key_len(len: usize) -> Option<Self> {
        [Self::MlKem512, Self::MlKem768, Self::MlKem1024]
            .into_iter()
            .find(|v| v.pub_key_len() == len)
    }

    /// Recovers the variant from an expanded decapsulation-key length.
    ///
    /// See [`from_pub_key_len`](Self::from_pub_key_len).
    pub fn from_sec_key_len(len: usize) -> Option<Self> {
        [Self::MlKem512, Self::MlKem768, Self::MlKem1024]
            .into_iter()
            .find(|v| v.sec_key_len() == len)
    }

    #[cfg(target_os = "windows")]
    pub(super) fn parameter_name(self) -> &'static str {
        match self {
            Self::MlKem512 => "512",
            Self::MlKem768 => "768",
            Self::MlKem1024 => "1024",
        }
    }

    #[cfg(all(target_os = "linux", ossl350))]
    pub(super) fn name(self) -> &'static std::ffi::CStr {
        match self {
            Self::MlKem512 => c"ML-KEM-512",
            Self::MlKem768 => c"ML-KEM-768",
            Self::MlKem1024 => c"ML-KEM-1024",
        }
    }
}

#[cfg(all(test, any(target_os = "windows", ossl350)))]
mod tests;
