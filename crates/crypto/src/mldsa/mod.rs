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
//!
//! # Platform Support
//!
//! Unlike the classical algorithms in this crate there is no platform backend to
//! select between: neither OpenSSL nor CNG exposes ML-DSA, so it comes from the
//! pure-Rust `ml-dsa` crate and behaves identically on every host.
//!
//! That is a deliberate choice as well as a constraint. The Cortex-M firmware
//! runs its own implementation on the fastpath cores, so this one is independent
//! of it: the known-answer tests in this module are generated from that
//! implementation, so they compare two unrelated codebases and a mistake in
//! either shows up as a disagreement rather than as agreement on a wrong answer.
//!
//! # Randomness
//!
//! Signing randomness is drawn from the platform generator by default; see
//! [`MlDsaAlgo`] for the constructor that pins it instead, and why two callers
//! need that.
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
//! - Signing is *hedged*: the same message signed twice under different
//!   randomness yields different, equally valid signatures
//! - The signing randomness must come from a cryptographically secure generator
//! - Expanded signing keys must be protected as private key material
//! - The FIPS 204 context string is bound into the signature, so verification
//!   must use the same context that signing did

mod key;
mod sign;

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
}

#[cfg(test)]
mod tests;

/// Instantiates a generic body for the parameter set named by `$variant`.
///
/// The three sets are distinct types, so each arm monomorphises separately; the
/// macro keeps the three-way match out of every operation.
macro_rules! dispatch {
    ($variant:expr, $f:ident($($arg:expr),* $(,)?)) => {
        match $variant {
            MlDsaVariant::MlDsa44 => $f::<MlDsa44>($($arg),*),
            MlDsaVariant::MlDsa65 => $f::<MlDsa65>($($arg),*),
            MlDsaVariant::MlDsa87 => $f::<MlDsa87>($($arg),*),
        }
    };
}
use dispatch;
