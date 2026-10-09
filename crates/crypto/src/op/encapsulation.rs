// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key encapsulation operation traits.
//!
//! This module defines the [`EncapsulateOp`] and [`DecapsulateOp`] traits, which
//! provide a generic interface for key encapsulation mechanisms (KEMs). A KEM
//! establishes a shared secret between two parties: the sender encapsulates to
//! the recipient's public key, producing a ciphertext and a shared secret, and
//! the recipient decapsulates that ciphertext with its private key to recover
//! the same shared secret.
//!
//! # Relationship to key derivation
//!
//! A KEM resembles [`DeriveOp`] in that both end with shared key material, but
//! the shapes differ: derivation is a local computation over key material the
//! caller already holds, whereas encapsulation additionally emits a ciphertext
//! that must travel to the recipient. That extra output is why these are
//! separate traits rather than a special case of derivation.

use super::*;

/// Trait for key encapsulation.
///
/// Encapsulation is the sender's half of a KEM. It takes the recipient's public
/// key and produces two outputs: a ciphertext to transmit, and the shared secret
/// to keep.
///
/// # Security Considerations
///
/// - The shared secret must never be transmitted; only the ciphertext is public.
/// - Encapsulation consumes entropy. Implementations that accept it as a
///   parameter must be given output from a cryptographically secure generator,
///   as it fully determines both outputs.
/// - The shared secret is usually fed to a KDF rather than used directly as a key.
pub trait EncapsulateOp {
    /// The public key type encapsulated to.
    type Key: EncapsulationKey;

    /// Performs the encapsulation operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The recipient's public key to encapsulate to
    /// * `ciphertext` - Optional output buffer for the ciphertext. If `None`,
    ///   only calculates the required size.
    /// * `shared_secret` - Optional output buffer for the shared secret. If
    ///   `None`, only calculates the required size.
    ///
    /// # Returns
    ///
    /// Returns the ciphertext and shared secret lengths, written or required.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Either output buffer is the wrong size when provided
    /// - The key is invalid or incompatible with this operation
    /// - Insufficient entropy is available
    /// - The underlying cryptographic operation fails
    fn encapsulate(
        &mut self,
        key: &Self::Key,
        ciphertext: Option<&mut [u8]>,
        shared_secret: Option<&mut [u8]>,
    ) -> Result<(usize, usize), CryptoError>;
}

/// Trait for key decapsulation.
///
/// Decapsulation is the recipient's half of a KEM: it recovers from the
/// ciphertext the same shared secret the sender derived.
///
/// # Security Considerations
///
/// Decapsulation must not reveal whether a ciphertext was well-formed. FIPS 203
/// specifies implicit rejection — an invalid ciphertext yields a pseudo-random
/// shared secret derived from the private key rather than an error — so that a
/// caller cannot use the outcome as a decryption oracle. Implementations must
/// preserve that behaviour and report errors only for malformed *inputs*, never
/// for a ciphertext that simply failed to decrypt.
pub trait DecapsulateOp {
    /// The private key type used to decapsulate.
    type Key: DecapsulationKey;

    /// Performs the decapsulation operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The recipient's private key
    /// * `ciphertext` - The ciphertext produced by encapsulation
    /// * `shared_secret` - Optional output buffer for the shared secret. If
    ///   `None`, only calculates the required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the shared secret buffer, or the
    /// required buffer size if `shared_secret` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is the wrong size when provided
    /// - The ciphertext is the wrong length for this algorithm
    /// - The key is invalid or incompatible with this operation
    /// - The underlying cryptographic operation fails
    ///
    /// A ciphertext of the correct length that does not decrypt is *not* an
    /// error; see the trait-level security note on implicit rejection.
    fn decapsulate(
        &mut self,
        key: &Self::Key,
        ciphertext: &[u8],
        shared_secret: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError>;
}
