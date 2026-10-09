// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-KEM encapsulation and decapsulation operations.
//!
//! This module defines [`MlKemAlgo`], which implements the crate's
//! [`EncapsulateOp`] and [`DecapsulateOp`] traits for ML-KEM.
//!
//! # Configuration lives in the engine
//!
//! FIPS 203 encapsulation takes a 32-byte message that fully determines both
//! outputs. It does not fit the [`EncapsulateOp::encapsulate`] signature, so the
//! engine holds it — the same shape [`EcdsaAlgo`](crate::EcdsaAlgo) uses to
//! carry its hash algorithm.
//!
//! The expanded decapsulation key form is deprecated upstream in favour of the
//! seed; [`key`](super::key) explains why the HSM wire format pins us to it.
#![allow(deprecated)]

use ml_kem::ExpandedKeyEncoding;
use ml_kem::Key as MlKemEncoded;
use ml_kem::kem::Decapsulate;

use super::*;

/// ML-KEM encapsulation and decapsulation engine.
///
/// One engine serves both directions, as [`EcdsaAlgo`](crate::EcdsaAlgo) does
/// for signing and verification.
///
/// # Randomness
///
/// The FIPS 203 encapsulation message is drawn from the platform generator,
/// freshly for every encapsulation, and is never a parameter — the same
/// arrangement ECDSA's nonce and RSA-PSS's salt already have in this crate.
/// That message fully determines both the ciphertext and the shared secret.
pub struct MlKemAlgo {
    /// Message pinned by a known-answer test; see
    /// [`with_message`](Self::with_message). Production always draws.
    #[cfg(test)]
    pinned_m: Option<[u8; MLKEM_M_LEN]>,
}

impl MlKemAlgo {
    /// Creates an ML-KEM engine.
    pub fn new() -> Self {
        Self {
            #[cfg(test)]
            pinned_m: None,
        }
    }

    /// Creates an engine that encapsulates under a fixed message.
    ///
    /// Test-only, and deliberately so. A published ciphertext can only be
    /// reproduced by supplying the message that produced it, so the
    /// known-answer tests need this; no caller does. Pinning it in production
    /// would fix the shared secret too, which is the one thing a KEM must
    /// never let an outsider influence.
    #[cfg(test)]
    pub(crate) fn with_message(m: [u8; MLKEM_M_LEN]) -> Self {
        Self { pinned_m: Some(m) }
    }

    /// Draws the message for one encapsulation.
    fn encaps_message(&self) -> Result<[u8; MLKEM_M_LEN], CryptoError> {
        #[cfg(test)]
        if let Some(m) = self.pinned_m {
            return Ok(m);
        }

        let mut m = [0u8; MLKEM_M_LEN];
        Rng::rand_bytes(&mut m).map_err(|_| CryptoError::MlKemEncapsError)?;
        Ok(m)
    }
}

impl Default for MlKemAlgo {
    fn default() -> Self {
        Self::new()
    }
}

impl EncapsulateOp for MlKemAlgo {
    /// Encoded ML-KEM encapsulation key.
    type Key = MlKemPublicKey;

    /// Encapsulates to `key`, producing a ciphertext and a shared secret.
    ///
    /// # Arguments
    ///
    /// * `key` - The recipient's encapsulation key
    /// * `ciphertext` - Optional output buffer. If `None`, only calculates the
    ///   required size.
    /// * `shared_secret` - Optional output buffer. If `None`, only calculates
    ///   the required size.
    ///
    /// # Returns
    ///
    /// The ciphertext and shared-secret lengths, written or required.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`CryptoError::MlKemEncapsError`] - the key does not decode, or the
    ///   platform generator failed
    /// - [`CryptoError::MlKemBufferTooSmall`] - an output buffer is too small
    fn encapsulate(
        &mut self,
        key: &Self::Key,
        ciphertext: Option<&mut [u8]>,
        shared_secret: Option<&mut [u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        let lens = (key.variant().ciphertext_len(), MLKEM_SHARED_SECRET_LEN);
        let (Some(ciphertext), Some(shared_secret)) = (ciphertext, shared_secret) else {
            return Ok(lens);
        };

        let m = self.encaps_message()?;
        let pub_key = key.as_bytes();
        dispatch!(key.variant(), |p| {
            let enc = MlKemEncoded::<p::EncapsulationKey>::try_from(pub_key)
                .map_err(|_| CryptoError::MlKemEncapsError)?;
            let ek = p::EncapsulationKey::new(&enc).map_err(|_| CryptoError::MlKemEncapsError)?;
            let (ct, ss) = ek.encapsulate_deterministic((&m).into());
            write_out(ciphertext, &ct)?;
            write_out(shared_secret, &ss)?;
            Ok::<_, CryptoError>(lens)
        })
    }
}

impl DecapsulateOp for MlKemAlgo {
    /// Expanded ML-KEM decapsulation key.
    type Key = MlKemPrivateKey;

    /// Recovers the shared secret from `ciphertext`.
    ///
    /// # Arguments
    ///
    /// * `key` - The recipient's decapsulation key
    /// * `ciphertext` - The ciphertext produced by encapsulation
    /// * `shared_secret` - Optional output buffer. If `None`, only calculates
    ///   the required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written, or the required size if `shared_secret` is
    /// `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`CryptoError::MlKemDecapsError`] - the key or ciphertext is malformed
    /// - [`CryptoError::MlKemBufferTooSmall`] - the output buffer is too small
    ///
    /// A ciphertext of the correct length that does not decrypt is *not* an
    /// error: FIPS 203 returns an implicit-rejection secret derived from the key
    /// and the ciphertext, which is what stops an attacker learning anything
    /// from whether decapsulation "worked".
    fn decapsulate(
        &mut self,
        key: &Self::Key,
        ciphertext: &[u8],
        shared_secret: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let Some(shared_secret) = shared_secret else {
            return Ok(MLKEM_SHARED_SECRET_LEN);
        };

        let sec_key = key.as_bytes();
        dispatch!(key.variant(), |p| {
            let enc = p::ExpandedDecapsulationKey::try_from(sec_key)
                .map_err(|_| CryptoError::MlKemDecapsError)?;
            let dk = p::DecapsulationKey::from_expanded_bytes(&enc)
                .map_err(|_| CryptoError::MlKemDecapsError)?;
            let ct =
                p::Ciphertext::try_from(ciphertext).map_err(|_| CryptoError::MlKemDecapsError)?;
            write_out(shared_secret, &dk.decapsulate(&ct))?;
            Ok::<_, CryptoError>(MLKEM_SHARED_SECRET_LEN)
        })
    }
}

/// Writes `src` into `dst`, reporting a too-small buffer.
fn write_out(dst: &mut [u8], src: &[u8]) -> Result<(), CryptoError> {
    dst.get_mut(..src.len())
        .ok_or(CryptoError::MlKemBufferTooSmall)?
        .copy_from_slice(src);
    Ok(())
}
