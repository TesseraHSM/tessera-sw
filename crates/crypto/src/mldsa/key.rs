// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA key types.
//!
//! This module defines the signing and verifying key types, in the encodings
//! FIPS 204 specifies and the HSM wire protocol carries: the private key is the
//! *expanded* signing key, and the public key is the encoded verifying key.
//!
//! Both types carry their [`MlDsaVariant`] alongside the bytes so that an
//! operation cannot silently pair a key with the wrong parameter set.
//!
//! # The expanded signing key
//!
//! `ml-dsa` deprecates the expanded key form in favour of the 32-byte seed.
//! This code uses it anyway because the HSM wire format already does: the masked
//! key blob stores seed followed by expanded key, and signing is handed only the
//! expanded half, so that it does not repeat the key expansion on every call.
//! Switching would change the on-wire blob and break every key already issued,
//! so the deprecation is acknowledged and overridden here rather than followed.
#![allow(deprecated)]

use ml_dsa::EncodedVerifyingKey;
use ml_dsa::ExpandedSigningKey;
use ml_dsa::ExpandedSigningKeyBytes;
use ml_dsa::MlDsa44;
use ml_dsa::MlDsa65;
use ml_dsa::MlDsa87;
use ml_dsa::MlDsaParams;
use ml_dsa::SigningKey as MlDsaSigningKey;

use super::*;

/// An ML-DSA signing key, in expanded form.
///
/// Created from a seed with [`from_seed`](Self::from_seed), or from an existing
/// encoding with [`ImportableKey::from_bytes`].
#[derive(Clone)]
pub struct MlDsaPrivateKey {
    variant: MlDsaVariant,
    expanded: Vec<u8>,
}

impl MlDsaPrivateKey {
    /// Generates a signing key from a FIPS 204 `xi` seed.
    ///
    /// Key generation is deterministic: the same seed and parameter set always
    /// produce the same key.
    ///
    /// # Arguments
    ///
    /// * `variant` - The parameter set to generate for
    /// * `seed` - The 32-byte seed
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsaKeyGenError`] if `seed` is not
    /// [`MLDSA_SEED_LEN`] bytes.
    pub fn from_seed(variant: MlDsaVariant, seed: &[u8]) -> Result<Self, CryptoError> {
        fn inner<P: MlDsaParams>(seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let xi = seed.try_into().map_err(|_| CryptoError::MlDsaKeyGenError)?;
            Ok(MlDsaSigningKey::<P>::from_seed(xi)
                .expanded_key()
                .to_expanded()
                .to_vec())
        }

        let expanded = dispatch!(variant, inner(seed))?;
        Ok(Self { variant, expanded })
    }

    /// Returns the parameter set this key belongs to.
    pub fn variant(&self) -> MlDsaVariant {
        self.variant
    }

    /// Borrows the expanded key bytes.
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.expanded
    }
}

impl Key for MlDsaPrivateKey {
    /// Returns the expanded key length in bytes: 2560, 4032 or 4896.
    fn size(&self) -> usize {
        self.expanded.len()
    }

    /// Returns the expanded key length in bits.
    fn bits(&self) -> usize {
        self.expanded.len() * 8
    }
}

/// Marks this type as a signing key for ML-DSA operations.
impl SigningKey for MlDsaPrivateKey {}

impl PrivateKey for MlDsaPrivateKey {
    type PublicKey = MlDsaPublicKey;

    /// Derives the verifying key from this signing key.
    ///
    /// The expanded key retains everything needed to recompute the public half,
    /// so this does not require the original seed.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsaKeyGenError`] if the stored bytes are not a
    /// valid expanded key for this key's parameter set.
    fn public_key(&self) -> Result<Self::PublicKey, CryptoError> {
        fn inner<P: MlDsaParams>(expanded: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let enc = ExpandedSigningKeyBytes::<P>::try_from(expanded)
                .map_err(|_| CryptoError::MlDsaKeyGenError)?;
            let sk = ExpandedSigningKey::<P>::from_expanded(&enc);
            Ok(sk.verifying_key().encode().to_vec())
        }

        let encoded = dispatch!(self.variant, inner(&self.expanded))?;
        Ok(MlDsaPublicKey {
            variant: self.variant,
            encoded,
        })
    }
}

impl ImportableKey for MlDsaPrivateKey {
    /// Imports an expanded signing key.
    ///
    /// The parameter set is recovered from the length, which is unambiguous
    /// across the three sets.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsaKeyImportError`] if `bytes` is not a valid
    /// expanded-key length for any parameter set.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let variant =
            MlDsaVariant::from_sec_key_len(bytes.len()).ok_or(CryptoError::MlDsaKeyImportError)?;
        Ok(Self {
            variant,
            expanded: bytes.to_vec(),
        })
    }
}

impl ExportableKey for MlDsaPrivateKey {
    /// Exports the expanded signing key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required size.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsaBufferTooSmall`] if the supplied buffer is
    /// shorter than the key.
    ///
    /// # Security
    ///
    /// This exports private key material; the caller is responsible for
    /// protecting and zeroizing the result.
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        write_key(&self.expanded, bytes, CryptoError::MlDsaBufferTooSmall)
    }
}

/// An ML-DSA verifying key, in the FIPS 204 encoding.
#[derive(Clone)]
pub struct MlDsaPublicKey {
    variant: MlDsaVariant,
    encoded: Vec<u8>,
}

impl MlDsaPublicKey {
    /// Returns the parameter set this key belongs to.
    pub fn variant(&self) -> MlDsaVariant {
        self.variant
    }

    /// Borrows the encoded key bytes.
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

impl Key for MlDsaPublicKey {
    /// Returns the encoded key length in bytes: 1312, 1952 or 2592.
    fn size(&self) -> usize {
        self.encoded.len()
    }

    /// Returns the encoded key length in bits.
    fn bits(&self) -> usize {
        self.encoded.len() * 8
    }
}

/// Marks this type as a verification key for ML-DSA operations.
impl VerificationKey for MlDsaPublicKey {}

/// Marks this type as the public half of an ML-DSA key pair.
impl PublicKey for MlDsaPublicKey {}

impl ImportableKey for MlDsaPublicKey {
    /// Imports an encoded verifying key.
    ///
    /// The parameter set is recovered from the length, which is unambiguous
    /// across the three sets. The encoding is validated here rather than at
    /// first use, so that an unusable key is rejected at import.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsaKeyImportError`] if `bytes` is not a valid
    /// encoded verifying key for any parameter set.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        fn inner<P: MlDsaParams>(bytes: &[u8]) -> Result<(), CryptoError> {
            EncodedVerifyingKey::<P>::try_from(bytes)
                .map(|_| ())
                .map_err(|_| CryptoError::MlDsaKeyImportError)
        }

        let variant =
            MlDsaVariant::from_pub_key_len(bytes.len()).ok_or(CryptoError::MlDsaKeyImportError)?;
        dispatch!(variant, inner(bytes))?;
        Ok(Self {
            variant,
            encoded: bytes.to_vec(),
        })
    }
}

impl ExportableKey for MlDsaPublicKey {
    /// Exports the encoded verifying key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required size.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsaBufferTooSmall`] if the supplied buffer is
    /// shorter than the key.
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        write_key(&self.encoded, bytes, CryptoError::MlDsaBufferTooSmall)
    }
}

/// Implements the crate's optional-buffer export contract.
///
/// `None` queries the required size; `Some` writes and returns the length.
fn write_key(src: &[u8], dst: Option<&mut [u8]>, err: CryptoError) -> Result<usize, CryptoError> {
    let Some(dst) = dst else {
        return Ok(src.len());
    };
    let dst = dst.get_mut(..src.len()).ok_or(err)?;
    dst.copy_from_slice(src);
    Ok(src.len())
}
