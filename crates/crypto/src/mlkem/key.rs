// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-KEM key types.
//!
//! This module defines the encapsulation and decapsulation key types, in the
//! encodings FIPS 203 specifies and the HSM wire protocol carries: the private
//! key is the *expanded* decapsulation key, and the public key is the encoded
//! encapsulation key.
//!
//! Both types carry their [`MlKemVariant`] alongside the bytes so that an
//! operation cannot silently pair a key with the wrong parameter set.
//!
//! # The expanded decapsulation key
//!
//! `ml-kem` deprecates the expanded key form in favour of the 64-byte seed, and
//! for a new protocol the seed would be the right choice — it is smaller and
//! cannot be internally inconsistent. This code uses the expanded form anyway
//! because the HSM wire format already does: the masked key blob stores seed
//! followed by expanded key, and decapsulation is handed only the expanded half.
//! Switching would change the on-wire blob and break every key already issued,
//! so the deprecation is acknowledged and overridden here rather than followed.
#![allow(deprecated)]

use ml_kem::ExpandedKeyEncoding;
use ml_kem::Key as MlKemEncoded;
use ml_kem::KeyExport;

use super::*;

/// An ML-KEM decapsulation key, in expanded form.
///
/// Created from a seed with [`from_seed`](Self::from_seed), or from an existing
/// encoding with [`ImportableKey::from_bytes`].
#[derive(Clone)]
pub struct MlKemPrivateKey {
    variant: MlKemVariant,
    expanded: Vec<u8>,
}

impl MlKemPrivateKey {
    /// Generates a decapsulation key from a FIPS 203 `d ‖ z` seed.
    ///
    /// Key generation is deterministic: the same seed and parameter set always
    /// produce the same key.
    ///
    /// # Arguments
    ///
    /// * `variant` - The parameter set to generate for
    /// * `seed` - The 64-byte seed
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlKemKeyGenError`] if `seed` is not
    /// [`MLKEM_SEED_LEN`] bytes.
    pub fn from_seed(variant: MlKemVariant, seed: &[u8]) -> Result<Self, CryptoError> {
        let expanded = dispatch!(variant, |p| {
            let s = seed.try_into().map_err(|_| CryptoError::MlKemKeyGenError)?;
            Ok::<_, CryptoError>(
                p::DecapsulationKey::from_seed(s)
                    .to_expanded_bytes()
                    .to_vec(),
            )
        })?;
        Ok(Self { variant, expanded })
    }

    /// Returns the parameter set this key belongs to.
    pub fn variant(&self) -> MlKemVariant {
        self.variant
    }

    /// Borrows the expanded key bytes.
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.expanded
    }
}

impl Key for MlKemPrivateKey {
    /// Returns the expanded key length in bytes: 1632, 2400 or 3168.
    fn size(&self) -> usize {
        self.expanded.len()
    }

    /// Returns the expanded key length in bits.
    fn bits(&self) -> usize {
        self.expanded.len() * 8
    }
}

/// Marks this type as a decapsulation key for ML-KEM operations.
impl DecapsulationKey for MlKemPrivateKey {}

impl PrivateKey for MlKemPrivateKey {
    type PublicKey = MlKemPublicKey;

    /// Derives the encapsulation key from this decapsulation key.
    ///
    /// The expanded key retains the public half, so this does not require the
    /// original seed.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlKemKeyGenError`] if the stored bytes are not a
    /// valid expanded key for this key's parameter set.
    fn public_key(&self) -> Result<Self::PublicKey, CryptoError> {
        let expanded = &self.expanded;
        let encoded = dispatch!(self.variant, |p| {
            let enc = p::ExpandedDecapsulationKey::try_from(expanded.as_slice())
                .map_err(|_| CryptoError::MlKemKeyGenError)?;
            let dk = p::DecapsulationKey::from_expanded_bytes(&enc)
                .map_err(|_| CryptoError::MlKemKeyGenError)?;
            Ok::<_, CryptoError>(dk.encapsulation_key().to_bytes().to_vec())
        })?;
        Ok(MlKemPublicKey {
            variant: self.variant,
            encoded,
        })
    }
}

impl ImportableKey for MlKemPrivateKey {
    /// Imports an expanded decapsulation key.
    ///
    /// The parameter set is recovered from the length, which is unambiguous
    /// across the three sets.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlKemKeyImportError`] if `bytes` is not a valid
    /// expanded-key length for any parameter set.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let variant =
            MlKemVariant::from_sec_key_len(bytes.len()).ok_or(CryptoError::MlKemKeyImportError)?;
        Ok(Self {
            variant,
            expanded: bytes.to_vec(),
        })
    }
}

impl ExportableKey for MlKemPrivateKey {
    /// Exports the expanded decapsulation key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required size.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlKemBufferTooSmall`] if the supplied buffer is
    /// shorter than the key.
    ///
    /// # Security
    ///
    /// This exports private key material; the caller is responsible for
    /// protecting and zeroizing the result.
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        write_key(&self.expanded, bytes, CryptoError::MlKemBufferTooSmall)
    }
}

/// An ML-KEM encapsulation key, in the FIPS 203 encoding.
#[derive(Clone)]
pub struct MlKemPublicKey {
    variant: MlKemVariant,
    encoded: Vec<u8>,
}

impl MlKemPublicKey {
    /// Returns the parameter set this key belongs to.
    pub fn variant(&self) -> MlKemVariant {
        self.variant
    }

    /// Borrows the encoded key bytes.
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

impl Key for MlKemPublicKey {
    /// Returns the encoded key length in bytes: 800, 1184 or 1568.
    fn size(&self) -> usize {
        self.encoded.len()
    }

    /// Returns the encoded key length in bits.
    fn bits(&self) -> usize {
        self.encoded.len() * 8
    }
}

/// Marks this type as an encapsulation key for ML-KEM operations.
impl EncapsulationKey for MlKemPublicKey {}

/// Marks this type as the public half of an ML-KEM key pair.
impl PublicKey for MlKemPublicKey {}

impl ImportableKey for MlKemPublicKey {
    /// Imports an encoded encapsulation key.
    ///
    /// The parameter set is recovered from the length, which is unambiguous
    /// across the three sets. The encoding is validated here rather than at
    /// first use, so that an unusable key is rejected at import.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlKemKeyImportError`] if `bytes` is not a valid
    /// encapsulation key for any parameter set.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let variant =
            MlKemVariant::from_pub_key_len(bytes.len()).ok_or(CryptoError::MlKemKeyImportError)?;
        dispatch!(variant, |p| {
            let enc = MlKemEncoded::<p::EncapsulationKey>::try_from(bytes)
                .map_err(|_| CryptoError::MlKemKeyImportError)?;
            p::EncapsulationKey::new(&enc).map_err(|_| CryptoError::MlKemKeyImportError)?;
            Ok::<_, CryptoError>(())
        })?;
        Ok(Self {
            variant,
            encoded: bytes.to_vec(),
        })
    }
}

impl ExportableKey for MlKemPublicKey {
    /// Exports the encoded encapsulation key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required size.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlKemBufferTooSmall`] if the supplied buffer is
    /// shorter than the key.
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        write_key(&self.encoded, bytes, CryptoError::MlKemBufferTooSmall)
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
