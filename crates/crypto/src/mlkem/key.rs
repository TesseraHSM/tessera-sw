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
use zeroize::Zeroizing;

use super::*;

/// An ML-KEM decapsulation key, in expanded form.
///
/// Created from a seed with [`from_seed`](Self::from_seed), or from an existing
/// encoding with [`ImportableKey::from_bytes`].
#[derive(Clone)]
pub struct MlKemPrivateKey {
    variant: MlKemVariant,
    expanded: Zeroizing<Vec<u8>>,
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
        if seed.len() != MLKEM_SEED_LEN {
            return Err(CryptoError::MlKemKeyGenError);
        }
        let expanded = platform::expand_key(variant, seed)?;
        Ok(Self { variant, expanded })
    }

    /// Returns the parameter set this key belongs to.
    pub fn variant(&self) -> MlKemVariant {
        self.variant
    }

    /// Borrows the expanded key bytes.
    #[cfg(any(target_os = "windows", ossl350))]
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
        let encoded = platform::public_key(self.variant, &self.expanded)?;
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
            expanded: Zeroizing::new(bytes.to_vec()),
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
    #[cfg(any(target_os = "windows", ossl350))]
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
        platform::validate_public_key(variant, bytes)?;
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
