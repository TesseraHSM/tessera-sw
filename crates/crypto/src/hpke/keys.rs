// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE key handles.
//!
//! DHKEM suites use the typed [`EccPrivateKey`] / [`EccPublicKey`]
//! handles. The post-quantum KEMs have no `tsra_crypto` key type that
//! matches their HPKE serialization, so they use the raw HPKE
//! encodings:
//!
//! | KEM             | Public key                 | Private key           |
//! |-----------------|----------------------------|-----------------------|
//! | DHKEM(P-N)      | [`EccPublicKey`]           | [`EccPrivateKey`]     |
//! | ML-KEM-1024     | 1568-byte `ek`             | 64-byte `d ‖ z` seed  |
//! | MLKEM1024-P384  | 1665-byte `ek_PQ ‖ ek_T`   | 32-byte seed          |
//!
//! `From<&EccPublicKey>` / `From<&EccPrivateKey>` let DHKEM callers
//! pass typed keys straight into the config constructors.

use std::fmt;

use zeroize::Zeroizing;

use super::kem;
use super::suite::HpkeSuite;
use super::suite::KemKind;
use crate::CryptoError;
use crate::EccPrivateKey;
use crate::EccPublicKey;

/// Borrowed HPKE recipient public key.
#[derive(Debug, Clone, Copy)]
pub enum HpkePublicKey<'a> {
    /// DHKEM public key.
    Ecc(&'a EccPublicKey),
    /// ML-KEM-1024 encapsulation key (1568 bytes).
    MlKem1024(&'a [u8]),
    /// MLKEM1024-P384 public key `ek_PQ ‖ SEC1(ek_T)` (1665 bytes).
    MlKem1024P384(&'a [u8]),
}

impl<'a> From<&'a EccPublicKey> for HpkePublicKey<'a> {
    fn from(pk: &'a EccPublicKey) -> Self {
        Self::Ecc(pk)
    }
}

impl HpkePublicKey<'_> {
    /// `true` if this key kind belongs to `suite`'s KEM.
    pub(crate) fn matches(&self, suite: HpkeSuite) -> bool {
        matches!(
            (suite.kem(), self),
            (
                KemKind::DhP256 | KemKind::DhP384 | KemKind::DhP521,
                Self::Ecc(_)
            ) | (KemKind::MlKem1024, Self::MlKem1024(_))
                | (KemKind::MlKem1024P384, Self::MlKem1024P384(_))
        )
    }

    /// Serialize the public key: SEC1 uncompressed for ECC keys, the
    /// raw bytes for the post-quantum KEMs.
    ///
    /// # Errors
    ///
    /// Propagates [`CryptoError`] from the ECC coordinate export.
    pub fn to_vec(&self) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Ecc(pk) => kem::dh::encode_pk(crate::EccKeyOp::curve(*pk), pk),
            Self::MlKem1024(pk) | Self::MlKem1024P384(pk) => Ok(pk.to_vec()),
        }
    }

    /// Check that this key is usable with `suite`: kind, length,
    /// FIPS 203 encapsulation-key check and P-384 point validation.
    ///
    /// # Errors
    ///
    /// [`CryptoError::HpkeInvalidPublicKey`] if the key is rejected.
    pub fn validate(&self, suite: HpkeSuite) -> Result<(), CryptoError> {
        if !self.matches(suite) {
            return Err(CryptoError::HpkeInvalidPublicKey);
        }
        match self {
            Self::Ecc(pk) => {
                if Some(crate::EccKeyOp::curve(*pk)) == suite.kem_curve() {
                    Ok(())
                } else {
                    Err(CryptoError::HpkeInvalidPublicKey)
                }
            }
            Self::MlKem1024(pk) | Self::MlKem1024P384(pk) => kem::check_pq_pk(suite, pk),
        }
    }
}

/// Borrowed HPKE recipient private key.
///
/// The `Debug` output never includes seed bytes.
#[derive(Clone, Copy)]
pub enum HpkePrivateKey<'a> {
    /// DHKEM private key.
    Ecc(&'a EccPrivateKey),
    /// ML-KEM-1024 `d ‖ z` seed (64 bytes).
    MlKem1024(&'a [u8]),
    /// MLKEM1024-P384 seed (32 bytes).
    MlKem1024P384(&'a [u8]),
}

impl<'a> From<&'a EccPrivateKey> for HpkePrivateKey<'a> {
    fn from(sk: &'a EccPrivateKey) -> Self {
        Self::Ecc(sk)
    }
}

impl fmt::Debug for HpkePrivateKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ecc(sk) => f.debug_tuple("Ecc").field(sk).finish(),
            Self::MlKem1024(_) => f.write_str("MlKem1024(<redacted>)"),
            Self::MlKem1024P384(_) => f.write_str("MlKem1024P384(<redacted>)"),
        }
    }
}

enum KeyPairInner {
    Ecc {
        sk: EccPrivateKey,
        pk: EccPublicKey,
    },
    Seed {
        seed: Zeroizing<Vec<u8>>,
        pk: Vec<u8>,
    },
}

/// Owned HPKE key pair produced by [`HpkeSuite::generate_keypair`] or
/// [`HpkeSuite::derive_keypair`].
///
/// Post-quantum seeds are zeroized on drop and never printed by
/// `Debug`.
pub struct HpkeKeyPair {
    suite: HpkeSuite,
    inner: KeyPairInner,
}

impl HpkeKeyPair {
    pub(crate) fn ecc(suite: HpkeSuite, sk: EccPrivateKey, pk: EccPublicKey) -> Self {
        Self {
            suite,
            inner: KeyPairInner::Ecc { sk, pk },
        }
    }

    pub(crate) fn seed(suite: HpkeSuite, seed: Zeroizing<Vec<u8>>, pk: Vec<u8>) -> Self {
        Self {
            suite,
            inner: KeyPairInner::Seed { seed, pk },
        }
    }

    /// Suite the key pair was generated for.
    pub fn suite(&self) -> HpkeSuite {
        self.suite
    }

    /// Borrow the public key.
    pub fn public_key(&self) -> HpkePublicKey<'_> {
        match (&self.inner, self.suite.kem()) {
            (KeyPairInner::Ecc { pk, .. }, _) => HpkePublicKey::Ecc(pk),
            (KeyPairInner::Seed { pk, .. }, KemKind::MlKem1024) => HpkePublicKey::MlKem1024(pk),
            (KeyPairInner::Seed { pk, .. }, _) => HpkePublicKey::MlKem1024P384(pk),
        }
    }

    /// Borrow the private key.
    pub fn private_key(&self) -> HpkePrivateKey<'_> {
        match (&self.inner, self.suite.kem()) {
            (KeyPairInner::Ecc { sk, .. }, _) => HpkePrivateKey::Ecc(sk),
            (KeyPairInner::Seed { seed, .. }, KemKind::MlKem1024) => {
                HpkePrivateKey::MlKem1024(seed)
            }
            (KeyPairInner::Seed { seed, .. }, _) => HpkePrivateKey::MlKem1024P384(seed),
        }
    }
}

impl fmt::Debug for HpkeKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HpkeKeyPair")
            .field("suite", &self.suite)
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl HpkeSuite {
    /// Generate a fresh random key pair for this suite's KEM.
    ///
    /// # Errors
    ///
    /// Propagates [`CryptoError`] from the RNG or key generation.
    pub fn generate_keypair(&self) -> Result<HpkeKeyPair, CryptoError> {
        kem::generate_keypair(*self)
    }

    /// `DeriveKeyPair(ikm)` (RFC 9180 §7.1.3, draft-ietf-hpke-pq):
    /// deterministically derive a key pair from `ikm`, which should
    /// carry at least [`HpkeSuite::nsk`] bytes of entropy.
    ///
    /// # Errors
    ///
    /// [`CryptoError::HpkeInvalidPrivateKey`] if no valid key can be
    /// derived (DHKEM after 256 candidates, or an out-of-range hybrid
    /// P-384 scalar); other [`CryptoError`] variants from the KDF.
    pub fn derive_keypair(&self, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
        kem::derive_keypair(*self, ikm)
    }
}
