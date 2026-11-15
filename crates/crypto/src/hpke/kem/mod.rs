// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE KEMs — Encap / Decap / DeriveKeyPair dispatch over the suite's
//! KEM.
//!
//! * `dh` — DHKEM(P-256/P-384/P-521) (RFC 9180 §4.1), including the
//!   Auth variants.
//! * `mlkem` — ML-KEM-1024 (draft-ietf-hpke-pq §3).
//! * `hybrid` — MLKEM1024-P384 (draft-ietf-hpke-pq §4,
//!   draft-irtf-cfrg-concrete-hybrid-kems).
//!
//! The post-quantum KEMs have no Auth variants; [`auth_encap`] /
//! [`auth_decap`] reject them.

pub(crate) mod dh;
mod hybrid;
mod mlkem;

use zeroize::Zeroizing;

use super::keys::HpkeKeyPair;
use super::keys::HpkePrivateKey;
use super::keys::HpkePublicKey;
use super::suite::HpkeSuite;
use super::suite::KemKind;
use crate::CryptoError;
use crate::EccPrivateKey;
use crate::EccPublicKey;
use crate::PrivateKey;
use crate::Rng;

/// Encap output: `(enc, shared_secret)`.
pub(crate) type EncapOutput = (Vec<u8>, Zeroizing<Vec<u8>>);

fn is_dh(suite: HpkeSuite) -> bool {
    matches!(
        suite.kem(),
        KemKind::DhP256 | KemKind::DhP384 | KemKind::DhP521
    )
}

/// Encap (Base / PSK modes).
pub(crate) fn encap(suite: HpkeSuite, pk_r: HpkePublicKey<'_>) -> Result<EncapOutput, CryptoError> {
    match (suite.kem(), pk_r) {
        (KemKind::DhP256 | KemKind::DhP384 | KemKind::DhP521, HpkePublicKey::Ecc(pk)) => {
            dh::encap(suite, pk)
        }
        (KemKind::MlKem1024, HpkePublicKey::MlKem1024(pk)) => mlkem::encaps(pk),
        (KemKind::MlKem1024P384, HpkePublicKey::MlKem1024P384(pk)) => hybrid::encap(pk),
        _ => Err(CryptoError::HpkeInvalidPublicKey),
    }
}

/// Decap (Base / PSK modes). The post-quantum KEMs derive everything
/// from the seed, so `pk_r` only has to be of the matching kind.
pub(crate) fn decap(
    suite: HpkeSuite,
    enc: &[u8],
    sk_r: HpkePrivateKey<'_>,
    pk_r: HpkePublicKey<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    match (suite.kem(), sk_r, pk_r) {
        (
            KemKind::DhP256 | KemKind::DhP384 | KemKind::DhP521,
            HpkePrivateKey::Ecc(sk),
            HpkePublicKey::Ecc(pk),
        ) => dh::decap(suite, enc, sk, pk),
        (KemKind::MlKem1024, HpkePrivateKey::MlKem1024(seed), HpkePublicKey::MlKem1024(_)) => {
            mlkem::decaps(seed, enc)
        }
        (
            KemKind::MlKem1024P384,
            HpkePrivateKey::MlKem1024P384(seed),
            HpkePublicKey::MlKem1024P384(_),
        ) => hybrid::decap(enc, seed),
        (_, _, pk) if !pk.matches(suite) => Err(CryptoError::HpkeInvalidPublicKey),
        _ => Err(CryptoError::HpkeInvalidPrivateKey),
    }
}

/// AuthEncap (Auth / AuthPSK modes, DHKEM only).
pub(crate) fn auth_encap(
    suite: HpkeSuite,
    pk_r: HpkePublicKey<'_>,
    sk_s: &EccPrivateKey,
) -> Result<EncapOutput, CryptoError> {
    if !suite.supports_auth() {
        return Err(CryptoError::HpkeInvalidModeConfig);
    }
    match pk_r {
        HpkePublicKey::Ecc(pk) => dh::auth_encap(suite, pk, sk_s),
        _ => Err(CryptoError::HpkeInvalidPublicKey),
    }
}

/// AuthDecap (Auth / AuthPSK modes, DHKEM only).
pub(crate) fn auth_decap(
    suite: HpkeSuite,
    enc: &[u8],
    sk_r: HpkePrivateKey<'_>,
    pk_r: HpkePublicKey<'_>,
    pk_s: &EccPublicKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if !suite.supports_auth() {
        return Err(CryptoError::HpkeInvalidModeConfig);
    }
    match (sk_r, pk_r) {
        (HpkePrivateKey::Ecc(sk), HpkePublicKey::Ecc(pk)) => {
            dh::auth_decap(suite, enc, sk, pk, pk_s)
        }
        (HpkePrivateKey::Ecc(_), _) => Err(CryptoError::HpkeInvalidPublicKey),
        _ => Err(CryptoError::HpkeInvalidPrivateKey),
    }
}

/// Validate a serialized post-quantum public key for `suite`.
pub(crate) fn check_pq_pk(suite: HpkeSuite, pk: &[u8]) -> Result<(), CryptoError> {
    match suite.kem() {
        KemKind::MlKem1024 => mlkem::check_ek(pk),
        KemKind::MlKem1024P384 => hybrid::check_pk(pk),
        _ => Err(CryptoError::HpkeInvalidPublicKey),
    }
}

/// `DeriveKeyPair(ikm)` for the suite's KEM.
pub(crate) fn derive_keypair(suite: HpkeSuite, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    let kem_suite_id = suite.kem_suite_id();
    match suite.kem() {
        KemKind::DhP256 | KemKind::DhP384 | KemKind::DhP521 => {
            let (sk, pk) = dh::derive_keypair(suite, ikm)?;
            Ok(HpkeKeyPair::ecc(suite, sk, pk))
        }
        KemKind::MlKem1024 => {
            let (seed, pk) = mlkem::derive_keypair(&kem_suite_id, ikm)?;
            Ok(HpkeKeyPair::seed(suite, seed, pk))
        }
        KemKind::MlKem1024P384 => {
            let (seed, pk) = hybrid::derive_keypair(&kem_suite_id, ikm)?;
            Ok(HpkeKeyPair::seed(suite, seed, pk))
        }
    }
}

/// Attempts at a fresh hybrid seed before giving up. A random seed
/// yields an out-of-range P-384 scalar with probability ~2^-190.
const HYBRID_KEYGEN_ATTEMPTS: usize = 4;

/// `GenerateKeyPair()` for the suite's KEM.
pub(crate) fn generate_keypair(suite: HpkeSuite) -> Result<HpkeKeyPair, CryptoError> {
    if is_dh(suite) {
        let curve = suite.kem_curve().ok_or(CryptoError::HpkeUnsupportedSuite)?;
        let sk = EccPrivateKey::from_curve(curve)?;
        let pk = sk.public_key()?;
        return Ok(HpkeKeyPair::ecc(suite, sk, pk));
    }
    let mut seed = Zeroizing::new(vec![0u8; suite.nsk()]);
    let attempts = match suite.kem() {
        KemKind::MlKem1024P384 => HYBRID_KEYGEN_ATTEMPTS,
        _ => 1,
    };
    for _ in 0..attempts {
        Rng::rand_bytes(&mut seed)?;
        let pk = match suite.kem() {
            KemKind::MlKem1024 => mlkem::public_key(&seed),
            _ => hybrid::public_key(&seed),
        };
        match pk {
            Ok(pk) => return Ok(HpkeKeyPair::seed(suite, seed, pk)),
            Err(CryptoError::HpkeInvalidPrivateKey) => {}
            Err(e) => return Err(e),
        }
    }
    Err(CryptoError::HpkeInvalidPrivateKey)
}
