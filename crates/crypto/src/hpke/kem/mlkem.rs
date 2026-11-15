// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-KEM-1024 HPKE KEM (draft-ietf-hpke-pq §3), `kem_id = 0x0042`.
//!
//! The private key is the 64-byte FIPS 203 seed `d ‖ z`; the public
//! key and `enc` are the 1568-byte encapsulation key and ciphertext.
//! The KEM shared secret is used directly as `shared_secret`.

use zeroize::Zeroizing;

use super::super::kdf::labeled_derive;
use crate::CryptoError;
use crate::DecapsulateOp;
use crate::EncapsulateOp;
use crate::ExportableKey;
use crate::ImportableKey;
use crate::MlKemAlgo;
use crate::MlKemPrivateKey;
use crate::MlKemPublicKey;
use crate::MlKemVariant;
use crate::PrivateKey;

const VARIANT: MlKemVariant = MlKemVariant::MlKem1024;

/// Encapsulation-key length (`Npk`).
pub(super) const EK_LEN: usize = 1568;

/// Ciphertext length (`Nenc`).
pub(super) const CT_LEN: usize = 1568;

/// Seed (`d ‖ z`) length (`Nsk`).
pub(super) const SEED_LEN: usize = 64;

/// ML-KEM shared-secret length.
pub(super) const SS_LEN: usize = 32;

/// ML-KEM modulus.
const Q: u16 = 3329;

/// FIPS 203 §7.2 encapsulation-key modulus check: every packed 12-bit
/// coefficient of `ek[..1536]` must be `< q`.
pub(super) fn check_ek(ek: &[u8]) -> Result<(), CryptoError> {
    if ek.len() != EK_LEN {
        return Err(CryptoError::HpkeInvalidPublicKey);
    }
    // The trailing 32 bytes are the public seed `rho`.
    for c in ek[..EK_LEN - 32].chunks_exact(3) {
        let lo = u16::from(c[0]) | (u16::from(c[1] & 0x0f) << 8);
        let hi = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
        if lo >= Q || hi >= Q {
            return Err(CryptoError::HpkeInvalidPublicKey);
        }
    }
    Ok(())
}

/// `ML-KEM.Encaps(ek)` → `(ct, ss)`.
pub(super) fn encaps(ek: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    check_ek(ek)?;
    let key = MlKemPublicKey::from_bytes(ek).map_err(|_| CryptoError::HpkeInvalidPublicKey)?;
    let mut ct = vec![0u8; CT_LEN];
    let mut ss = Zeroizing::new(vec![0u8; SS_LEN]);
    MlKemAlgo::new()
        .encapsulate(&key, Some(&mut ct), Some(&mut ss))
        .map_err(|_| CryptoError::HpkeKemEncapFailed)?;
    Ok((ct, ss))
}

/// Expand a 64-byte seed into the decapsulation key.
fn expand(seed: &[u8]) -> Result<MlKemPrivateKey, CryptoError> {
    if seed.len() != SEED_LEN {
        return Err(CryptoError::HpkeInvalidPrivateKey);
    }
    MlKemPrivateKey::from_seed(VARIANT, seed).map_err(|_| CryptoError::HpkeInvalidPrivateKey)
}

/// `ML-KEM.Decaps(dk(seed), ct)` → `ss`.
pub(super) fn decaps(seed: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if ct.len() != CT_LEN {
        return Err(CryptoError::HpkeKemDecapFailed);
    }
    let dk = expand(seed)?;
    let mut ss = Zeroizing::new(vec![0u8; SS_LEN]);
    MlKemAlgo::new()
        .decapsulate(&dk, ct, Some(&mut ss))
        .map_err(|_| CryptoError::HpkeKemDecapFailed)?;
    Ok(ss)
}

/// Encapsulation key for a 64-byte seed.
pub(super) fn public_key(seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let pk = expand(seed)?
        .public_key()
        .map_err(|_| CryptoError::HpkeInvalidPrivateKey)?;
    let mut ek = vec![0u8; EK_LEN];
    if pk.to_bytes(Some(&mut ek))? != EK_LEN {
        return Err(CryptoError::HpkeInvalidPrivateKey);
    }
    Ok(ek)
}

/// `DeriveKeyPair(ikm)`: `dk = LabeledDerive(ikm, "DeriveKeyPair", "",
/// 64)` under the KEM suite id. Returns `(seed, ek)`.
pub(super) fn derive_keypair(
    kem_suite_id: &[u8],
    ikm: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CryptoError> {
    let mut seed = Zeroizing::new(vec![0u8; SEED_LEN]);
    labeled_derive(kem_suite_id, &[ikm], b"DeriveKeyPair", &[], &mut seed)?;
    let ek = public_key(&seed)?;
    Ok((seed, ek))
}
