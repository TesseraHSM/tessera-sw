// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MLKEM1024-P384 hybrid HPKE KEM (draft-ietf-hpke-pq §4),
//! `kem_id = 0x0051`.
//!
//! The KEM is the CG-framework hybrid of
//! draft-irtf-cfrg-concrete-hybrid-kems: ML-KEM-1024 with the P-384
//! nominal group, SHAKE256 as the PRG and SHA3-256 as the KDF.
//!
//! ```text
//! sk  = seed (32 bytes)
//! seed_full        = SHAKE256(seed, 112)
//! seed_PQ, seed_T  = seed_full[..64], seed_full[64..]
//! dk_PQ, ek_PQ     = ML-KEM-1024.KeyGen_internal(seed_PQ)
//! dk_T             = OS2IP(seed_T)          (error if 0 or >= n)
//! ek_T             = SEC1(dk_T * G)
//! pk  = ek_PQ ‖ ek_T                        (1568 + 97 bytes)
//! enc = ct_PQ ‖ ct_T                        (1568 + 97 bytes)
//! ss  = SHA3-256(ss_PQ ‖ ss_T ‖ ct_T ‖ ek_T ‖ "MLKEM1024-P384")
//! ```
//!
//! `ct_T` is an ephemeral P-384 public key and `ss_T` the big-endian
//! x-coordinate of the ECDH point.

use std::num::NonZeroUsize;

use zeroize::Zeroizing;

use super::dh;
use super::mlkem;
use crate::CryptoError;
use crate::EccCurve;
use crate::EccPrivateKey;
use crate::HashAlgo;
use crate::Hasher;
use crate::PrivateKey;

const LABEL: &[u8] = b"MLKEM1024-P384";

const CURVE: EccCurve = EccCurve::P384;

/// P-384 coordinate / scalar length.
const COORD: usize = 48;

/// SEC1 uncompressed P-384 element length.
const ELEM: usize = 1 + 2 * COORD;

/// Hybrid seed length (`Nsk`).
pub(super) const SEED_LEN: usize = 32;

/// Public-key / `enc` length.
const NPK: usize = mlkem::EK_LEN + ELEM;

const SEED_FULL_LEN: NonZeroUsize = match NonZeroUsize::new(mlkem::SEED_LEN + COORD) {
    Some(n) => n,
    None => panic!("zero SHAKE output"),
};

/// Expanded hybrid decapsulation key.
struct Expanded {
    seed_pq: Zeroizing<Vec<u8>>,
    dk_t: EccPrivateKey,
    ek_t: Vec<u8>,
}

/// `expandDecapsKey(seed)`.
fn expand(seed: &[u8]) -> Result<Expanded, CryptoError> {
    if seed.len() != SEED_LEN {
        return Err(CryptoError::HpkeInvalidPrivateKey);
    }
    let mut seed_full = Zeroizing::new(vec![0u8; SEED_FULL_LEN.get()]);
    Hasher::hash(
        &mut HashAlgo::shake256(SEED_FULL_LEN),
        seed,
        Some(&mut seed_full),
    )?;
    let (seed_pq, seed_t) = seed_full.split_at(mlkem::SEED_LEN);
    // Single attempt: out-of-range scalars are an error, not a retry.
    let dk_t = EccPrivateKey::from_scalar(CURVE, seed_t)
        .map_err(|_| CryptoError::HpkeInvalidPrivateKey)?;
    let pk_t = dk_t
        .public_key()
        .map_err(|_| CryptoError::HpkeInvalidPrivateKey)?;
    let ek_t = dh::encode_pk(CURVE, &pk_t)?;
    Ok(Expanded {
        seed_pq: Zeroizing::new(seed_pq.to_vec()),
        dk_t,
        ek_t,
    })
}

/// `SHA3-256(ss_PQ ‖ ss_T ‖ ct_T ‖ ek_T ‖ label)`.
fn combine(
    ss_pq: &[u8],
    ss_t: &[u8],
    ct_t: &[u8],
    ek_t: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut input = Zeroizing::new(Vec::with_capacity(
        ss_pq.len() + ss_t.len() + ct_t.len() + ek_t.len() + LABEL.len(),
    ));
    for part in [ss_pq, ss_t, ct_t, ek_t, LABEL] {
        input.extend_from_slice(part);
    }
    let mut ss = Zeroizing::new(vec![0u8; mlkem::SS_LEN]);
    Hasher::hash(&mut HashAlgo::sha3_256(), &input, Some(&mut ss))?;
    Ok(ss)
}

/// Validate a serialized hybrid public key.
pub(super) fn check_pk(pk: &[u8]) -> Result<(), CryptoError> {
    if pk.len() != NPK {
        return Err(CryptoError::HpkeInvalidPublicKey);
    }
    let (ek_pq, ek_t) = pk.split_at(mlkem::EK_LEN);
    mlkem::check_ek(ek_pq)?;
    dh::decode_pk(CURVE, ek_t)?;
    Ok(())
}

/// Hybrid Encap. Returns `(enc, shared_secret)`.
pub(super) fn encap(pk_r: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    if pk_r.len() != NPK {
        return Err(CryptoError::HpkeInvalidPublicKey);
    }
    let (ek_pq, ek_t) = pk_r.split_at(mlkem::EK_LEN);
    let pk_t = dh::decode_pk(CURVE, ek_t)?;

    let (mut enc, ss_pq) = mlkem::encaps(ek_pq)?;
    let (sk_e, ct_t) = dh::ephemeral(CURVE)?;
    let mut ss_t = Zeroizing::new(vec![0u8; COORD]);
    dh::ecdh(CURVE, &sk_e, &pk_t, &mut ss_t).map_err(|_| CryptoError::HpkeKemEncapFailed)?;

    let ss = combine(&ss_pq, &ss_t, &ct_t, ek_t)?;
    enc.extend_from_slice(&ct_t);
    Ok((enc, ss))
}

/// Hybrid Decap.
pub(super) fn decap(enc: &[u8], seed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if enc.len() != NPK {
        return Err(CryptoError::HpkeKemDecapFailed);
    }
    let (ct_pq, ct_t) = enc.split_at(mlkem::CT_LEN);
    let pk_e = dh::decode_pk(CURVE, ct_t)?;
    let dk = expand(seed)?;

    let ss_pq = mlkem::decaps(&dk.seed_pq, ct_pq)?;
    let mut ss_t = Zeroizing::new(vec![0u8; COORD]);
    dh::ecdh(CURVE, &dk.dk_t, &pk_e, &mut ss_t).map_err(|_| CryptoError::HpkeKemDecapFailed)?;
    combine(&ss_pq, &ss_t, ct_t, &dk.ek_t)
}

/// Serialized public key `ek_PQ ‖ ek_T` for a 32-byte seed.
pub(super) fn public_key(seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let dk = expand(seed)?;
    let mut pk = mlkem::public_key(&dk.seed_pq)?;
    pk.extend_from_slice(&dk.ek_t);
    Ok(pk)
}

/// `DeriveKeyPair(ikm)`: `seed = LabeledDerive(ikm, "DeriveKeyPair",
/// "", 32)` under the KEM suite id. Returns `(seed, pk)`.
pub(super) fn derive_keypair(
    kem_suite_id: &[u8],
    ikm: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CryptoError> {
    let mut seed = Zeroizing::new(vec![0u8; SEED_LEN]);
    super::super::kdf::labeled_derive(kem_suite_id, &[ikm], b"DeriveKeyPair", &[], &mut seed)?;
    let pk = public_key(&seed)?;
    Ok((seed, pk))
}
