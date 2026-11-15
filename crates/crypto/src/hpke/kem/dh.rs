// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DHKEM (RFC 9180 §4.1) — Encap / Decap, their Auth variants and
//! DeriveKeyPair (§7.1.3).
//!
//! All four KEM entry points produce a [`HpkeSuite::nsecret`]-byte
//! shared secret via:
//!
//! 1. One ECDH (or two for Auth) using either an ephemeral keypair
//!    (Encap / AuthEncap) or the recipient's static private key
//!    (Decap / AuthDecap).
//! 2. A `kem_context` of `enc ‖ pk_r` (Base) or `enc ‖ pk_r ‖ pk_s`
//!    (Auth) — the SEC1 uncompressed serialisations are concatenated
//!    per RFC 9180.
//! 3. `ExtractAndExpand(dh, kem_context)` (the KEM-suite-scoped HKDF).
//!
//! Public keys and the encapsulated key cross the wire as SEC1
//! uncompressed (`0x04 ‖ x ‖ y`) — see [`encode_pk`] / [`decode_pk`].

use zeroize::Zeroizing;

use super::super::kdf::labeled_expand;
use super::super::kdf::labeled_extract;
use super::super::suite::HpkeSuite;
use crate::CryptoError;
use crate::DeriveOp;
use crate::EccCurve;
use crate::EccKeyOp;
use crate::EccPrivateKey;
use crate::EccPublicKey;
use crate::EcdhAlgo;
use crate::ExportableKey;
use crate::PrivateKey;

/// SEC1 uncompressed-point tag byte (0x04).
const SEC1_UNCOMPRESSED: u8 = 0x04;

// =============================================================================
// SEC1 uncompressed encoding
// =============================================================================

/// Encode `pk` in SEC1 uncompressed form (`0x04 ‖ x ‖ y`).
pub(crate) fn encode_pk(curve: EccCurve, pk: &EccPublicKey) -> Result<Vec<u8>, CryptoError> {
    if pk.curve() != curve {
        return Err(CryptoError::HpkeInvalidPublicKey);
    }
    let coord_len = curve.point_size();
    let mut out = vec![0u8; 1 + 2 * coord_len];
    out[0] = SEC1_UNCOMPRESSED;
    let (x, y) = out[1..].split_at_mut(coord_len);
    pk.coord(Some((x, y)))?;
    Ok(out)
}

/// Decode a SEC1 uncompressed point on `curve`, rejecting
/// out-of-range coordinates and points that are not on the curve.
pub(crate) fn decode_pk(curve: EccCurve, bytes: &[u8]) -> Result<EccPublicKey, CryptoError> {
    let coord_len = curve.point_size();
    if bytes.len() != 1 + 2 * coord_len || bytes[0] != SEC1_UNCOMPRESSED {
        return Err(CryptoError::HpkeInvalidPublicKey);
    }
    let (x, y) = bytes[1..].split_at(coord_len);
    if !curve.coordinate_in_range(x)
        || !curve.coordinate_in_range(y)
        || !EccPublicKey::is_on_curve(curve, x, y).unwrap_or(false)
    {
        return Err(CryptoError::HpkeInvalidPublicKey);
    }
    EccPublicKey::from_coordinates(curve, x, y).map_err(|_| CryptoError::HpkeInvalidPublicKey)
}

// =============================================================================
// Helpers
// =============================================================================

fn dh_curve(suite: HpkeSuite) -> Result<EccCurve, CryptoError> {
    suite.kem_curve().ok_or(CryptoError::HpkeUnsupportedSuite)
}

fn check_pk_curve(pk: &EccPublicKey, curve: EccCurve) -> Result<(), CryptoError> {
    if pk.curve() != curve {
        Err(CryptoError::HpkeInvalidPublicKey)
    } else {
        Ok(())
    }
}

fn check_sk_curve(sk: &EccPrivateKey, curve: EccCurve) -> Result<EccPublicKey, CryptoError> {
    let pk = sk
        .public_key()
        .map_err(|_| CryptoError::HpkeInvalidPrivateKey)?;
    if pk.curve() != curve {
        return Err(CryptoError::HpkeInvalidPrivateKey);
    }
    Ok(pk)
}

/// Raw ECDH: the big-endian x-coordinate of `sk · pk` (`Ndh` bytes).
pub(crate) fn ecdh(
    curve: EccCurve,
    sk: &EccPrivateKey,
    pk: &EccPublicKey,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let ndh = curve.point_size();
    if out.len() != ndh {
        return Err(CryptoError::HpkeInvalidBufferSize);
    }
    let secret = EcdhAlgo::new(pk).derive(sk, ndh)?;
    if secret.to_bytes(Some(out))? != ndh {
        return Err(CryptoError::HpkeInvalidBufferSize);
    }
    Ok(())
}

/// `ExtractAndExpand(dh, kem_context) → shared_secret` (RFC 9180 §4.1).
fn extract_and_expand(
    suite: HpkeSuite,
    dh: &[u8],
    kem_context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let algo = suite.kdf_hash().ok_or(CryptoError::HpkeUnsupportedSuite)?;
    let kem_suite_id = suite.kem_suite_id();
    let eae_prk = Zeroizing::new(labeled_extract(&algo, &kem_suite_id, &[], b"eae_prk", dh)?);
    Ok(Zeroizing::new(labeled_expand(
        &algo,
        &kem_suite_id,
        &eae_prk,
        b"shared_secret",
        kem_context,
        suite.nsecret(),
    )?))
}

/// `kem_context` = `enc ‖ pk_r` (Base) or `enc ‖ pk_r ‖ pk_s` (Auth).
fn kem_context(enc: &[u8], pk_r: &[u8], pk_s: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(enc.len() + pk_r.len() + pk_s.map_or(0, <[u8]>::len));
    out.extend_from_slice(enc);
    out.extend_from_slice(pk_r);
    if let Some(pk_s) = pk_s {
        out.extend_from_slice(pk_s);
    }
    out
}

pub(super) fn ephemeral(curve: EccCurve) -> Result<(EccPrivateKey, Vec<u8>), CryptoError> {
    let sk_e = EccPrivateKey::from_curve(curve).map_err(|_| CryptoError::HpkeKemEncapFailed)?;
    let pk_e = sk_e
        .public_key()
        .map_err(|_| CryptoError::HpkeKemEncapFailed)?;
    let enc = encode_pk(curve, &pk_e)?;
    Ok((sk_e, enc))
}

// =============================================================================
// Encap / Decap
// =============================================================================

/// DHKEM Encap (Base mode). Returns `(enc, shared_secret)`.
pub(crate) fn encap(
    suite: HpkeSuite,
    pk_r: &EccPublicKey,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let curve = dh_curve(suite)?;
    let pk_r_bytes = encode_pk(curve, pk_r)?;
    let (sk_e, enc) = ephemeral(curve)?;

    let mut dh = Zeroizing::new(vec![0u8; suite.ndh()]);
    ecdh(curve, &sk_e, pk_r, &mut dh).map_err(|_| CryptoError::HpkeKemEncapFailed)?;

    let ctx = kem_context(&enc, &pk_r_bytes, None);
    let ss = extract_and_expand(suite, &dh, &ctx)?;
    Ok((enc, ss))
}

/// DHKEM Decap (Base mode).
pub(crate) fn decap(
    suite: HpkeSuite,
    enc: &[u8],
    sk_r: &EccPrivateKey,
    pk_r: &EccPublicKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let curve = dh_curve(suite)?;
    let pk_e = decode_pk(curve, enc)?;
    check_sk_curve(sk_r, curve)?;
    let pk_r_bytes = encode_pk(curve, pk_r)?;

    let mut dh = Zeroizing::new(vec![0u8; suite.ndh()]);
    ecdh(curve, sk_r, &pk_e, &mut dh).map_err(|_| CryptoError::HpkeKemDecapFailed)?;

    let ctx = kem_context(enc, &pk_r_bytes, None);
    extract_and_expand(suite, &dh, &ctx)
}

/// DHKEM AuthEncap (RFC 9180 §4.1). The sender's public key is derived
/// from `sk_s`.
pub(crate) fn auth_encap(
    suite: HpkeSuite,
    pk_r: &EccPublicKey,
    sk_s: &EccPrivateKey,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let curve = dh_curve(suite)?;
    let pk_r_bytes = encode_pk(curve, pk_r)?;
    let pk_s = check_sk_curve(sk_s, curve)?;
    let pk_s_bytes = encode_pk(curve, &pk_s)?;
    let (sk_e, enc) = ephemeral(curve)?;

    let ndh = suite.ndh();
    let mut dh = Zeroizing::new(vec![0u8; 2 * ndh]);
    ecdh(curve, &sk_e, pk_r, &mut dh[..ndh]).map_err(|_| CryptoError::HpkeKemEncapFailed)?;
    ecdh(curve, sk_s, pk_r, &mut dh[ndh..]).map_err(|_| CryptoError::HpkeKemEncapFailed)?;

    let ctx = kem_context(&enc, &pk_r_bytes, Some(&pk_s_bytes));
    let ss = extract_and_expand(suite, &dh, &ctx)?;
    Ok((enc, ss))
}

/// DHKEM AuthDecap.
pub(crate) fn auth_decap(
    suite: HpkeSuite,
    enc: &[u8],
    sk_r: &EccPrivateKey,
    pk_r: &EccPublicKey,
    pk_s: &EccPublicKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let curve = dh_curve(suite)?;
    let pk_e = decode_pk(curve, enc)?;
    check_sk_curve(sk_r, curve)?;
    check_pk_curve(pk_s, curve)?;
    let pk_r_bytes = encode_pk(curve, pk_r)?;
    let pk_s_bytes = encode_pk(curve, pk_s)?;

    let ndh = suite.ndh();
    let mut dh = Zeroizing::new(vec![0u8; 2 * ndh]);
    ecdh(curve, sk_r, &pk_e, &mut dh[..ndh]).map_err(|_| CryptoError::HpkeKemDecapFailed)?;
    ecdh(curve, sk_r, pk_s, &mut dh[ndh..]).map_err(|_| CryptoError::HpkeKemDecapFailed)?;

    let ctx = kem_context(enc, &pk_r_bytes, Some(&pk_s_bytes));
    extract_and_expand(suite, &dh, &ctx)
}

// =============================================================================
// DeriveKeyPair
// =============================================================================

/// DHKEM DeriveKeyPair for the NIST curves (RFC 9180 §7.1.3):
///
/// ```text
/// dkp_prk = LabeledExtract("", "dkp_prk", ikm)
/// for counter in 0..=255:
///     bytes    = LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), Nsk)
///     bytes[0] &= bitmask            (0xFF, or 0x01 for P-521)
///     if 0 < OS2IP(bytes) < order: return bytes
/// ```
pub(crate) fn derive_keypair(
    suite: HpkeSuite,
    ikm: &[u8],
) -> Result<(EccPrivateKey, EccPublicKey), CryptoError> {
    let curve = dh_curve(suite)?;
    let algo = suite.kdf_hash().ok_or(CryptoError::HpkeUnsupportedSuite)?;
    let kem_suite_id = suite.kem_suite_id();
    let bitmask = if curve == EccCurve::P521 { 0x01 } else { 0xFF };
    let dkp_prk = Zeroizing::new(labeled_extract(&algo, &kem_suite_id, &[], b"dkp_prk", ikm)?);
    for counter in 0..=u8::MAX {
        let mut candidate = Zeroizing::new(labeled_expand(
            &algo,
            &kem_suite_id,
            &dkp_prk,
            b"candidate",
            &[counter],
            suite.nsk(),
        )?);
        candidate[0] &= bitmask;
        if curve.validate_scalar(&candidate).is_ok() {
            let sk = EccPrivateKey::from_scalar(curve, &candidate)
                .map_err(|_| CryptoError::HpkeInvalidPrivateKey)?;
            let pk = sk
                .public_key()
                .map_err(|_| CryptoError::HpkeInvalidPrivateKey)?;
            return Ok((sk, pk));
        }
    }
    Err(CryptoError::HpkeInvalidPrivateKey)
}
