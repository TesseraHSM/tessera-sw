// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FIPS key assurance for imported private keys on the std PAL.
//!
//! Mirrors the Uno PAL's import checks (`fw/plat/uno/fw/pal/src/crypto/ecc.rs`
//! and `rsa.rs`) and returns the same statuses, so std matches Uno:
//!
//! * **ECC** — the PKCS#8 / SEC1 key must carry its public key, as an
//!   uncompressed point, in the `[1] publicKey` field and no `[0]
//!   parameters`. That point must be the one derived from the private
//!   scalar, and the key pair must pass the PCT that the caller selects.
//! * **RSA** — the key components must be consistent (`n = p·q`,
//!   `d·e ≡ 1` mod `p-1` and `q-1`, and the CRT values `dp`, `dq` and `qInv`)
//!   and the key pair must pass the PCT that the caller selects. The
//!   consistency check covers what the backend's private operation hides: it
//!   verifies its CRT result and falls back to `d`, and the non-CRT vault
//!   recomputes `d`.

use der::asn1::AnyRef;
use der::asn1::BitStringRef;
use der::asn1::ContextSpecific;
use der::asn1::ObjectIdentifier;
use der::asn1::OctetStringRef;
use der::Decode;
use der::Reader;
use der::SliceReader;
use der::TagNumber;
use num_bigint::BigUint;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::ExportableHsmRsaKey;
use tsra_crypto::Key;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaPrivateKey;
use zeroize::Zeroizing;

use super::*;

/// id-ecPublicKey (1.2.840.10045.2.1).
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// Named-curve OIDs (RFC 5480 §2.1.1.1).
const P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// SEC1 marker byte for an uncompressed point.
const UNCOMPRESSED_POINT: u8 = 0x04;

/// The SEC1 fields of a PKCS#8 EC private key that the import checks use.
pub(crate) struct DecodedEcKey<'a> {
    pub(crate) curve: HsmEccCurve,
    has_parameters: bool,
    public_key: Option<BitStringRef<'a>>,
}

fn curve_from_oid(oid: ObjectIdentifier) -> Option<HsmEccCurve> {
    if oid == P256_OID {
        Some(HsmEccCurve::P256)
    } else if oid == P384_OID {
        Some(HsmEccCurve::P384)
    } else if oid == P521_OID {
        Some(HsmEccCurve::P521)
    } else {
        None
    }
}

/// Decodes a PKCS#8 `PrivateKeyInfo` that wraps a SEC1 `ECPrivateKey`.
///
/// Validates the versions (PKCS#8 0, SEC1 1), the `id-ecPublicKey` algorithm
/// and a supported `namedCurve`, like Uno's `parse_ec_private_key`.
pub(crate) fn parse_ec_private_key(der: &[u8]) -> Option<DecodedEcKey<'_>> {
    let mut outer = SliceReader::new(der).ok()?;
    let (version, alg, named_curve, key) = outer
        .sequence(|r| {
            let version = u8::decode(r)?;
            let (alg, named_curve) =
                r.sequence(|a| Ok((ObjectIdentifier::decode(a)?, ObjectIdentifier::decode(a)?)))?;
            let key = OctetStringRef::decode(r)?;
            Ok((version, alg, named_curve, key))
        })
        .ok()?;
    outer.finish(()).ok()?;
    if version != 0 || alg != EC_PUBLIC_KEY {
        return None;
    }
    let (curve, sec1) = (curve_from_oid(named_curve)?, key.as_bytes());

    let mut inner = SliceReader::new(sec1).ok()?;
    let (version, parameters, public_key) = inner
        .sequence(|r| {
            let version = u8::decode(r)?;
            OctetStringRef::decode(r)?;
            let parameters = ContextSpecific::<AnyRef<'_>>::decode_explicit(r, TagNumber::N0)?;
            let public_key =
                ContextSpecific::<BitStringRef<'_>>::decode_explicit(r, TagNumber::N1)?;
            Ok((version, parameters, public_key))
        })
        .ok()?;
    inner.finish(()).ok()?;
    if version != 1 {
        return None;
    }
    Some(DecodedEcKey {
        curve,
        has_parameters: parameters.is_some(),
        public_key: public_key.map(|cs| cs.value),
    })
}

/// Returns the big-endian `x ‖ y` public key that an imported ECC key
/// carries.
///
/// # Errors
/// * [`HsmError::KeyDecodeFailed`] — the key carries no public key, or
///   carries `[0] parameters`.
/// * [`HsmError::KeyStructuralValidationFailed`] — the public key isn't an
///   uncompressed point of the curve's size.
pub(crate) fn embedded_public_key<'a>(key: &DecodedEcKey<'a>) -> HsmResult<&'a [u8]> {
    let bits = match key.public_key {
        Some(bits) if !key.has_parameters => bits,
        _ => return Err(HsmError::KeyDecodeFailed),
    };
    if bits.unused_bits() != 0 {
        return Err(HsmError::KeyStructuralValidationFailed);
    }
    match bits.raw_bytes().split_first() {
        Some((&UNCOMPRESSED_POINT, xy)) if xy.len() == 2 * key.curve.priv_key_len() => Ok(xy),
        _ => Err(HsmError::KeyStructuralValidationFailed),
    }
}

/// Constant-time byte-slice equality.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Digest length of the PCT hash for an ECC curve (SHA-256/384/512).
fn ecc_pct_digest_len(curve: HsmEccCurve) -> usize {
    match curve {
        HsmEccCurve::P256 => 32,
        HsmEccCurve::P384 => 48,
        HsmEccCurve::P521 => 64,
    }
}

/// Digest length of the PCT hash for an RSA modulus (SHA-256/384/512).
fn rsa_pct_digest_len(modulus_len: usize) -> usize {
    match modulus_len {
        0..=256 => 32,
        257..=384 => 48,
        _ => 64,
    }
}

impl StdHsmPal {
    /// Checks an imported ECC key pair: the public key derived from `pk` must
    /// equal `embedded` (big-endian `x ‖ y`), then the pair must pass `pct`.
    ///
    /// # Errors
    /// * [`HsmError::KeyStructuralValidationFailed`] — the public keys differ.
    /// * [`HsmError::PctValidationRsaUnwrapEccKeyFailed`] — the PCT failed.
    pub(crate) async fn check_ecc_import(
        &self,
        curve: HsmEccCurve,
        pct: HsmEccPct,
        pk: &EccPrivateKey,
        embedded: &[u8],
    ) -> HsmResult<()> {
        let raw = curve.priv_key_len();
        let coord = curve.wire_coord_len();
        let pub_key = pk
            .public_key()
            .map_err(|_| HsmError::EccGetCoordinatesError)?;
        let mut derived = vec![0u8; 2 * coord];
        self.ecc.pub_coords(&pub_key, true, &mut derived).await?;
        let same = embedded.len() == 2 * raw
            && embedded
                .chunks_exact(raw)
                .zip(derived.chunks_exact(coord))
                .all(|(e, d)| e == &d[..raw]);
        if !same {
            return Err(HsmError::KeyStructuralValidationFailed);
        }

        let passed = match pct {
            HsmEccPct::None => true,
            HsmEccPct::SignVerify => {
                let digest = vec![100u8; ecc_pct_digest_len(curve)];
                let sig = self.ecc.ecc_sign(pk, &digest).await?;
                self.ecc.ecc_verify(&pub_key, &digest, &sig).await?
            }
            HsmEccPct::KeyAgreement => {
                let (peer_priv, peer_pub) = self.ecc.gen_keypair(EccKeyOp::curve(pk)).await?;
                let len = curve.secret_len();
                let mut ours = Zeroizing::new(vec![0u8; len]);
                let mut theirs = Zeroizing::new(vec![0u8; len]);
                self.ecc.ecdh_derive(pk, &peer_pub, &mut ours).await?;
                self.ecc
                    .ecdh_derive(&peer_priv, &pub_key, &mut theirs)
                    .await?;
                ct_eq(&ours, &theirs)
            }
        };
        if !passed {
            return Err(HsmError::PctValidationRsaUnwrapEccKeyFailed);
        }
        Ok(())
    }

    /// Checks an imported RSA key pair: its components must be consistent
    /// and the pair must pass `pct`. Does nothing when `pct` is `None`.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] — the public exponent is zero.
    /// * [`HsmError::PctValidationRsaUnwrapRsaKeyFailed`] — the components
    ///   are inconsistent or the PCT failed.
    pub(crate) async fn check_rsa_import(
        &self,
        pk: &RsaPrivateKey,
        pct: HsmRsaPct,
    ) -> HsmResult<()> {
        if matches!(pct, HsmRsaPct::None) {
            return Ok(());
        }
        let k = pk.size();
        let mut comps = Zeroizing::new(vec![0u8; pk.hsm_crt_bytes_len()]);
        pk.to_hsm_crt_bytes(&mut comps)
            .map_err(|_| HsmError::InvalidArg)?;
        if !rsa_components_consistent(&comps, k)? {
            return Err(HsmError::PctValidationRsaUnwrapRsaKeyFailed);
        }
        if !self.rsa_pct(pk, pct, k).await? {
            return Err(HsmError::PctValidationRsaUnwrapRsaKeyFailed);
        }
        Ok(())
    }

    /// Runs the RSA PCT on wire (little-endian) operands, like Uno's
    /// `rsa_pct`: the intermediate value must differ from the input and the
    /// round trip must recover it.
    async fn rsa_pct(&self, pk: &RsaPrivateKey, pct: HsmRsaPct, k: usize) -> HsmResult<bool> {
        let pubk = pk.public_key().map_err(|_| HsmError::RsaGenerateError)?;
        let mut input = vec![0u8; k];
        let mut middle = vec![0u8; k];
        let mut output = vec![0u8; k];
        match pct {
            HsmRsaPct::None => return Ok(true),
            HsmRsaPct::SignVerify => {
                input[..rsa_pct_digest_len(k)].fill(100);
                self.rsa.mod_exp_priv(pk, &input, &mut middle).await?;
                self.rsa.mod_exp_pub(&pubk, &middle, &mut output).await?;
            }
            HsmRsaPct::EncryptDecrypt => {
                // Little-endian: the most significant byte is the last one.
                input[..k - 1].fill(0x5A);
                self.rsa.mod_exp_pub(&pubk, &input, &mut middle).await?;
                self.rsa.mod_exp_priv(pk, &middle, &mut output).await?;
            }
        }
        Ok(middle != input && output == input)
    }
}

/// Checks the components of an RSA key exported in the CRT HSM layout
/// `n(k) ‖ e(4) ‖ d(k) ‖ p ‖ q ‖ dp ‖ dq ‖ qInv` (each `k/2`, big-endian).
///
/// Returns `Ok(false)` if `n ≠ p·q`, `d·e ≢ 1` mod `p-1` or `q-1`,
/// `dp·e ≢ 1` mod `p-1`, `dq·e ≢ 1` mod `q-1`, or `qInv·q ≢ 1` mod `p`.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — the layout is malformed or `e` is zero.
fn rsa_components_consistent(comps: &[u8], k: usize) -> HsmResult<bool> {
    let half = k / 2;
    if k == 0 || comps.len() < 2 * k + 4 + 5 * half {
        return Err(HsmError::InvalidArg);
    }
    let (n, rest) = comps.split_at(k);
    let (e, rest) = rest.split_at(4);
    let (d, rest) = rest.split_at(k);
    let mut it = rest.chunks_exact(half).map(BigUint::from_bytes_be);
    let mut next = || it.next().ok_or(HsmError::InvalidArg);
    let (p, q, dp, dq, qinv) = (next()?, next()?, next()?, next()?, next()?);
    let (n, e, d) = (
        BigUint::from_bytes_be(n),
        BigUint::from_bytes_be(e),
        BigUint::from_bytes_be(d),
    );
    let one = BigUint::from(1u8);
    if e.bits() == 0 {
        return Err(HsmError::InvalidArg);
    }
    if p <= one || q <= one {
        return Ok(false);
    }
    let (p1, q1) = (&p - &one, &q - &one);
    Ok(n == &p * &q
        && (&d * &e) % &p1 == one
        && (&d * &e) % &q1 == one
        && (&dp * &e) % &p1 == one
        && (&dq * &e) % &q1 == one
        && (&qinv * &q) % &p == one)
}
