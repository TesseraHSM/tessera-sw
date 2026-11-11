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
//!   and the key pair must pass the PCT that the caller selects.
//!
//! Every check runs on the decoded DER components, before the key reaches
//! the crypto backend: OpenSSL and CNG validate, drop or recompute some
//! components on import, which would otherwise change the status or hide a
//! corrupted value. Arithmetic on secret components uses zeroizing storage.

use der::asn1::AnyRef;
use der::asn1::BitStringRef;
use der::asn1::ContextSpecific;
use der::asn1::Null;
use der::asn1::ObjectIdentifier;
use der::asn1::OctetStringRef;
use der::asn1::UintRef;
use der::Decode;
use der::Reader;
use der::SliceReader;
use der::TagNumber;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::Key;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaPrivateKey;
use zeroize::Zeroizing;

use super::*;

/// rsaEncryption (1.2.840.113549.1.1.1).
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// id-ecPublicKey (1.2.840.10045.2.1).
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// Named-curve OIDs (RFC 5480 §2.1.1.1).
const P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// SEC1 marker byte for an uncompressed point.
const UNCOMPRESSED_POINT: u8 = 0x04;

/// Big-endian curve orders `n`, for the `1 <= d < n` scalar check.
const ORDER_P256: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const ORDER_P384: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
];
const ORDER_P521: [u8; 66] = [
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
    0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
    0x64, 0x09,
];

/// The SEC1 fields of a PKCS#8 EC private key that the import checks use.
pub(crate) struct DecodedEcKey<'a> {
    pub(crate) curve: HsmEccCurve,
    /// The raw big-endian private scalar `d`.
    pub(crate) scalar: &'a [u8],
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
    let (version, scalar, parameters, public_key) = inner
        .sequence(|r| {
            let version = u8::decode(r)?;
            let scalar = OctetStringRef::decode(r)?;
            let parameters = ContextSpecific::<AnyRef<'_>>::decode_explicit(r, TagNumber::N0)?;
            let public_key =
                ContextSpecific::<BitStringRef<'_>>::decode_explicit(r, TagNumber::N1)?;
            Ok((version, scalar, parameters, public_key))
        })
        .ok()?;
    inner.finish(()).ok()?;
    if version != 1 {
        return None;
    }
    Some(DecodedEcKey {
        curve,
        scalar: scalar.as_bytes(),
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

/// Checks the private scalar like Uno: exactly the curve's raw width and in
/// `[1, n-1]`, compared in constant time.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — the scalar has the wrong length or is out of
///   range.
pub(crate) fn check_ecc_scalar(curve: HsmEccCurve, scalar: &[u8]) -> HsmResult<()> {
    let order: &[u8] = match curve {
        HsmEccCurve::P256 => &ORDER_P256,
        HsmEccCurve::P384 => &ORDER_P384,
        HsmEccCurve::P521 => &ORDER_P521,
    };
    if scalar.len() != order.len() {
        return Err(HsmError::InvalidArg);
    }
    let nonzero = scalar.iter().fold(0u8, |acc, &b| acc | b) != 0;
    // `scalar - order` borrows out of the top byte iff `scalar < order`.
    let mut borrow = 0i32;
    for (&v, &n) in scalar.iter().zip(order).rev() {
        borrow = ((i32::from(v) - i32::from(n) - borrow) >> 8) & 1;
    }
    if !(nonzero & (borrow == 1)) {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
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

    /// Runs the RSA PCT selected by `pct` on an imported key pair.
    ///
    /// # Errors
    /// * [`HsmError::PctValidationRsaUnwrapRsaKeyFailed`] — the PCT failed.
    pub(crate) async fn check_rsa_pct(&self, pk: &RsaPrivateKey, pct: HsmRsaPct) -> HsmResult<()> {
        if !self.rsa_pct(pk, pct, pk.size()).await? {
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

/// The big-endian magnitudes of a PKCS#1 two-prime `RSAPrivateKey`.
pub(crate) struct DecodedRsaKey<'a> {
    pub(crate) n: &'a [u8],
    e: &'a [u8],
    d: &'a [u8],
    p: &'a [u8],
    q: &'a [u8],
    dp: &'a [u8],
    dq: &'a [u8],
    qinv: &'a [u8],
}

/// Decodes a PKCS#8 `PrivateKeyInfo` that wraps a PKCS#1 `RSAPrivateKey`,
/// like Uno's `parse_rsa_private_key`: PKCS#8 version 0, `rsaEncryption`
/// with `NULL` parameters, and a two-prime (version 0) key.
pub(crate) fn parse_rsa_private_key(der: &[u8]) -> Option<DecodedRsaKey<'_>> {
    let mut outer = SliceReader::new(der).ok()?;
    let (version, alg, key) = outer
        .sequence(|r| {
            let version = u8::decode(r)?;
            let alg = r.sequence(|a| {
                let oid = ObjectIdentifier::decode(a)?;
                Null::decode(a)?;
                Ok(oid)
            })?;
            Ok((version, alg, OctetStringRef::decode(r)?))
        })
        .ok()?;
    outer.finish(()).ok()?;
    if version != 0 || alg != RSA_ENCRYPTION {
        return None;
    }

    let mut inner = SliceReader::new(key.as_bytes()).ok()?;
    let (version, f) = inner
        .sequence(|r| {
            let version = u8::decode(r)?;
            let mut f = [&[][..]; 8];
            for field in f.iter_mut() {
                *field = UintRef::decode(r)?.as_bytes();
            }
            Ok((version, f))
        })
        .ok()?;
    inner.finish(()).ok()?;
    if version != 0 {
        return None;
    }
    let [n, e, d, p, q, dp, dq, qinv] = f;
    Some(DecodedRsaKey {
        n,
        e,
        d,
        p,
        q,
        dp,
        dq,
        qinv,
    })
}

/// Checks the sizes and, unless `pct` is `None`, the consistency of the
/// components that the selected layout uses.
///
/// Like Uno, the modulus must be 256, 384 or 512 bytes and `e` at most 4
/// bytes. A CRT key uses `p`, `q`, `dp`, `dq` and `qInv`, each at most half
/// the modulus, and ignores `d`. A non-CRT key uses `d`, at most the modulus
/// width, and ignores `dp`, `dq` and `qInv`; std also stores it by its primes,
/// so `p` and `q` must fit half the modulus and `n = p·q`.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — a used component has an unsupported size, or
///   `e` is zero.
/// * [`HsmError::PctValidationRsaUnwrapRsaKeyFailed`] — the used components
///   are inconsistent, or `e` is one (the public operation is the identity,
///   so the PCT can't pass).
pub(crate) fn check_rsa_components(
    key: &DecodedRsaKey<'_>,
    crt: bool,
    pct: &HsmRsaPct,
) -> HsmResult<()> {
    let half = key.n.len() / 2;
    let oversized = if crt {
        [key.p, key.q, key.dp, key.dq, key.qinv]
            .iter()
            .any(|c| c.len() > half)
    } else {
        key.d.len() > key.n.len() || key.p.len() > half || key.q.len() > half
    };
    if !matches!(key.n.len(), 256 | 384 | 512) || key.e.len() > 4 || oversized {
        return Err(HsmError::InvalidArg);
    }
    if matches!(pct, HsmRsaPct::None) {
        return Ok(());
    }
    let e = limbs(key.e);
    if !gt(&e, &[0]) {
        return Err(HsmError::InvalidArg);
    }
    if !gt(&e, &[1]) || !rsa_components_consistent(key, crt, &e) {
        return Err(HsmError::PctValidationRsaUnwrapRsaKeyFailed);
    }
    Ok(())
}

/// Returns whether `n = p·q` and, for a CRT key, `dp·e ≡ 1` mod `p-1`,
/// `dq·e ≡ 1` mod `q-1` and `qInv·q ≡ 1` mod `p`, or, for a non-CRT key,
/// `d·e ≡ 1` mod `p-1` and `q-1`.
fn rsa_components_consistent(key: &DecodedRsaKey<'_>, crt: bool, e: &[u64]) -> bool {
    let (p, q) = (limbs(key.p), limbs(key.q));
    if !gt(&p, &[1]) || !gt(&q, &[1]) || !eq(&mul(&p, &q), &limbs(key.n)) {
        return false;
    }
    let (p1, q1) = (minus_one(&p), minus_one(&q));
    if crt {
        eq(&rem(&mul(&limbs(key.dp), e), &p1), &[1])
            && eq(&rem(&mul(&limbs(key.dq), e), &q1), &[1])
            && eq(&rem(&mul(&limbs(key.qinv), &q), &p), &[1])
    } else {
        let de = mul(&limbs(key.d), e);
        eq(&rem(&de, &p1), &[1]) && eq(&rem(&de, &q1), &[1])
    }
}

/// Returns the components std stores, `n(k) || e(4) || p(k/2) || q(k/2)`,
/// followed by `dp || dq || qInv` (each `k/2`), big-endian and left-padded.
/// Call only after [`check_rsa_components`] accepted the sizes; `d` is not
/// included, as the backends derive it from the primes.
pub(crate) fn rsa_stored_components(key: &DecodedRsaKey<'_>) -> Zeroizing<Vec<u8>> {
    let k = key.n.len();
    let half = k / 2;
    let mut out = Zeroizing::new(vec![0u8; 2 * k + 4 + 3 * half]);
    let mut off = 0;
    for (field, width) in [
        (key.n, k),
        (key.e, 4),
        (key.p, half),
        (key.q, half),
        (key.dp, half),
        (key.dq, half),
        (key.qinv, half),
    ] {
        // A non-CRT key's unused CRT fields may be oversized; leave them zero.
        if let Some(pad) = width.checked_sub(field.len()) {
            out[off + pad..off + width].copy_from_slice(field);
        }
        off += width;
    }
    out
}

// Minimal unsigned arithmetic on little-endian `u64` limbs. Every value,
// including intermediates, lives in zeroizing storage and is never
// reallocated, so no copy of the key material outlives the check.
type Limbs = Zeroizing<Vec<u64>>;

/// Converts a big-endian magnitude to limbs.
fn limbs(be: &[u8]) -> Limbs {
    let mut out = Zeroizing::new(vec![0u64; be.len().div_ceil(8).max(1)]);
    for (i, &b) in be.iter().rev().enumerate() {
        out[i / 8] |= u64::from(b) << (8 * (i % 8));
    }
    out
}

/// Limb `i` of `a`, zero past its end.
fn limb(a: &[u64], i: usize) -> u64 {
    a.get(i).copied().unwrap_or(0)
}

/// `a == b`, regardless of leading zero limbs.
fn eq(a: &[u64], b: &[u64]) -> bool {
    (0..a.len().max(b.len())).fold(0, |acc, i| acc | (limb(a, i) ^ limb(b, i))) == 0
}

/// `a > b`.
fn gt(a: &[u64], b: &[u64]) -> bool {
    for i in (0..a.len().max(b.len())).rev() {
        if limb(a, i) != limb(b, i) {
            return limb(a, i) > limb(b, i);
        }
    }
    false
}

/// `a - 1`, for `a > 0`.
fn minus_one(a: &[u64]) -> Limbs {
    let mut out = Zeroizing::new(a.to_vec());
    for l in out.iter_mut() {
        let (v, borrow) = l.overflowing_sub(1);
        *l = v;
        if !borrow {
            break;
        }
    }
    out
}

/// `a · b`.
fn mul(a: &[u64], b: &[u64]) -> Limbs {
    let mut out = Zeroizing::new(vec![0u64; a.len() + b.len()]);
    for (i, &x) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &y) in b.iter().enumerate() {
            let t = u128::from(x) * u128::from(y) + u128::from(out[i + j]) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + b.len()] = carry as u64;
    }
    out
}

/// `a mod m`, for `m > 0`, by binary long division with a branch-free
/// conditional subtraction.
fn rem(a: &[u64], m: &[u64]) -> Limbs {
    let w = m.len() + 1;
    let mut r = Zeroizing::new(vec![0u64; w]);
    let mut t = Zeroizing::new(vec![0u64; w]);
    for bit in (0..a.len() * 64).rev() {
        // r = 2r + bit; r < m beforehand, so r < 2m fits in `w` limbs.
        let mut carry = (a[bit / 64] >> (bit % 64)) & 1;
        for l in r.iter_mut() {
            let top = *l >> 63;
            *l = (*l << 1) | carry;
            carry = top;
        }
        // t = r - m; keep it unless the subtraction borrowed.
        let mut borrow = 0u64;
        for (i, (ti, &ri)) in t.iter_mut().zip(r.iter()).enumerate() {
            let (v1, b1) = ri.overflowing_sub(limb(m, i));
            let (v2, b2) = v1.overflowing_sub(borrow);
            *ti = v2;
            borrow = u64::from(b1 | b2);
        }
        let keep = borrow.wrapping_sub(1);
        for (ri, &ti) in r.iter_mut().zip(t.iter()) {
            *ri = (ti & keep) | (*ri & !keep);
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be(v: u128) -> Vec<u8> {
        v.to_be_bytes().to_vec()
    }

    #[test]
    fn limb_arithmetic_matches_u128() {
        let cases = [
            (0u128, 7u128),
            (1, 1),
            (u64::MAX as u128, 3),
            (
                0x1234_5678_9abc_def0_1122_3344_5566_7788,
                0xffff_ffff_0000_0001,
            ),
            (u128::MAX, u64::MAX as u128 + 2),
        ];
        for (a, m) in cases {
            assert!(eq(&rem(&limbs(&be(a)), &limbs(&be(m))), &limbs(&be(a % m))));
        }
        let (x, y) = (0xdead_beef_cafe_f00du128, 0x1_0000_0001u128);
        assert!(eq(&mul(&limbs(&be(x)), &limbs(&be(y))), &limbs(&be(x * y))));
        assert!(eq(
            &minus_one(&limbs(&be(1u128 << 64))),
            &limbs(&be(u64::MAX as u128))
        ));
        assert!(gt(&limbs(&be(1u128 << 64)), &[u64::MAX]));
        assert!(!gt(&[5, 0, 0], &[5]));
    }

    #[test]
    fn ecc_scalar_range() {
        let mut d = ORDER_P256;
        assert_eq!(
            check_ecc_scalar(HsmEccCurve::P256, &d),
            Err(HsmError::InvalidArg)
        );
        d[31] -= 1;
        assert_eq!(check_ecc_scalar(HsmEccCurve::P256, &d), Ok(()));
        assert_eq!(
            check_ecc_scalar(HsmEccCurve::P256, &[0; 32]),
            Err(HsmError::InvalidArg)
        );
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(check_ecc_scalar(HsmEccCurve::P256, &one), Ok(()));
        assert_eq!(
            check_ecc_scalar(HsmEccCurve::P256, &one[1..]),
            Err(HsmError::InvalidArg)
        );
    }
}
