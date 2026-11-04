// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! EC2 (`kty = 2`) `COSE_Key` private-key encode / decode.
//!
//! Wire shape (RFC 9052 §7, constrained by the internal COSE Key
//! Definition Format spec §3–§4):
//!
//! ```text
//! {
//!    1: 2,            / kty: EC2 /
//!    2: h'<kid>',     / key id  /
//!    3: <alg>,        / algorithm /
//!    4: [+ int],      / key_ops (non-empty) /
//!   -1: <crv>,        / curve /
//!   -2: h'<x>',       / affine X (big-endian, field width) /
//!   -3: h'<y>',       / affine Y (big-endian, field width) /
//!   -4: h'<d>',       / private scalar (big-endian, field width) /
//! }
//! ```
//!
//! Coordinates and the scalar are unsigned, fixed-width, big-endian byte
//! strings whose length equals the curve field size (P-256 32, P-384 48,
//! P-521 66 bytes).

use minicbor::Decoder;
use minicbor::Encoder;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

// COSE common and EC2 key-type parameter labels (IANA COSE registry).
const COSE_KTY: i32 = 1;
const COSE_KID: i32 = 2;
const COSE_ALG: i32 = 3;
const COSE_KEY_OPS: i32 = 4;
const COSE_EC2_CRV: i32 = -1;
const COSE_EC2_X: i32 = -2;
const COSE_EC2_Y: i32 = -3;
const COSE_EC2_D: i32 = -4;

/// COSE key type EC2 (RFC 9052 Table 2).
const COSE_KTY_EC2: u8 = 2;

// COSE elliptic-curve identifiers (RFC 9053 Table 18).
const COSE_CRV_P256: i32 = 1;
const COSE_CRV_P384: i32 = 2;
const COSE_CRV_P521: i32 = 3;

// Deprecated polymorphic ECDSA algorithm identifiers (IANA COSE
// Algorithms registry).  New implementations MUST NOT create them and a
// conforming validator rejects them (spec §4.2 / §10.10).
const COSE_ALG_ES256_DEPRECATED: i32 = -7;
const COSE_ALG_ES384_DEPRECATED: i32 = -35;
const COSE_ALG_ES512_DEPRECATED: i32 = -36;

/// Highest COSE key-operation value defined by RFC 9052 §7.1 (Table 4).
const COSE_KEY_OP_MAX: u8 = 10;

/// Registered COSE key-operation values (RFC 9052 §7.1, Table 4).
///
/// Used by callers to interpret [`CoseKeyOps`].
pub mod key_op {
    /// `1` — create a signature (private).
    pub const CREATE_SIGNATURE: u8 = 1;
    /// `2` — verify a signature (public).
    pub const VERIFY_SIGNATURE: u8 = 2;
    /// `3` — key-transport encryption.
    pub const ENCRYPT: u8 = 3;
    /// `4` — key-transport decryption.
    pub const DECRYPT: u8 = 4;
    /// `5` — wrap a key.
    pub const WRAP_KEY: u8 = 5;
    /// `6` — unwrap a key.
    pub const UNWRAP_KEY: u8 = 6;
    /// `7` — derive a key.
    pub const DERIVE_KEY: u8 = 7;
    /// `8` — derive non-key bits.
    pub const DERIVE_BITS: u8 = 8;
    /// `9` — create a MAC.
    pub const MAC_CREATE: u8 = 9;
    /// `10` — verify a MAC.
    pub const MAC_VERIFY: u8 = 10;
}

/// The `key_ops` restriction of a decoded `COSE_Key`: a compact set of
/// the registered operation values (1..=10) permitted for the key.
///
/// Stored as a bitset with bit `v` set iff operation value `v` is
/// present.  Always non-empty for a decoded key (RFC 9052 requires a
/// non-empty array; the decoder enforces it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoseKeyOps(u16);

impl CoseKeyOps {
    /// Whether operation value `op` (one of the [`key_op`] constants) is
    /// permitted by this key.
    #[inline]
    pub const fn contains(self, op: u8) -> bool {
        self.0 & (1u16 << op) != 0
    }

    /// The raw bitset (bit `v` set iff operation value `v` is present).
    #[inline]
    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// A parsed EC2 private `COSE_Key`: the curve, algorithm, and key-op
/// restriction plus zero-copy big-endian field elements borrowing from
/// the input buffer.
pub struct Ec2PrivateCoseKey<'a> {
    /// NIST curve the key is on.
    pub curve: HsmEccCurve,
    /// COSE algorithm identifier the key is restricted to (`alg`).
    pub alg: i32,
    /// Permitted key operations (`key_ops`), always non-empty.
    pub key_ops: CoseKeyOps,
    /// Big-endian affine X coordinate (`curve.priv_key_len()` bytes).
    pub x: &'a HsmDmaBuf,
    /// Big-endian affine Y coordinate (`curve.priv_key_len()` bytes).
    pub y: &'a HsmDmaBuf,
    /// Big-endian private scalar (`curve.priv_key_len()` bytes).
    pub d: &'a HsmDmaBuf,
}

/// Map a `minicbor` decode error to [`HsmError::InvalidArg`].
fn map_err<T, E>(result: Result<T, E>) -> HsmResult<T> {
    result.map_err(|_| HsmError::InvalidArg)
}

/// Read a bstr at the decoder's current position and return the
/// `[start, end)` offsets of its content within the decoder input.
fn bytes_span(d: &mut Decoder<'_>) -> HsmResult<(usize, usize)> {
    let len = map_err(d.bytes())?.len();
    let end = d.position();
    let start = end.checked_sub(len).ok_or(HsmError::InvalidArg)?;
    Ok((start, end))
}

/// Map a COSE curve identifier onto its [`HsmEccCurve`].
fn curve_from_cose(crv: i32) -> HsmResult<HsmEccCurve> {
    match crv {
        COSE_CRV_P256 => Ok(HsmEccCurve::P256),
        COSE_CRV_P384 => Ok(HsmEccCurve::P384),
        COSE_CRV_P521 => Ok(HsmEccCurve::P521),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Map a curve onto its COSE identifier.
fn cose_from_curve(curve: HsmEccCurve) -> i32 {
    match curve {
        HsmEccCurve::P256 => COSE_CRV_P256,
        HsmEccCurve::P384 => COSE_CRV_P384,
        HsmEccCurve::P521 => COSE_CRV_P521,
    }
}

/// Reject the deprecated polymorphic ECDSA algorithm identifiers
/// (spec §4.2 / §10.10); any other value is passed through for the
/// caller's own `alg`/`key_ops` policy to enforce.
fn validate_alg(alg: i32) -> HsmResult<()> {
    match alg {
        COSE_ALG_ES256_DEPRECATED | COSE_ALG_ES384_DEPRECATED | COSE_ALG_ES512_DEPRECATED => {
            Err(HsmError::InvalidArg)
        }
        _ => Ok(()),
    }
}

/// Decode the `key_ops` array at the decoder's current position into a
/// [`CoseKeyOps`] bitset, rejecting an empty array, a duplicate op, an
/// indefinite-length array, or an unknown op value.
fn decode_key_ops(d: &mut Decoder<'_>) -> HsmResult<CoseKeyOps> {
    let count = map_err(d.array())?.ok_or(HsmError::InvalidArg)?;
    if count == 0 {
        return Err(HsmError::InvalidArg);
    }
    let mut ops = 0u16;
    for _ in 0..count {
        let op = map_err(d.u8())?;
        if op == 0 || op > COSE_KEY_OP_MAX {
            return Err(HsmError::InvalidArg);
        }
        let bit = 1u16 << op;
        if ops & bit != 0 {
            return Err(HsmError::InvalidArg);
        }
        ops |= bit;
    }
    Ok(CoseKeyOps(ops))
}

/// Decode an EC2 **private** `COSE_Key`, returning a zero-copy
/// [`Ec2PrivateCoseKey`] borrowing the field elements from `cose_key`.
///
/// Enforces the profile's validation requirements (spec §4.1, §10):
///
/// * definite-length CBOR map, no duplicate labels, no trailing bytes;
/// * `kty` (EC2), `kid`, `alg`, and a non-empty `key_ops` are present;
/// * the curve is one of P-256 / P-384 / P-521;
/// * `x`, `y`, and `d` are present and each exactly the curve field width;
/// * the algorithm is not a deprecated polymorphic ECDSA identifier.
///
/// It does **not** verify that the point lies on the curve or that the
/// public point corresponds to `d` — that is the cryptographic PAL's
/// job (see the caller's `ecc_priv_to_vault`).
///
/// # Errors
/// * [`HsmError::InvalidArg`] — any malformed or out-of-profile input.
pub fn parse_ec2_private_cose_key(cose_key: &HsmDmaBuf) -> HsmResult<Ec2PrivateCoseKey<'_>> {
    let mut kty_seen = false;
    let mut kid_seen = false;
    let mut alg: Option<i32> = None;
    let mut key_ops: Option<CoseKeyOps> = None;
    let mut crv: Option<i32> = None;
    let mut x_span: Option<(usize, usize)> = None;
    let mut y_span: Option<(usize, usize)> = None;
    let mut d_span: Option<(usize, usize)> = None;

    {
        let mut dec = Decoder::new(cose_key);
        // Definite-length map only (reject indefinite / non-deterministic
        // encodings, spec §10.2).
        let entries = map_err(dec.map())?.ok_or(HsmError::InvalidArg)?;
        for _ in 0..entries {
            match map_err(dec.i32())? {
                COSE_KTY => {
                    if kty_seen {
                        return Err(HsmError::InvalidArg);
                    }
                    kty_seen = true;
                    if map_err(dec.u8())? != COSE_KTY_EC2 {
                        return Err(HsmError::InvalidArg);
                    }
                }
                COSE_KID => {
                    if kid_seen {
                        return Err(HsmError::InvalidArg);
                    }
                    kid_seen = true;
                    // `kid` is an opaque identifier; skip its bytes.
                    let _ = bytes_span(&mut dec)?;
                }
                COSE_ALG => {
                    if alg.is_some() {
                        return Err(HsmError::InvalidArg);
                    }
                    alg = Some(map_err(dec.i32())?);
                }
                COSE_KEY_OPS => {
                    if key_ops.is_some() {
                        return Err(HsmError::InvalidArg);
                    }
                    key_ops = Some(decode_key_ops(&mut dec)?);
                }
                COSE_EC2_CRV => {
                    if crv.is_some() {
                        return Err(HsmError::InvalidArg);
                    }
                    crv = Some(map_err(dec.i32())?);
                }
                COSE_EC2_X => {
                    if x_span.is_some() {
                        return Err(HsmError::InvalidArg);
                    }
                    x_span = Some(bytes_span(&mut dec)?);
                }
                COSE_EC2_Y => {
                    if y_span.is_some() {
                        return Err(HsmError::InvalidArg);
                    }
                    y_span = Some(bytes_span(&mut dec)?);
                }
                COSE_EC2_D => {
                    if d_span.is_some() {
                        return Err(HsmError::InvalidArg);
                    }
                    d_span = Some(bytes_span(&mut dec)?);
                }
                // Unknown / out-of-profile label (including the optional
                // Base IV `5`, or the boolean compressed-`y` form which is
                // rejected here because it is not a byte string).
                _ => return Err(HsmError::InvalidArg),
            }
        }
        // Reject trailing bytes after the COSE_Key map.
        if dec.position() != cose_key.len() {
            return Err(HsmError::InvalidArg);
        }
    }

    // Required common parameters (spec §3.1, §10.3 / §10.4).
    if !kty_seen || !kid_seen {
        return Err(HsmError::InvalidArg);
    }
    let alg = alg.ok_or(HsmError::InvalidArg)?;
    validate_alg(alg)?;
    let key_ops = key_ops.ok_or(HsmError::InvalidArg)?;

    let curve = curve_from_cose(crv.ok_or(HsmError::InvalidArg)?)?;

    // A private key requires the scalar; EC2 requires both coordinates.
    let (x0, x1) = x_span.ok_or(HsmError::InvalidArg)?;
    let (y0, y1) = y_span.ok_or(HsmError::InvalidArg)?;
    let (d0, d1) = d_span.ok_or(HsmError::InvalidArg)?;

    // Each field element must be exactly the curve field width, unsigned
    // big-endian, no leading-zero trimming (spec §4.1, §10.8).
    let field = curve.priv_key_len();
    if x1 - x0 != field || y1 - y0 != field || d1 - d0 != field {
        return Err(HsmError::InvalidArg);
    }

    Ok(Ec2PrivateCoseKey {
        curve,
        alg,
        key_ops,
        x: &cose_key[x0..x1],
        y: &cose_key[y0..y1],
        d: &cose_key[d0..d1],
    })
}

/// Encode an EC2 private `COSE_Key` into `out`, returning the number of
/// bytes written.  The inverse of [`parse_ec2_private_cose_key`].
///
/// `kid` is opaque; `key_ops` is a non-empty slice of operation values
/// (see [`key_op`]); `x`, `y`, and `d` are big-endian field elements
/// each exactly `curve.priv_key_len()` bytes.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — an out-of-profile field width, an empty
///   or oversized `key_ops`, or `out` too small.
pub fn encode_ec2_private_cose_key(
    curve: HsmEccCurve,
    kid: &[u8],
    alg: i32,
    key_ops: &[u8],
    x: &[u8],
    y: &[u8],
    d: &[u8],
    out: &mut [u8],
) -> HsmResult<usize> {
    let field = curve.priv_key_len();
    if x.len() != field || y.len() != field || d.len() != field {
        return Err(HsmError::InvalidArg);
    }
    if key_ops.is_empty() {
        return Err(HsmError::InvalidArg);
    }
    for &op in key_ops {
        if op == 0 || op > COSE_KEY_OP_MAX {
            return Err(HsmError::InvalidArg);
        }
    }
    validate_alg(alg)?;

    let out_len = out.len();
    let mut enc = Encoder::new(out);
    let key_ops_len = u64::try_from(key_ops.len()).map_err(|_| HsmError::InvalidArg)?;
    let enc_err =
        |r: Result<&mut Encoder<&mut [u8]>, _>| r.map(|_| ()).map_err(|_| HsmError::InvalidArg);

    enc_err(enc.map(8))?;
    enc_err(enc.i32(COSE_KTY))?;
    enc_err(enc.u8(COSE_KTY_EC2))?;
    enc_err(enc.i32(COSE_KID))?;
    enc_err(enc.bytes(kid))?;
    enc_err(enc.i32(COSE_ALG))?;
    enc_err(enc.i32(alg))?;
    enc_err(enc.i32(COSE_KEY_OPS))?;
    enc_err(enc.array(key_ops_len))?;
    for &op in key_ops {
        enc_err(enc.u8(op))?;
    }
    enc_err(enc.i32(COSE_EC2_CRV))?;
    enc_err(enc.i32(cose_from_curve(curve)))?;
    enc_err(enc.i32(COSE_EC2_X))?;
    enc_err(enc.bytes(x))?;
    enc_err(enc.i32(COSE_EC2_Y))?;
    enc_err(enc.bytes(y))?;
    enc_err(enc.i32(COSE_EC2_D))?;
    enc_err(enc.bytes(d))?;

    Ok(out_len - enc.writer().len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use tsra_fw_hsm_pal_traits::HsmDmaBuf;

    use super::*;

    /// Brand a borrowed slice as a `HsmDmaBuf` for the parser under test.
    #[allow(unsafe_code)]
    fn dbuf(bytes: &[u8]) -> &HsmDmaBuf {
        // SAFETY: test-only; the slice is ordinary heap/stack memory and
        // the parser never issues DMA against it.
        unsafe { HsmDmaBuf::from_raw(bytes) }
    }

    /// Build a P-256 private-key COSE blob with a single `sign` op.
    fn sample_p256(out: &mut [u8]) -> usize {
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let d = [0x33u8; 32];
        encode_ec2_private_cose_key(
            HsmEccCurve::P256,
            b"kid-1",
            -9, // ESP256
            &[key_op::CREATE_SIGNATURE],
            &x,
            &y,
            &d,
            out,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_p256_private_key() {
        let mut buf = [0u8; 256];
        let n = sample_p256(&mut buf);
        let parsed = parse_ec2_private_cose_key(dbuf(&buf[..n])).unwrap();
        assert_eq!(parsed.curve, HsmEccCurve::P256);
        assert_eq!(parsed.alg, -9);
        assert!(parsed.key_ops.contains(key_op::CREATE_SIGNATURE));
        assert!(!parsed.key_ops.contains(key_op::DERIVE_KEY));
        assert!(*parsed.x == [0x11u8; 32][..]);
        assert!(*parsed.y == [0x22u8; 32][..]);
        assert!(*parsed.d == [0x33u8; 32][..]);
    }

    #[test]
    fn round_trips_p521_field_widths() {
        let x = [0x01u8; 66];
        let y = [0x02u8; 66];
        let d = [0x03u8; 66];
        let mut buf = [0u8; 512];
        let n = encode_ec2_private_cose_key(
            HsmEccCurve::P521,
            b"k",
            -52,
            &[key_op::DERIVE_BITS],
            &x,
            &y,
            &d,
            &mut buf,
        )
        .unwrap();
        let parsed = parse_ec2_private_cose_key(dbuf(&buf[..n])).unwrap();
        assert_eq!(parsed.curve, HsmEccCurve::P521);
        assert_eq!(parsed.d.len(), 66);
        assert!(parsed.key_ops.contains(key_op::DERIVE_BITS));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut buf = [0u8; 256];
        let n = sample_p256(&mut buf);
        // Append a stray byte after the map.
        buf[n] = 0x00;
        assert!(matches!(
            parse_ec2_private_cose_key(dbuf(&buf[..n + 1])),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn rejects_wrong_coord_width() {
        // Hand-build a P-256 key whose X is only 31 bytes.
        let x = [0x11u8; 31];
        let y = [0x22u8; 32];
        let d = [0x33u8; 32];
        let mut buf = [0u8; 256];
        let cap = buf.len();
        let mut enc = Encoder::new(&mut buf[..]);
        enc.map(8).unwrap();
        enc.i32(COSE_KTY).unwrap();
        enc.u8(COSE_KTY_EC2).unwrap();
        enc.i32(COSE_KID).unwrap();
        enc.bytes(b"k").unwrap();
        enc.i32(COSE_ALG).unwrap();
        enc.i32(-9).unwrap();
        enc.i32(COSE_KEY_OPS).unwrap();
        enc.array(1).unwrap();
        enc.u8(1).unwrap();
        enc.i32(COSE_EC2_CRV).unwrap();
        enc.i32(COSE_CRV_P256).unwrap();
        enc.i32(COSE_EC2_X).unwrap();
        enc.bytes(&x).unwrap();
        enc.i32(COSE_EC2_Y).unwrap();
        enc.bytes(&y).unwrap();
        enc.i32(COSE_EC2_D).unwrap();
        enc.bytes(&d).unwrap();
        let used = cap - enc.writer().len();
        assert!(matches!(
            parse_ec2_private_cose_key(dbuf(&buf[..used])),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn rejects_missing_scalar() {
        // A public-only EC2 key (kty, kid, alg, key_ops, crv, x, y — no
        // `d`) must be rejected by the private-key parser.
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let mut buf = [0u8; 256];
        let cap = buf.len();
        let mut enc = Encoder::new(&mut buf[..]);
        enc.map(7).unwrap();
        enc.i32(COSE_KTY).unwrap();
        enc.u8(COSE_KTY_EC2).unwrap();
        enc.i32(COSE_KID).unwrap();
        enc.bytes(b"k").unwrap();
        enc.i32(COSE_ALG).unwrap();
        enc.i32(-9).unwrap();
        enc.i32(COSE_KEY_OPS).unwrap();
        enc.array(1).unwrap();
        enc.u8(2).unwrap();
        enc.i32(COSE_EC2_CRV).unwrap();
        enc.i32(COSE_CRV_P256).unwrap();
        enc.i32(COSE_EC2_X).unwrap();
        enc.bytes(&x).unwrap();
        enc.i32(COSE_EC2_Y).unwrap();
        enc.bytes(&y).unwrap();
        let used = cap - enc.writer().len();
        assert!(matches!(
            parse_ec2_private_cose_key(dbuf(&buf[..used])),
            Err(HsmError::InvalidArg)
        ));
    }

    #[test]
    fn rejects_deprecated_alg() {
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let d = [0x33u8; 32];
        let mut buf = [0u8; 256];
        let r = encode_ec2_private_cose_key(
            HsmEccCurve::P256,
            b"k",
            -7, // deprecated ES256
            &[key_op::CREATE_SIGNATURE],
            &x,
            &y,
            &d,
            &mut buf,
        );
        assert_eq!(r, Err(HsmError::InvalidArg));
    }

    #[test]
    fn rejects_empty_key_ops() {
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let d = [0x33u8; 32];
        let mut buf = [0u8; 256];
        let cap = buf.len();
        let mut enc = Encoder::new(&mut buf[..]);
        enc.map(8).unwrap();
        enc.i32(COSE_KTY).unwrap();
        enc.u8(COSE_KTY_EC2).unwrap();
        enc.i32(COSE_KID).unwrap();
        enc.bytes(b"k").unwrap();
        enc.i32(COSE_ALG).unwrap();
        enc.i32(-9).unwrap();
        enc.i32(COSE_KEY_OPS).unwrap();
        enc.array(0).unwrap();
        enc.i32(COSE_EC2_CRV).unwrap();
        enc.i32(COSE_CRV_P256).unwrap();
        enc.i32(COSE_EC2_X).unwrap();
        enc.bytes(&x).unwrap();
        enc.i32(COSE_EC2_Y).unwrap();
        enc.bytes(&y).unwrap();
        enc.i32(COSE_EC2_D).unwrap();
        enc.bytes(&d).unwrap();
        let used = cap - enc.writer().len();
        assert!(matches!(
            parse_ec2_private_cose_key(dbuf(&buf[..used])),
            Err(HsmError::InvalidArg)
        ));
    }
}
