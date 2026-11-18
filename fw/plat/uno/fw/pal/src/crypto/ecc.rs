// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC trait implementation for the Uno PAL.
//!
//! All curve arithmetic is performed by the on-chip PKA engine; this file
//! is a thin adapter that:
//!
//! 1. Maps the trait-level [`HsmEccCurve`] enum to the driver-level
//!    [`UpkaEccCurve`] enum via [`map_ecc_curve`].
//! 2. Forwards the public/private key, hash, and signature buffers to
//!    [`UnoHsmPal::pka`].
//! 3. Performs one piece of buffer surgery for
//!    [`HsmEcc::ecc_gen_keypair`]: the PKA driver writes
//!    `pub_key ‖ priv_key` contiguously into scoped scratch, so this
//!    layer splits that scratch and copies the two halves into the
//!    caller's separate output buffers.
//!
//! Key generation runs the pairwise consistency test (PCT) that the caller
//! selects, using the Uno PCT crate ([`tsra_fw_uno_pct`]). A key pair that
//! fails its PCT enters the FIPS error state
//! ([`tsra_fw_uno_fault::enter_error_state`]). [`HsmEcc::ecc_priv_der_to_vault`]
//! checks the key it converts: the public key that the key carries must match
//! its private key, and the key pair must pass the PCT that the caller
//! selects. A key that fails either check is rejected with an error.

use core::cmp::Ordering;

use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmCryptoOrder;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEcc;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmEccPct;
use tsra_fw_hsm_pal_traits::HsmEcdsaNonce;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmVault;
use tsra_fw_uno_drivers_upka::UpkaEccCurve;
use tsra_fw_uno_drivers_upka::hsm_point_size;
use tsra_fw_uno_drivers_upka::mont_operand_size;
use tsra_fw_uno_pct::ecc_pct;
use zeroize::Zeroize;

use super::ecc_det::ORDER384_BE;
use super::ecc_det::ct_in_range;
use super::ecc_det::ct_in_range_le;
use super::reverse_copy;
use crate::UnoHsmIo;
use crate::UnoHsmPal;
use crate::asn1::DecodedEcKey;
use crate::asn1::parse_ec_private_key;

// =============================================================================
// Curve mapping
// =============================================================================

/// Translate the trait-level [`HsmEccCurve`] enum to the PKA driver's
/// [`UpkaEccCurve`] enum.
///
/// # Parameters
/// * `curve` — the curve identifier supplied by the caller.
///
/// # Returns
/// * `Ok(UpkaEccCurve)` — the corresponding driver-level variant
///   (`P256`, `P384`, or `P521`).
///
/// # Errors
/// * [`HsmError::InvalidArg`] if a future variant is added to
///   [`HsmEccCurve`] that this PAL does not yet support. The wildcard
///   arm exists so adding a new variant in the trait crate fails
///   gracefully at runtime instead of failing to compile here.
#[allow(unreachable_patterns)]
fn map_ecc_curve(curve: HsmEccCurve) -> HsmResult<UpkaEccCurve> {
    match curve {
        HsmEccCurve::P256 => Ok(UpkaEccCurve::P256),
        HsmEccCurve::P384 => Ok(UpkaEccCurve::P384),
        HsmEccCurve::P521 => Ok(UpkaEccCurve::P521),
        _ => Err(HsmError::InvalidArg),
    }
}

/// NIST P-256 prime modulus in PKA little-endian operand order.
const PRIME256_LE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
];

/// NIST P-384 prime modulus in PKA little-endian operand order.
pub(super) const PRIME384_LE: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// NIST P-521 prime modulus in PKA little-endian operand order (68-byte,
/// DWORD-aligned per PKA hardware requirement).
const PRIME521_LE: [u8; 68] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x01, 0x00, 0x00,
];

/// Curve prime modulus (PKA little-endian) for the Montgomery-constant setup.
fn curve_prime_le(curve: UpkaEccCurve) -> &'static [u8] {
    match curve {
        UpkaEccCurve::P256 => &PRIME256_LE,
        UpkaEccCurve::P384 => &PRIME384_LE,
        UpkaEccCurve::P521 => &PRIME521_LE,
    }
}

/// NIST P-256 base point `G` x-coordinate in PKA little-endian operand order.
const BASE256_X_LE: [u8; 32] = [
    0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4, 0xa0, 0x33, 0xeb, 0x2d, 0x81, 0x7d, 0x03, 0x77,
    0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8, 0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1, 0x17, 0x6b,
];

/// NIST P-256 base point `G` y-coordinate in PKA little-endian operand order.
const BASE256_Y_LE: [u8; 32] = [
    0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb, 0xce, 0x5e, 0x31, 0x6b, 0x57, 0x33, 0xce, 0x2b,
    0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e, 0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42, 0xe3, 0x4f,
];

/// NIST P-384 base point `G` x-coordinate in PKA little-endian operand order.
pub(super) const BASE384_X_LE: [u8; 48] = [
    0xb7, 0x0a, 0x76, 0x72, 0x38, 0x5e, 0x54, 0x3a, 0x6c, 0x29, 0x55, 0xbf, 0x5d, 0xf2, 0x02, 0x55,
    0x38, 0x2a, 0x54, 0x82, 0xe0, 0x41, 0xf7, 0x59, 0x98, 0x9b, 0xa7, 0x8b, 0x62, 0x3b, 0x1d, 0x6e,
    0x74, 0xad, 0x20, 0xf3, 0x1e, 0xc7, 0xb1, 0x8e, 0x37, 0x05, 0x8b, 0xbe, 0x22, 0xca, 0x87, 0xaa,
];

/// NIST P-384 base point `G` y-coordinate in PKA little-endian operand order.
pub(super) const BASE384_Y_LE: [u8; 48] = [
    0x5f, 0x0e, 0xea, 0x90, 0x7c, 0x1d, 0x43, 0x7a, 0x9d, 0x81, 0x7e, 0x1d, 0xce, 0xb1, 0x60, 0x0a,
    0xc0, 0xb8, 0xf0, 0xb5, 0x13, 0x31, 0xda, 0xe9, 0x7c, 0x14, 0x9a, 0x28, 0xbd, 0x1d, 0xf4, 0xf8,
    0x29, 0xdc, 0x92, 0x92, 0xbf, 0x98, 0x9e, 0x5d, 0x6f, 0x2c, 0x26, 0x96, 0x4a, 0xde, 0x17, 0x36,
];

/// NIST P-521 base point `G` x-coordinate in PKA little-endian operand order
/// (68-byte, DWORD-aligned per PKA hardware requirement).
const BASE521_X_LE: [u8; 68] = [
    0x66, 0xbd, 0xe5, 0xc2, 0x31, 0x7e, 0x7e, 0xf9, 0x9b, 0x42, 0x6a, 0x85, 0xc1, 0xb3, 0x48, 0x33,
    0xde, 0xa8, 0xff, 0xa2, 0x27, 0xc1, 0x1d, 0xfe, 0x28, 0x59, 0xe7, 0xef, 0x77, 0x5e, 0x4b, 0xa1,
    0xba, 0x3d, 0x4d, 0x6b, 0x60, 0xaf, 0x28, 0xf8, 0x21, 0xb5, 0x3f, 0x05, 0x39, 0x81, 0x64, 0x9c,
    0x42, 0xb4, 0x95, 0x23, 0x66, 0xcb, 0x3e, 0x9e, 0xcd, 0xe9, 0x04, 0x04, 0xb7, 0x06, 0x8e, 0x85,
    0xc6, 0x00, 0x00, 0x00,
];

/// NIST P-521 base point `G` y-coordinate in PKA little-endian operand order
/// (68-byte, DWORD-aligned per PKA hardware requirement).
const BASE521_Y_LE: [u8; 68] = [
    0x50, 0x66, 0xd1, 0x9f, 0x76, 0x94, 0xbe, 0x88, 0x40, 0xc2, 0x72, 0xa2, 0x86, 0x70, 0x3c, 0x35,
    0x61, 0x07, 0xad, 0x3f, 0x01, 0xb9, 0x50, 0xc5, 0x40, 0x26, 0xf4, 0x5e, 0x99, 0x72, 0xee, 0x97,
    0x2c, 0x66, 0x3e, 0x27, 0x17, 0xbd, 0xaf, 0x17, 0x68, 0x44, 0x9b, 0x57, 0x49, 0x44, 0xf5, 0x98,
    0xd9, 0x1b, 0x7d, 0x2c, 0xb4, 0x5f, 0x8a, 0x5c, 0x04, 0xc0, 0x3b, 0x9a, 0x78, 0x6a, 0x29, 0x39,
    0x18, 0x01, 0x00, 0x00,
];

/// Curve base point `G = (x, y)` in PKA little-endian operand order, for the
/// `Q = d·G` point multiply.
fn curve_base_point_le(curve: UpkaEccCurve) -> (&'static [u8], &'static [u8]) {
    match curve {
        UpkaEccCurve::P256 => (&BASE256_X_LE, &BASE256_Y_LE),
        UpkaEccCurve::P384 => (&BASE384_X_LE, &BASE384_Y_LE),
        UpkaEccCurve::P521 => (&BASE521_X_LE, &BASE521_Y_LE),
    }
}

/// NIST P-256 curve order `n` in big-endian (for the `1 <= d < n` scalar check).
const ORDER256_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// NIST P-521 curve order `n` in big-endian (for the `1 <= d < n` scalar check).
const ORDER521_BE: [u8; 66] = [
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
    0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
    0x64, 0x09,
];

/// Curve order `n` (big-endian, raw `priv_key_len` bytes) used to validate an
/// imported scalar is in range `[1, n-1]`. P-384's lives in [`super::ecc_det`].
fn curve_order_be(curve: HsmEccCurve) -> &'static [u8] {
    match curve {
        HsmEccCurve::P256 => &ORDER256_BE,
        HsmEccCurve::P384 => &ORDER384_BE,
        HsmEccCurve::P521 => &ORDER521_BE,
    }
}

/// Checks an ECDSA input of `lanes` coordinate lanes followed by a digest
/// lane against the trait contract.
///
/// # Errors
/// * [`HsmError::UnsupportedDigestHashAlgorithm`] — `hash` is not SHA-1 or
///   SHA-2.
/// * [`HsmError::InvalidArg`] — `input` has the wrong length, or a byte
///   after the digest in its lane is not zero.
fn check_ecdsa_input(
    curve: HsmEccCurve,
    hash: HsmHashAlgo,
    lanes: usize,
    input: &[u8],
) -> HsmResult<()> {
    if !matches!(
        hash,
        HsmHashAlgo::Sha1 | HsmHashAlgo::Sha256 | HsmHashAlgo::Sha384 | HsmHashAlgo::Sha512
    ) {
        return Err(HsmError::UnsupportedDigestHashAlgorithm);
    }
    let pad = UnoHsmPal::ECC_COORD_PAD;
    let at = lanes * curve.wire_coord_len(pad);
    if input.len() != at + curve.ecdsa_digest_lane_len(hash, pad)
        || input[at + hash.digest_len()..].iter().any(|&b| b != 0)
    {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Checks the ECDSA nonce source: the engine always generates `k`.
fn check_nonce(nonce: HsmEcdsaNonce) -> HsmResult<()> {
    match nonce {
        HsmEcdsaNonce::Generated => Ok(()),
        HsmEcdsaNonce::Supplied => Err(HsmError::CryptoUnsupportedMode),
    }
}

// =============================================================================
// Peer public-key range validation
// =============================================================================

/// Validate that a single coordinate satisfies `1 <= coordinate <= p - 1`.
///
/// `coordinate` and `p` are equal-length big numbers in little-endian byte
/// order. This is a byte-wise port of the reference firmware's
/// `EccPublicKeyRangeValidation::is_in_valid_range`: it walks from the most
/// significant byte (highest index in little-endian) down to the least,
/// short-circuiting as soon as the comparison is decided.
///
/// # Returns
/// * `true` — the coordinate is in the closed interval `[1, p - 1]`.
/// * `false` — the coordinate is `0`, is `>= p`, or the lengths differ.
fn coord_in_valid_range(coordinate: &[u8], p: &[u8]) -> bool {
    // A length mismatch means a malformed coordinate; reject it.
    if coordinate.len() != p.len() {
        return false;
    }

    // Tracks whether any non-least-significant byte of the coordinate is > 0,
    // i.e. whether the coordinate is already known to be >= 1.
    let mut coord_gt_zero = false;

    // Compare bytes from most to least significant (right to left in
    // little-endian). At a non-LSB position i:
    // - p[i] > coordinate[i]: the gap is at least 2^8, so coordinate < p.
    // - p[i] < coordinate[i]: coordinate exceeds p, so coordinate >= p.
    // - equal: continue to the next lower byte.
    for i in (1..p.len()).rev() {
        coord_gt_zero |= coordinate[i] > 0;

        match p[i].cmp(&coordinate[i]) {
            Ordering::Greater => {
                if coord_gt_zero {
                    return true;
                }
                // coordinate < p is established; it is valid iff coordinate >= 1.
                return coordinate[1..i].iter().rev().any(|&byte| byte > 0) || coordinate[0] >= 1;
            }
            Ordering::Less => return false,
            Ordering::Equal => {}
        }
    }

    // All non-LSB bytes were equal: valid iff coordinate >= 1 and
    // coordinate[0] <= p[0] - 1 (i.e. coordinate[0] < p[0], as p[0] > 0 for
    // every supported curve prime).
    (coord_gt_zero || coordinate[0] >= 1) && coordinate[0] < p[0]
}

/// Validate that a peer public key `(X ‖ Y)` has both coordinates in
/// `[1, p - 1]` for the given curve.
///
/// `pub_key` is the little-endian wire buffer laid out as two
/// [`hsm_point_size`] slots (`X` then `Y`). Each coordinate is validated at
/// its **full wire width** against the wire-width curve prime
/// ([`curve_prime_le`], whose P-521 DWORD-alignment pad bytes are zero).
/// Comparing the padded coordinate against the padded prime means a
/// non-zero MSB pad byte (P-521's 2 trailing bytes) makes the coordinate
/// compare `>= p` and is rejected here, rather than being silently ignored
/// and slipping an out-of-range coordinate through to the PKA. This matches
/// the exact bytes the hardware will consume. The caller must have ensured
/// `pub_key.len() >= hsm_point_size(curve) * 2`.
fn pub_key_in_valid_range(pub_key: &[u8], curve: UpkaEccCurve) -> bool {
    let wire = hsm_point_size(curve);
    let p = &curve_prime_le(curve)[..wire];

    let x = &pub_key[..wire];
    let y = &pub_key[wire..wire * 2];

    coord_in_valid_range(x, p) && coord_in_valid_range(y, p)
}

// =============================================================================
// Pairwise consistency test at key generation
// =============================================================================

impl UnoHsmPal {
    fn generation_pct_workspace_len(curve: HsmEccCurve, pct: &HsmEccPct) -> usize {
        let coord = curve.wire_coord_len(Self::ECC_COORD_PAD);
        let backend = match pct {
            HsmEccPct::None => 0,
            HsmEccPct::SignVerify => 2 * coord + 4,
            HsmEccPct::KeyAgreement => 4 * coord + 4,
        };
        tsra_fw_uno_pct::ecc_pct_workspace_len::<Self>(curve, pct) + backend
    }

    async fn ecc_verify_in_workspace(
        &self,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
        pub_key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        workspace: &mut HsmDmaBuf,
    ) -> HsmResult<bool> {
        let pka_curve = map_ecc_curve(curve)?;
        check_ecdsa_input(curve, hash, 2, input)?;
        let prime_le = curve_prime_le(pka_curve);
        if workspace.len() < 2 * prime_le.len() + 4 {
            return Err(HsmError::NotEnoughSpace);
        }
        let (prime, rest) = workspace.split_at_mut(prime_le.len());
        prime.copy_from_slice(prime_le);
        let (mont_result, rest) = rest.split_at_mut(prime_le.len());
        let result = &mut rest[..4];
        result.fill(0xFF);
        self.pka
            .ecc_verify(pka_curve, hash, pub_key, input, result, prime, mont_result)
            .await?;
        Ok(result[0] & 1 == 0)
    }

    async fn ecdh_derive_in_workspace(
        &self,
        curve: HsmEccCurve,
        priv_key: &HsmDmaBuf,
        pub_key: &HsmDmaBuf,
        secret: &mut HsmDmaBuf,
        workspace: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let pka_curve = map_ecc_curve(curve)?;
        let wire = hsm_point_size(pka_curve);
        if pub_key.len() < wire * 2 {
            return Err(HsmError::EccDerKeyShorterThanCurve);
        }
        let secret_len = curve.secret_len();
        if secret.len() < secret_len {
            return Err(HsmError::InvalidArg);
        }
        if !pub_key_in_valid_range(pub_key, pka_curve) {
            return Err(HsmError::EccPublicKeyValidationFailed);
        }
        if workspace.len() < 4 * wire + 4 {
            return Err(HsmError::NotEnoughSpace);
        }
        let (prime, rest) = workspace.split_at_mut(wire);
        prime.copy_from_slice(curve_prime_le(pka_curve));
        let (mont_result, rest) = rest.split_at_mut(wire);
        let (point_valid, rest) = rest.split_at_mut(4);
        let point = &mut rest[..wire * 2];
        let result = self
            .pka
            .ecdh_derive(
                pka_curve,
                priv_key,
                pub_key,
                &mut *point,
                prime,
                mont_result,
                point_valid,
            )
            .await;
        if result.is_ok() {
            secret[..secret_len].copy_from_slice(&point[..secret_len]);
        }
        point.zeroize();
        result
    }

    /// Runs the PCT that `pct` selects on a key pair this PAL just generated.
    ///
    /// A key pair that fails the test enters the FIPS error state. An
    /// operation that fails returns its error, and the caller discards the
    /// key.
    async fn generation_pct(
        &self,
        io: &UnoHsmIo,
        workspace: &mut HsmDmaBuf,
        curve: HsmEccCurve,
        pct: &HsmEccPct,
        priv_key: &HsmDmaBuf,
        pub_key: &HsmDmaBuf,
    ) -> HsmResult<()> {
        if !tsra_fw_uno_pct::ecc_pct_in_workspace(
            self,
            io,
            curve,
            pct,
            priv_key,
            pub_key,
            workspace,
            async |operation, scratch| match operation {
                tsra_fw_uno_pct::EccPctOperation::Verify {
                    hash,
                    public,
                    input,
                    valid,
                } => {
                    *valid = self
                        .ecc_verify_in_workspace(curve, hash, public, input, scratch)
                        .await?;
                    Ok(())
                }
                tsra_fw_uno_pct::EccPctOperation::Derive {
                    private,
                    public,
                    secret,
                } => {
                    self.ecdh_derive_in_workspace(curve, private, public, secret, scratch)
                        .await
                }
            },
        )
        .await?
        {
            tsra_fw_uno_fault::enter_error_state(HsmError::PctValidationEccGenKeyFailed);
        }
        Ok(())
    }
}

// =============================================================================
// Imported-key assurance
// =============================================================================

/// SEC1 marker byte for an uncompressed point.
const UNCOMPRESSED_POINT: u8 = 0x04;

/// Returns the public key that an imported ECC key carries, as big-endian
/// `x ‖ y`.
///
/// The key must carry its public key in the SEC1 `[1] publicKey` field,
/// right after the private key, as an uncompressed point on the key's curve.
/// So a key that carries `[0] parameters` is rejected; the curve comes from
/// the PKCS#8 algorithm.
///
/// # Errors
/// * [`HsmError::KeyDecodeFailed`] — the key carries no public key, or
///   carries `[0] parameters`.
/// * [`HsmError::KeyStructuralValidationFailed`] — its public key isn't an
///   uncompressed point of the curve's size.
fn embedded_public_key<'a>(key: &DecodedEcKey<'a>) -> HsmResult<&'a [u8]> {
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

/// Returns `true` if `wire_pub`, a public key in the PAL's wire format, is
/// the point `xy`.
///
/// `xy` is big-endian `x ‖ y`, each coordinate [`HsmEccCurve::priv_key_len`]
/// bytes. Each wire coordinate is little-endian and
/// [`HsmEccCurve::wire_coord_len`] bytes, so the two padding bytes of a P-521
/// wire coordinate must be zero.
fn is_wire_point(curve: HsmEccCurve, xy: &[u8], wire_pub: &[u8]) -> bool {
    let raw = curve.priv_key_len();
    let coord = curve.wire_coord_len(UnoHsmPal::ECC_COORD_PAD);
    xy.len() == 2 * raw
        && wire_pub.len() == 2 * coord
        && xy
            .chunks_exact(raw)
            .zip(wire_pub.chunks_exact(coord))
            .all(|(be, le)| be.iter().rev().eq(&le[..raw]) && le[raw..].iter().all(|&b| b == 0))
}

impl UnoHsmPal {
    /// Checks an imported ECC key pair after its conversion to the vault
    /// format.
    ///
    /// The public key derived from `priv_key` must equal `embedded`, the
    /// big-endian `x ‖ y` that the key carries. Then the key pair must pass
    /// the PCT that `pct` selects, which runs on the derived public key.
    ///
    /// # Errors
    /// * [`HsmError::KeyStructuralValidationFailed`] — the public keys
    ///   differ.
    /// * [`HsmError::PctValidationRsaUnwrapEccKeyFailed`] — the key pair
    ///   failed its PCT.
    /// * Any [`HsmError`] from the public-key derivation, the scoped
    ///   allocator, or an operation that the PCT runs.
    async fn check_ecc_import(
        &self,
        io: &UnoHsmIo,
        curve: HsmEccCurve,
        pct: HsmEccPct,
        priv_key: &HsmDmaBuf,
        embedded: &[u8],
    ) -> HsmResult<()> {
        self.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
            let pub_key =
                tsra_fw_uno_pct::scratch(alloc, curve.wire_pub_key_len(UnoHsmPal::ECC_COORD_PAD))?;
            self.ecc_priv_pub_key(io, priv_key, Some(&mut *pub_key))
                .await?;
            if !is_wire_point(curve, embedded, pub_key) {
                return Err(HsmError::KeyStructuralValidationFailed);
            }
            if !ecc_pct(self, io, alloc, curve, &pct, priv_key, pub_key).await? {
                return Err(HsmError::PctValidationRsaUnwrapEccKeyFailed);
            }
            Ok(())
        })
        .await
    }
}

// =============================================================================
// HsmEcc trait impl
// =============================================================================
//
// The primary contract for each method (intended semantics, parameter
// shapes, error model) lives on the [`HsmEcc`] trait itself. The notes
// below describe only the Uno-specific behaviour and the buffer
// surgery `ecc_gen_keypair` performs on top of the PKA driver.

impl HsmEcc for UnoHsmPal {
    /// Generate an ECC key pair on the selected NIST curve.
    ///
    /// # Layout
    ///
    /// The PKA driver writes `pub_key ‖ priv_key` contiguously into a
    /// internally scoped workspace. This PAL then copies the
    /// public and private halves into the caller's separate output
    /// buffers.
    ///
    /// `pub_len` is `2 * hsm_point_size(curve)` (X ‖ Y in HSM
    /// wire-format coordinates); `priv_len` is whatever remains of the
    /// `total_len` returned by the driver.
    ///
    /// # Parameters
    /// * `curve` — NIST curve to use ([`HsmEccCurve::P256`],
    ///   [`HsmEccCurve::P384`], or [`HsmEccCurve::P521`]).
    /// * `pct` — pairwise consistency test to run on the new key pair
    ///   before it's returned. A failing pair enters the FIPS error state.
    /// * `out` — `None` to query required buffer sizes, or
    ///   `Some((priv_key, pub_key))` to generate. Temporary storage
    ///   includes the contiguous PKA output and all nested PCT scratch.
    ///
    /// # Returns
    /// * `Ok((priv_len, pub_len))` — output sizes.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if the supplied curve is not one of
    ///   P-256/P-384/P-521, or `out` is `Some` and either output buffer
    ///   is shorter than required.
    /// * Any [`HsmError`] surfaced by [`UnoHsmPal::pka.ecc_gen_keypair`],
    ///   or an operation that the PCT runs.
    async fn ecc_gen_keypair(
        &self,
        io: &UnoHsmIo,
        curve: HsmEccCurve,
        pct: HsmEccPct,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        let pka_curve = map_ecc_curve(curve)?;
        let priv_len = hsm_point_size(pka_curve);
        let pub_len = hsm_point_size(pka_curve) * 2;

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_len, pub_len));
        };

        if priv_out.len() < priv_len || pub_out.len() < pub_len {
            return Err(HsmError::InvalidArg);
        }

        self.alloc_scoped_async(io, async |scope| {
            let workspace_len =
                (priv_len + pub_len).max(Self::generation_pct_workspace_len(curve, &pct));
            let workspace = scope.dma_alloc(workspace_len)?;
            let scratch = &mut workspace[..pub_len + priv_len];
            let total_len = self.pka.ecc_gen_keypair(pka_curve, scratch).await?;
            let (pub_key, priv_key) = scratch[..total_len].split_at(pub_len);

            priv_out[..priv_len].copy_from_slice(priv_key);
            pub_out[..pub_len].copy_from_slice(pub_key);

            self.generation_pct(
                io,
                workspace,
                curve,
                &pct,
                &priv_out[..priv_len],
                &pub_out[..pub_len],
            )
            .await?;

            Ok((priv_len, pub_len))
        })
        .await
    }

    /// Deterministic ECC key generation from a caller-supplied
    /// key-derivation root (the partition `PartRoot`).
    ///
    /// Routes to [`UnoHsmPal::ecc_gen_keypair_deterministic`], which
    /// HKDF-expands `root` and applies FIPS 186-5 §A.2.2 rejection
    /// sampling to obtain the private scalar, then computes the public
    /// point `Q = d·G` on the PKA. §A.2.2 (not §A.2.1) is used because
    /// the UPKA Montgomery modular unit cannot reduce by the even
    /// value `n − 1`; rejection sampling needs only a range check.
    /// Only P-384 — the PTA / alias identity curve — is supported;
    /// other curves surface as [`HsmError::UnsupportedCmd`] from the
    /// inner primitive.
    ///
    /// The private scalar and both public coordinates are returned in
    /// PKA-native little-endian wire form, identical to
    /// [`Self::ecc_gen_keypair`]; byte-order canonicalisation is the
    /// DDI handler's responsibility.
    ///
    /// The std PAL derives from the same `root` with a different info
    /// string, OKM length and §A.2 method, so it produces a
    /// **different** keypair. Determinism holds per-platform only; see
    /// the trait doc.
    ///
    /// # Parameters
    /// * `curve` — must be [`HsmEccCurve::P384`].
    /// * `root` — the 48-byte partition `PartRoot`, used as the HKDF
    ///   PRK for the per-attempt candidate derivation.
    /// * `pct` — pairwise consistency test to run on the derived key pair
    ///   before it's returned. A failing pair enters the FIPS error state.
    /// * `out` — `None` to query `(priv_len, pub_len)`, or
    ///   `Some((priv_key, pub_key))` to derive into caller buffers.
    ///
    /// # Returns
    /// * `Ok((priv_len, pub_len))` — output sizes.
    ///
    /// # Errors
    /// * [`HsmError::UnsupportedCmd`] if `curve` is not P-384.
    /// * [`HsmError::InvalidArg`] if `out` is `Some` and either output
    ///   buffer is shorter than required, or `root` is not 48 bytes.
    /// * Any [`HsmError`] surfaced by the HKDF / SHA / PKA drivers, or by an
    ///   operation that the PCT runs.
    async fn ecc_gen_keypair_from_root(
        &self,
        io: &UnoHsmIo,
        curve: HsmEccCurve,
        root: &HsmDmaBuf,
        pct: HsmEccPct,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        let pka_curve = map_ecc_curve(curve)?;
        // Only P-384 (the PTA / alias identity curve) is supported. Reject
        // other curves here rather than deep inside the derivation, so
        // query mode agrees with use mode instead of handing back sizes
        // for a curve that would later fail with `UnsupportedCmd`.
        if pka_curve != UpkaEccCurve::P384 {
            return Err(HsmError::UnsupportedCmd);
        }

        let priv_len = hsm_point_size(pka_curve);
        let pub_len = hsm_point_size(pka_curve) * 2;

        // `root` is the derivation input in both modes, so validate its
        // length before the query-mode return — the documented
        // `InvalidArg` on a non-48-byte root must not depend on `out`.
        if root.len() != priv_len {
            return Err(HsmError::InvalidArg);
        }

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_len, pub_len));
        };

        if priv_out.len() < priv_len || pub_out.len() < pub_len {
            return Err(HsmError::InvalidArg);
        }

        self.alloc_scoped_async(io, async |scope| {
            let workspace_len = Self::ecc_keypair_root_workspace_len()
                .max(Self::generation_pct_workspace_len(curve, &pct));
            let workspace = scope.dma_alloc(workspace_len)?;
            self.ecc_gen_keypair_deterministic(io, pka_curve, root, priv_out, pub_out, workspace)
                .await?;

            self.generation_pct(
                io,
                workspace,
                curve,
                &pct,
                &priv_out[..priv_len],
                &pub_out[..pub_len],
            )
            .await?;

            Ok((priv_len, pub_len))
        })
        .await
    }

    /// ECDSA sign over a pre-computed digest.
    ///
    /// The PKA reads the digest operand straight from `input`.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is not one of the supported
    ///   NIST curves, or a buffer has the wrong shape.
    /// * [`HsmError::CryptoUnsupportedMode`] for a supplied `k`.
    /// * Any [`HsmError`] surfaced by the PKA driver.
    async fn ecc_sign(
        &self,
        _io: &UnoHsmIo,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        nonce: HsmEcdsaNonce,
        input: &mut HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let pka_curve = map_ecc_curve(curve)?;
        check_ecdsa_input(curve, hash, 1, input)?;
        check_nonce(nonce)?;
        let wire_len = curve.wire_sig_len(Self::ECC_COORD_PAD);
        if priv_key.len() != hsm_point_size(pka_curve) {
            return Err(HsmError::InvalidArg);
        }
        let Some(signature) = out else {
            return Ok(wire_len);
        };
        if signature.len() < wire_len {
            return Err(HsmError::InvalidArg);
        }
        self.service_pka();
        let signed = self
            .pka
            .ecc_sign(pka_curve, hash, priv_key, input, &mut signature[..wire_len])
            .await;
        // Other engines may have finished while this one signed; see to
        // them before the reply goes out.
        self.service_pka();
        signed?;
        Ok(wire_len)
    }

    /// ECDSA sign, writing `r ‖ s` over the start of `k_sig`.
    ///
    /// The PKA reads the digest operand from `k_sig` and writes the
    /// signature back into it, so no staging copy is made.
    async fn ecc_sign_in_place(
        &self,
        _io: &UnoHsmIo,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        nonce: HsmEcdsaNonce,
        k_sig: &mut HsmDmaBuf,
    ) -> HsmResult<usize> {
        let pka_curve = map_ecc_curve(curve)?;
        check_ecdsa_input(curve, hash, 1, k_sig)?;
        check_nonce(nonce)?;
        if priv_key.len() != hsm_point_size(pka_curve) {
            return Err(HsmError::InvalidArg);
        }
        self.service_pka();
        let signed = self
            .pka
            .ecc_sign_in_place(pka_curve, hash, priv_key, k_sig)
            .await;
        self.service_pka();
        signed?;
        Ok(curve.wire_sig_len(Self::ECC_COORD_PAD))
    }

    /// ECDSA verify of `r ‖ s` over a pre-computed digest.
    ///
    /// The PKA reads the signature and digest straight from `input`; DMA
    /// status and Montgomery scratch are scoped internally.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is not one of the supported
    ///   NIST curves, or a buffer has the wrong shape.
    /// * Any [`HsmError`] surfaced by the PKA driver (e.g. malformed
    ///   inputs, hardware fault).
    async fn ecc_verify(
        &self,
        io: &UnoHsmIo,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
        pub_key: &HsmDmaBuf,
        input: &HsmDmaBuf,
    ) -> HsmResult<bool> {
        let pka_curve = map_ecc_curve(curve)?;
        self.alloc_scoped_async(io, async |scope| {
            let workspace = scope.dma_alloc(2 * hsm_point_size(pka_curve) + 4)?;
            self.ecc_verify_in_workspace(curve, hash, pub_key, input, workspace)
                .await
        })
        .await
    }

    /// Derive an ECDH shared secret.
    ///
    /// Delegates to [`UnoHsmPal::pka.ecdh_derive`] after curve mapping.
    ///
    /// # Parameters
    /// * `curve` — NIST curve both peers agreed on.
    /// * `priv_key` — local private key.
    /// * `pub_key` — remote party's public key as `(X ‖ Y)`.
    /// * `out` — `None` to query the secret length without deriving a secret;
    ///   `Some(secret)` to write it. Any output tail is untouched.
    ///
    /// # Returns
    /// * `Ok(len)` — required capacity in query mode; otherwise bytes written.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is not one of the supported
    ///   NIST curves.
    /// * [`HsmError::EccDerKeyShorterThanCurve`] if `pub_key` is too short to
    ///   hold both wire-format coordinates.
    /// * [`HsmError::EccPublicKeyValidationFailed`] if either coordinate is
    ///   outside `[1, p - 1]`.
    /// * [`HsmError::EccPointValidationFailed`] if the point is not on the
    ///   curve.
    /// * Any [`HsmError`] surfaced by the PKA driver (e.g. undersized buffer,
    ///   hardware fault).
    async fn ecdh_derive(
        &self,
        io: &UnoHsmIo,
        curve: HsmEccCurve,
        priv_key: &HsmDmaBuf,
        pub_key: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let pka_curve = map_ecc_curve(curve)?;

        // Reject a peer public key that cannot even hold both wire-format
        // coordinates, then reject one whose coordinates are out of range,
        // before touching the PKA. This mirrors the reference firmware, which
        // range-checks the software-visible coordinates prior to the hardware
        // on-curve validation, and also prevents a coordinate equal to the
        // curve prime from ever reaching the engine.
        let wire = hsm_point_size(pka_curve);
        if pub_key.len() < wire * 2 {
            return Err(HsmError::EccDerKeyShorterThanCurve);
        }
        let secret_len = curve.secret_len();
        if priv_key.len() != wire {
            return Err(HsmError::InvalidArg);
        }
        if !pub_key_in_valid_range(pub_key, pka_curve) {
            return Err(HsmError::EccPublicKeyValidationFailed);
        }
        let Some(secret) = out else {
            return Ok(secret_len);
        };
        if secret.len() < secret_len {
            return Err(HsmError::InvalidArg);
        }

        self.alloc_scoped_async(io, async |scope| {
            let workspace = scope.dma_alloc(4 * wire + 4)?;
            self.ecdh_derive_in_workspace(curve, priv_key, pub_key, secret, workspace)
                .await?;
            Ok(secret_len)
        })
        .await
    }

    /// Converts an imported PKCS#8 ECC private key into the vault format, and
    /// checks it.
    ///
    /// Both modes check the form of the public key that the key carries (see
    /// `embedded_public_key`). In use mode, the public key derived from the
    /// converted key must also match it, and the key pair must pass the PCT
    /// that `pct` selects.
    async fn ecc_priv_der_to_vault(
        &self,
        io: &UnoHsmIo,
        der: &HsmDmaBuf,
        pct: HsmEccPct,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<(usize, HsmEccCurve)> {
        // Parse the recovered PKCS#8 ECC private key (curve from its `namedCurve`
        // OID, the raw big-endian scalar `d`, and the SEC1 optional fields).
        let key = parse_ec_private_key(der).ok_or(HsmError::InvalidArg)?;
        // The key must carry a well-formed public key, whatever `pct` selects.
        let embedded = embedded_public_key(&key)?;
        let (curve, scalar) = (key.curve, key.scalar);
        let vault_len = curve.wire_coord_len(UnoHsmPal::ECC_COORD_PAD);
        // SEC1 / RFC 5915 encodes the scalar as a fixed-width octet string for
        // the curve (P-256 32, P-384 48, P-521 66 bytes). Require exactly that
        // raw length — reject shorter (non-canonical) or overlong scalars,
        // matching the std PAL. `vault_len` is only the (padded) vault / output
        // size, used for wire zero-padding below.
        if scalar.len() != curve.priv_key_len() {
            return Err(HsmError::InvalidArg);
        }
        // SEC1 requires the scalar in `[1, n-1]`; reject `d == 0` or `d >= n`
        // (the curve order). `ct_in_range` compares the same-length big-endian
        // `d` and `n` in constant time, matching the std PAL's `check_key`.
        if !ct_in_range(scalar, curve_order_be(curve)) {
            return Err(HsmError::InvalidArg);
        }
        let Some(out) = out else {
            return Ok((vault_len, curve));
        };
        if out.len() < vault_len {
            return Err(HsmError::InvalidArg);
        }
        // The vault stores the scalar little-endian (PKA-native),
        // zero-padded to the wire coordinate length. `reverse_copy` only
        // writes `scalar.len()` bytes, so clear the high remainder.
        reverse_copy(&mut out[..vault_len], scalar);
        out[scalar.len()..vault_len].fill(0);
        self.check_ecc_import(io, curve, pct, &out[..vault_len], embedded)
            .await?;
        Ok((vault_len, curve))
    }

    fn ecc_priv_to_vault(
        &self,
        _io: &UnoHsmIo,
        curve: HsmEccCurve,
        d: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // The COSE EC2 `d` field is the raw big-endian scalar at the
        // curve's field width (P-256 32, P-384 48, P-521 66). Reject any
        // other length, matching `ecc_priv_der_to_vault`.
        if d.len() != curve.priv_key_len() {
            return Err(HsmError::InvalidArg);
        }
        let vault_len = curve.wire_coord_len(UnoHsmPal::ECC_COORD_PAD);
        // Require the scalar in `[1, n-1]`; reject `d == 0` or `d >= n`
        // (the curve order) in constant time, mirroring the DER path.
        if !ct_in_range(d, curve_order_be(curve)) {
            return Err(HsmError::InvalidArg);
        }
        if let Some(out) = out {
            if out.len() < vault_len {
                return Err(HsmError::InvalidArg);
            }
            // The vault stores the scalar little-endian (PKA-native),
            // zero-padded to the wire coordinate length. `reverse_copy`
            // only writes `d.len()` bytes, so clear the high remainder.
            reverse_copy(&mut out[..vault_len], d);
            out[d.len()..vault_len].fill(0);
        }
        Ok(vault_len)
    }

    fn ecc_vault_to_priv(
        &self,
        _io: &UnoHsmIo,
        curve: HsmEccCurve,
        vault: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // The vault stores the scalar little-endian (PKA-native),
        // zero-padded to `wire_coord_len`. Recover the canonical
        // big-endian COSE `d` by reversing the low `priv_key_len` bytes.
        if vault.len() != curve.wire_coord_len(UnoHsmPal::ECC_COORD_PAD) {
            return Err(HsmError::InvalidArg);
        }
        let field = curve.priv_key_len();
        // For P-521 the 66-byte scalar is padded to 68 bytes; the high
        // (little-endian) bytes above the field width must be zero, else
        // the vault holds a non-canonical / out-of-range scalar.
        if vault[field..].iter().any(|&b| b != 0) {
            return Err(HsmError::InvalidArg);
        }
        // Validate the scalar is in `[1, n-1]` against the curve order.
        // `ct_in_range` compares a big-endian scalar; the vault low bytes
        // are little-endian, so validate after reversing into a scratch.
        if let Some(out) = out {
            if out.len() < field {
                return Err(HsmError::InvalidArg);
            }
            reverse_copy(&mut out[..field], &vault[..field]);
            if !ct_in_range(&out[..field], curve_order_be(curve)) {
                out[..field].fill(0);
                return Err(HsmError::InvalidArg);
            }
        }
        Ok(field)
    }

    async fn ecc_priv_pub_key(
        &self,
        io: &UnoHsmIo,
        priv_key: &HsmDmaBuf,
        pub_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // The vault scalar length is the wire coordinate length, which is
        // unique per curve (32 / 48 / 68).
        let curve = match priv_key.len() {
            32 => HsmEccCurve::P256,
            48 => HsmEccCurve::P384,
            68 => HsmEccCurve::P521,
            _ => return Err(HsmError::InvalidArg),
        };
        // P-521's 66-byte raw scalar is zero-padded to the 68-byte wire length;
        // the two high (little-endian) bytes must be zero, otherwise the scalar
        // is out of range and would feed a malformed operand to the PKA.
        if priv_key.len() == 68 && (priv_key[66] != 0 || priv_key[67] != 0) {
            return Err(HsmError::InvalidArg);
        }
        // Validate the scalar is in `[1, n-1]` against the curve order — the
        // same trust-boundary contract as the import path / std PAL, since this
        // is called on untrusted vault keys (import / unmask / unwrap). Read
        // the LE scalar directly against the BE order (no reversed-copy scratch
        // of the secret scalar).
        let raw_len = curve.priv_key_len();
        if !ct_in_range_le(&priv_key[..raw_len], curve_order_be(curve)) {
            return Err(HsmError::InvalidArg);
        }
        let wire_pub_len = curve.wire_pub_key_len(UnoHsmPal::ECC_COORD_PAD);
        let Some(pub_out) = pub_out else {
            return Ok(wire_pub_len);
        };
        if pub_out.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }
        let pka_curve = map_ecc_curve(curve)?;
        let field = curve.wire_coord_len(UnoHsmPal::ECC_COORD_PAD);
        let (bx, by) = curve_base_point_le(pka_curve);
        let mont = mont_operand_size(pka_curve);

        // Q = d·G on one held engine: `ecc_mont_const_calc` over the field
        // prime, then `ecc_point_mul` with the base point `G` supplied
        // explicitly (the proven primitive — the driver's `ecc_gen_pub_key`
        // issues the opcode with a null scalar operand and faults). Every
        // operand is a GSRAM DMA buffer, which the PKA requires.
        self.alloc_scoped_async(io, async |scope| -> HsmResult<usize> {
            let prime = scope.dma_alloc(field)?;
            prime.copy_from_slice(curve_prime_le(pka_curve));
            let base_xy = scope.dma_alloc(field * 2)?;
            base_xy[..field].copy_from_slice(bx);
            base_xy[field..].copy_from_slice(by);
            let mont_scratch = scope.dma_alloc(mont)?;
            self.pka
                .with_engine(async |eng| {
                    eng.ecc_mont_const_calc(pka_curve, prime, mont_scratch)
                        .await?;
                    eng.ecc_point_mul(
                        pka_curve,
                        base_xy,
                        &priv_key[..field],
                        &mut pub_out[..wire_pub_len],
                    )
                    .await
                })
                .await?;
            Ok(wire_pub_len)
        })
        .await
    }

    async fn ecc_vault_pub_key(
        &self,
        io: &UnoHsmIo,
        key_id: HsmKeyId,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let len = self
            .ecc_priv_pub_key(io, self.vault_key(io, key_id)?, None)
            .await?;
        let Some(pub_out) = out else {
            return Ok(len);
        };
        if pub_out.len() < len {
            return Err(HsmError::InvalidArg);
        }
        if !(pub_out.as_ptr() as usize).is_multiple_of(4) {
            return Err(HsmError::InvalidArg);
        }
        self.alloc_scoped_async(io, async |scope| {
            // Snapshot vault storage before the engine operation can yield.
            let key = self.vault_key(io, key_id)?;
            let private = scope.dma_alloc(key.len())?;
            private.copy_from_slice(key);
            self.ecc_priv_pub_key(io, private, Some(pub_out)).await
        })
        .await
    }

    /// Derive the public key from a raw private scalar (`pub = priv · G`).
    ///
    /// Delegates to [`ecc_priv_pub_key`](Self::ecc_priv_pub_key), which
    /// performs the point multiply with every operand in a GSRAM DMA
    /// buffer.
    ///
    /// This deliberately does **not** use the PKA driver's
    /// `ecc_gen_pub_key`: that issues the point-mul opcode with a null (0)
    /// scalar operand, so the engine reads the scalar from address 0
    /// rather than GSRAM and faults with an AXI `BUS_ERROR`
    /// (`0x08f0c003`). The same note appears on the deterministic-keygen
    /// path in `ecc_det.rs`, which avoids the primitive for the same
    /// reason. Emulator builds do not model PKA operand addressing, so
    /// this fault only ever appears on silicon.
    ///
    /// `ecc_priv_pub_key` infers the curve from the scalar length — which
    /// is exactly `wire_priv_key_len()`, itself defined as
    /// `wire_coord_len()` — so the mapping is equivalent to the explicit
    /// `curve` argument, and it additionally range-checks the scalar
    /// against the curve order.
    ///
    /// # Parameters
    /// * `curve` — NIST curve the private key is on.
    /// * `priv_key` — raw HSM-format private scalar
    ///   ([`HsmEccCurve::wire_priv_key_len`] bytes).
    /// * `out` — `None` to query the public-key length without deriving a
    ///   point; `Some(pub_key)` to write `X ‖ Y`. Any output tail is untouched.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `curve` is unsupported, a buffer is
    ///   undersized, or the scalar is out of range.
    /// * Any [`HsmError`] surfaced by the PKA driver.
    async fn ecc_pub_from_priv(
        &self,
        io: &UnoHsmIo,
        curve: HsmEccCurve,
        priv_key: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // Validate `curve` up front rather than leaving it implicit in the
        // length check below. `ecc_priv_pub_key` re-derives the curve from
        // the scalar length, so without this an unsupported variant would
        // never meet the documented `InvalidArg` contract here — it would
        // either be rejected further down for the wrong reason, or, if a
        // future variant shared a wire length with a supported one, be
        // computed on the wrong curve. `wire_priv_key_len` is pairwise
        // distinct across the supported curves (32 / 48 / 68), which
        // `wire_priv_key_len_is_unambiguous` in the traits crate pins so a
        // colliding variant fails CI rather than mis-dispatching here.
        map_ecc_curve(curve)?;
        if priv_key.len() != curve.wire_priv_key_len(UnoHsmPal::ECC_COORD_PAD) {
            return Err(HsmError::InvalidArg);
        }
        self.ecc_priv_pub_key(io, priv_key, out).await
    }
}
