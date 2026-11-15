// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public-key thumbprints over the canonical P-384 SubjectPublicKeyInfo.
//!
//! A thumbprint is `SHA-384(DER(SubjectPublicKeyInfo))` where the SPKI is
//! the canonical RFC 5480 form: `id-ecPublicKey` with the `secp384r1`
//! named curve and an uncompressed `04 ‖ X ‖ Y` point. The SPKI is always
//! rebuilt from the raw point, so a certificate's own (possibly
//! differently-encoded) SPKI bytes never influence the result.

use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHash;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmResult;

/// Byte length of a public-key thumbprint (SHA-384 digest).
pub const SPKI_THUMBPRINT_LEN: usize = 48;

/// Byte length of a raw P-384 public point (`X ‖ Y`, no `0x04` prefix).
pub const P384_POINT_LEN: usize = 96;

/// Fixed DER prefix of a canonical P-384 SPKI, up to and including the
/// uncompressed-point marker: `SEQUENCE { SEQUENCE { ecPublicKey,
/// secp384r1 }, BIT STRING (0 unused bits) 04 … }`.
const P384_SPKI_PREFIX: [u8; 24] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
];

/// Byte length of a canonical P-384 SPKI.
pub const P384_SPKI_LEN: usize = P384_SPKI_PREFIX.len() + P384_POINT_LEN;

/// Compute the thumbprint of a P-384 public key.
///
/// # Parameters
/// * `scratch` — DMA scratch of exactly [`P384_SPKI_LEN`] bytes; receives
///   the canonical SPKI.
/// * `point` — raw big-endian `X ‖ Y` ([`P384_POINT_LEN`] bytes).
/// * `out` — receives the [`SPKI_THUMBPRINT_LEN`]-byte digest.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — a buffer has the wrong length.
/// * Any [`HsmError`] surfaced by `pal.hash`.
pub async fn p384_spki_thumbprint<P: HsmHash>(
    pal: &P,
    io: &P::Io,
    scratch: &mut HsmDmaBuf,
    point: &[u8],
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    if scratch.len() != P384_SPKI_LEN
        || point.len() != P384_POINT_LEN
        || out.len() != SPKI_THUMBPRINT_LEN
    {
        return Err(HsmError::InvalidArg);
    }
    let (prefix, body) = scratch.split_at_mut(P384_SPKI_PREFIX.len());
    prefix.copy_from_slice(&P384_SPKI_PREFIX);
    body.copy_from_slice(point);
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        scratch,
        out,
        HsmDigestForm::Standard,
    )
    .await
}

/// DER prefix of an ML-DSA-87 SubjectPublicKeyInfo, up to the raw key:
/// `SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.3.19 }, BIT STRING 0x00 ‖ key }`.
const MLDSA87_SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x0a, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x13, 0x03, 0x82, 0x0a, 0x21, 0x00,
];

/// Length of an encoded ML-DSA-87 public key.
pub const MLDSA87_PUB_KEY_LEN: usize = 2592;

/// Length of an ML-DSA-87 SubjectPublicKeyInfo.
pub const MLDSA87_SPKI_LEN: usize = MLDSA87_SPKI_PREFIX.len() + MLDSA87_PUB_KEY_LEN;

/// SHA-384 thumbprint of the DER SubjectPublicKeyInfo of the encoded
/// ML-DSA-87 public key `key`, built in `scratch`
/// ([`MLDSA87_SPKI_LEN`] bytes).
pub async fn mldsa87_spki_thumbprint<P: HsmHash>(
    pal: &P,
    io: &P::Io,
    scratch: &mut HsmDmaBuf,
    key: &[u8],
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    if scratch.len() != MLDSA87_SPKI_LEN
        || key.len() != MLDSA87_PUB_KEY_LEN
        || out.len() != SPKI_THUMBPRINT_LEN
    {
        return Err(HsmError::InvalidArg);
    }
    let (prefix, body) = scratch.split_at_mut(MLDSA87_SPKI_PREFIX.len());
    prefix.copy_from_slice(&MLDSA87_SPKI_PREFIX);
    body.copy_from_slice(key);
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        scratch,
        out,
        HsmDigestForm::Standard,
    )
    .await
}

/// SHA-384 thumbprint of an ML-DSA-87 SubjectPublicKeyInfo `spki` that
/// already sits in DMA memory, hashed in place.
///
/// `spki` must be exactly the canonical encoding
/// ([`MLDSA87_SPKI_PREFIX`] ‖ key) that [`mldsa87_spki_thumbprint`]
/// would build, so both functions agree on every accepted key.
///
/// # Errors
///
/// * [`HsmError::InvalidArg`] — `spki` is not a canonical ML-DSA-87
///   SubjectPublicKeyInfo, or `out` is not [`SPKI_THUMBPRINT_LEN`] bytes.
/// * Any error from [`HsmHash::hash`].
pub(crate) async fn mldsa87_spki_thumbprint_in_place<P: HsmHash>(
    pal: &P,
    io: &P::Io,
    spki: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    if spki.len() != MLDSA87_SPKI_LEN
        || !spki.starts_with(&MLDSA87_SPKI_PREFIX)
        || out.len() != SPKI_THUMBPRINT_LEN
    {
        return Err(HsmError::InvalidArg);
    }
    pal.hash(io, HsmHashAlgo::Sha384, spki, out, HsmDigestForm::Standard)
        .await
}
