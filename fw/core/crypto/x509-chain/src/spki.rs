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
