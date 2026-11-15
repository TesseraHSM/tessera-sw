// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime certificate builder.
//!
//! Mirrors the surface shape of
//! [`tsra_fw_core_crypto_key_report::key_report`]: async,
//! `pal + io + alloc` plumbing, query/copy on `Option<&mut [u8]>`.
//!
//! Patches variable fields into pre-generated TBS (To-Be-Signed)
//! templates ([`crate::root_cert`], [`crate::leaf_cert`]), drives
//! SHA-384 + ECDSA-P384 or ML-DSA-87 signing through the PAL, and
//! assembles complete DER-encoded X.509 certificates in the caller's
//! output buffer. ML-DSA-87 subject keys and issuers reuse the P-384
//! templates through [`crate::retarget`].
//!
//! CN and SN strings are validated and padded internally — callers
//! pass plain `&str` values.

use bitfield_struct::bitfield;
use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmByteOrder;
use tsra_fw_hsm_pal_traits::HsmCrypto;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmMlDsaHedge;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsg;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsgType;
use tsra_fw_hsm_pal_traits::HsmMlDsaParamSet;
use tsra_fw_hsm_pal_traits::HsmMlDsaPrivKey;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::csr_builder::PRIV_KEY_LEN;
use crate::csr_builder::SIGNATURE_LEN;
use crate::der_helpers::ECDSA_SHA384_ALG_ID;
use crate::der_helpers::MAX_ECDSA384_SIG_DER_LEN;
use crate::der_helpers::MLDSA87_ALG_ID;
use crate::der_helpers::MLDSA87_PUBLIC_KEY_LEN;
use crate::der_helpers::MLDSA87_SIGNATURE_LEN;
use crate::der_helpers::MLDSA87_SIG_BIT_STRING_HEADER;
use crate::der_helpers::{self};
use crate::retarget;
use crate::retarget::KeyAlg;
use crate::retarget::SigAlg;
use crate::retarget::SubjectKey;
use crate::retarget::TbsKind;

/// Length of Common Name field (space-padded ASCII, 32 bytes).
pub const CN_LEN: usize = 32;

/// Length of DN serialNumber field (hex-encoded, 64 bytes).
pub const SN_LEN: usize = 64;

/// SHA-384 digest length in bytes.
const SHA384_DIGEST_LEN: usize = 48;

/// Upper bound on the TBS scratch buffer used internally. Sized for any
/// template in this crate, including the retargeted ML-DSA-87 subject keys.
const MAX_TBS_LEN: usize = 4096;

/// X.509 Key Usage extension as a DER BIT STRING value (2 bytes).
///
/// The 2-byte encoding matches the DER BIT STRING content for the
/// KeyUsage extension: `[unused_bits_count, usage_flags_byte]`.
///
/// - `unused_bits_count`: number of unused trailing bits (0–7) in the
///   flags byte.
/// - `usage_flags_byte`: bit flags where MSB = digitalSignature, per
///   RFC 5280 §4.2.1.3.
///
/// # Bit Ordering Note
///
/// `bitfield_struct` packs bits LSB-first, but X.509 KeyUsage uses
/// MSB-first. The [`to_bytes`](KeyUsage::to_bytes) method reverses the
/// flags byte automatically.
///
/// # Predefined Constants
///
/// - [`DIGITAL_SIGNATURE`](KeyUsage::DIGITAL_SIGNATURE) — `[0x07, 0x80]`
/// - [`KEY_CERT_SIGN_CRL_SIGN`](KeyUsage::KEY_CERT_SIGN_CRL_SIGN) — `[0x01, 0x06]`
/// - [`KEY_AGREEMENT`](KeyUsage::KEY_AGREEMENT) — `[0x03, 0x08]`
#[bitfield(u16)]
#[derive(PartialEq, Eq)]
pub struct KeyUsage {
    /// Number of unused trailing bits in the usage flags byte.
    #[bits(8)]
    pub unused_bits: u8,

    /// digitalSignature (bit 7 of usage byte).
    #[bits(1)]
    pub digital_signature: bool,

    /// contentCommitment / nonRepudiation (bit 6).
    #[bits(1)]
    pub content_commitment: bool,

    /// keyEncipherment (bit 5).
    #[bits(1)]
    pub key_encipherment: bool,

    /// dataEncipherment (bit 4).
    #[bits(1)]
    pub data_encipherment: bool,

    /// keyAgreement (bit 3).
    #[bits(1)]
    pub key_agreement: bool,

    /// keyCertSign (bit 2).
    #[bits(1)]
    pub key_cert_sign: bool,

    /// cRLSign (bit 1).
    #[bits(1)]
    pub crl_sign: bool,

    /// encipherOnly (bit 0).
    #[bits(1)]
    pub encipher_only: bool,
}

impl KeyUsage {
    /// digitalSignature only: `[0x07, 0x80]`.
    pub const DIGITAL_SIGNATURE: Self =
        Self::new().with_digital_signature(true).with_unused_bits(7);

    /// keyCertSign + cRLSign: `[0x01, 0x06]`.
    pub const KEY_CERT_SIGN_CRL_SIGN: Self = Self::new()
        .with_key_cert_sign(true)
        .with_crl_sign(true)
        .with_unused_bits(1);

    /// keyAgreement only: `[0x03, 0x08]`.
    pub const KEY_AGREEMENT: Self = Self::new().with_key_agreement(true).with_unused_bits(3);

    /// Convert to the 2-byte DER BIT STRING value `[unused_bits, flags]`.
    ///
    /// The flags byte is bit-reversed to convert from bitfield_struct's
    /// LSB-first layout to X.509's MSB-first layout.
    pub const fn to_bytes(self) -> [u8; 2] {
        let raw = self.into_bits();
        let unused_bits = raw as u8;
        let flags_lsb = (raw >> 8) as u8;
        let flags = flags_lsb.reverse_bits();
        [unused_bits, flags]
    }
}

/// Parameters for building a self-signed Root CA certificate.
///
/// Because the root is self-signed, the issuer DN is set equal to the
/// subject DN — only `subject_cn` and `subject_sn` are needed.
///
/// All CN/SN strings are validated and padded internally by the builder.
pub struct RootCertParams<'a> {
    /// Uncompressed P-384 public key (97 bytes: `0x04 || x || y`).
    pub public_key: &'a [u8; 97],
    /// Serial number (20 bytes, first byte must have bit 7 = 0 for positive DER INTEGER).
    pub serial_number: &'a [u8; 20],
    /// NOT_BEFORE as GeneralizedTime ASCII (15 bytes, e.g. `b"20250101000000Z"`).
    pub not_before: &'a [u8; 15],
    /// NOT_AFTER as GeneralizedTime ASCII (15 bytes).
    pub not_after: &'a [u8; 15],
    /// Subject (and issuer) Common Name (ASCII, max [`CN_LEN`] bytes; space-padded internally).
    pub subject_cn: &'a str,
    /// Subject (and issuer) serialNumber (max [`SN_LEN`] bytes; zero-padded internally).
    pub subject_sn: &'a str,
    /// Subject Key Identifier (SHA-1 of the public key, 20 bytes).
    pub subject_key_id: &'a [u8; 20],
}

/// Parameters for building the partition-id (PID) leaf certificate.
///
/// The leaf uses the single-`commonName` profile (issuer `CN(64)`, subject
/// `CN(32)`) so its issuer DN byte-matches the CP alias certificate's subject
/// DN and the leaf chains to it. Every field is a fixed-size raw byte array
/// patched verbatim (no CN/SN string validation or padding): in particular
/// `issuer_cn` is copied byte-for-byte from the alias cert's subject CN.
///
/// `K` is the subject public key: the uncompressed P-384 point (default)
/// or, for [`build_mldsa_leaf_cert`] and
/// [`build_mldsa_leaf_cert_ecc_issuer`], the raw ML-DSA-87 public key.
pub struct LeafCertParams<'a, K = [u8; 97]> {
    /// Subject public key: uncompressed P-384 (97 bytes: `0x04 || x || y`)
    /// or raw ML-DSA-87 ([`MLDSA87_PUBLIC_KEY_LEN`] bytes).
    pub public_key: &'a K,
    /// Serial number (20 bytes, first byte must have bit 7 = 0 for positive DER INTEGER).
    pub serial_number: &'a [u8; 20],
    /// NOT_BEFORE as GeneralizedTime ASCII (15 bytes, e.g. `b"20250101000000Z"`).
    pub not_before: &'a [u8; 15],
    /// NOT_AFTER as GeneralizedTime ASCII (15 bytes).
    pub not_after: &'a [u8; 15],
    /// Issuer commonName value (64 bytes) — the alias certificate's subject CN.
    pub issuer_cn: &'a [u8; 64],
    /// Subject commonName value (32 bytes).
    pub subject_cn: &'a [u8; 32],
    /// Subject Key Identifier (SHA-1 of the subject's public key, 20 bytes).
    pub subject_key_id: &'a [u8; 20],
    /// Authority Key Identifier (the alias cert's Subject Key Identifier, 20 bytes).
    pub authority_key_id: &'a [u8; 20],
}

/// Pad an ASCII CN string to exactly [`CN_LEN`] bytes with trailing spaces.
///
/// Returns `None` if the input is too long or contains non-ASCII bytes.
pub fn pad_cn(cn: &str) -> Option<[u8; CN_LEN]> {
    if cn.len() > CN_LEN || !cn.is_ascii() {
        return None;
    }
    let mut result = [b' '; CN_LEN];
    result[..cn.len()].copy_from_slice(cn.as_bytes());
    Some(result)
}

/// Pad an ASCII SN string to exactly [`SN_LEN`] bytes with trailing `'0'` chars.
///
/// Returns `None` if the input is too long or contains characters that
/// are not ASCII hex digits (`0..=9 | a..=f | A..=F`).
pub fn pad_sn(sn: &str) -> Option<[u8; SN_LEN]> {
    if sn.len() > SN_LEN || !sn.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut result = [b'0'; SN_LEN];
    result[..sn.len()].copy_from_slice(sn.as_bytes());
    Some(result)
}

/// Build a self-signed Root CA certificate from the
/// [`root_cert`](crate::root_cert) template.
///
/// See the crate-level docs for the shared `(pal, io, alloc, params,
/// priv_key, out)` contract and query/copy semantics.
pub async fn build_root_cert<'a, P: HsmCrypto + HsmAlloc + 'a>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    params: &RootCertParams<'_>,
    priv_key: &HsmDmaBuf,
    out: Option<&mut [u8]>,
) -> HsmResult<usize> {
    use crate::root_cert::TBS_TEMPLATE;
    let tbs_len = TBS_TEMPLATE.len();
    preflight(priv_key, tbs_len)?;
    let max_size = max_signed_size(tbs_len);
    let Some(out) = out else {
        return Ok(max_size);
    };
    if out.len() < max_size {
        return Err(HsmError::InvalidArg);
    }
    let (tbs_dma, sig_dma) = sign(pal, io, alloc, priv_key, tbs_len, |tbs| {
        patch_root_tbs(tbs, params)
    })
    .await?;
    assemble_signed(P::BYTE_ORDER, out, tbs_dma, sig_dma)
}

/// Build a Leaf (end-entity) certificate from the
/// [`leaf_cert`](crate::leaf_cert) template.
///
/// Thin wrapper over [`build_leaf_cert_with_signer`]: constructs the default
/// P-384 [`TbsSigner`] (`pal.ecc_sign` + `priv_key`) and delegates. The
/// public contract — `(pal, io, alloc, params, priv_key, out)` with the
/// query/copy semantics from the crate-level docs — is unchanged.
pub async fn build_leaf_cert<'a, P: HsmCrypto + HsmAlloc + 'a>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    params: &LeafCertParams<'_>,
    priv_key: &HsmDmaBuf,
    out: Option<&mut [u8]>,
) -> HsmResult<usize> {
    // Validate `priv_key` up front so even the query path (`out = None`)
    // rejects a bad key, matching pre-refactor behaviour. The `_with_signer`
    // variant has no priv_key to check, so this preflight is exclusive to
    // this default-signer entry point.
    preflight(priv_key, crate::leaf_cert::TBS_TEMPLATE.len())?;
    let signer = EccP384Signer {
        pal,
        alloc,
        priv_key,
    };
    build_leaf_cert_with_signer(pal, io, alloc, params, &signer, out).await
}

/// Signer hook for [`build_leaf_cert_with_signer`].
///
/// Produces a raw ECDSA-P384 signature — `r || s`, each half in the PAL's
/// operand order, `SIGNATURE_LEN` (96) bytes — over a caller-supplied SHA-384 `digest`,
/// writing it into `sig`. Implement this to inject a signer other than the
/// PAL's default [`HsmEcc::ecc_sign`]; in particular a *deterministic*
/// (RFC 6979) signer, so the resulting certificate is byte-stable across
/// regenerations (required for cacheable, lazily-regenerated leaf certs).
///
/// [`HsmEcc::ecc_sign`]: tsra_fw_hsm_pal_traits::HsmEcc::ecc_sign
#[allow(async_fn_in_trait)]
pub trait TbsSigner<I: HsmIo> {
    /// Sign `digest` (48-byte standard SHA-384) into `sig` (`r || s`, each
    /// half in the PAL's operand order, 96 B). The signer converts the
    /// digest to its backend's operand order.
    async fn sign_digest(&self, io: &I, digest: &HsmDmaBuf, sig: &mut HsmDmaBuf) -> HsmResult<()>;
}

/// Build a Leaf certificate whose TBS signature is produced by `signer`
/// instead of the PAL's default `ecc_sign`.
///
/// Identical to [`build_leaf_cert`] except for the signing step: use this
/// with a deterministic (RFC 6979) [`TbsSigner`] so the leaf is byte-stable
/// across regenerations. `pal` is still used for the SHA-384 over the TBS.
///
/// Query/copy: `out = None` returns the worst-case size; `Some(buf)` builds.
pub async fn build_leaf_cert_with_signer<'a, P: HsmCrypto + HsmAlloc + 'a>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    params: &LeafCertParams<'_>,
    signer: &impl TbsSigner<P::Io>,
    out: Option<&mut [u8]>,
) -> HsmResult<usize> {
    build_signed_from_template(
        pal,
        io,
        alloc,
        crate::leaf_cert::TBS_TEMPLATE.len(),
        |tbs| patch_leaf_tbs(tbs, params),
        signer,
        out,
    )
    .await
}

/// Shared core for the `build_*_with_signer` entry points: size-check the
/// template, then (in copy mode) patch a fresh TBS via `patch`, SHA-384 it,
/// sign it with `signer`, and assemble the DER certificate into `out`.
///
/// The per-profile difference is exactly `template_len` + `patch`; keeping
/// this plumbing in one place avoids duplicating it per certificate profile.
/// In query mode (`out = None`) it returns the worst-case signed size without
/// allocating or patching.
async fn build_signed_from_template<'a, P: HsmCrypto + HsmAlloc + 'a>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    template_len: usize,
    patch: impl FnOnce(&mut [u8]) -> HsmResult<()>,
    signer: &impl TbsSigner<P::Io>,
    out: Option<&mut [u8]>,
) -> HsmResult<usize> {
    if template_len > MAX_TBS_LEN {
        return Err(HsmError::InvalidArg);
    }
    let max_size = max_signed_size(template_len);
    let Some(out) = out else {
        return Ok(max_size);
    };
    if out.len() < max_size {
        return Err(HsmError::InvalidArg);
    }

    let tbs_dma = alloc.dma_alloc(template_len)?;
    patch(tbs_dma)?;

    let digest_dma = alloc.dma_alloc(SHA384_DIGEST_LEN)?;
    // Standard SHA-384 over the TBS; the `TbsSigner` converts it to its
    // operand order.
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        tbs_dma,
        digest_dma,
        HsmDigestForm::Standard,
    )
    .await?;

    let sig_dma = alloc.dma_alloc(SIGNATURE_LEN)?;
    signer.sign_digest(io, digest_dma, sig_dma).await?;

    assemble_signed(P::BYTE_ORDER, out, tbs_dma, sig_dma)
}

/// ML-DSA-87 counterpart of [`TbsSigner`].
///
/// Signs the complete TBS (ML-DSA has no separate digest step) with
/// ML-DSA-87, pure, empty context. Implementations should sign
/// deterministically so certificates are byte-stable across regenerations.
#[allow(async_fn_in_trait)]
pub trait MlDsaTbsSigner<I: HsmIo> {
    /// Sign `tbs` into `sig` ([`MLDSA87_SIGNATURE_LEN`] bytes).
    async fn sign_tbs(&self, io: &I, tbs: &HsmDmaBuf, sig: &mut HsmDmaBuf) -> HsmResult<()>;
}

/// [`MlDsaTbsSigner`] backed by the PAL's [`HsmMlDsa::mldsa_sign`] with a
/// seed-form or expanded ML-DSA-87 private key; signs deterministically.
///
/// [`HsmMlDsa::mldsa_sign`]: tsra_fw_hsm_pal_traits::HsmMlDsa::mldsa_sign
pub struct MlDsa87Signer<'a, P> {
    pal: &'a P,
    key: HsmMlDsaPrivKey<'a>,
}

impl<'a, P: HsmCrypto> MlDsa87Signer<'a, P> {
    /// Signer for the ML-DSA-87 private key `key`.
    pub fn new(pal: &'a P, key: HsmMlDsaPrivKey<'a>) -> Self {
        Self { pal, key }
    }
}

impl<P: HsmCrypto> MlDsaTbsSigner<P::Io> for MlDsa87Signer<'_, P> {
    async fn sign_tbs(&self, io: &P::Io, tbs: &HsmDmaBuf, sig: &mut HsmDmaBuf) -> HsmResult<()> {
        let msg = HsmMlDsaMsg::new(HsmMlDsaMsgType::Pure, 0, tbs)?;
        let len = self
            .pal
            .mldsa_sign(
                io,
                HsmMlDsaParamSet::MlDsa87,
                self.key,
                HsmMlDsaHedge::Deterministic,
                msg,
                Some(sig),
            )
            .await?;
        if len != MLDSA87_SIGNATURE_LEN {
            return Err(HsmError::InternalError);
        }
        Ok(())
    }
}

/// Build an ML-DSA-87 Leaf certificate signed by an ML-DSA-87 issuer.
///
/// Same single-CN profile as [`build_leaf_cert`]: the
/// [`leaf_cert`](crate::leaf_cert) template retargeted to an ML-DSA-87
/// subject key and signature algorithm. `params.authority_key_id` is the
/// issuer's ML-DSA subject key identifier.
///
/// Query/copy: `out = None` returns the exact size; `Some(buf)` builds.
pub async fn build_mldsa_leaf_cert<I: HsmIo>(
    io: &I,
    alloc: &impl HsmScopedAlloc,
    params: &LeafCertParams<'_, [u8; MLDSA87_PUBLIC_KEY_LEN]>,
    signer: &impl MlDsaTbsSigner<I>,
    out: Option<&mut HsmDmaBuf>,
) -> HsmResult<usize> {
    let tbs_len = mldsa_leaf_tbs_len(SigAlg::MlDsa87)?;
    let Some(out) = out else {
        return Ok(mldsa_signed_len(tbs_len));
    };
    let render = |tbs: &mut HsmDmaBuf| render_mldsa_leaf_tbs(alloc, params, SigAlg::MlDsa87, tbs);
    sign_mldsa(io, tbs_len, &render, signer, out).await
}

/// Build an ML-DSA-87 Leaf certificate signed by an ECDSA-P384 issuer.
///
/// Same single-CN profile as [`build_leaf_cert_with_signer`], with the
/// subject key retargeted to ML-DSA-87; the issuer (for example the CP alias
/// key) signs with `signer` exactly as for a P-384 leaf.
///
/// Query/copy: `out = None` returns the worst-case size; `Some(buf)` builds.
pub async fn build_mldsa_leaf_cert_ecc_issuer<'a, P: HsmCrypto + HsmAlloc + 'a>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    params: &LeafCertParams<'_, [u8; MLDSA87_PUBLIC_KEY_LEN]>,
    signer: &impl TbsSigner<P::Io>,
    out: Option<&mut [u8]>,
) -> HsmResult<usize> {
    build_signed_from_template(
        pal,
        io,
        alloc,
        mldsa_leaf_tbs_len(SigAlg::EcdsaP384Sha384)?,
        |tbs| render_mldsa_leaf_tbs(alloc, params, SigAlg::EcdsaP384Sha384, tbs),
        signer,
        out,
    )
    .await
}

/// Worst-case DER size of [`build_mldsa_leaf_cert_ecc_issuer`]'s output,
/// without needing the subject key.
pub fn mldsa_leaf_cert_ecc_issuer_max_len() -> HsmResult<usize> {
    Ok(max_signed_size(mldsa_leaf_tbs_len(
        SigAlg::EcdsaP384Sha384,
    )?))
}

fn mldsa_leaf_tbs_len(issuer: SigAlg) -> HsmResult<usize> {
    retarget::retarget_len(
        &crate::leaf_cert::TBS_TEMPLATE,
        TbsKind::Certificate,
        issuer,
        KeyAlg::MlDsa87,
    )
    .ok_or(HsmError::InternalError)
}

/// Patch the P-384 leaf template in NonDma scratch, then retarget it into
/// `out` for an ML-DSA-87 subject key and `issuer`.
fn render_mldsa_leaf_tbs(
    alloc: &impl HsmScopedAlloc,
    params: &LeafCertParams<'_, [u8; MLDSA87_PUBLIC_KEY_LEN]>,
    issuer: SigAlg,
    out: &mut [u8],
) -> HsmResult<()> {
    let scratch = alloc.alloc(crate::leaf_cert::TBS_TEMPLATE.len())?;
    patch_leaf_fields(scratch, params)?;
    let len = retarget::retarget_tbs(
        scratch,
        TbsKind::Certificate,
        issuer,
        SubjectKey::MlDsa87(params.public_key),
        out,
    )
    .ok_or(HsmError::InternalError)?;
    if len != out.len() {
        return Err(HsmError::InternalError);
    }
    Ok(())
}

/// Exact size of an ML-DSA-87-signed certificate or CSR with a TBS of
/// `tbs_len` bytes.
pub(crate) fn mldsa_signed_len(tbs_len: usize) -> usize {
    der_helpers::signed_len(
        tbs_len,
        MLDSA87_ALG_ID.len(),
        MLDSA87_SIG_BIT_STRING_HEADER.len() + MLDSA87_SIGNATURE_LEN,
    )
}

/// Assemble an ML-DSA-87-signed DER document (certificate or CSR) in
/// place: `render` writes the TBS straight into its final position in
/// `out`, which `signer` then signs into the trailing signature field.
///
/// Needs no TBS or signature scratch, so the whole document costs one
/// buffer of [`mldsa_signed_len`]`(tbs_len)` bytes. `render` is a trait
/// object so certificates and CSRs share one copy of this function.
pub(crate) async fn sign_mldsa<I: HsmIo>(
    io: &I,
    tbs_len: usize,
    render: &dyn Fn(&mut HsmDmaBuf) -> HsmResult<()>,
    signer: &impl MlDsaTbsSigner<I>,
    out: &mut HsmDmaBuf,
) -> HsmResult<usize> {
    let size = mldsa_signed_len(tbs_len);
    if out.len() < size {
        return Err(HsmError::InvalidArg);
    }
    let content_len = tbs_len
        + MLDSA87_ALG_ID.len()
        + MLDSA87_SIG_BIT_STRING_HEADER.len()
        + MLDSA87_SIGNATURE_LEN;
    out[0] = 0x30;
    let tbs_at = 1 + der_helpers::encode_der_length(&mut out[1..], content_len)
        .ok_or(HsmError::InternalError)?;
    let alg_at = tbs_at + tbs_len;
    let sig_at = alg_at + MLDSA87_ALG_ID.len() + MLDSA87_SIG_BIT_STRING_HEADER.len();
    if sig_at + MLDSA87_SIGNATURE_LEN != size {
        return Err(HsmError::InternalError);
    }
    render(&mut out[tbs_at..alg_at])?;
    out[alg_at..alg_at + MLDSA87_ALG_ID.len()].copy_from_slice(&MLDSA87_ALG_ID);
    out[alg_at + MLDSA87_ALG_ID.len()..sig_at].copy_from_slice(&MLDSA87_SIG_BIT_STRING_HEADER);
    let (head, sig) = out[..size].split_at_mut(sig_at);
    signer.sign_tbs(io, &head[tbs_at..alg_at], sig).await?;
    Ok(size)
}

struct EccP384Signer<'a, P: HsmCrypto, A: HsmScopedAlloc> {
    pal: &'a P,
    alloc: &'a A,
    priv_key: &'a HsmDmaBuf,
}

impl<P: HsmCrypto, A: HsmScopedAlloc> TbsSigner<P::Io> for EccP384Signer<'_, P, A> {
    async fn sign_digest(
        &self,
        io: &P::Io,
        digest: &HsmDmaBuf,
        sig: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        // `ecc_sign` consumes the message hash in operand order; `digest`
        // is the standard SHA-384 (per the `TbsSigner` contract).
        let e = self.alloc.dma_alloc(SHA384_DIGEST_LEN)?;
        byte_order::int_copy_from_be(P::BYTE_ORDER, e, digest)?;
        self.pal
            .ecc_sign(io, HsmEccCurve::P384, self.priv_key, e, sig)
            .await
    }
}

fn preflight(priv_key: &HsmDmaBuf, tbs_len: usize) -> HsmResult<()> {
    if priv_key.len() != PRIV_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    if tbs_len > MAX_TBS_LEN {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Allocate the TBS scratch buffer, hand it to the caller's `patch`
/// closure, run `SHA-384 → ECDSA-P384 sign` against the supplied
/// private key, and return the DMA buffers holding the patched TBS
/// and the operand-order signature.
async fn sign<'a, P: HsmCrypto + HsmAlloc + 'a, F>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    priv_key: &HsmDmaBuf,
    tbs_len: usize,
    patch: F,
) -> HsmResult<(&'a mut HsmDmaBuf, &'a mut HsmDmaBuf)>
where
    F: FnOnce(&mut [u8]) -> HsmResult<()>,
{
    let tbs_dma = alloc.dma_alloc(tbs_len)?;
    patch(tbs_dma)?;

    // SHA-384 straight into the operand form `ecc_sign` consumes.
    let digest_dma = alloc.dma_alloc(SHA384_DIGEST_LEN)?;
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        tbs_dma,
        digest_dma,
        HsmDigestForm::Operand,
    )
    .await?;

    let sig_dma = alloc.dma_alloc(SIGNATURE_LEN)?;
    pal.ecc_sign(io, HsmEccCurve::P384, priv_key, digest_dma, sig_dma)
        .await?;

    Ok((tbs_dma, sig_dma))
}

/// Worst-case `Certificate ::= SEQUENCE { TBS, AlgId, BIT STRING sig }`
/// size for a TBS of the given length.
fn max_signed_size(tbs_len: usize) -> usize {
    let max_content = tbs_len + ECDSA_SHA384_ALG_ID.len() + MAX_ECDSA384_SIG_DER_LEN;
    1 + der_helpers::der_length_size(max_content) + max_content
}

fn patch_root_tbs(out: &mut [u8], params: &RootCertParams<'_>) -> HsmResult<()> {
    use crate::root_cert::*;
    validate_serial(params.serial_number)?;
    let subject_cn = pad_cn(params.subject_cn).ok_or(HsmError::InvalidArg)?;
    let subject_sn = pad_sn(params.subject_sn).ok_or(HsmError::InvalidArg)?;

    out[..TBS_TEMPLATE.len()].copy_from_slice(&TBS_TEMPLATE);
    patch_field(out, PUBLIC_KEY_OFFSET, params.public_key);
    patch_field(out, SERIAL_NUMBER_OFFSET, params.serial_number);
    patch_field(out, NOT_BEFORE_OFFSET, params.not_before);
    patch_field(out, NOT_AFTER_OFFSET, params.not_after);
    patch_field(out, ISSUER_CN_OFFSET, &subject_cn);
    patch_field(out, ISSUER_SN_OFFSET, &subject_sn);
    patch_field(out, SUBJECT_CN_OFFSET, &subject_cn);
    patch_field(out, SUBJECT_SN_OFFSET, &subject_sn);
    patch_field(out, SUBJECT_KEY_ID_OFFSET, params.subject_key_id);
    Ok(())
}

fn patch_leaf_tbs(out: &mut [u8], params: &LeafCertParams<'_>) -> HsmResult<()> {
    patch_leaf_fields(out, params)?;
    patch_field(out, crate::leaf_cert::PUBLIC_KEY_OFFSET, params.public_key);
    Ok(())
}

/// Copy the leaf template into `out` and patch every field except the
/// public key.
fn patch_leaf_fields<K>(out: &mut [u8], params: &LeafCertParams<'_, K>) -> HsmResult<()> {
    use crate::leaf_cert::*;
    validate_serial(params.serial_number)?;

    out[..TBS_TEMPLATE.len()].copy_from_slice(&TBS_TEMPLATE);
    patch_field(out, SERIAL_NUMBER_OFFSET, params.serial_number);
    patch_field(out, NOT_BEFORE_OFFSET, params.not_before);
    patch_field(out, NOT_AFTER_OFFSET, params.not_after);
    patch_field(out, ISSUER_CN_OFFSET, params.issuer_cn);
    patch_field(out, SUBJECT_CN_OFFSET, params.subject_cn);
    patch_field(out, SUBJECT_KEY_ID_OFFSET, params.subject_key_id);
    patch_field(out, AUTHORITY_KEY_ID_OFFSET, params.authority_key_id);
    Ok(())
}

fn validate_serial(serial: &[u8; 20]) -> HsmResult<()> {
    if serial[0] & 0x80 != 0 {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

fn patch_field(tbs: &mut [u8], offset: usize, value: &[u8]) {
    tbs[offset..offset + value.len()].copy_from_slice(value);
}

/// Assemble `SEQUENCE { TBS, AlgId, BIT STRING sig }` into `out`.
/// PAL signature is `r || s` in operand order; convert each half to BE
/// for the DER INTEGERs.
fn assemble_signed(
    order: HsmByteOrder,
    out: &mut [u8],
    tbs: &HsmDmaBuf,
    sig: &HsmDmaBuf,
) -> HsmResult<usize> {
    let (sig_r_be, sig_s_be) = sig_halves_to_be(order, sig)?;

    let mut sig_buf = [0u8; MAX_ECDSA384_SIG_DER_LEN];
    let sig_len = der_helpers::encode_ecdsa_signature(&mut sig_buf, &sig_r_be, &sig_s_be)
        .ok_or(HsmError::InternalError)?;

    let tbs_bytes: &[u8] = tbs;
    let content_len = tbs_bytes.len() + ECDSA_SHA384_ALG_ID.len() + sig_len;
    let header_len = 1 + der_helpers::der_length_size(content_len);
    let total_len = header_len + content_len;
    if out.len() < total_len {
        return Err(HsmError::InvalidArg);
    }

    let mut pos = 0;
    out[pos] = 0x30;
    pos += 1;
    pos += der_helpers::encode_der_length(&mut out[pos..], content_len)
        .ok_or(HsmError::InternalError)?;

    out[pos..pos + tbs_bytes.len()].copy_from_slice(tbs_bytes);
    pos += tbs_bytes.len();

    out[pos..pos + ECDSA_SHA384_ALG_ID.len()].copy_from_slice(&ECDSA_SHA384_ALG_ID);
    pos += ECDSA_SHA384_ALG_ID.len();

    out[pos..pos + sig_len].copy_from_slice(&sig_buf[..sig_len]);
    pos += sig_len;

    Ok(pos)
}

/// Convert the PAL ECDSA-P384 signature (`r || s`, each 48 B in operand
/// order) into the big-endian halves required for DER INTEGER encoding.
fn sig_halves_to_be(order: HsmByteOrder, sig: &HsmDmaBuf) -> HsmResult<([u8; 48], [u8; 48])> {
    let bytes: &[u8] = sig;
    if bytes.len() != SIGNATURE_LEN {
        return Err(HsmError::InternalError);
    }
    let (r_op, s_op) = bytes.split_at(SIGNATURE_LEN / 2);
    let mut r = [0u8; 48];
    let mut s = [0u8; 48];
    byte_order::int_copy_to_be(order, &mut r, r_op)?;
    byte_order::int_copy_to_be(order, &mut s, s_op)?;
    Ok((r, s))
}
