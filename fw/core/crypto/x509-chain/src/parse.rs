// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 certificate DER parser.
//!
//! Extracts exactly the fields needed for chain validation from a
//! DER-encoded X.509 v3 certificate. All returned slices borrow from
//! the input buffer — zero allocation.
//!
//! ## Parsing strategy
//!
//! The outer Certificate SEQUENCE is entered, and the TBSCertificate
//! is first captured as raw DER bytes (preserving exact bytes for
//! signature verification), then parsed internally for individual
//! fields. Extensions are iterated lazily — only AKID, SKID,
//! BasicConstraints, and KeyUsage are decoded; all others are skipped
//! (but checked for unrecognized critical extensions).

use der::asn1::BitStringRef;
use der::asn1::ObjectIdentifier;
use der::asn1::OctetStringRef;
use der::asn1::SequenceRef;
use der::asn1::UintRef;
use der::Reader;
use der::SliceReader;
use der::Tag;
use der::TagMode;
use der::TagNumber;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmMlDsaParamSet;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRsaKey;

use crate::types::BasicConstraints;
use crate::types::CertInfo;
use crate::types::EcPubKey;
use crate::types::PssParams;
use crate::types::PubKey;
use crate::types::RsaPubKey;
use crate::types::SigAlgo;

const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const OID_MLDSA44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const OID_MLDSA65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const OID_MLDSA87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

const OID_AKID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const OID_SKID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_CERT_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_CRL_DIST_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
const OID_AUTH_INFO_ACCESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
const OID_SUBJECT_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.11");
const OID_NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");
const OID_POLICY_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.36");
const OID_INHIBIT_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.54");
const OID_POLICY_MAPPINGS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.33");
const OID_ISSUER_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.18");

/// Known extension OIDs that we can safely skip even when critical.
/// These are recognized by RFC 5280 but not needed for our simplified
/// chain validation (no CRL, no policy).
const KNOWN_EXTENSION_OIDS: &[ObjectIdentifier] = &[
    OID_AKID,
    OID_SKID,
    OID_BASIC_CONSTRAINTS,
    OID_KEY_USAGE,
    OID_SUBJECT_ALT_NAME,
    OID_CERT_POLICIES,
    OID_EXT_KEY_USAGE,
    OID_CRL_DIST_POINTS,
    OID_AUTH_INFO_ACCESS,
    OID_SUBJECT_INFO_ACCESS,
    OID_NAME_CONSTRAINTS,
    OID_POLICY_CONSTRAINTS,
    OID_INHIBIT_ANY_POLICY,
    OID_POLICY_MAPPINGS,
    OID_ISSUER_ALT_NAME,
];

/// Internal error type for use inside `der` parser closures.
///
/// Wraps an [`HsmError`] so that both `der::Error` (via `?`) and
/// specific `HsmError` variants can flow through the same closure
/// return type. Converted back to `HsmError` at the public API
/// boundary.
#[derive(Debug, Clone, Copy)]
struct X509ParseError(HsmError);

type X509ParseResult<T> = Result<T, X509ParseError>;

impl From<der::Error> for X509ParseError {
    fn from(_: der::Error) -> Self {
        Self(HsmError::X509ParseError)
    }
}

impl From<HsmError> for X509ParseError {
    fn from(error: HsmError) -> Self {
        Self(error)
    }
}

impl From<X509ParseError> for HsmError {
    fn from(error: X509ParseError) -> Self {
        error.0
    }
}

/// Parse a DER-encoded X.509 certificate into a [`CertInfo`].
///
/// All returned slices borrow from `der`. The caller must keep
/// `der` alive for as long as the returned `CertInfo` is used.
///
/// # Parameters
/// * `der` — DMA-accessible buffer containing the raw DER bytes
///   of the complete Certificate SEQUENCE.
///
/// # Returns
/// * `Ok(CertInfo)` on success.
/// * `Err(HsmError::X509ParseError)` if the DER is malformed.
/// * `Err(HsmError::X509UnsupportedAlgorithm)` if the signature or
///   key algorithm or its parameters are unsupported.
/// * `Err(HsmError::X509UnrecognizedCriticalExtension)` if a critical
///   extension is present that this parser does not recognize.
pub fn parse_cert(der: &HsmDmaBuf) -> HsmResult<CertInfo<'_>> {
    let mut outer = SliceReader::new(der).map_err(X509ParseError::from)?;
    let cert = outer.sequence(|cert| -> X509ParseResult<_> {
        let tbs_raw = to_dma(der, cert.tlv_bytes()?);
        let sig_algo = parse_sig_algo_id(cert)?;
        let sig_bits = cert.decode::<BitStringRef<'_>>()?;
        let signature = to_dma(der, sig_bits.as_bytes().ok_or(HsmError::X509ParseError)?);
        cert.clone().finish()?;

        let (issuer_raw, subject_raw, pub_key, spki_raw, akid, skid, basic_constraints, key_usage) =
            parse_tbs(der, tbs_raw, sig_algo)?;

        Ok(CertInfo {
            tbs_raw,
            sig_algo,
            signature,
            issuer_raw,
            subject_raw,
            pub_key,
            spki_raw,
            akid,
            skid,
            basic_constraints,
            key_usage,
        })
    })?;
    outer.finish().map_err(X509ParseError::from)?;
    Ok(cert)
}

/// Convert a `&[u8]` sub-slice of a `&HsmDmaBuf` back into a `&HsmDmaBuf`
/// by computing its byte offset within the original buffer.
///
/// `der` parser callbacks return `&[u8]` views, but downstream
/// consumers (hash and ECC verify) require `&HsmDmaBuf` to prove the
/// bytes live in DMA-accessible memory. Since the parser only ever
/// hands back sub-slices of the original DMA buffer, we can safely
/// re-borrow them through the `HsmDmaBuf` type by computing the offset.
///
/// # Parameters
/// * `root` — the original DMA buffer the sub-slice was taken from.
/// * `sub` — a sub-slice that points strictly inside `root`.
///
/// # Returns
/// A `&HsmDmaBuf` view covering the same bytes as `sub`.
///
/// # Panics
///
/// Panics if `sub` does not point within `root` (either starts before
/// `root` or extends past its end).
fn to_dma<'a>(root: &'a HsmDmaBuf, sub: &'a [u8]) -> &'a HsmDmaBuf {
    let root_ptr = root.as_ptr() as usize;
    let sub_ptr = sub.as_ptr() as usize;
    assert!(sub_ptr >= root_ptr, "sub-slice starts before root buffer");
    let offset = sub_ptr - root_ptr;
    assert!(
        offset + sub.len() <= root.len(),
        "sub-slice extends past root buffer"
    );
    &root[offset..offset + sub.len()]
}

/// Tuple of fields extracted from a parsed TBSCertificate, returned
/// by [`parse_tbs`].
///
/// In order:
/// 1. raw issuer Name (DER SEQUENCE bytes, in DMA memory)
/// 2. raw subject Name (DER SEQUENCE bytes, in DMA memory)
/// 3. parsed public key
/// 4. raw SubjectPublicKeyInfo
/// 5. AuthorityKeyIdentifier `keyIdentifier`, if present
/// 6. SubjectKeyIdentifier value, if present
/// 7. parsed BasicConstraints, if present
/// 8. parsed KeyUsage bits, if present
type ParsedTbs<'a> = (
    &'a HsmDmaBuf,
    &'a HsmDmaBuf,
    PubKey<'a>,
    &'a HsmDmaBuf,
    Option<&'a [u8]>,
    Option<&'a [u8]>,
    Option<BasicConstraints>,
    Option<u16>,
);

/// Parse the TBSCertificate fields needed for chain validation.
///
/// Walks the TBSCertificate SEQUENCE in order, capturing the issuer
/// Name, subject Name, SubjectPublicKeyInfo, and (optionally) the
/// extensions block. Fields that are not used by the simplified
/// validator (version, serial, validity,
/// issuer/subject UIDs) are skipped over but still consumed so the
/// reader stays in sync.
///
/// # Parameters
/// * `root` — the original certificate DMA buffer; used as the base
///   for [`to_dma`] when re-borrowing slices.
/// * `tbs_raw` — DMA slice covering the full TBSCertificate SEQUENCE
///   (tag + length + value).
///
/// # Returns
/// * `Ok(ParsedTbs)` — see [`ParsedTbs`] for field order.
/// * `Err(X509ParseError)` wrapping [`HsmError::X509ParseError`] on
///   malformed DER, or [`HsmError::X509UnsupportedAlgorithm`] /
///   [`HsmError::X509UnrecognizedCriticalExtension`] from the
///   nested SPKI / extension parsers.
fn parse_tbs<'a>(
    root: &'a HsmDmaBuf,
    tbs_raw: &'a HsmDmaBuf,
    sig_algo: SigAlgo,
) -> X509ParseResult<ParsedTbs<'a>> {
    let mut reader = SliceReader::new(tbs_raw).map_err(X509ParseError::from)?;
    let parsed = reader.sequence(|tbs| -> X509ParseResult<_> {
        let _version: Option<u8> = tbs.context_specific(TagNumber(0), TagMode::Explicit)?;
        let _serial = tbs.decode::<UintRef<'_>>()?;
        if parse_sig_algo_id(tbs)? != sig_algo {
            return Err(HsmError::X509ParseError.into());
        }
        let issuer_raw = to_dma(root, tbs.tlv_bytes()?);
        let _validity = tbs.tlv_bytes()?;
        let subject_raw = to_dma(root, tbs.tlv_bytes()?);
        let spki_raw = to_dma(root, tbs.tlv_bytes()?);
        let pub_key = parse_spki(root, spki_raw)?;
        let _issuer_uid: Option<BitStringRef<'_>> =
            tbs.context_specific(TagNumber(1), TagMode::Implicit)?;
        let _subject_uid: Option<BitStringRef<'_>> =
            tbs.context_specific(TagNumber(2), TagMode::Implicit)?;

        let mut akid = None;
        let mut skid = None;
        let mut basic_constraints = None;
        let mut key_usage = None;

        let extensions: Option<&SequenceRef> =
            tbs.context_specific(TagNumber(3), TagMode::Explicit)?;
        if let Some(exts) = extensions {
            parse_extensions(
                exts.as_bytes(),
                &mut akid,
                &mut skid,
                &mut basic_constraints,
                &mut key_usage,
            )?;
        }

        tbs.clone().finish()?;
        Ok((
            issuer_raw,
            subject_raw,
            pub_key,
            spki_raw,
            akid,
            skid,
            basic_constraints,
            key_usage,
        ))
    })?;
    reader.finish().map_err(X509ParseError::from)?;
    Ok(parsed)
}

/// Parse the outer signatureAlgorithm `AlgorithmIdentifier` and map
/// its OID to a [`SigAlgo`] variant.
///
/// Accepts ECDSA, SHA-2 RSA PKCS#1 v1.5 / PSS, and pure ML-DSA.
///
/// # Parameters
/// * `reader` — a `SliceReader` positioned at the start of an
///   `AlgorithmIdentifier` SEQUENCE.
///
/// # Returns
/// * `Ok(SigAlgo)` — a recognized signature algorithm and parameters.
/// * `Err` wrapping [`HsmError::X509UnsupportedAlgorithm`] for
///   unrecognized OIDs, or [`HsmError::X509ParseError`] on malformed
///   DER.
fn parse_sig_algo_id(reader: &mut SliceReader<'_>) -> X509ParseResult<SigAlgo> {
    reader.sequence(|algo| -> X509ParseResult<_> {
        let oid = algo.decode::<ObjectIdentifier>()?;
        let signature = match oid {
            x if x == OID_ECDSA_SHA256 => SigAlgo::EcdsaSha256,
            x if x == OID_ECDSA_SHA384 => SigAlgo::EcdsaSha384,
            x if x == OID_ECDSA_SHA512 => SigAlgo::EcdsaSha512,
            x if x == OID_RSA_SHA256 || x == OID_RSA_SHA384 || x == OID_RSA_SHA512 => {
                if !algo.is_finished() {
                    algo.decode::<()>()?;
                }
                SigAlgo::RsaPkcs1(if oid == OID_RSA_SHA256 {
                    HsmHashAlgo::Sha256
                } else if oid == OID_RSA_SHA384 {
                    HsmHashAlgo::Sha384
                } else {
                    HsmHashAlgo::Sha512
                })
            }
            x if x == OID_RSA_PSS => {
                SigAlgo::RsaPss(parse_pss_params(algo.decode::<&SequenceRef>()?)?)
            }
            _ => SigAlgo::MlDsa(mldsa_param(oid).ok_or(HsmError::X509UnsupportedAlgorithm)?),
        };
        algo.clone().finish()?;
        Ok(signature)
    })
}

fn mldsa_param(oid: ObjectIdentifier) -> Option<HsmMlDsaParamSet> {
    match oid {
        x if x == OID_MLDSA44 => Some(HsmMlDsaParamSet::MlDsa44),
        x if x == OID_MLDSA65 => Some(HsmMlDsaParamSet::MlDsa65),
        x if x == OID_MLDSA87 => Some(HsmMlDsaParamSet::MlDsa87),
        _ => None,
    }
}

/// Split one DER TLV (definite length up to 64 KiB) off the front of `buf`,
/// returning `(tag, content, rest)`.
fn read_tlv(buf: &[u8]) -> X509ParseResult<(u8, &[u8], &[u8])> {
    let err = || X509ParseError::from(HsmError::X509ParseError);
    let (&tag, buf) = buf.split_first().ok_or_else(err)?;
    let (&first, buf) = buf.split_first().ok_or_else(err)?;
    let (len, buf) = match first {
        0..=0x7f => (usize::from(first), buf),
        0x81 if buf.first().is_some_and(|&b| b >= 0x80) => (usize::from(buf[0]), &buf[1..]),
        0x82 if buf.len() >= 2 && buf[0] != 0 => {
            (usize::from(buf[0]) << 8 | usize::from(buf[1]), &buf[2..])
        }
        _ => return Err(err()),
    };
    if len > buf.len() {
        return Err(err());
    }
    let (content, rest) = buf.split_at(len);
    Ok((tag, content, rest))
}

/// Like [`read_tlv`], but requires `tag` and returns only the content.
fn read_tlv_tag<'a>(buf: &mut &'a [u8], tag: u8) -> X509ParseResult<&'a [u8]> {
    let (found, content, rest) = read_tlv(buf)?;
    if found != tag {
        return Err(HsmError::X509ParseError.into());
    }
    *buf = rest;
    Ok(content)
}

/// Read the SEQUENCE content that must fill `content` exactly.
fn only_sequence(mut content: &[u8]) -> X509ParseResult<&[u8]> {
    let inner = read_tlv_tag(&mut content, 0x30)?;
    if !content.is_empty() {
        return Err(HsmError::X509ParseError.into());
    }
    Ok(inner)
}

/// Parse `AlgorithmIdentifier` content `{ OID, NULL? }` of a hash.
fn parse_hash_id(mut content: &[u8]) -> X509ParseResult<HsmHashAlgo> {
    let oid = read_tlv_tag(&mut content, 0x06)?;
    if !content.is_empty() && content != [0x05, 0x00] {
        return Err(HsmError::X509ParseError.into());
    }
    match oid {
        x if x == OID_SHA1.as_bytes() => Ok(HsmHashAlgo::Sha1),
        x if x == OID_SHA256.as_bytes() => Ok(HsmHashAlgo::Sha256),
        x if x == OID_SHA384.as_bytes() => Ok(HsmHashAlgo::Sha384),
        x if x == OID_SHA512.as_bytes() => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::X509UnsupportedAlgorithm.into()),
    }
}

/// Parse the content of `[n] EXPLICIT INTEGER` as a small unsigned value.
fn parse_explicit_u16(mut content: &[u8]) -> X509ParseResult<u16> {
    let int = read_tlv_tag(&mut content, 0x02)?;
    let int = match int {
        [0, rest @ ..] if rest.first().is_some_and(|&b| b & 0x80 != 0) => rest,
        [b, ..] if b & 0x80 != 0 || (*b == 0 && int.len() > 1) => {
            return Err(HsmError::X509ParseError.into())
        }
        _ => int,
    };
    if int.is_empty() || int.len() > 2 || !content.is_empty() {
        return Err(HsmError::X509ParseError.into());
    }
    Ok(int.iter().fold(0, |acc, &b| acc << 8 | u16::from(b)))
}

fn parse_pss_params(sequence: &SequenceRef) -> X509ParseResult<PssParams> {
    let mut rest = sequence.as_bytes();
    // SHA-1 defaults are unsupported, so both hash identifiers are required.
    let mut field = |tag: u8| -> X509ParseResult<Option<&[u8]>> {
        match rest.first() {
            Some(&t) if t == tag => read_tlv_tag(&mut rest, tag).map(Some),
            _ => Ok(None),
        }
    };
    let hash = field(0xa0)?.ok_or(HsmError::X509UnsupportedAlgorithm)?;
    let hash = parse_hash_id(only_sequence(hash)?)?;
    let mgf = field(0xa1)?.ok_or(HsmError::X509UnsupportedAlgorithm)?;
    let mut mgf = only_sequence(mgf)?;
    if read_tlv_tag(&mut mgf, 0x06)? != OID_MGF1.as_bytes() {
        return Err(HsmError::X509UnsupportedAlgorithm.into());
    }
    let mgf_hash = parse_hash_id(read_tlv_tag(&mut mgf, 0x30)?)?;
    if !mgf.is_empty() {
        return Err(HsmError::X509ParseError.into());
    }
    let salt_len = match field(0xa2)? {
        Some(content) => parse_explicit_u16(content)?,
        None => 20,
    };
    let trailer = match field(0xa3)? {
        Some(content) => {
            u8::try_from(parse_explicit_u16(content)?).map_err(|_| HsmError::X509ParseError)?
        }
        None => 1,
    };
    if !rest.is_empty() {
        return Err(HsmError::X509ParseError.into());
    }
    if !matches!(
        hash,
        HsmHashAlgo::Sha256 | HsmHashAlgo::Sha384 | HsmHashAlgo::Sha512
    ) || hash != mgf_hash
        || trailer != 1
    {
        return Err(HsmError::X509UnsupportedAlgorithm.into());
    }
    Ok(PssParams { hash, salt_len })
}

/// Parse a supported SubjectPublicKeyInfo, retaining only borrowed views.
pub(crate) fn parse_spki<'a>(root: &'a HsmDmaBuf, spki_raw: &'a [u8]) -> HsmResult<PubKey<'a>> {
    let mut reader = SliceReader::new(spki_raw).map_err(X509ParseError::from)?;
    let pub_key = reader.sequence(|seq| -> X509ParseResult<_> {
        let (oid, curve, pss_params) = seq.sequence(|algo| -> X509ParseResult<_> {
            let oid = algo.decode::<ObjectIdentifier>()?;
            let mut curve = None;
            let mut pss_params = None;
            if oid == OID_EC_PUBLIC_KEY {
                curve = Some(match algo.decode::<ObjectIdentifier>()? {
                    x if x == OID_P256 => HsmEccCurve::P256,
                    x if x == OID_P384 => HsmEccCurve::P384,
                    x if x == OID_P521 => HsmEccCurve::P521,
                    _ => return Err(HsmError::X509UnsupportedAlgorithm.into()),
                });
            } else if oid == OID_RSA {
                if !algo.is_finished() {
                    algo.decode::<()>()?;
                }
            } else if oid == OID_RSA_PSS {
                if !algo.is_finished() {
                    pss_params = Some(parse_pss_params(algo.decode::<&SequenceRef>()?)?);
                }
            } else if mldsa_param(oid).is_none() {
                return Err(HsmError::X509UnsupportedAlgorithm.into());
            }
            algo.clone().finish()?;
            Ok((oid, curve, pss_params))
        })?;
        let pk_bits = seq.decode::<BitStringRef<'_>>()?;
        let bytes = to_dma(root, pk_bits.as_bytes().ok_or(HsmError::X509ParseError)?);
        seq.clone().finish()?;
        if let Some(curve) = curve {
            if bytes.first() != Some(&0x04) || bytes.len() != 1 + curve.priv_key_len() * 2 {
                return Err(HsmError::X509ParseError.into());
            }
            Ok(PubKey::Ec(EcPubKey {
                curve,
                point: &bytes[1..],
            }))
        } else if oid == OID_RSA || oid == OID_RSA_PSS {
            let mut reader = SliceReader::new(bytes)?;
            let key = reader.sequence(|rsa| -> X509ParseResult<_> {
                let modulus = rsa.decode::<UintRef<'_>>()?;
                let exponent = rsa.decode::<UintRef<'_>>()?;
                rsa.clone().finish()?;
                let modulus = modulus.as_bytes();
                let exponent = exponent.as_bytes();
                let key_size = match modulus.len() {
                    256 => HsmRsaKey::Rsa2048Pub,
                    384 => HsmRsaKey::Rsa3072Pub,
                    512 => HsmRsaKey::Rsa4096Pub,
                    _ => return Err(HsmError::X509UnsupportedAlgorithm.into()),
                };
                if modulus[0] & 0x80 == 0
                    || modulus[modulus.len() - 1] & 1 == 0
                    || exponent.is_empty()
                    || exponent.len() > 4
                    || exponent[exponent.len() - 1] & 1 == 0
                    || (exponent.len() == 1 && exponent[0] < 3)
                {
                    return Err(HsmError::X509ParseError.into());
                }
                Ok(RsaPubKey {
                    key_size,
                    modulus: to_dma(root, modulus),
                    exponent: to_dma(root, exponent),
                    encoded: bytes,
                    pss_only: oid == OID_RSA_PSS,
                    pss_params,
                })
            })?;
            reader.finish()?;
            Ok(PubKey::Rsa(key))
        } else {
            let param = mldsa_param(oid).ok_or(HsmError::X509UnsupportedAlgorithm)?;
            if bytes.len() != param.pk_len() {
                return Err(HsmError::X509ParseError.into());
            }
            Ok(PubKey::MlDsa { param, key: bytes })
        }
    })?;
    reader.finish().map_err(X509ParseError::from)?;
    Ok(pub_key)
}

/// Iterate the Extensions SEQUENCE-OF, decoding the four extensions
/// the validator cares about and rejecting unknown critical ones.
///
/// AKID, SKID, BasicConstraints, and KeyUsage are decoded into the
/// caller-supplied out-parameters when present. All other extensions
/// are ignored unless they are marked critical — critical extensions
/// not in [`KNOWN_EXTENSION_OIDS`] cause this function to fail per
/// RFC 5280 §4.2.
///
/// Extensions whose value bytes fail to decode are silently treated
/// as absent (the corresponding out-parameter remains unchanged).
///
/// # Parameters
/// * `extensions` — contents of the Extensions SEQUENCE-OF (i.e.
///   the inner bytes after the SEQUENCE tag/length).
/// * `akid` — receives the AuthorityKeyIdentifier `keyIdentifier`
///   bytes if the extension is present and well-formed.
/// * `skid` — receives the SubjectKeyIdentifier OCTET STRING bytes
///   if the extension is present and well-formed.
/// * `basic_constraints` — receives the parsed BasicConstraints if
///   the extension is present and well-formed.
/// * `key_usage` — receives the KeyUsage bits packed into a `u16`
///   if the extension is present and well-formed.
///
/// # Returns
/// * `Ok(())` if iteration completed (any of the out-parameters may
///   or may not have been populated).
/// * `Err` wrapping [`HsmError::X509UnrecognizedCriticalExtension`]
///   if an unrecognized extension is marked critical, or
///   [`HsmError::X509ParseError`] on malformed extension framing.
fn parse_extensions<'a>(
    extensions: &'a [u8],
    akid: &mut Option<&'a [u8]>,
    skid: &mut Option<&'a [u8]>,
    basic_constraints: &mut Option<BasicConstraints>,
    key_usage: &mut Option<u16>,
) -> X509ParseResult<()> {
    let mut exts = SliceReader::new(extensions).map_err(X509ParseError::from)?;

    while !exts.is_finished() {
        let (oid, critical, value_bytes) = exts.sequence(|ext| -> X509ParseResult<_> {
            let oid = ext.decode::<ObjectIdentifier>()?;
            let critical = match Tag::peek(ext)? {
                Tag::Boolean => ext.decode::<bool>()?,
                _ => false,
            };
            let value_bytes = ext.decode::<&OctetStringRef>()?;
            ext.clone().finish()?;
            Ok((oid, critical, value_bytes.as_bytes()))
        })?;

        match oid {
            x if x == OID_AKID => {
                if let Ok(parsed) = parse_akid(value_bytes) {
                    *akid = Some(parsed);
                }
            }
            x if x == OID_SKID => {
                if let Ok(parsed) = parse_skid(value_bytes) {
                    *skid = Some(parsed);
                }
            }
            x if x == OID_BASIC_CONSTRAINTS => {
                if let Ok(parsed) = parse_basic_constraints(value_bytes) {
                    *basic_constraints = Some(parsed);
                }
            }
            x if x == OID_KEY_USAGE => {
                if key_usage.is_some() {
                    return Err(HsmError::X509ParseError.into());
                }
                *key_usage = Some(parse_key_usage(value_bytes)?);
            }
            _ if critical && !KNOWN_EXTENSION_OIDS.contains(&oid) => {
                return Err(HsmError::X509UnrecognizedCriticalExtension.into());
            }
            _ => {}
        }
    }

    exts.finish().map_err(X509ParseError::from)?;
    Ok(())
}

/// Parse the AuthorityKeyIdentifier extension and return the
/// `keyIdentifier` bytes.
///
/// AKID is a SEQUENCE that may contain three optional fields; only
/// the `[0] IMPLICIT OCTET STRING keyIdentifier` is needed for chain
/// validation. If the extension is present but omits the
/// `keyIdentifier`, this is treated as a parse error.
///
/// # Parameters
/// * `value` — the OCTET STRING contents of the AKID extension
///   (i.e. after the outer extnValue OCTET STRING wrapper has been
///   stripped).
///
/// # Returns
/// * `Ok(&[u8])` — the raw `keyIdentifier` bytes, borrowing from
///   `value`.
/// * `Err` wrapping [`HsmError::X509ParseError`] for malformed DER
///   or a missing `keyIdentifier`.
fn parse_akid(value: &[u8]) -> X509ParseResult<&[u8]> {
    let mut reader = SliceReader::new(value).map_err(X509ParseError::from)?;
    let key_id = reader.sequence(|seq| -> X509ParseResult<_> {
        let kid: Option<&OctetStringRef> = seq.context_specific(TagNumber(0), TagMode::Implicit)?;
        seq.clone().finish()?;
        kid.map(|key_id| key_id.as_bytes())
            .ok_or(HsmError::X509ParseError.into())
    })?;
    reader.finish().map_err(X509ParseError::from)?;
    Ok(key_id)
}

/// Parse the SubjectKeyIdentifier extension and return its raw
/// OCTET STRING bytes.
///
/// # Parameters
/// * `value` — the OCTET STRING contents of the SKID extension
///   (after the outer extnValue OCTET STRING wrapper has been
///   stripped).
///
/// # Returns
/// * `Ok(&[u8])` — the SKID bytes, borrowing from `value`.
/// * `Err` wrapping [`HsmError::X509ParseError`] on malformed DER.
fn parse_skid(value: &[u8]) -> X509ParseResult<&[u8]> {
    let mut reader = SliceReader::new(value).map_err(X509ParseError::from)?;
    let skid = reader.decode::<&OctetStringRef>()?;
    reader.finish().map_err(X509ParseError::from)?;
    Ok(skid.as_bytes())
}

/// Parse the BasicConstraints extension.
///
/// Per RFC 5280 §4.2.1.9 the syntax is
/// `SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }`.
/// The `cA` boolean is omitted when `FALSE`, so a missing boolean is
/// treated as `false`. The `pathLenConstraint` is optional and is
/// only meaningful when `cA` is `true`.
///
/// # Parameters
/// * `value` — the OCTET STRING contents of the BasicConstraints
///   extension.
///
/// # Returns
/// * `Ok(BasicConstraints)` populated from the parsed fields.
/// * `Err` wrapping [`HsmError::X509ParseError`] on malformed DER
///   or a `pathLenConstraint` that does not fit in a `u16`.
fn parse_basic_constraints(value: &[u8]) -> X509ParseResult<BasicConstraints> {
    let mut reader = SliceReader::new(value).map_err(X509ParseError::from)?;
    let constraints = reader.sequence(|seq| -> X509ParseResult<_> {
        let ca = match Tag::peek(seq)? {
            Tag::Boolean => seq.decode::<bool>()?,
            _ => false,
        };

        let path_len = if seq.is_finished() {
            None
        } else {
            Some(parse_small_uint(seq.decode::<UintRef<'_>>()?.as_bytes())? as u16)
        };

        seq.clone().finish()?;
        Ok(BasicConstraints { ca, path_len })
    })?;
    reader.finish().map_err(X509ParseError::from)?;
    Ok(constraints)
}

/// Parse the KeyUsage extension into a packed 16-bit field.
///
/// KeyUsage is a BIT STRING of up to nine bits. The first two bytes
/// of the value are loaded into the high and low halves of a `u16`
/// respectively, matching the layout documented on the [`key_usage`]
/// constants. Values longer than the nine defined bits are rejected.
///
/// [`key_usage`]: crate::types::key_usage
///
/// # Parameters
/// * `value` — the OCTET STRING contents of the KeyUsage extension.
///
/// # Returns
/// * `Ok(u16)` — the packed KeyUsage bits.
/// * `Err` wrapping [`HsmError::X509ParseError`] on malformed DER.
fn parse_key_usage(value: &[u8]) -> X509ParseResult<u16> {
    let mut reader = SliceReader::new(value).map_err(X509ParseError::from)?;
    let bits = reader.decode::<BitStringRef<'_>>()?;
    reader.finish().map_err(X509ParseError::from)?;
    if bits.bit_len() > 9 {
        return Err(HsmError::X509ParseError.into());
    }

    let bytes = bits.raw_bytes();
    let mut bits_value = 0u16;
    if let Some(first) = bytes.first() {
        bits_value = u16::from(*first) << 8;
    }
    if bytes.len() > 1 {
        bits_value |= u16::from(bytes[1]);
    }
    Ok(bits_value)
}

/// Decode a small DER INTEGER (≤ 8 bytes) as a big-endian unsigned
/// integer.
///
/// Used for `pathLenConstraint`, which is bounded in practice to
/// values that fit easily in a `u64` (and ultimately a `u16`).
///
/// # Parameters
/// * `bytes` — DER INTEGER content bytes (big-endian magnitude).
///
/// # Returns
/// * `Ok(u64)` — the decoded magnitude.
/// * `Err` wrapping [`HsmError::X509ParseError`] if more than 8
///   bytes were supplied (i.e. the value would not fit in a `u64`).
fn parse_small_uint(bytes: &[u8]) -> X509ParseResult<u64> {
    if bytes.len() > 8 {
        return Err(HsmError::X509ParseError.into());
    }

    let mut value = 0u64;
    for &byte in bytes {
        value = (value << 8) | u64::from(byte);
    }
    Ok(value)
}
