// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signature-algorithm and subject-key retargeting of P-384 TBS templates.
//!
//! The TBS templates in this crate are generated for a P-384 subject key
//! certified with ECDSA-SHA384. As in Caliptra, the issuer's signature
//! algorithm and the subject's key algorithm are independent, so every other
//! combination (ML-DSA-87 → ML-DSA-87, ECDSA-P384 → ML-DSA-87, ...) reuses the
//! same templates: [`retarget_tbs`] replaces the TBS `signature`
//! AlgorithmIdentifier and the `subjectPublicKeyInfo`, re-encodes the outer
//! `SEQUENCE` length, and copies every other byte unchanged. Callers patch
//! the variable fields into the P-384 template first and leave its public
//! key placeholder in place.

use super::der_helpers;
use super::der_helpers::ECDSA_SHA384_ALG_ID;
use super::der_helpers::MLDSA87_ALG_ID;
use super::der_helpers::MLDSA87_PUBLIC_KEY_LEN;
use super::der_helpers::MLDSA87_SPKI_HEADER;
use super::der_helpers::P384_PUBLIC_KEY_LEN;
use super::der_helpers::P384_SPKI_HEADER;

/// Signature algorithm of the key that signs a TBS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    /// ECDSA over P-384 with SHA-384.
    EcdsaP384Sha384,
    /// ML-DSA-87 (pure, empty context).
    MlDsa87,
}

impl SigAlg {
    /// The DER AlgorithmIdentifier of this algorithm.
    pub const fn alg_id(self) -> &'static [u8] {
        match self {
            Self::EcdsaP384Sha384 => &ECDSA_SHA384_ALG_ID,
            Self::MlDsa87 => &MLDSA87_ALG_ID,
        }
    }
}

/// Subject public key certified (or requested) by a TBS.
#[derive(Clone, Copy, Debug)]
pub enum SubjectKey<'a> {
    /// Uncompressed P-384 point (`0x04 || x || y`).
    P384(&'a [u8; P384_PUBLIC_KEY_LEN]),
    /// Raw ML-DSA-87 public key.
    MlDsa87(&'a [u8; MLDSA87_PUBLIC_KEY_LEN]),
}

/// Algorithm of a [`SubjectKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlg {
    /// P-384.
    P384,
    /// ML-DSA-87.
    MlDsa87,
}

impl KeyAlg {
    fn spki_len(self) -> usize {
        match self {
            Self::P384 => P384_SPKI_HEADER.len() + P384_PUBLIC_KEY_LEN,
            Self::MlDsa87 => MLDSA87_SPKI_HEADER.len() + MLDSA87_PUBLIC_KEY_LEN,
        }
    }
}

impl SubjectKey<'_> {
    /// The key's algorithm.
    pub fn alg(&self) -> KeyAlg {
        match self {
            Self::P384(_) => KeyAlg::P384,
            Self::MlDsa87(_) => KeyAlg::MlDsa87,
        }
    }

    fn spki_header(&self) -> &'static [u8] {
        match self {
            Self::P384(_) => &P384_SPKI_HEADER,
            Self::MlDsa87(_) => &MLDSA87_SPKI_HEADER,
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::P384(key) => *key,
            Self::MlDsa87(key) => *key,
        }
    }
}

/// Structure of the TBS being retargeted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TbsKind {
    /// `TBSCertificate`: `signature` is element 2, `subjectPublicKeyInfo`
    /// element 6.
    Certificate,
    /// `CertificationRequestInfo`: no `signature`; `subjectPublicKeyInfo`
    /// is element 2. The issuer algorithm is ignored.
    Csr,
}

impl TbsKind {
    fn sig_alg_index(self) -> Option<usize> {
        match self {
            Self::Certificate => Some(2),
            Self::Csr => None,
        }
    }

    fn spki_index(self) -> usize {
        match self {
            Self::Certificate => 6,
            Self::Csr => 2,
        }
    }
}

/// Byte ranges of a P-384 TBS that retargeting replaces.
struct Layout {
    content_start: usize,
    sig_alg: (usize, usize),
    spki: (usize, usize),
}

/// Length of the TBS [`retarget_tbs`] writes for `tbs` and a key of
/// algorithm `key`.
///
/// # Returns
/// `None` if `tbs` is not a P-384 TBS of `kind` or the result exceeds the
/// supported DER length.
pub fn retarget_len(tbs: &[u8], kind: TbsKind, issuer: SigAlg, key: KeyAlg) -> Option<usize> {
    let layout = locate(tbs, kind)?;
    encoded_len(content_len(tbs, kind, &layout, issuer, key))
}

fn encoded_len(content: usize) -> Option<usize> {
    if content > usize::from(u16::MAX) {
        return None;
    }
    Some(1 + der_helpers::der_length_size(content) + content)
}

/// Rewrite the P-384 TBS `tbs` so that it is signed with `issuer` and
/// certifies `key`, writing the result into `out`.
///
/// For [`TbsKind::Csr`] only the subject key is replaced.
///
/// # Returns
/// `Some(n)` — bytes written, or `None` if `tbs` is not a P-384 TBS of
/// `kind`, or `out` is shorter than [`retarget_len`].
pub fn retarget_tbs(
    tbs: &[u8],
    kind: TbsKind,
    issuer: SigAlg,
    key: SubjectKey<'_>,
    out: &mut [u8],
) -> Option<usize> {
    let layout = locate(tbs, kind)?;
    let content = content_len(tbs, kind, &layout, issuer, key.alg());
    if out.len() < encoded_len(content)? {
        return None;
    }
    let alg_id = match kind {
        TbsKind::Certificate => issuer.alg_id(),
        TbsKind::Csr => &[],
    };
    *out.first_mut()? = 0x30;
    let mut pos = 1 + der_helpers::encode_der_length(&mut out[1..], content)?;
    for part in [
        &tbs[layout.content_start..layout.sig_alg.0],
        alg_id,
        &tbs[layout.sig_alg.1..layout.spki.0],
        key.spki_header(),
        key.bytes(),
        &tbs[layout.spki.1..],
    ] {
        out[pos..pos + part.len()].copy_from_slice(part);
        pos += part.len();
    }
    Some(pos)
}

fn content_len(tbs: &[u8], kind: TbsKind, layout: &Layout, issuer: SigAlg, key: KeyAlg) -> usize {
    let alg_id_len = match kind {
        TbsKind::Certificate => issuer.alg_id().len(),
        TbsKind::Csr => 0,
    };
    let kept = (tbs.len() - layout.content_start)
        - (layout.sig_alg.1 - layout.sig_alg.0)
        - (layout.spki.1 - layout.spki.0);
    kept + alg_id_len + key.spki_len()
}

/// Find the `signature` and `subjectPublicKeyInfo` elements of a P-384
/// TBS and check that they hold ECDSA-SHA384 and a P-384 key.
fn locate(tbs: &[u8], kind: TbsKind) -> Option<Layout> {
    if *tbs.first()? != 0x30 {
        return None;
    }
    let (content_start, end) = tlv(tbs, 0)?;
    if end != tbs.len() {
        return None;
    }

    let mut sig_alg = None;
    let mut spki = None;
    let mut pos = content_start;
    let mut index = 0;
    while pos < end {
        let (_, next) = tlv(tbs, pos)?;
        if Some(index) == kind.sig_alg_index() {
            sig_alg = Some((pos, next));
        }
        if index == kind.spki_index() {
            spki = Some((pos, next));
        }
        pos = next;
        index += 1;
    }
    if pos != end {
        return None;
    }

    let spki = spki?;
    let spki_bytes = &tbs[spki.0..spki.1];
    if spki_bytes.len() != P384_SPKI_HEADER.len() + P384_PUBLIC_KEY_LEN
        || !spki_bytes.starts_with(&P384_SPKI_HEADER)
    {
        return None;
    }
    let sig_alg = match kind {
        TbsKind::Certificate => {
            let sig_alg = sig_alg?;
            if tbs[sig_alg.0..sig_alg.1] != ECDSA_SHA384_ALG_ID {
                return None;
            }
            sig_alg
        }
        // An empty range just before the SPKI keeps the copy uniform.
        TbsKind::Csr => (spki.0, spki.0),
    };
    Some(Layout {
        content_start,
        sig_alg,
        spki,
    })
}

/// `(content_start, end)` of the DER TLV at `buf[pos..]`, with
/// `end <= buf.len()`.
fn tlv(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *buf.get(pos.checked_add(1)?)?;
    let (header, len) = match first {
        0x00..=0x7F => (2, usize::from(first)),
        0x81 => (3, usize::from(*buf.get(pos + 2)?)),
        0x82 => (
            4,
            usize::from(u16::from_be_bytes([*buf.get(pos + 2)?, *buf.get(pos + 3)?])),
        ),
        _ => return None,
    };
    let start = pos + header;
    let end = start.checked_add(len)?;
    (end <= buf.len()).then_some((start, end))
}
