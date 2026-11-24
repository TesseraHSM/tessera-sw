// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! minicbor codec structs for the COSE_Sign1 key-attestation report.
//!
//! These mirror the wire schema of the host report codec
//! (`ddi/mbor/test_helpers/src/report.rs`). Deriving [`Encode`] and [`CborLen`]
//! lets `minicbor::len` compute every encoded length exactly, so no
//! byte-counting constants are hand-maintained. Byte fields borrow
//! `&[u8]` (which `HsmDmaBuf` derefs to) — encoding writes into `HsmDmaBuf`
//! output, and the zero-copy decoder ([`crate::decode`]) is unaffected.

use minicbor::CborLen;
use minicbor::Encode;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;

/// Reborrow a `&mut HsmDmaBuf` as its underlying mutable byte slice, so it
/// can be handed to `minicbor::encode` (whose `Write` bound is satisfied
/// by `&mut [u8]`, not `&mut HsmDmaBuf`).
pub(crate) fn as_mut_slice(buf: &mut HsmDmaBuf) -> &mut [u8] {
    buf
}

/// COSE_Sign1 `Sig_structure` (RFC 9052 §4.4):
/// `[ "Signature1", body_protected, external_aad, payload ]`.
#[derive(Encode, CborLen)]
#[cbor(array)]
pub(crate) struct SigStructure<'a> {
    /// Context string; always `"Signature1"`.
    #[n(0)]
    pub context: &'a str,
    /// Encoded protected header.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub body_protected: &'a [u8],
    /// Application signature domain; empty only for PublicKey attestations.
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub external_aad: &'a [u8],
    /// Encoded payload bytes.
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub payload: &'a [u8],
}

/// Empty COSE unprotected header (`{}`).
#[derive(Encode, CborLen)]
#[cbor(map)]
pub(crate) struct UnprotectedHeader {}

/// Tagged COSE_Sign1 object body (the CBOR tag byte is written
/// separately): `[ protected, unprotected, payload, signature ]`.
#[derive(Encode, CborLen)]
#[cbor(array)]
pub(crate) struct CoseSign1<'a> {
    /// Encoded protected header (bstr-wrapped).
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub protected_header: &'a [u8],
    /// Empty unprotected header map.
    #[n(1)]
    pub unprotected: UnprotectedHeader,
    /// Encoded payload (bstr-wrapped).
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub payload: &'a [u8],
    /// ES384 signature `r || s`, big-endian per component (bstr-wrapped).
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub signature: &'a [u8],
}

/// Public-key payload. v2 permits the signed `PublicKey` discriminator at
/// key 8; reports without it retain their original wire format.
#[derive(Encode, CborLen)]
#[cbor(map)]
pub(crate) struct KeyReportPayload<'a> {
    /// Report format version.
    #[n(0)]
    pub version: u16,
    /// Fixed-size `public_key` bstr wrapping the inner COSE_Key
    /// (`PUBLIC_KEY_MAX_SIZE` bytes, zero-padded).
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub public_key: &'a [u8],
    /// Real length of the COSE_Key within `public_key`.
    #[n(2)]
    pub public_key_size: u16,
    /// Capability flags.
    #[n(3)]
    pub flags: u32,
    /// Owning application UUID.
    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    pub app_uuid: &'a [u8],
    /// Report data.
    #[n(5)]
    #[cbor(with = "minicbor::bytes")]
    pub report_data: &'a [u8],
    /// VM launch ID.
    #[n(6)]
    #[cbor(with = "minicbor::bytes")]
    pub vm_launch_id: &'a [u8],
    /// Optional SHA-384 digest of the PartPolicy (v2 only; map key 7).
    /// Required for v2 public-key reports without a discriminator.
    #[n(7)]
    #[cbor(with = "minicbor::bytes")]
    pub policy_hash: Option<&'a [u8]>,
    /// Signed discriminator (v2 only); absent in legacy key reports.
    #[n(8)]
    pub report_kind: Option<u8>,
}

/// The `Sig_structure` context literal (`"Signature1"`).
pub(crate) const SIG_STRUCTURE_CONTEXT: &str = "Signature1";
