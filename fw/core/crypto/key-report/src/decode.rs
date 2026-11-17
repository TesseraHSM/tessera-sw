// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Zero-copy decoder / verifier for COSE_Sign1 key-attestation reports.
//!
//! [`parse_key_report`] walks the CBOR with a minicbor `Decoder` only to
//! locate field boundaries, then returns a [`KeyReportView`] whose byte
//! fields are `&HsmDmaBuf` sub-views of the input report buffer — no copies
//! and no owned arrays. [`verify_key_report`] rebuilds the COSE
//! `Sig_structure` and checks the ES384 signature.

use minicbor::Decoder;
use tsra_fw_hsm_pal_traits::HsmCrypto;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::codec::SigStructure;
use crate::codec::SIG_STRUCTURE_CONTEXT;
use crate::consts::*;
use crate::sig::sig_halves_swap;
use crate::ReportKind;
use crate::ReportView;
use crate::TransferReportView;

/// Zero-copy view over a decoded COSE_Sign1 key-attestation report.
///
/// Scalar fields are decoded by value; every byte field is a `&HsmDmaBuf`
/// sub-view borrowing directly from the input report buffer.
pub struct KeyReportView<'a> {
    /// Report format version.
    pub version: u16,
    /// Real length of the COSE_Key within [`public_key`](Self::public_key).
    pub public_key_size: u16,
    /// Capability flags for the attested key.
    pub flags: u32,
    /// The `public_key` field (fixed [`PUBLIC_KEY_MAX_SIZE`] bytes; the
    /// COSE_Key occupies the first `public_key_size`, rest zero-padded).
    pub public_key: &'a HsmDmaBuf,
    /// Owning application UUID.
    pub app_uuid: &'a HsmDmaBuf,
    /// Report data.
    pub report_data: &'a HsmDmaBuf,
    /// VM launch ID.
    pub vm_launch_id: &'a HsmDmaBuf,
    /// Optional SHA-384 PartPolicy digest. Required for v2 public-key
    /// reports without a signed kind discriminator.
    pub policy_hash: Option<&'a HsmDmaBuf>,
    /// COSE_Sign1 protected header (signed input).
    pub protected_header: &'a HsmDmaBuf,
    /// Encoded payload bytes (the Sig_structure input).
    pub payload: &'a HsmDmaBuf,
    /// COSE_Sign1 signature (`r || s`, big-endian per half).
    pub signature: &'a HsmDmaBuf,
}

/// Map a minicbor decode error to [`HsmError::InvalidArg`].
pub(crate) fn map_decode_err<T, E>(result: Result<T, E>) -> HsmResult<T> {
    result.map_err(|_| HsmError::InvalidArg)
}

/// Read a bstr at the decoder's current position and return the
/// `[start, end)` offsets of its content in the decoder's input.
pub(crate) fn bytes_span(d: &mut Decoder<'_>) -> HsmResult<(usize, usize)> {
    let len = map_decode_err(d.bytes())?.len();
    let end = d.position();
    let start = end.checked_sub(len).ok_or(HsmError::InvalidArg)?;
    Ok((start, end))
}

pub(crate) struct CoseReportView<'a> {
    pub(crate) protected_header: &'a HsmDmaBuf,
    pub(crate) payload: &'a HsmDmaBuf,
    pub(crate) signature: &'a HsmDmaBuf,
}

/// Parse a tagged COSE_Sign1 key-attestation report, returning a
/// zero-copy [`KeyReportView`] borrowing from `report`.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — malformed report (bad tag, structure, or
///   CBOR).
pub fn parse_key_report(report: &HsmDmaBuf) -> HsmResult<KeyReportView<'_>> {
    match parse_payload(parse_cose_report(report)?)? {
        ReportView::PublicKey(view) => Ok(view),
        _ => Err(HsmError::InvalidArg),
    }
}

fn parse_cose_report(report: &HsmDmaBuf) -> HsmResult<CoseReportView<'_>> {
    if report.len() <= COSE_SIGN1_TAG_SIZE || report[0] != COSE_SIGN1_TAG {
        return Err(HsmError::InvalidArg);
    }
    let rest = &report[COSE_SIGN1_TAG_SIZE..];

    // COSE_Sign1 = [ protected, unprotected{}, payload, signature ].
    let (prot, payload_span, sig) = {
        let mut d = Decoder::new(rest);
        if map_decode_err(d.array())? != Some(4) {
            return Err(HsmError::InvalidArg);
        }
        let prot = bytes_span(&mut d)?;
        // unprotected header is an empty map.
        if map_decode_err(d.map())? != Some(0) {
            return Err(HsmError::InvalidArg);
        }
        let payload_span = bytes_span(&mut d)?;
        let sig = bytes_span(&mut d)?;
        // Reject trailing bytes after the COSE_Sign1 object.
        if d.position() != rest.len() {
            return Err(HsmError::InvalidArg);
        }
        (prot, payload_span, sig)
    };

    // Enforce the fixed COSE-envelope field lengths.
    if prot.1 - prot.0 != PROTECTED_HEADER.len() || sig.1 - sig.0 != SIGNATURE_LEN {
        return Err(HsmError::InvalidArg);
    }
    let protected_header = &rest[prot.0..prot.1];
    let payload = &rest[payload_span.0..payload_span.1];
    let signature = &rest[sig.0..sig.1];

    Ok(CoseReportView {
        protected_header,
        payload,
        signature,
    })
}

/// Parse a kind-discriminated v2 report or a legacy public-key report.
///
/// Each kind has a strict field set. Unknown or duplicate fields, missing
/// fields, version mismatches, and invalid SHA-384 field lengths are errors.
/// Parsing does not verify signatures or operation authorization.
pub fn parse_report(report: &HsmDmaBuf) -> HsmResult<ReportView<'_>> {
    if report.len() > KEY_REPORT_MAX_LEN {
        return Err(HsmError::InvalidArg);
    }
    parse_payload(parse_cose_report(report)?)
}

fn parse_payload(view: CoseReportView<'_>) -> HsmResult<ReportView<'_>> {
    let payload = view.payload;
    let mut version = 0u16;
    let mut public_key_size = 0u16;
    let mut flags = 0u32;
    let mut report_kind = None;
    let mut fields = [(0usize, 0usize); 12];
    let mut seen = 0u16;
    let mut d = Decoder::new(payload);
    let entries = map_decode_err(d.map())?.ok_or(HsmError::InvalidArg)?;
    if !(5..=9).contains(&entries) {
        return Err(HsmError::InvalidArg);
    }
    for _ in 0..entries {
        let key = map_decode_err(d.u8())?;
        if key > 11 || seen & (1 << key) != 0 {
            return Err(HsmError::InvalidArg);
        }
        seen |= 1 << key;
        match key {
            0 => version = map_decode_err(d.u16())?,
            2 => public_key_size = map_decode_err(d.u16())?,
            3 => flags = map_decode_err(d.u32())?,
            8 => report_kind = Some(map_decode_err(d.u8())?),
            _ => fields[key as usize] = bytes_span(&mut d)?,
        }
    }
    if d.position() != payload.len() {
        return Err(HsmError::InvalidArg);
    }
    let policy = fields[7];
    let have_policy_hash = seen & (1 << 7) != 0;
    if have_policy_hash && policy.1 - policy.0 != POLICY_HASH_LEN {
        return Err(HsmError::InvalidArg);
    }
    let kind = match report_kind {
        None | Some(0) => {
            let expected_version = if report_kind.is_some() || have_policy_hash {
                REPORT_VERSION_V2
            } else {
                REPORT_VERSION
            };
            let pk = fields[1];
            let uuid = fields[4];
            let rd = fields[5];
            let vm = fields[6];
            if seen & 0x7f != 0x7f
                || seen & !0x1ff != 0
                || version != expected_version
                || pk.1 - pk.0 != PUBLIC_KEY_MAX_SIZE
                || uuid.1 - uuid.0 != APP_UUID_LEN
                || rd.1 - rd.0 != REPORT_DATA_LEN
                || vm.1 - vm.0 != VM_LAUNCH_ID_LEN
                || public_key_size as usize > PUBLIC_KEY_MAX_SIZE
            {
                return Err(HsmError::InvalidArg);
            }
            return Ok(ReportView::PublicKey(KeyReportView {
                version,
                public_key_size,
                flags,
                public_key: &payload[pk.0..pk.1],
                app_uuid: &payload[uuid.0..uuid.1],
                report_data: &payload[rd.0..rd.1],
                vm_launch_id: &payload[vm.0..vm.1],
                policy_hash: have_policy_hash.then(|| &payload[policy.0..policy.1]),
                protected_header: view.protected_header,
                payload,
                signature: view.signature,
            }));
        }
        Some(1) => ReportKind::Darc,
        Some(2) => ReportKind::SdBackup,
        _ => return Err(HsmError::InvalidArg),
    };
    let required = (1 << 0) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11);
    let required = if kind == ReportKind::SdBackup {
        required | (1 << 7)
    } else {
        required
    };
    let source = fields[9];
    let recipient = fields[10];
    let envelope = fields[11];
    if seen != required
        || version != REPORT_VERSION_V2
        || source.1 - source.0 != SHA384_LEN
        || recipient.1 - recipient.0 != SHA384_LEN
        || envelope.1 - envelope.0 != SHA384_LEN
        || (kind == ReportKind::SdBackup && policy.1 - policy.0 != POLICY_HASH_LEN)
    {
        return Err(HsmError::InvalidArg);
    }
    let transfer = TransferReportView {
        source_pid_key_id: &payload[source.0..source.1],
        recipient_key_id: &payload[recipient.0..recipient.1],
        envelope_hash: &payload[envelope.0..envelope.1],
        protected_header: view.protected_header,
        payload,
        signature: view.signature,
    };
    match kind {
        ReportKind::Darc => Ok(ReportView::Darc(transfer)),
        ReportKind::SdBackup => Ok(ReportView::SdBackup {
            transfer: crate::SdBackupReportView {
                source_pid_spki_thumbprint: transfer.source_pid_key_id,
                recipient_spki_thumbprint: transfer.recipient_key_id,
                envelope_hash: transfer.envelope_hash,
                protected_header: transfer.protected_header,
                payload: transfer.payload,
                signature: transfer.signature,
            },
            policy_hash: &payload[policy.0..policy.1],
        }),
        ReportKind::PublicKey => Err(HsmError::InvalidArg),
    }
}

/// Verify the ES384 signature of a COSE_Sign1 key-attestation report.
///
/// Rebuilds the COSE `Sig_structure` over the report's protected header
/// and payload, hashes it (SHA-384), and verifies against `signer_pub`.
///
/// # Parameters
/// * `signer_pub` — signer's P-384 public key, `x || y` with each
///   coordinate in the PAL's operand order (the `ecc_verify` wire form).
///
/// # Returns
/// * `Ok(true)` — signature is valid.
/// * `Ok(false)` — signature is invalid.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — malformed report.
/// * Other [`HsmError`] values propagated from the PAL.
pub async fn verify_key_report<'a, P>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    report: &HsmDmaBuf,
    signer_pub: &HsmDmaBuf,
) -> HsmResult<bool>
where
    P: HsmCrypto + 'a,
{
    let view = parse_key_report(report)?;

    verify_signature(
        pal,
        io,
        alloc,
        CoseReportView {
            protected_header: view.protected_header,
            payload: view.payload,
            signature: view.signature,
        },
        signer_pub,
    )
    .await
}

/// Verify an ES384 report signature and require the expected signed kind.
///
/// This does not authorize the signer or verify the envelope digest,
/// recipient identity, or policy binding. The receiving command must do so.
pub async fn verify_report<'a, P>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    report: &HsmDmaBuf,
    signer_pub: &HsmDmaBuf,
    expected_kind: ReportKind,
) -> HsmResult<bool>
where
    P: HsmCrypto + 'a,
{
    let view = parse_report(report)?;
    if view.kind() != expected_kind {
        return Err(HsmError::InvalidArg);
    }
    let cose = match view {
        ReportView::PublicKey(view) => CoseReportView {
            protected_header: view.protected_header,
            payload: view.payload,
            signature: view.signature,
        },
        ReportView::Darc(transfer) => CoseReportView {
            protected_header: transfer.protected_header,
            payload: transfer.payload,
            signature: transfer.signature,
        },
        ReportView::SdBackup { transfer, .. } => CoseReportView {
            protected_header: transfer.protected_header,
            payload: transfer.payload,
            signature: transfer.signature,
        },
    };
    verify_signature(pal, io, alloc, cose, signer_pub).await
}

pub(crate) async fn verify_signature<'a, P>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    view: CoseReportView<'_>,
    signer_pub: &HsmDmaBuf,
) -> HsmResult<bool>
where
    P: HsmCrypto + 'a,
{
    // The protected header is signed input. Our fixed wire format mandates
    // the canonical ES384 header, and the Sig_structure below is rebuilt
    // from that constant — so bind it by rejecting any report whose
    // protected header differs (otherwise a tampered header would not be
    // covered by the signature check below).
    let protected: &[u8] = view.protected_header;
    if protected != &PROTECTED_HEADER[..] {
        return Err(HsmError::InvalidArg);
    }

    // Rebuild the Sig_structure over (protected_header, payload) and
    // measure/encode it with `minicbor::len` — no hand byte-counting.
    let sig_struct_val = SigStructure {
        context: SIG_STRUCTURE_CONTEXT,
        body_protected: &PROTECTED_HEADER,
        external_aad: &[],
        payload: view.payload,
    };
    // Zeroed so any `len`/`encode` divergence can't feed stale DMA bytes
    // into the verified digest.
    let sig_struct = alloc.dma_alloc_zeroed(minicbor::len(&sig_struct_val))?;
    minicbor::encode(&sig_struct_val, crate::codec::as_mut_slice(sig_struct))
        .map_err(|_| HsmError::InternalError)?;

    // SHA-384 in the operand order `ecc_verify` consumes.
    let digest = alloc.dma_alloc(SHA384_LEN)?;
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        sig_struct,
        digest,
        HsmDigestForm::Operand,
    )
    .await?;

    // The COSE signature stores `r || s` big-endian per half; a
    // big-endian PAL verifies it in place, otherwise convert a copy.
    if view.signature.len() != SIGNATURE_LEN {
        return Err(HsmError::InvalidArg);
    }
    let sig: &HsmDmaBuf = if P::BYTE_ORDER.is_be() {
        view.signature
    } else {
        let sig = alloc.dma_alloc(SIGNATURE_LEN)?;
        sig.copy_from_slice(view.signature);
        sig_halves_swap(P::BYTE_ORDER, sig)?;
        sig
    };

    let result = alloc.dma_alloc(4)?;
    pal.ecc_verify(io, HsmEccCurve::P384, signer_pub, digest, sig, result)
        .await?;

    // Per the trait contract, bit 0 clear indicates a valid signature.
    Ok(result[0] & 1 == 0)
}
