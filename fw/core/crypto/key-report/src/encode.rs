// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime builder for COSE_Sign1 key-attestation reports.
//!
//! The report is signed with ES384 (ECDSA-P384) or ML-DSA-87, as the
//! supplied [`ReportSigner`] selects. The attested public key may be ECC,
//! RSA, ML-DSA-87, or symmetric (see [`AttestedPubKey`]).
//!
//! All working buffers are [`HsmDmaBuf`] allocations. Payload and
//! `Sig_structure` lengths are computed by `minicbor::len` on the
//! [`codec`](crate::codec) structs. The fixed COSE_Sign1 envelope is laid
//! out by hand so the payload and signature land at their final offsets
//! in the caller's buffer, keeping ML-DSA-87 reports within the per-IO DMA
//! budget. The inner COSE_Key uses
//! negative integer map keys (which minicbor's derive cannot express), so
//! it alone is written with an imperative `Encoder` (see
//! [`to_cose_key`](crate::cose_key)).

use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmCrypto;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmEcdsaNonce;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmMlDsaHedge;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsg;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsgType;
use tsra_fw_hsm_pal_traits::HsmMlDsaParamSet;
use tsra_fw_hsm_pal_traits::HsmMlDsaPrivKey;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::codec::as_mut_slice;
use crate::codec::KeyReportPayload;
use crate::codec::SigStructure;
use crate::codec::SIG_STRUCTURE_CONTEXT;
use crate::consts::*;
use crate::cose_key::to_cose_key;
use crate::cose_key::AttestedPubKey;
use crate::sig::sig_halves_swap;
use crate::ReportAlg;
use crate::ReportKind;
use crate::ReportParams;
use crate::ReportSigner;

/// Caller-supplied inputs for the attestation report.
pub struct KeyReportParams<'a> {
    /// Public-key material for the attested key.
    pub key: AttestedPubKey<'a>,
    /// Capability flags for the attested key (build via [`KeyFlags`]).
    ///
    /// [`KeyFlags`]: crate::KeyFlags
    pub flags: u32,
    /// Owning application UUID; must be [`APP_UUID_LEN`] bytes.
    pub app_uuid: &'a HsmDmaBuf,
    /// Report data; must be [`REPORT_DATA_LEN`] bytes.
    pub report_data: &'a HsmDmaBuf,
    /// VM launch ID; must be [`VM_LAUNCH_ID_LEN`] bytes.
    pub vm_launch_id: &'a HsmDmaBuf,
    /// Optional SHA-384 PartPolicy digest. When `Some`, the report is
    /// emitted as **v2** (carrying `policy_hash`); when `None`, as **v1**.
    /// Must be [`POLICY_HASH_LEN`] bytes when present.
    pub policy_hash: Option<&'a HsmDmaBuf>,
}

impl KeyReportParams<'_> {
    fn validate(&self) -> HsmResult<()> {
        if self.app_uuid.len() != APP_UUID_LEN
            || self.report_data.len() != REPORT_DATA_LEN
            || self.vm_launch_id.len() != VM_LAUNCH_ID_LEN
        {
            return Err(HsmError::InvalidArg);
        }
        if let Some(policy_hash) = self.policy_hash {
            if policy_hash.len() != POLICY_HASH_LEN {
                return Err(HsmError::InvalidArg);
            }
        }
        self.key.validate()
    }
}

/// Build a COSE_Sign1 key-attestation report, signed ES384 with
/// `priv_key` (see [`key_report_with`] for other signers).
///
/// Follows the codebase's query/copy convention:
///
/// * `out == None` — query mode: returns the exact report size. Encodes
///   the COSE_Key into scoped scratch to measure the report with
///   `minicbor::len`, then frees it; performs no signing.
/// * `out == Some(buf)` — copy mode: writes the tagged COSE_Sign1 report
///   into `buf[..size]` and returns `size`.
///
/// # Parameters
/// * `pal` — [`HsmCrypto`] (SHA-384 + ECDSA-P384) and [`HsmAlloc`].
/// * `io` — caller's IO scope.
/// * `params` — attested key material, flags, UUIDs, report data.
/// * `priv_key` — P-384 attestation private key (raw scalar, exactly
///   [`PRIV_KEY_LEN`] bytes).
/// * `out` — output buffer, or `None` to query the required size.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — a `params` field or `priv_key` has the
///   wrong length, or `out` is shorter than the required size.
/// * Other [`HsmError`] values propagated from the PAL.
pub async fn key_report<P>(
    pal: &P,
    io: &P::Io,
    params: &KeyReportParams<'_>,
    priv_key: &HsmDmaBuf,
    out: Option<&mut HsmDmaBuf>,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc,
{
    key_report_with(pal, io, params, ReportSigner::Es384(priv_key), out).await
}

/// [`key_report`] signed by `signer`, whose algorithm the report's
/// protected header names.
pub async fn key_report_with<P>(
    pal: &P,
    io: &P::Io,
    params: &KeyReportParams<'_>,
    signer: ReportSigner<'_>,
    out: Option<&mut HsmDmaBuf>,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc,
{
    build_key_report(pal, io, (params, None), signer, out).await
}

/// Sign a public-key attestation or a complete canonical transfer envelope.
///
/// Query mode (`out = None`) validates inputs and returns the encoded size
/// without signing. Only exporting command handlers may supply operation
/// envelopes; this function does not perform command authorization.
pub async fn report<P>(
    pal: &P,
    io: &P::Io,
    params: &ReportParams<'_>,
    priv_key: &HsmDmaBuf,
    out: Option<&mut HsmDmaBuf>,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc,
{
    report_with(pal, io, params, ReportSigner::Es384(priv_key), out).await
}

/// [`report`] signed by `signer`, whose algorithm the report's protected
/// header names.
pub async fn report_with<P>(
    pal: &P,
    io: &P::Io,
    params: &ReportParams<'_>,
    signer: ReportSigner<'_>,
    out: Option<&mut HsmDmaBuf>,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc,
{
    signer.validate()?;
    match params {
        ReportParams::PublicKey(params) => {
            build_key_report(pal, io, (params, Some(ReportKind::PublicKey)), signer, out).await
        }
        ReportParams::Transfer(envelope) => {
            let kind = crate::transfer::parse_transfer_envelope(envelope)?
                .header
                .kind();
            match out {
                Some(out) => {
                    let encode = |payload: &mut [u8]| {
                        payload.copy_from_slice(envelope);
                        Ok(())
                    };
                    sign_into(pal, io, kind, signer, envelope.len(), &encode, out).await
                }
                None => Ok(Sign1Layout::new(kind, signer.alg(), envelope.len())?.total),
            }
        }
    }
}

async fn build_key_report<P>(
    pal: &P,
    io: &P::Io,
    (params, kind): (&KeyReportParams<'_>, Option<ReportKind>),
    signer: ReportSigner<'_>,
    out: Option<&mut HsmDmaBuf>,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc,
{
    params.validate()?;
    signer.validate()?;

    let Some(out) = out else {
        // Query pass: measure in a nested scope so the scratch frees
        // before returning (the size query retains nothing).
        return pal.alloc_scoped(io, |scoped| report_size(scoped, params, kind, signer.alg()));
    };

    do_build(pal, io, (params, kind), signer, out).await
}

/// Encode the inner COSE_Key into `cose_key` scratch and build the
/// payload codec struct describing it.
///
/// A discriminator or policy hash selects v2; otherwise use legacy v1.
fn build_payload_struct<'a>(
    params: &'a KeyReportParams<'a>,
    cose_key: &'a HsmDmaBuf,
    cose_len: usize,
    kind: Option<ReportKind>,
) -> KeyReportPayload<'a> {
    let policy_hash = params.policy_hash.map(|d| &**d);
    let version = if kind.is_some() || policy_hash.is_some() {
        REPORT_VERSION_V2
    } else {
        REPORT_VERSION
    };
    KeyReportPayload {
        version,
        public_key: cose_key,
        public_key_size: cose_len as u16,
        flags: params.flags,
        app_uuid: params.app_uuid,
        report_data: params.report_data,
        vm_launch_id: params.vm_launch_id,
        policy_hash,
        report_kind: kind.map(|k| k as u8),
    }
}

/// Compute the exact tagged-report size for `params`, encoding the
/// COSE_Key into transient scratch from `scoped` to measure the payload.
fn report_size(
    scoped: &impl HsmScopedAlloc,
    params: &KeyReportParams<'_>,
    kind: Option<ReportKind>,
    alg: ReportAlg,
) -> HsmResult<usize> {
    let payload_len = key_payload_len(scoped, params, kind)?;
    Ok(Sign1Layout::new(ReportKind::PublicKey, alg, payload_len)?.total)
}

/// Encoded length of the key-report payload map.
fn key_payload_len(
    scoped: &impl HsmScopedAlloc,
    params: &KeyReportParams<'_>,
    kind: Option<ReportKind>,
) -> HsmResult<usize> {
    let (cose_key, cose_len) = encode_cose_key(scoped, params)?;
    Ok(minicbor::len(build_payload_struct(
        params, cose_key, cose_len, kind,
    )))
}

/// Encode the attested key's COSE_Key into a zeroed `public_key` field,
/// returning the field and the COSE_Key's length within it.
fn encode_cose_key<'a>(
    alloc: &'a impl HsmScopedAlloc,
    params: &KeyReportParams<'_>,
) -> HsmResult<(&'a HsmDmaBuf, usize)> {
    let field = alloc.dma_alloc_zeroed(params.key.field_len())?;
    let cose_len = to_cose_key(&params.key, field)?;
    if field.len() > PUBLIC_KEY_MAX_SIZE && cose_len != field.len() {
        return Err(HsmError::InternalError);
    }
    Ok((field, cose_len))
}

/// Byte layout of a tagged COSE_Sign1
/// `18([ bstr(protected), {}, bstr(payload), bstr(signature) ])`.
///
/// Lets the payload and signature be written at their final offsets in
/// the caller's buffer, so building a report needs no payload, signature
/// or envelope scratch — only the transient `Sig_structure`.
struct Sign1Layout {
    protected_header: &'static [u8],
    sig_len: usize,
    payload_at: usize,
    payload_len: usize,
    sig_at: usize,
    total: usize,
}

impl Sign1Layout {
    fn new(kind: ReportKind, alg: ReportAlg, payload_len: usize) -> HsmResult<Self> {
        let protected_header = kind.protected_header(alg);
        let protected = protected_header.len();
        let payload_at = COSE_SIGN1_TAG_SIZE + 1 + bstr_head_len(protected)? + protected + 1;
        let payload_at = payload_at + bstr_head_len(payload_len)?;
        let sig_len = alg.signature_len();
        let sig_at = payload_at + payload_len + bstr_head_len(sig_len)?;
        Ok(Self {
            protected_header,
            sig_len,
            payload_at,
            payload_len,
            sig_at,
            total: sig_at + sig_len,
        })
    }

    /// Write every envelope byte outside the payload and signature.
    fn write_envelope(&self, out: &mut [u8]) -> HsmResult<()> {
        let protected = self.protected_header;
        out[0] = COSE_SIGN1_TAG;
        out[1] = CBOR_ARRAY_4;
        let mut at = 2 + write_bstr_head(&mut out[2..], protected.len())?;
        out[at..at + protected.len()].copy_from_slice(protected);
        at += protected.len();
        out[at] = CBOR_EMPTY_MAP;
        at += 1;
        at += write_bstr_head(&mut out[at..], self.payload_len)?;
        if at != self.payload_at {
            return Err(HsmError::InternalError);
        }
        at += self.payload_len;
        at += write_bstr_head(&mut out[at..], self.sig_len)?;
        if at != self.sig_at {
            return Err(HsmError::InternalError);
        }
        Ok(())
    }
}

/// CBOR `array(4)` initial byte.
const CBOR_ARRAY_4: u8 = 0x84;
/// CBOR empty map `{}`.
const CBOR_EMPTY_MAP: u8 = 0xA0;

/// Length of a definite CBOR byte-string head for `len` content bytes.
fn bstr_head_len(len: usize) -> HsmResult<usize> {
    match len {
        0..=23 => Ok(1),
        24..=0xFF => Ok(2),
        0x100..=0xFFFF => Ok(3),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Write the shortest-form CBOR byte-string head for `len` into `out`.
fn write_bstr_head(out: &mut [u8], len: usize) -> HsmResult<usize> {
    const BSTR: u8 = 0x40;
    let head_len = bstr_head_len(len)?;
    let head = out.get_mut(..head_len).ok_or(HsmError::InternalError)?;
    match head {
        [b] => *b = BSTR | len as u8,
        [b, l] => {
            *b = BSTR | 24;
            *l = len as u8;
        }
        [b, rest @ ..] => {
            *b = BSTR | 25;
            rest.copy_from_slice(&(len as u16).to_be_bytes());
        }
        [] => return Err(HsmError::InternalError),
    }
    Ok(head_len)
}

async fn do_build<P>(
    pal: &P,
    io: &P::Io,
    (params, kind): (&KeyReportParams<'_>, Option<ReportKind>),
    signer: ReportSigner<'_>,
    out: &mut HsmDmaBuf,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc,
{
    let payload_len = pal.alloc_scoped(io, |scoped| key_payload_len(scoped, params, kind))?;
    // The COSE_Key scratch lives only while the payload is encoded into
    // its final position in `out`.
    let encode = |payload: &mut [u8]| {
        pal.alloc_scoped(io, |scoped| {
            let (cose_key, cose_len) = encode_cose_key(scoped, params)?;
            let payload_struct = build_payload_struct(params, cose_key, cose_len, kind);
            minicbor::encode(&payload_struct, payload).map_err(|_| HsmError::InternalError)
        })
    };
    sign_into(
        pal,
        io,
        ReportKind::PublicKey,
        signer,
        payload_len,
        &encode,
        out,
    )
    .await
}

/// Exact size of a COSE_Sign1 containing the complete SD encrypted envelope.
/// Exact size of COSE_Sign1 containing a complete encrypted transfer.
pub fn transfer_report_len(
    kind: ReportKind,
    kem: crate::transfer::TransferKem,
    alg: ReportAlg,
) -> HsmResult<usize> {
    let payload_len = match kind {
        ReportKind::Darc => crate::transfer::darc_envelope_len(kem),
        ReportKind::SdBackup => crate::transfer::sd_backup_envelope_len(kem),
        ReportKind::PublicKey => return Err(HsmError::InvalidArg),
    };
    Ok(Sign1Layout::new(kind, alg, payload_len)?.total)
}

/// Assemble a tagged COSE_Sign1 in `out`: `encode` writes the
/// `payload_len`-byte payload at its final offset and `signer` signs
/// straight into the trailing signature field.
///
/// `encode` is a trait object so the key and transfer reports share one
/// copy of this function.
async fn sign_into<P>(
    pal: &P,
    io: &P::Io,
    kind: ReportKind,
    signer: ReportSigner<'_>,
    payload_len: usize,
    encode: &dyn Fn(&mut [u8]) -> HsmResult<()>,
    out: &mut HsmDmaBuf,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc,
{
    let alg = signer.alg();
    let layout = Sign1Layout::new(kind, alg, payload_len)?;
    if out.len() < layout.total || layout.total > REPORT_MAX_LEN {
        return Err(HsmError::InvalidArg);
    }
    let out = &mut out[..layout.total];
    // `out` may be uninitialised DMA memory; zero it so a short
    // `minicbor::encode` write can't expose stale bytes to the host.
    out.fill(0);
    layout.write_envelope(out)?;
    let payload_end = layout.payload_at + payload_len;
    encode(&mut out[layout.payload_at..payload_end])?;

    let (head, sig) = out.split_at_mut(layout.sig_at);
    let payload = &head[layout.payload_at..payload_end];
    pal.alloc_scoped_async(io, async |alloc| {
        // Encode the COSE Sig_structure over (protected_header, payload).
        // Zeroed so any `len`/`encode` divergence can't feed stale DMA
        // bytes into the signed message.
        let sig_struct_val = SigStructure {
            context: SIG_STRUCTURE_CONTEXT,
            body_protected: layout.protected_header,
            external_aad: kind.external_aad(),
            payload,
        };
        let sig_struct = alloc.dma_alloc_zeroed(minicbor::len(&sig_struct_val))?;
        minicbor::encode(&sig_struct_val, as_mut_slice(sig_struct))
            .map_err(|_| HsmError::InternalError)?;

        match signer {
            ReportSigner::Es384(priv_key) => {
                // The final COSE signature field need not be word-aligned.
                let aligned_sig = alloc.dma_alloc(SIGNATURE_LEN)?;
                pal.hash(
                    io,
                    HsmHashAlgo::Sha384,
                    sig_struct,
                    HsmDigestForm::Operand,
                    Some(&mut aligned_sig[SIGNATURE_LEN / 2..]),
                )
                .await?;
                pal.ecc_sign_in_place(
                    io,
                    HsmEccCurve::P384,
                    HsmHashAlgo::Sha384,
                    priv_key,
                    HsmEcdsaNonce::Generated,
                    aligned_sig,
                )
                .await?;
                sig_halves_swap(P::BYTE_ORDER, aligned_sig)?;
                sig.copy_from_slice(aligned_sig);
                Ok(())
            }
            ReportSigner::MlDsa87Seed(seed) => {
                // ML-DSA-87 signs the Sig_structure itself (pure mode,
                // empty context), with required hedging.
                let msg = HsmMlDsaMsg::new(HsmMlDsaMsgType::Pure, 0, sig_struct)?;
                let len = pal
                    .mldsa_sign(
                        io,
                        HsmMlDsaParamSet::MlDsa87,
                        HsmMlDsaPrivKey::Seed(seed),
                        HsmMlDsaHedge::Required,
                        msg,
                        Some(&mut *sig),
                    )
                    .await?;
                if len != MLDSA87_SIGNATURE_LEN {
                    return Err(HsmError::InternalError);
                }
                Ok(())
            }
        }
    })
    .await?;
    Ok(layout.total)
}
