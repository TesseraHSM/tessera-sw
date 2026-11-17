// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! P-384 SD transfer sealing, PID reports, and verification before opening.

use tsra_fw_core_crypto_key_report::report;
use tsra_fw_core_crypto_key_report::transfer::*;
use tsra_fw_core_crypto_key_report::ReportKind;
use tsra_fw_core_crypto_key_report::KEY_REPORT_MAX_LEN;
use tsra_fw_core_crypto_x509_chain::p384_point_from_spki;
use tsra_fw_core_crypto_x509_chain::SPKI_THUMBPRINT_LEN;
use tsra_fw_core_evidence::verify_evidence_signer;
use tsra_fw_core_evidence::EvidenceRefs;
use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::*;

use crate::part_state;

pub(super) async fn policy_hash<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    policy: &HsmDmaBuf,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let hash = alloc.dma_alloc(48)?;
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        policy,
        hash,
        HsmDigestForm::Standard,
    )
    .await?;
    Ok(hash)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn seal_backup<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    policy_hash: &HsmDmaBuf,
    recipient: &HsmDmaBuf,
    bks3: &HsmDmaBuf,
    envelope: &mut HsmDmaBuf,
    signed_report: &mut HsmDmaBuf,
) -> HsmResult<usize> {
    let private = pal.vault_key(io, part_state::part_id_key_id(pal, io)?)?;
    let public = alloc.dma_alloc(97)?;
    public[0] = 4;
    pal.ecc_pub_from_priv(io, HsmEccCurve::P384, private, &mut public[1..])
        .await?;
    byte_order::pair_to_be(P::BYTE_ORDER, HsmEccCurve::P384, &mut public[1..])?;
    let ids = alloc.dma_alloc(96)?;
    let (source, destination) = ids.split_at_mut(48);
    sd_spki_thumbprint(pal, io, public, source, alloc).await?;
    sd_spki_thumbprint(pal, io, recipient, destination, alloc).await?;
    let source: &[u8] = source;
    let destination: &[u8] = destination;
    let hash: &[u8] = policy_hash;
    let header = TransferHeader::SdBackup {
        source_pid_spki_thumbprint: source.try_into().map_err(|_| HsmError::InternalError)?,
        recipient_spki_thumbprint: destination
            .try_into()
            .map_err(|_| HsmError::InternalError)?,
        policy_hash: hash.try_into().map_err(|_| HsmError::InternalError)?,
    };
    seal_transfer(pal, io, &header, recipient, bks3, envelope, alloc).await?;
    let digest = alloc.dma_alloc(48)?;
    transfer_envelope_hash(pal, io, envelope, digest, alloc).await?;
    let params = transfer_report_params(envelope, digest)?;
    report(pal, io, alloc, &params, private, Some(signed_report)).await
}

/// An absent anchor is intentional signature-only SA operation verification.
#[allow(clippy::too_many_arguments)]
pub(super) async fn source<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    evidence: &EvidenceRefs<'_>,
    anchor: Option<&[u8; SPKI_THUMBPRINT_LEN]>,
    pid_public: Option<&[u8]>,
) -> HsmResult<(&'a HsmDmaBuf, &'a HsmDmaBuf)> {
    let signer = alloc.dma_alloc(97)?;
    if let Some(anchor) = anchor {
        verify_evidence_signer(pal, io, evidence, anchor, signer).await?;
        if let Some(public) = pid_public {
            let actual: &[u8] = &signer[1..];
            if p384_point_from_spki(public)? != actual {
                return Err(HsmError::InvalidArg);
            }
        }
    } else {
        let public = pid_public.ok_or(HsmError::InvalidArg)?;
        signer[0] = 4;
        signer[1..].copy_from_slice(p384_point_from_spki(public)?);
    }
    let len = evidence.report.length.get() as usize;
    if len == 0 || len > KEY_REPORT_MAX_LEN {
        return Err(HsmError::InvalidArg);
    }
    let report = alloc.dma_alloc(len)?;
    pal.recv_oob(io, evidence.report.index as usize, report)
        .await?;
    Ok((signer, report))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn open_backup<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    private: &HsmDmaBuf,
    signer: &HsmDmaBuf,
    report: &HsmDmaBuf,
    envelope: &HsmDmaBuf,
    policy_hash: &HsmDmaBuf,
    bks3: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let recipient = alloc.dma_alloc(97)?;
    recipient[0] = 4;
    pal.ecc_pub_from_priv(io, HsmEccCurve::P384, private, &mut recipient[1..])
        .await?;
    byte_order::pair_to_be(P::BYTE_ORDER, HsmEccCurve::P384, &mut recipient[1..])?;
    let hash: &[u8] = policy_hash;
    let config = TransferOpenConfig {
        verification: TransferVerifyConfig {
            expected_kind: ReportKind::SdBackup,
            signer_public_key: signer,
            recipient_public_key: recipient,
            expected_policy_hash: Some(hash.try_into().map_err(|_| HsmError::InternalError)?),
        },
        recipient_private_key: private,
    };
    let len = open_transfer(pal, io, &config, envelope, report, bks3, alloc).await?;
    if len != 48 {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}
