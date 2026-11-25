// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! P-384 SD transfer sealing, PID reports, and verification before opening.

use tsra_fw_core_crypto_key_report::report;
use tsra_fw_core_crypto_key_report::transfer::*;
use tsra_fw_core_crypto_key_report::ReportKind;
use tsra_fw_core_crypto_key_report::ReportParams;
use tsra_fw_core_crypto_x509_chain::p384_point_from_spki;
use tsra_fw_core_crypto_x509_chain::SPKI_THUMBPRINT_LEN;
use tsra_fw_core_evidence::verify_evidence_signer;
use tsra_fw_core_evidence::IdentityRefs;
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
        HsmDigestForm::Standard,
        Some(hash),
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
    signed_envelope: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let private = pal.vault_key(io, part_state::part_id_key_id(pal, io)?)?;
    let public = alloc.dma_alloc(97)?;
    pal.ecc_pub_from_priv(io, HsmEccCurve::P384, private, Some(&mut public[..96]))
        .await?;
    byte_order::pair_to_be::<P>(HsmEccCurve::P384, &mut public[..96])?;
    public.copy_within(..96, 1);
    public[0] = 4;
    let ids = alloc.dma_alloc(96)?;
    let (source, destination) = ids.split_at_mut(48);
    transfer_spki_thumbprint(pal, io, public, source, alloc).await?;
    transfer_spki_thumbprint(pal, io, recipient, destination, alloc).await?;
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
    let envelope = alloc.dma_alloc(SD_BACKUP_ENVELOPE_LEN)?;
    seal_transfer(pal, io, &header, recipient, bks3, envelope, alloc).await?;
    let len = report(
        pal,
        io,
        alloc,
        &ReportParams::Transfer(envelope),
        private,
        Some(signed_envelope),
    )
    .await?;
    if len != SD_BACKUP_SIGNED_ENVELOPE_LEN {
        return Err(HsmError::InternalError);
    }
    Ok(())
}

/// An absent anchor is intentional signature-only SA operation verification.
#[allow(clippy::too_many_arguments)]
pub(super) async fn source<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    evidence: &IdentityRefs<'_>,
    anchor: Option<&[u8; SPKI_THUMBPRINT_LEN]>,
    pid_public: Option<&[u8]>,
) -> HsmResult<&'a HsmDmaBuf> {
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
    Ok(signer)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn open_backup<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    private: &HsmDmaBuf,
    signer: &HsmDmaBuf,
    signed_envelope: &HsmDmaBuf,
    policy_hash: &HsmDmaBuf,
    bks3: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let recipient = alloc.dma_alloc(97)?;
    pal.ecc_pub_from_priv(io, HsmEccCurve::P384, private, Some(&mut recipient[..96]))
        .await?;
    byte_order::pair_to_be::<P>(HsmEccCurve::P384, &mut recipient[..96])?;
    recipient.copy_within(..96, 1);
    recipient[0] = 4;
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
    let len = open_transfer(pal, io, &config, signed_envelope, bks3, alloc).await?;
    if len != 48 {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}
