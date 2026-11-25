// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Export a local DARC TMK to a DATA-authorized recipient using HPKE Base
//! (P-384, ML-KEM-1024 or MLKEM1024-P384), then PID-sign an operation report
//! over the exact encrypted envelope.
//!
//! The recipient is authenticated like an SD remote-backup receiver: the
//! target PID chain (P-384 or ML-DSA-87 leaf) must be anchored to the policy
//! DATA, and the target key report must be signed by that PID and attest a
//! device-generated DARC key-exchange key. No sender KEX key, caller-supplied
//! report claims, or persistent writes.

use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_report::ReportKind;
use tsra_fw_core_evidence::verify_receiver_cert_chain;
use tsra_fw_core_evidence::verify_receiver_key_report;
use tsra_fw_core_evidence::ATTESTED_KEY_MAX_LEN;
use tsra_fw_core_evidence::SIGNER_KEY_MAX_LEN;
use tsra_fw_ddi_tbor_types::tbor_int::U16;
use tsra_fw_ddi_tbor_types::TborDarcTmkExportReq;
use tsra_fw_ddi_tbor_types::TborDarcTmkExportResp;
use tsra_fw_ddi_tbor_types::DARC_REPORT_OOB_INDEX;
use tsra_fw_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_fw_ddi_tbor_types::TMK_LEN;
use tsra_fw_hsm_pal_traits::*;

use super::masking_key_id_for_scope;
use super::part_final::verify_policy_hash;
use super::sd_transfer;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// CO-only, SD-initialized, stateless export. IO teardown scrubs the TMK.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let tmk_mk_id = {
        let req = TborDarcTmkExportReq::decode(cmd.request())?;
        validate_crypto_officer_active_session(
            pal,
            io,
            HsmSessId::from(u16::from(req.session_id())),
        )?;
        if part_state::part_state(pal, io)? != HsmPartState::Initialized
            || !part_state::part_is_sd_initialized(pal, io)?
        {
            return Err(HsmError::InvalidArg);
        }
        masking_key_id_for_scope(
            pal,
            io,
            peek_metadata(req.masked_tmk())?.usage_flags().scope(),
        )?
    };
    // Only the authorized recipient and the TMK outlive the request; the
    // envelope is then sealed straight into its response slot.
    let recipient = pal.dma_alloc(io, ATTESTED_KEY_MAX_LEN)?;
    let blob = pal.dma_alloc(io, MASKED_TMK_LEN)?;
    let recipient_len = pal
        .alloc_scoped_async(io, async |alloc| {
            let req = TborDarcTmkExportReq::decode(cmd.request())?;
            verify_policy_hash(pal, io, req.policy(), alloc.dma_alloc(48)?).await?;
            let policy = super::policy::from_bytes(req.policy())?;
            let data = policy.data_spki_thumbprint.ok_or(HsmError::InvalidArg)?;
            let leaf = alloc.dma_alloc(SIGNER_KEY_MAX_LEN)?;
            let len =
                verify_receiver_cert_chain(pal, io, req.target_cert_chain(), data, leaf).await?;
            let report = req.target_key_report();
            let len =
                verify_receiver_key_report(pal, io, &leaf[..len], report, true, recipient).await?;
            blob.copy_from_slice(req.masked_tmk());
            Ok::<_, HsmError>(len)
        })
        .await?;
    let recipient = &recipient[..recipient_len];
    let view = unmask(pal, io, pal.vault_key(io, tmk_mk_id)?, blob).await?;
    if view.key_kind != HsmVaultKeyKind::DarcTmk {
        return Err(HsmError::UnsupportedKeyType);
    }
    if view.target_key.len() != TMK_LEN {
        return Err(HsmError::InvalidArg);
    }
    let (_, report_len) = sd_transfer::transfer_lens(pal, io, ReportKind::Darc, recipient)?;
    let report_len_wire = U16::new(u16::try_from(report_len).map_err(|_| HsmError::InternalError)?);
    let artifact = pal.dma_alloc(io, report_len)?;
    pal.alloc_scoped_async(io, async |alloc| {
        sd_transfer::seal_signed(pal, io, alloc, None, recipient, view.target_key, artifact)
            .await?;
        pal.send_oob_bounded(io, DARC_REPORT_OOB_INDEX, artifact)
            .await
    })
    .await?;
    cmd.encode_response(|buf| {
        Ok(TborDarcTmkExportResp::encode_for_request(buf, 0, false)?
            .report_len(report_len_wire)?
            .finish()
            .as_bytes()
            .len())
    })
}
