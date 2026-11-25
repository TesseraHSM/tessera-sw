// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Import a DARC TMK only after authenticating its operation report and
//! envelope against a POTA-endorsed source PID (P-384 or ML-DSA-87) and the
//! actual recipient key (P-384, ML-KEM-1024 or MLKEM1024-P384).
//! HPKE uses Base mode; TMK masking, state gates, and AES-KWP are unchanged.

use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_report::transfer::open_verified_transfer;
use tsra_fw_core_crypto_key_report::transfer::verify_transfer;
use tsra_fw_core_crypto_key_report::transfer::TransferVerifyConfig;
use tsra_fw_core_crypto_key_report::ReportKind;
use tsra_fw_core_evidence::verify_receiver_cert_chain;
use tsra_fw_core_evidence::SIGNER_KEY_MAX_LEN;
use tsra_fw_ddi_tbor_types::TborDarcTmkImportReq;
use tsra_fw_ddi_tbor_types::TborDarcTmkImportResp;
use tsra_fw_ddi_tbor_types::DARC_REPORT_MAX_LEN;
use tsra_fw_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_fw_ddi_tbor_types::TMK_LEN;
use tsra_fw_hsm_pal_traits::*;

use super::masking_key_id_for_scope;
use super::part_final::verify_policy_hash;
use super::sd_backup;
use super::sd_transfer;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// CO-only, SD-initialized, stateless import. No output before authentication.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let (kex_mk_id, sdmk_id) = {
        let req = TborDarcTmkImportReq::decode(cmd.request())?;
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
        (
            masking_key_id_for_scope(
                pal,
                io,
                peek_metadata(req.masked_kex_key())?.usage_flags().scope(),
            )?,
            masking_key_id_for_scope(pal, io, HsmKeyScope::SecurityDomain)?,
        )
    };
    let masked_tmk = pal.dma_alloc(io, MASKED_TMK_LEN)?;
    pal.alloc_scoped_async(io, async |alloc| {
        let req = TborDarcTmkImportReq::decode(cmd.request())?;
        let blob = alloc.dma_alloc(req.masked_kex_key().len())?;
        blob.copy_from_slice(req.masked_kex_key());
        let key = unmask(pal, io, pal.vault_key(io, kex_mk_id)?, blob).await?;
        let kem = sd_transfer::darc_kex_kem(key.key_kind)?;
        let recipient = sd_transfer::sealing_public(pal, io, alloc, kem, key.target_key).await?;
        let artifact =
            sd_transfer::recv_report(pal, io, alloc, req.sealed_tmk(), DARC_REPORT_MAX_LEN).await?;
        // The source PID chain and report are staged in a nested scope
        // released before the (ML-KEM) decapsulation scratch.
        let verified = pal
            .alloc_scoped_async(io, async |scratch| {
                verify_policy_hash(pal, io, req.policy(), scratch.dma_alloc(48)?).await?;
                let policy = super::policy::from_bytes(req.policy())?;
                let pota = policy.pota_spki_thumbprint;
                let signer = scratch.dma_alloc(SIGNER_KEY_MAX_LEN)?;
                let len =
                    verify_receiver_cert_chain(pal, io, req.remote_cert_chain(), pota, signer)
                        .await?;
                let config = TransferVerifyConfig {
                    expected_kind: ReportKind::Darc,
                    signer_public_key: &signer[..len],
                    recipient_public_key: recipient,
                    expected_policy_hash: None,
                };
                verify_transfer(pal, io, &config, artifact, scratch).await
            })
            .await?;
        let tmk = alloc.dma_alloc(TMK_LEN)?;
        let len = open_verified_transfer(pal, io, &verified, key.target_key, recipient, tmk, alloc)
            .await?;
        if len != TMK_LEN {
            return Err(HsmError::InvalidArg);
        }
        let (svn, owner) = sd_backup::platform_svn_owner(pal)?;
        super::darc_tmk::mask_tmk(
            pal,
            io,
            alloc,
            pal.vault_key(io, sdmk_id)?,
            svn,
            owner,
            tmk,
            masked_tmk,
        )
        .await
    })
    .await?;

    cmd.encode_response(|buf| {
        let frame = TborDarcTmkImportResp::encode_for_request(buf, 0, false)?
            .masked_tmk(masked_tmk)?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
