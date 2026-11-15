// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Import a DARC TMK only after authenticating its operation report and
//! envelope against a POTA-endorsed source PID and the actual recipient key.
//! HPKE uses Base mode; TMK masking, state gates, and AES-KWP are unchanged.

use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_report::transfer::open_transfer;
use tsra_fw_core_crypto_key_report::transfer::TransferOpenConfig;
use tsra_fw_core_crypto_key_report::transfer::TransferVerifyConfig;
use tsra_fw_core_crypto_key_report::ReportKind;
use tsra_fw_core_crypto_x509_chain::validate_chain;
use tsra_fw_ddi_tbor_types::TborDarcTmkImportReq;
use tsra_fw_ddi_tbor_types::TborDarcTmkImportResp;
use tsra_fw_ddi_tbor_types::DARC_SOURCE_CERT_CHAIN_MAX_CERTS;
use tsra_fw_ddi_tbor_types::MASKED_KEX_KEY_LEN;
use tsra_fw_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_fw_ddi_tbor_types::TMK_LEN;
use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmPartState;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::masking_key_id_for_scope;
use super::part_final::verify_policy_hash;
use super::sd_backup;
use super::validate_crypto_officer_active_session;
use crate::part_state;

async fn recover_signer_pub<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    req_buf: &HsmDmaBuf,
    public: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let req = TborDarcTmkImportReq::decode(req_buf)?;
    verify_policy_hash(pal, io, req.policy(), alloc.dma_alloc(48)?).await?;
    let policy = super::policy::from_bytes(req.policy())?;
    let pota = policy.pota_spki_thumbprint;
    let chain = req.remote_cert_chain();
    if chain.is_empty() || chain.len() > DARC_SOURCE_CERT_CHAIN_MAX_CERTS {
        return Err(HsmError::InvalidArg);
    }
    let len = validate_chain(
        pal,
        io,
        alloc,
        chain,
        Some(pota),
        &mut public[1..],
        async |index, buf| pal.recv_oob(io, index, buf).await,
    )
    .await?;
    // Only a P-384 leaf fills the `X ‖ Y` slot; shorter EC leaves are rejected.
    if len != public.len() - 1 {
        return Err(HsmError::InvalidArg);
    }
    public[0] = 4;
    Ok(())
}

/// CO-only, SD-initialized, stateless import. No output before authentication.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let (kex_mk_id, sdmk_id) = {
        let req = TborDarcTmkImportReq::decode(cmd_buf.request())?;
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
        let signer = alloc.dma_alloc(97)?;
        recover_signer_pub(pal, io, alloc, cmd_buf.request(), signer).await?;
        let req = TborDarcTmkImportReq::decode(cmd_buf.request())?;
        let blob = alloc.dma_alloc(MASKED_KEX_KEY_LEN)?;
        blob.copy_from_slice(req.masked_kex_key());
        let view = unmask(pal, io, pal.vault_key(io, kex_mk_id)?, blob).await?;
        if view.key_kind != HsmVaultKeyKind::DarcKex {
            return Err(HsmError::UnsupportedKeyType);
        }
        let recipient = alloc.dma_alloc(97)?;
        recipient[0] = 4;
        pal.ecc_pub_from_priv(io, HsmEccCurve::P384, view.target_key, &mut recipient[1..])
            .await?;
        byte_order::pair_to_be(P::BYTE_ORDER, HsmEccCurve::P384, &mut recipient[1..])?;
        let cfg = TransferOpenConfig {
            verification: TransferVerifyConfig {
                expected_kind: ReportKind::Darc,
                signer_public_key: signer,
                recipient_public_key: recipient,
                expected_policy_hash: None,
            },
            recipient_private_key: view.target_key,
        };
        let tmk = alloc.dma_alloc(TMK_LEN)?;
        open_transfer(pal, io, &cfg, req.sealed_tmk(), req.report(), tmk, alloc).await?;
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

    cmd_buf.encode_response(|buf| {
        let frame = TborDarcTmkImportResp::encode(buf, 0, false)?
            .masked_tmk(masked_tmk)?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
