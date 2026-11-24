// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Export a local DARC TMK to a DATA-authorized recipient using P-384 HPKE
//! Base, then directly PID-sign the complete encrypted envelope.
//! No sender KEX key, caller-supplied report claims, or persistent writes.

use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_report::report;
use tsra_fw_core_crypto_key_report::transfer::seal_transfer;
use tsra_fw_core_crypto_key_report::transfer::transfer_spki_thumbprint;
use tsra_fw_core_crypto_key_report::transfer::TransferHeader;
use tsra_fw_core_crypto_key_report::transfer::DARC_ENVELOPE_LEN;
use tsra_fw_core_crypto_key_report::transfer::DARC_SIGNED_ENVELOPE_LEN;
use tsra_fw_core_crypto_key_report::ReportParams;
use tsra_fw_core_crypto_x509_chain::validate_chain;
use tsra_fw_ddi_tbor_types::evidence::MAX_CERTS;
use tsra_fw_ddi_tbor_types::TborDarcTmkExportReq;
use tsra_fw_ddi_tbor_types::TborDarcTmkExportResp;
use tsra_fw_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_fw_ddi_tbor_types::SEALED_TMK_LEN;
use tsra_fw_ddi_tbor_types::TMK_LEN;
use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmPartState;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::masking_key_id_for_scope;
use super::part_final::verify_policy_hash;
use super::validate_crypto_officer_active_session;
use crate::part_state;

const _: () = assert!(SEALED_TMK_LEN == DARC_SIGNED_ENVELOPE_LEN);

async fn recover_target_pub<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    req_buf: &HsmDmaBuf,
    public: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let req = TborDarcTmkExportReq::decode(req_buf)?;
    verify_policy_hash(pal, io, alloc, req.policy()).await?;
    let policy = super::policy::from_bytes(req.policy())?;
    let data = policy.data_spki_thumbprint.ok_or(HsmError::InvalidArg)?;
    let chain = req.target_cert_chain();
    if chain.is_empty() || chain.len() > MAX_CERTS {
        return Err(HsmError::InvalidArg);
    }
    validate_chain(
        pal,
        io,
        alloc,
        chain,
        Some(data),
        &mut public[1..],
        async |index, buf| pal.recv_oob(io, index, buf).await,
    )
    .await?;
    public[0] = 4;
    Ok(())
}

/// CO-only, SD-initialized, stateless export. IO teardown scrubs the TMK.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let tmk_mk_id = {
        let req = TborDarcTmkExportReq::decode(cmd_buf.request())?;
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
    let sealed = pal.dma_alloc(io, SEALED_TMK_LEN)?;
    pal.alloc_scoped_async(io, async |alloc| {
        let recipient = alloc.dma_alloc(97)?;
        recover_target_pub(pal, io, alloc, cmd_buf.request(), recipient).await?;

        let blob = alloc.dma_alloc(MASKED_TMK_LEN)?;
        blob.copy_from_slice(TborDarcTmkExportReq::decode(cmd_buf.request())?.masked_tmk());
        let view = unmask(pal, io, pal.vault_key(io, tmk_mk_id)?, blob).await?;
        if view.key_kind != HsmVaultKeyKind::DarcTmk {
            return Err(HsmError::UnsupportedKeyType);
        }
        if view.target_key.len() != TMK_LEN {
            return Err(HsmError::InvalidArg);
        }

        let pid_private = pal.vault_key(io, part_state::part_id_key_id(pal, io)?)?;
        let pid_public = alloc.dma_alloc(97)?;
        pid_public[0] = 4;
        pal.ecc_pub_from_priv(
            io,
            HsmEccCurve::P384,
            pid_private,
            Some(&mut pid_public[1..]),
        )
        .await?;
        byte_order::pair_to_be::<P>(HsmEccCurve::P384, &mut pid_public[1..])?;
        let ids = alloc.dma_alloc(96)?;
        let (source_id, recipient_id) = ids.split_at_mut(48);
        transfer_spki_thumbprint(pal, io, pid_public, source_id, alloc).await?;
        transfer_spki_thumbprint(pal, io, recipient, recipient_id, alloc).await?;
        let source_bytes: &[u8] = source_id;
        let recipient_bytes: &[u8] = recipient_id;
        let header = TransferHeader::Darc {
            source_pid_spki_thumbprint: source_bytes
                .try_into()
                .map_err(|_| HsmError::InternalError)?,
            recipient_spki_thumbprint: recipient_bytes
                .try_into()
                .map_err(|_| HsmError::InternalError)?,
        };
        let envelope = alloc.dma_alloc(DARC_ENVELOPE_LEN)?;
        seal_transfer(
            pal,
            io,
            &header,
            recipient,
            view.target_key,
            envelope,
            alloc,
        )
        .await?;
        let len = report(
            pal,
            io,
            alloc,
            &ReportParams::Transfer(envelope),
            pid_private,
            Some(sealed),
        )
        .await?;
        if len != SEALED_TMK_LEN {
            return Err(HsmError::InternalError);
        }
        Ok(())
    })
    .await?;

    cmd_buf.encode_response(|buf| {
        let frame = TborDarcTmkExportResp::encode_for_request(buf, 0, false)?
            .sealed_tmk(sealed)?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
