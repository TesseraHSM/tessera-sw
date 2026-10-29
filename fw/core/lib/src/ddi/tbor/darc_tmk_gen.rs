// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcTmkGen` handler.
//!
//! Originates a fresh DARC Transfer Masking Key (TMK) — a random 32-byte
//! symmetric secret — and returns it masked under the partition
//! security-domain masking key (SDMK) so the caller can persist and later
//! re-import it.
//!
//! It is the source-side counterpart of
//! [`DarcTmkImport`](super::darc_tmk_import): where import recovers a TMK
//! HPKE-sealed off-device and re-masks it, this command *mints* the TMK
//! locally.  Both mask through the shared [`super::darc_tmk`] helper, so
//! the emitted 164-byte envelope is byte-identical and a created TMK is
//! interchangeable with an imported one downstream.
//!
//! Flow:
//!
//! 1. Decode; gate to a Crypto-Officer, `Active` session on an
//!    `Initialized` partition whose security domain is initialized (the
//!    SDMK the output is masked under is provisioned by SD setup).
//! 2. Draw a fresh 32-byte TMK from the RNG.
//! 3. Mask the TMK (AEAD-GCM-256) under the SDMK and return the masked
//!    envelope. IO teardown scrubs the raw TMK.
//!
//! The command **persists nothing** (no vault write, no lifecycle
//! advance), so it records no rollback on the undo log.  This command is
//! **Crypto-Officer-only**.

use tsra_fw_ddi_tbor_types::TborDarcTmkGenReq;
use tsra_fw_ddi_tbor_types::TborDarcTmkGenResp;
use tsra_fw_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_fw_ddi_tbor_types::TMK_LEN;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::PartState;

use super::masking_key_id_for_scope;
use super::sd_backup;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// Handle a TBOR `DarcTmkGen` request.
///
/// **Stateless**: mints a fresh TMK and returns it masked under the SDMK
/// without writing the vault or advancing any lifecycle, so it records no
/// rollback on the undo log. IO teardown scrubs the raw TMK.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    // Session/state gating + masking-key routing use only the shared
    // `decode` view; the resolved id is `Copy`, so it outlives the view.
    let sdmk_id: HsmKeyId = {
        let req = TborDarcTmkGenReq::decode(cmd_buf.request())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        validate_crypto_officer_active_session(pal, io, sess_id)?;

        // The SDMK the output is masked under is provisioned by SD setup,
        // which requires a finalized partition.
        if part_state::part_state(pal, io)? != PartState::Initialized {
            return Err(HsmError::InvalidArg);
        }
        if !part_state::part_is_sd_initialized(pal, io)? {
            return Err(HsmError::InvalidArg);
        }

        masking_key_id_for_scope(pal, io, HsmKeyScope::SecurityDomain)?
    };

    // Allocate the fixed-size output envelope in the IO scope so it
    // survives the crypto scratch allocator's reset.
    let masked_tmk_out = pal.dma_alloc(io, MASKED_TMK_LEN)?;

    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
        let (svn, owner) = sd_backup::platform_svn_owner(pal)?;

        // Mint the fresh TMK, then mask it under the SDMK.
        let tmk = alloc.dma_alloc(TMK_LEN)?;
        let mask_res = async {
            pal.rng_fill_bytes(io, tmk)?;

            let sdmk = pal.vault_key(io, sdmk_id)?;
            super::darc_tmk::mask_tmk(pal, io, alloc, sdmk, svn, owner, tmk, masked_tmk_out).await
        }
        .await;

        mask_res
    })
    .await?;

    encode_response(cmd_buf, masked_tmk_out)
}

/// Encode the `DarcTmkGen` response around the masked TMK.
fn encode_response(cmd_buf: &mut HsmCmdBuf<'_>, masked_tmk: &HsmDmaBuf) -> HsmResult<usize> {
    let resp = cmd_buf.encode_response(|buf| {
        let frame = TborDarcTmkGenResp::encode(buf, 0, false)?
            .masked_tmk(masked_tmk)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
