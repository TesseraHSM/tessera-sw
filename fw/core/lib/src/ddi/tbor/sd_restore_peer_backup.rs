// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Peer restore verifies POTA identity, signed policy and recipient before opening.

use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_evidence::EvidenceRefs;
use tsra_fw_ddi_tbor_types::*;
use tsra_fw_hsm_pal_traits::*;
use tsra_fw_hsm_undo::UndoLog;

use super::masking_key_id_for_scope;
use super::part_final::verify_policy_hash;
use super::sd_backup;
use super::sd_transfer;
use super::validate_crypto_officer_active_session;
use crate::part_state;

pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    cmd: &mut HsmCmdBuf<'_>,
    undo: &mut UndoLog<'p>,
) -> HsmResult<usize> {
    let mk_id = {
        let req = TborSdRestorePeerBackupReq::decode(cmd.request())?;
        validate_crypto_officer_active_session(
            pal,
            io,
            HsmSessId::from(u16::from(req.session_id())),
        )?;
        if part_state::part_state(pal, io)? != HsmPartState::Initialized {
            return Err(HsmError::InvalidArg);
        }
        if part_state::part_is_sd_initialized(pal, io)? {
            return Err(HsmError::SdAlreadyInitialized);
        }
        masking_key_id_for_scope(
            pal,
            io,
            peek_metadata(req.masked_sealing_key())?
                .usage_flags()
                .scope(),
        )?
    };
    // Only BKS3 and the previous SDMK backup outlive the request; the
    // refreshed backups are then written straight into their response slots.
    let bks3 = pal.dma_alloc(io, sd_backup::BKS3_LEN)?;
    let previous = pal.dma_alloc(io, SD_MK_BACKUP_LEN)?;
    // Unmasking, sender verification and decapsulation scratch is released
    // before re-provisioning.
    pal.alloc_scoped_async(io, async |scratch| {
        let req = TborSdRestorePeerBackupReq::decode(cmd.request())?;
        let hash = scratch.dma_alloc(48)?;
        verify_policy_hash(pal, io, req.policy(), hash).await?;
        let policy = super::policy::from_bytes(req.policy())?;
        if !policy.flags.allow_peer_cloning() {
            return Err(HsmError::SdPeerCloningNotAllowed);
        }
        let ev = req.src_evidence();
        let source = sd_transfer::BackupSource {
            masked_key: req.masked_sealing_key(),
            evidence: EvidenceRefs {
                mfgr_chain: ev.mfgr_cert_chain(),
                owner_chain: ev.owner_cert_chain(),
                part_owner_chain: ev.part_owner_cert_chain(),
                report: ev.evidence(),
            },
            anchor: Some(policy.pota_spki_thumbprint),
            pid_public: None,
            envelope: req.pok_peer_backup(),
        };
        sd_transfer::unseal_backup(pal, io, scratch, mk_id, &source, hash, bks3).await?;
        previous.copy_from_slice(req.prev_sd_mk_backup());
        Ok::<(), HsmError>(())
    })
    .await?;
    let len = cmd.encode_response(|buf| {
        Ok(TborSdRestorePeerBackupResp::encode(buf, 0, false)?
            .pok_local_backup_reserve(MASKED_SD_LEN)?
            .sd_mk_backup_reserve(SD_MK_BACKUP_LEN)?
            .finish()
            .as_bytes()
            .len())
    })?;
    let out = TborSdRestorePeerBackupResp::decode_mut(&mut cmd.buffer_mut()[..len])?;
    let (svn, owner) = sd_backup::platform_svn_owner(pal)?;
    pal.alloc_scoped_async(io, async |alloc| {
        sd_backup::reprovision_sd_from_bks3(
            pal,
            io,
            alloc,
            undo,
            svn,
            owner,
            bks3,
            previous,
            out.pok_local_backup,
            out.sd_mk_backup,
        )
        .await
    })
    .await?;
    Ok(len)
}
