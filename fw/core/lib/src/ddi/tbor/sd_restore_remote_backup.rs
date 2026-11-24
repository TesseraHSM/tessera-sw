// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Remote restore: SATA does not authorize senders; SAPOTA identity is optional.

use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_evidence::IdentityRefs;
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
        let req = TborSdRestoreRemoteBackupReq::decode(cmd.request())?;
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
    let local = pal.dma_alloc(io, MASKED_SD_LEN)?;
    let mk_backup = pal.dma_alloc(io, SD_MK_BACKUP_LEN)?;
    pal.alloc_scoped_async(io, async |alloc| {
        let req = TborSdRestoreRemoteBackupReq::decode(cmd.request())?;
        verify_policy_hash(pal, io, alloc, req.policy()).await?;
        let policy = super::policy::from_bytes(req.policy())?;
        let anchor = if policy.flags.require_trusted_sa_key() {
            let sapota = policy.sapota_spki_thumbprint.ok_or(HsmError::InvalidArg)?;
            Some(sapota)
        } else {
            None
        };
        let hash = sd_transfer::policy_hash(pal, io, alloc, req.policy()).await?;
        let ev = req.sender_evidence();
        let signer = sd_transfer::source(
            pal,
            io,
            alloc,
            &IdentityRefs {
                mfgr_chain: ev.mfgr_cert_chain(),
                owner_chain: ev.owner_cert_chain(),
                part_owner_chain: ev.part_owner_cert_chain(),
            },
            anchor,
            Some(req.sender_pid_pub_key()),
        )
        .await?;
        let blob = alloc.dma_alloc(MASKED_SEALING_KEY_LEN)?;
        blob.copy_from_slice(req.masked_sealing_key());
        let key = unmask(pal, io, pal.vault_key(io, mk_id)?, blob).await?;
        if key.key_kind != HsmVaultKeyKind::SdSealing {
            return Err(HsmError::UnsupportedKeyType);
        }
        let bks3 = alloc.dma_alloc(sd_backup::BKS3_LEN)?;
        sd_transfer::open_backup(
            pal,
            io,
            alloc,
            key.target_key,
            signer,
            req.src_remote_backup(),
            hash,
            bks3,
        )
        .await?;
        let previous = alloc.dma_alloc(SD_MK_BACKUP_LEN)?;
        previous.copy_from_slice(req.prev_sd_mk_backup());
        let (svn, owner) = sd_backup::platform_svn_owner(pal)?;
        sd_backup::reprovision_sd_from_bks3(
            pal, io, alloc, undo, svn, owner, bks3, previous, local, mk_backup,
        )
        .await
    })
    .await?;
    cmd.encode_response(|buf| {
        let frame = TborSdRestoreRemoteBackupResp::encode_for_request(buf, 0, false)?
            .pok_local_backup(local)?
            .sd_mk_backup(mk_backup)?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
