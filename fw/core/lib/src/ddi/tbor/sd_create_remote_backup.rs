// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Create an SD and PID-sign its Base-mode remote backup before provisioning.

use tsra_fw_core_crypto_x509_chain::p384_spki_thumbprint;
use tsra_fw_core_crypto_x509_chain::P384_POINT_LEN;
use tsra_fw_core_crypto_x509_chain::P384_SPKI_LEN;
use tsra_fw_core_crypto_x509_chain::SPKI_THUMBPRINT_LEN;
use tsra_fw_core_evidence::verify_evidence;
use tsra_fw_core_evidence::verify_receiver_cert_chain;
use tsra_fw_core_evidence::EvidenceRefs;
use tsra_fw_core_evidence::TrustAnchors;
use tsra_fw_ddi_tbor_types::*;
use tsra_fw_hsm_pal_traits::*;
use tsra_fw_hsm_undo::UndoLog;

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
    {
        let req = TborSdCreateRemoteBackupReq::decode(cmd.request())?;
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
    }
    let remote = pal.dma_alloc(io, POK_REMOTE_BACKUP_LEN)?;
    let local = pal.dma_alloc(io, MASKED_SD_LEN)?;
    let mk_backup = pal.dma_alloc(io, SD_MK_BACKUP_LEN)?;
    pal.alloc_scoped_async(io, async |alloc| {
        let req = TborSdCreateRemoteBackupReq::decode(cmd.request())?;
        verify_policy_hash(pal, io, alloc, req.policy()).await?;
        let policy = super::policy::from_bytes(req.policy())?;
        let backup = policy.backup_part.ok_or(HsmError::InvalidArg)?;
        if part_state::part_id(pal, io)?[..] != backup.id[..] {
            return Err(HsmError::InvalidArg);
        }
        let pid = alloc.dma_alloc(P384_POINT_LEN)?;
        part_state::part_id_pub_key(pal, io, pid).await?;
        let spki = alloc.dma_alloc(P384_SPKI_LEN)?;
        let thumbprint = alloc.dma_alloc(SPKI_THUMBPRINT_LEN)?;
        p384_spki_thumbprint(pal, io, spki, pid, thumbprint).await?;
        if thumbprint[..] != backup.spki_thumbprint[..] {
            return Err(HsmError::InvalidArg);
        }
        let sata = policy.sata_spki_thumbprint;
        let recipient = alloc.dma_alloc(97)?;
        verify_receiver_cert_chain(pal, io, req.receiver_cert_chain(), sata, recipient).await?;
        if policy.flags.require_trusted_sa_key() {
            let sapota = policy.sapota_spki_thumbprint.ok_or(HsmError::InvalidArg)?;
            let ev = req.receiver_evidence();
            let attested = alloc.dma_alloc(97)?;
            verify_evidence(
                pal,
                io,
                &EvidenceRefs {
                    mfgr_chain: ev.mfgr_cert_chain(),
                    owner_chain: ev.owner_cert_chain(),
                    part_owner_chain: ev.part_owner_cert_chain(),
                    report: ev.evidence(),
                },
                &TrustAnchors {
                    part_owner_anchor: sapota,
                    require_sd_sealing: false,
                },
                attested,
                None,
            )
            .await?;
            if attested[..] != recipient[..] {
                return Err(HsmError::InvalidArg);
            }
        }
        let hash = sd_transfer::policy_hash(pal, io, alloc, req.policy()).await?;
        let bks3 = alloc.dma_alloc(sd_backup::BKS3_LEN)?;
        pal.rng_fill_bytes(io, bks3)?;
        sd_transfer::seal_backup(pal, io, alloc, hash, recipient, bks3, remote).await?;
        let (svn, owner) = sd_backup::platform_svn_owner(pal)?;
        let sdbmk = sd_backup::derive_sdbmk(pal, io, alloc, bks3, svn, owner).await?;
        let sdmk = alloc.dma_alloc(sd_backup::SDMK_LEN)?;
        pal.rng_fill_bytes(io, sdmk)?;
        sd_backup::mask_sd_mk_backup(pal, io, alloc, sdbmk, sdmk, svn, owner, mk_backup).await?;
        sd_backup::mask_pok_local_backup(pal, io, alloc, bks3, svn, owner, local).await?;
        sd_backup::commit_sd_to_vault(pal, io, undo, sdmk).await?;
        Ok(())
    })
    .await?;
    cmd.encode_response(|buf| {
        let frame = TborSdCreateRemoteBackupResp::encode_for_request(buf, 0, false)?
            .pok_remote_backup(remote)?
            .pok_local_backup(local)?
            .sd_mk_backup(mk_backup)?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
