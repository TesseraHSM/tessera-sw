// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stateless peer export with policy equality and PID-signed operation binding.

use tsra_fw_core_evidence::verify_evidence;
use tsra_fw_core_evidence::EvidenceRefs;
use tsra_fw_core_evidence::TrustAnchors;
use tsra_fw_ddi_tbor_types::*;
use tsra_fw_hsm_pal_traits::*;

use super::part_final::verify_policy_hash;
use super::sd_backup;
use super::sd_transfer;
use super::validate_crypto_officer_active_session;
use crate::part_state;

pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    {
        let req = TborSdCreatePeerBackupReq::decode(cmd.request())?;
        validate_crypto_officer_active_session(
            pal,
            io,
            HsmSessId::from(u16::from(req.session_id())),
        )?;
        if part_state::part_state(pal, io)? != HsmPartState::Initialized {
            return Err(HsmError::InvalidArg);
        }
    }
    let envelope = pal.dma_alloc(io, POK_REMOTE_BACKUP_LEN)?;
    let report = pal.dma_alloc(io, SD_BACKUP_REPORT_MAX_LEN)?;
    let report_len = pal
        .alloc_scoped_async(io, async |alloc| {
            let req = TborSdCreatePeerBackupReq::decode(cmd.request())?;
            verify_policy_hash(pal, io, alloc, req.policy()).await?;
            let policy = super::policy::from_bytes(req.policy())?;
            if !policy.flags.allow_peer_cloning() {
                return Err(HsmError::SdPeerCloningNotAllowed);
            }
            let pota = policy.pota_spki_thumbprint;
            let hash = sd_transfer::policy_hash(pal, io, alloc, req.policy()).await?;
            let recipient = alloc.dma_alloc(97)?;
            let attested_hash = alloc.dma_alloc(48)?;
            let ev = req.dst_evidence();
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
                    part_owner_anchor: pota,
                    require_sd_sealing: true,
                },
                recipient,
                Some(attested_hash),
            )
            .await?;
            if hash[..] != attested_hash[..] {
                return Err(HsmError::InvalidArg);
            }
            let local = alloc.dma_alloc(MASKED_SD_LEN)?;
            local.copy_from_slice(req.pok_local_backup());
            let (svn, _) = sd_backup::platform_svn_owner(pal)?;
            let bks3 = sd_backup::recover_bks3_from_pok_local(pal, io, svn, local).await?;
            sd_transfer::seal_backup(pal, io, alloc, hash, recipient, bks3, envelope, report).await
        })
        .await?;
    cmd.encode_response(|buf| {
        let frame = TborSdCreatePeerBackupResp::encode(buf, 0, false)?
            .pok_peer_backup(envelope)?
            .report(&report[..report_len])?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
