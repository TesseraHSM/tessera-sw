// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stateless peer export with policy equality and PID-signed operation binding.

use tsra_fw_core_evidence::verify_evidence;
use tsra_fw_core_evidence::EvidenceRefs;
use tsra_fw_core_evidence::KeySink;
use tsra_fw_core_evidence::TrustAnchors;
use tsra_fw_core_evidence::ATTESTED_KEY_MAX_LEN;
use tsra_fw_ddi_tbor_types::tbor_int::U16;
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
    // Only the recipient, policy hash and BKS3 outlive the request; the
    // envelope and report are written straight into their response slots.
    let recipient = pal.dma_alloc(io, ATTESTED_KEY_MAX_LEN)?;
    let hash = pal.dma_alloc(io, 48)?;
    let bks3 = pal.dma_alloc(io, sd_backup::BKS3_LEN)?;
    let recipient_len = pal
        .alloc_scoped_async(io, async |alloc| {
            let req = TborSdCreatePeerBackupReq::decode(cmd.request())?;
            verify_policy_hash(pal, io, req.policy(), hash).await?;
            let policy = super::policy::from_bytes(req.policy())?;
            if !policy.flags.allow_peer_cloning() {
                return Err(HsmError::SdPeerCloningNotAllowed);
            }
            let pota = policy.pota_spki_thumbprint;
            let attested_hash = alloc.dma_alloc(48)?;
            let ev = req.dst_evidence();
            let recipient_len = verify_evidence(
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
                KeySink::Out(recipient),
                Some(attested_hash),
            )
            .await?;
            if hash[..] != attested_hash[..] {
                return Err(HsmError::InvalidArg);
            }
            let local = alloc.dma_alloc(MASKED_SD_LEN)?;
            local.copy_from_slice(req.pok_local_backup());
            let (svn, _) = sd_backup::platform_svn_owner(pal)?;
            let recovered = sd_backup::recover_bks3_from_pok_local(pal, io, svn, local).await?;
            bks3.copy_from_slice(recovered);
            Ok(recipient_len)
        })
        .await?;
    let recipient = &recipient[..recipient_len];
    let (envelope_len, report_len) = sd_transfer::backup_lens(pal, io, recipient)?;
    let report_len_wire = U16::new(u16::try_from(report_len).map_err(|_| HsmError::InternalError)?);
    let len = cmd.encode_response(|buf| {
        Ok(TborSdCreatePeerBackupResp::encode(buf, 0, false)?
            .pok_peer_backup_reserve(envelope_len)?
            .report_len(report_len_wire)?
            .finish()
            .as_bytes()
            .len())
    })?;
    let out = TborSdCreatePeerBackupResp::decode_mut(&mut cmd.buffer_mut()[..len])?;
    pal.alloc_scoped_async(io, async |alloc| {
        let report = sd_transfer::seal_backup(
            pal,
            io,
            alloc,
            hash,
            recipient,
            bks3,
            out.pok_peer_backup,
            report_len,
        )
        .await?;
        pal.send_oob_bounded(io, SD_BACKUP_REPORT_OOB_INDEX, report)
            .await
    })
    .await?;
    Ok(len)
}
