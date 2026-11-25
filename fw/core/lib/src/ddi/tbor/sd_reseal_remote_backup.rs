// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Verify the client's complete signed backup before opening and resealing.

use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_evidence::verify_evidence;
use tsra_fw_core_evidence::EvidenceRefs;
use tsra_fw_core_evidence::IdentityRefs;
use tsra_fw_core_evidence::KeySink;
use tsra_fw_core_evidence::TrustAnchors;
use tsra_fw_core_evidence::ATTESTED_KEY_MAX_LEN;
use tsra_fw_ddi_tbor_types::tbor_int::U16;
use tsra_fw_ddi_tbor_types::*;
use tsra_fw_hsm_pal_traits::*;

use super::masking_key_id_for_scope;
use super::sd_backup;
use super::sd_transfer;
use super::validate_crypto_officer_active_session;
use crate::part_state;

pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let mk_id = {
        let req = TborSdResealRemoteBackupReq::decode(cmd.request())?;
        validate_crypto_officer_active_session(
            pal,
            io,
            HsmSessId::from(u16::from(req.session_id())),
        )?;
        if part_state::part_state(pal, io)? != HsmPartState::Initialized {
            return Err(HsmError::InvalidArg);
        }
        masking_key_id_for_scope(
            pal,
            io,
            peek_metadata(req.masked_sealing_key())?
                .usage_flags()
                .scope(),
        )?
    };
    let recipient = pal.dma_alloc(io, ATTESTED_KEY_MAX_LEN)?;
    let hash = pal.dma_alloc(io, 48)?;
    let bks3 = pal.dma_alloc(io, sd_backup::BKS3_LEN)?;
    let req = TborSdResealRemoteBackupReq::decode(cmd.request())?;
    let policy = super::policy::from_bytes(req.policy())?;
    pal.alloc_scoped_async(io, async |scratch| {
        sd_transfer::hash_policy(pal, io, req.policy(), hash).await?;
        let ev = req.src_evidence();
        let envelope =
            sd_transfer::receive_backup(pal, io, scratch, req.src_remote_backup()).await?;
        let source = sd_transfer::BackupSource {
            masked_key: req.masked_sealing_key(),
            evidence: IdentityRefs {
                mfgr_chain: ev.mfgr_cert_chain(),
                owner_chain: ev.owner_cert_chain(),
                part_owner_chain: ev.part_owner_cert_chain(),
            },
            anchor: Some(policy.pota_spki_thumbprint),
            pid_public: None,
            envelope,
        };
        sd_transfer::unseal_backup(pal, io, scratch, mk_id, &source, hash, bks3).await
    })
    .await?;
    let recipient_len = pal
        .alloc_scoped_async(io, async |alloc| {
            let ev = req.dest_evidence();
            let dst_hash = alloc.dma_alloc(48)?;
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
                    part_owner_anchor: policy.pota_spki_thumbprint,
                    require_sd_sealing: true,
                },
                KeySink::Out(recipient),
                Some(dst_hash),
            )
            .await?;
            if hash[..] != dst_hash[..] {
                return Err(HsmError::InvalidArg);
            }
            Ok(recipient_len)
        })
        .await?;
    let recipient = &recipient[..recipient_len];
    let (_, report_len) = sd_transfer::backup_lens(pal, io, recipient)?;
    pal.alloc_scoped_async(io, async |alloc| {
        let backup = alloc.dma_alloc(report_len)?;
        sd_transfer::seal_backup(pal, io, alloc, hash, recipient, bks3, backup).await?;
        pal.send_oob_bounded(io, SD_BACKUP_REPORT_OOB_INDEX, backup)
            .await
    })
    .await?;
    let report_len = U16::new(u16::try_from(report_len).map_err(|_| HsmError::InternalError)?);
    cmd.encode_response(|buf| {
        Ok(
            TborSdResealRemoteBackupResp::encode_for_request(buf, 0, false)?
                .report_len(report_len)?
                .finish()
                .as_bytes()
                .len(),
        )
    })
}
