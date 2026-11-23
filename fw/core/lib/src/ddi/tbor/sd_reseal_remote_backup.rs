// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Verify the client's signed SD operation before opening and PID-signing a reseal.

use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_evidence::verify_evidence;
use tsra_fw_core_evidence::EvidenceRefs;
use tsra_fw_core_evidence::TrustAnchors;
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
    let envelope = pal.dma_alloc(io, POK_REMOTE_BACKUP_LEN)?;
    let report = pal.dma_alloc(io, SD_BACKUP_REPORT_MAX_LEN)?;
    let report_len = pal
        .alloc_scoped_async(io, async |alloc| {
            let req = TborSdResealRemoteBackupReq::decode(cmd.request())?;
            let policy = super::policy::from_bytes(req.policy())?;
            let pota = policy.pota_spki_thumbprint;
            let hash = sd_transfer::policy_hash(pal, io, alloc, req.policy()).await?;
            let ev = req.src_evidence();
            let (signer, source_report) = sd_transfer::source(
                pal,
                io,
                alloc,
                &EvidenceRefs {
                    mfgr_chain: ev.mfgr_cert_chain(),
                    owner_chain: ev.owner_cert_chain(),
                    part_owner_chain: ev.part_owner_cert_chain(),
                    report: ev.evidence(),
                },
                Some(pota),
                None,
            )
            .await?;
            let ev = req.dest_evidence();
            let recipient = alloc.dma_alloc(97)?;
            let dst_hash = alloc.dma_alloc(48)?;
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
                Some(dst_hash),
            )
            .await?;
            if hash[..] != dst_hash[..] {
                return Err(HsmError::InvalidArg);
            }
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
                source_report,
                req.src_remote_backup(),
                hash,
                bks3,
            )
            .await?;
            sd_transfer::seal_backup(pal, io, alloc, hash, recipient, bks3, envelope, report).await
        })
        .await?;
    cmd.encode_response(|buf| {
        let frame = TborSdResealRemoteBackupResp::encode_for_request(buf, 0, false)?
            .dst_remote_backup(envelope)?
            .report(&report[..report_len])?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
