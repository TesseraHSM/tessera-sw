// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Create an SD and PID-sign its Base-mode remote backup before provisioning.

use tsra_fw_core_crypto_key_report::ReportKind;
use tsra_fw_core_crypto_x509_chain::p384_spki_thumbprint;
use tsra_fw_core_crypto_x509_chain::P384_POINT_LEN;
use tsra_fw_core_crypto_x509_chain::P384_SPKI_LEN;
use tsra_fw_core_crypto_x509_chain::SPKI_THUMBPRINT_LEN;
use tsra_fw_core_evidence::verify_evidence;
use tsra_fw_core_evidence::verify_receiver_cert_chain;
use tsra_fw_core_evidence::verify_receiver_key_report;
use tsra_fw_core_evidence::EvidenceRefs;
use tsra_fw_core_evidence::KeySink;
use tsra_fw_core_evidence::TrustAnchors;
use tsra_fw_core_evidence::ATTESTED_KEY_LEN;
use tsra_fw_core_evidence::ATTESTED_KEY_MAX_LEN;
use tsra_fw_core_evidence::SIGNER_KEY_MAX_LEN;
use tsra_fw_ddi_tbor_types::tbor_int::U16;
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
    // Only the authorized recipient and the policy hash outlive the
    // request; every output is then written straight into its response slot.
    let recipient = pal.dma_alloc(io, ATTESTED_KEY_MAX_LEN)?;
    let hash = pal.dma_alloc(io, 48)?;
    let recipient_len = async {
        let req = TborSdCreateRemoteBackupReq::decode(cmd.request())?;
        verify_policy_hash(pal, io, req.policy(), hash).await?;
        let policy = super::policy::from_bytes(req.policy())?;
        let backup = policy.backup_part.ok_or(HsmError::InvalidArg)?;
        if part_state::part_id(pal, io)?[..] != backup.id[..] {
            return Err(HsmError::InvalidArg);
        }
        pal.alloc_scoped_async(io, async |alloc| {
            let pid = alloc.dma_alloc(P384_POINT_LEN)?;
            part_state::part_id_pub_key(pal, io, pid).await?;
            let spki = alloc.dma_alloc(P384_SPKI_LEN)?;
            let thumbprint = alloc.dma_alloc(SPKI_THUMBPRINT_LEN)?;
            p384_spki_thumbprint(pal, io, spki, pid, thumbprint).await?;
            if thumbprint[..] != backup.spki_thumbprint[..] {
                return Err(HsmError::InvalidArg);
            }
            Ok(())
        })
        .await?;
        let sata = policy.sata_spki_thumbprint;
        // The SATA leaf (P-384 or ML-DSA-87) and its key report are
        // scoped; only the authorized recipient KEM key survives.
        let recipient_len = pal
            .alloc_scoped_async(io, async |alloc| {
                let leaf = alloc.dma_alloc(SIGNER_KEY_MAX_LEN)?;
                let chain = req.receiver_cert_chain();
                let len = verify_receiver_cert_chain(pal, io, chain, sata, leaf).await?;
                let leaf = &leaf[..len];
                match req.receiver_key_report() {
                    // Without a key report the leaf itself is the P-384
                    // recipient.
                    [] if len == ATTESTED_KEY_LEN => {
                        recipient[..len].copy_from_slice(leaf);
                        Ok(len)
                    }
                    [report] => {
                        verify_receiver_key_report(pal, io, leaf, report, false, recipient).await
                    }
                    _ => Err(HsmError::InvalidArg),
                }
            })
            .await?;
        if policy.flags.require_trusted_sa_key() {
            let sapota = policy.sapota_spki_thumbprint.ok_or(HsmError::InvalidArg)?;
            let ev = req.receiver_evidence();
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
                KeySink::Expect(&recipient[..recipient_len]),
                None,
            )
            .await?;
        }
        Ok::<_, HsmError>(recipient_len)
    }
    .await?;
    let recipient = &recipient[..recipient_len];
    let (remote_len, report_len) =
        sd_transfer::transfer_lens(pal, io, ReportKind::SdBackup, recipient)?;
    let report_len_wire = U16::new(u16::try_from(report_len).map_err(|_| HsmError::InternalError)?);
    let len = cmd.encode_response(|buf| {
        Ok(TborSdCreateRemoteBackupResp::encode(buf, 0, false)?
            .pok_remote_backup_reserve(remote_len)?
            .pok_local_backup_reserve(MASKED_SD_LEN)?
            .sd_mk_backup_reserve(SD_MK_BACKUP_LEN)?
            .report_len(report_len_wire)?
            .finish()
            .as_bytes()
            .len())
    })?;
    let out = TborSdCreateRemoteBackupResp::decode_mut(&mut cmd.buffer_mut()[..len])?;
    pal.alloc_scoped_async(io, async |alloc| {
        let bks3 = alloc.dma_alloc(sd_backup::BKS3_LEN)?;
        pal.rng_fill_bytes(io, bks3)?;
        let report = sd_transfer::seal_signed(
            pal,
            io,
            alloc,
            Some(hash),
            recipient,
            bks3,
            out.pok_remote_backup,
            report_len,
        )
        .await?;
        let (svn, owner) = sd_backup::platform_svn_owner(pal)?;
        let sdbmk = sd_backup::derive_sdbmk(pal, io, alloc, bks3, svn, owner).await?;
        let sdmk = alloc.dma_alloc(sd_backup::SDMK_LEN)?;
        pal.rng_fill_bytes(io, sdmk)?;
        sd_backup::mask_sd_mk_backup(pal, io, alloc, sdbmk, sdmk, svn, owner, out.sd_mk_backup)
            .await?;
        sd_backup::mask_pok_local_backup(pal, io, alloc, bks3, svn, owner, out.pok_local_backup)
            .await?;
        pal.send_oob_bounded(io, SD_BACKUP_REPORT_OOB_INDEX, report)
            .await?;
        sd_backup::commit_sd_to_vault(pal, io, undo, sdmk).await
    })
    .await?;
    Ok(len)
}
