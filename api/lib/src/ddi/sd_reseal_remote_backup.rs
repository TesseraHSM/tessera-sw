// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdResealRemoteBackup` (opcode `0x0B`) over the TBOR transport at the
//! DDI layer.
//!
//! Reseals an existing remote backup from a source recipient to a
//! destination recipient. Runs **inside an already-open session**; the
//! request carries the active session id, which the firmware dispatcher
//! cross-checks against the SQE-carried session id. Attestation evidence
//! travels out of band (see [`super::sd_evidence`]).

use tsra_ddi::TborOobItem;
use tsra_ddi_tbor_types::*;

use super::*;

/// Issue `SdResealRemoteBackup` (opcode `0x0B`) on the active session.
///
/// HPKE-opens `src_remote_backup` with the receiver's `masked_sealing_key`
/// (authenticated by the source sender key in `src_evidence`) and reseals
/// the recovered backup to the destination receiver (`dest_evidence`),
/// returning the resealed remote backup.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `masked_sealing_key` - The receiver's masked SD-sealing key (from
///   `SdSealingKeyGen`) that unseals the source backup:
///   a P-384, ML-KEM-1024 or MLKEM1024-P384 masked sealing key.
/// * `src_evidence` - Source (sender) attestation evidence, transmitted
///   out of band.
/// * `dest_evidence` - Destination (receiver) attestation evidence.
/// * `policy` - Partition policy CBOR document (`1..=`[`PART_POLICY_MAX_LEN`] bytes).
/// * `src_remote_backup` - The source remote backup to reseal:
///   an SD envelope (322, 1793 or 1890 bytes, by recipient KEM).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_sealing_key` or `src_remote_backup`, or a malformed `policy`,
/// and surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_reseal_remote_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    masked_sealing_key: &[u8],
    src_evidence: &HsmSdEvidence<'_>,
    dest_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    src_remote_backup: &[u8],
    ddi_cookie: &parking_lot::Mutex<Option<u64>>,
) -> HsmResult<HsmSdTransferResult> {
    let masked_sealing_key = masked_sealing_key_wire(masked_sealing_key)?;
    let src_remote_backup = remote_backup_wire(src_remote_backup)?;
    let policy = policy_wire(policy)?;

    // Both parties' evidence share one OOB list; push the source first,
    // then the destination, so descriptor indices stay contiguous.
    let mut report = vec![0u8; SD_BACKUP_REPORT_MAX_LEN];
    let mut oob: Vec<TborOobItem<'_>> = Vec::new();
    push_report_out(&mut report, &mut oob)?;
    let src = super::sd_evidence::push_transfer_evidence(src_evidence, &mut oob)?;
    let dest = push_evidence(dest_evidence, &mut oob)?;

    let req = TborSdResealRemoteBackupReq {
        session_id,
        masked_sealing_key,
        policy,
        src_mfgr_cert_chain: src.mfgr,
        src_owner_cert_chain: src.owner,
        src_part_owner_cert_chain: src.part_owner,
        src_report: src.report,
        dest_mfgr_cert_chain: dest.mfgr,
        dest_owner_cert_chain: dest.owner,
        dest_part_owner_cert_chain: dest.part_owner,
        dest_report: dest.report,
        src_remote_backup,
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    // See `part_init_ex` (`ddi/partition_ex.rs`): thread the session's
    // cookie explicitly since this call also runs outside
    // `with_session_cookie`'s scope.
    let resp = with_explicit_cookie(ddi_cookie, |cookie| {
        dev.exec_op_tbor(&req, &mut oob, cookie)
            .map_err(HsmError::from)
    })?;
    drop(oob);
    Ok(HsmSdTransferResult {
        backup: resp.dst_remote_backup,
        report: take_report(report, resp.report_len)?,
    })
}
