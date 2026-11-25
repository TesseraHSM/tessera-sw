// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdCreatePeerBackup` (opcode `0x0E`) over the TBOR transport at the DDI
//! layer.
//!
//! Creates a peer-transferable backup of a security domain: recovers BKS3
//! from the caller's device-local backup (`pok_local_backup`) and
//! Base-seals it to the destination peer named by `dst_evidence`, returning
//! one PID-signed SdBackup envelope. Peer cloning is gated by the security
//! domain's `allow_peer_cloning` policy flag. Runs **inside an already-open
//! session**; the request carries the active session id, which the firmware
//! dispatcher cross-checks against the SQE-carried session id. Attestation
//! evidence travels out of band (see [`super::sd_evidence`]).

use tsra_ddi_tbor_types::*;

use super::*;

/// Issue `SdCreatePeerBackup` (opcode `0x0E`) on the active session.
///
/// Recovers BKS3 from `pok_local_backup` and Base-seals it to the authorized
/// same-policy peer, returning one directly PID-signed envelope.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `api_rev` - The active session's negotiated API revision.
/// * `session_id` - The active session id this request binds to.
/// * `dst_evidence` - Destination (peer) attestation evidence (cert chains
///   and report), transmitted out of band.
/// * `policy` - Partition policy CBOR document (`1..=`[`PART_POLICY_MAX_LEN`] bytes).
/// * `pok_local_backup` - The device-local partition-owner-key backup from
///   which BKS3 is recovered, exactly [`MASKED_SD_LEN`] bytes.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `pok_local_backup`, or a malformed `policy`, and
/// surfaces DDI/device failures from the round-trip (including
/// `SdPeerCloningNotAllowed` when the policy clears `allow_peer_cloning`).
pub(crate) fn sd_create_peer_backup_ex(
    partition: &HsmPartition,
    api_rev: HsmApiRev,
    session_id: u16,
    dst_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    pok_local_backup: &[u8],
    ddi_cookie: &parking_lot::Mutex<Option<u64>>,
) -> HsmResult<HsmSdTransferResult> {
    let pok_local_backup: [u8; MASKED_SD_LEN] = pok_local_backup
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = policy_wire(policy)?;

    // Flatten the destination evidence into descriptors + shared OOB items.
    let mut report = vec![0u8; SD_BACKUP_REPORT_MAX_LEN];
    let mut oob: Vec<TborOobItem<'_>> = Vec::new();
    push_report_out(&mut report, &mut oob)?;
    let dst = push_evidence(dst_evidence, &mut oob)?;

    let req = TborSdCreatePeerBackupReq {
        session_id,
        policy,
        dst_mfgr_cert_chain: dst.mfgr,
        dst_owner_cert_chain: dst.owner,
        dst_part_owner_cert_chain: dst.part_owner,
        dst_report: dst.report,
        pok_local_backup,
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    // See `part_init_ex` (`ddi/partition_ex.rs`): thread the session's
    // cookie explicitly since this call also runs outside
    // `with_session_cookie`'s scope.
    let resp = with_explicit_cookie(ddi_cookie, |cookie| {
        dev.exec_op_tbor_oob(api_rev, &req, &mut oob, cookie)
            .map_err(HsmError::from)
    })?;
    drop(oob);
    Ok(HsmSdTransferResult {
        backup: take_sd_backup(report, resp.report_len)?,
    })
}
