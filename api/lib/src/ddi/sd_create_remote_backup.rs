// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdCreateRemoteBackup` (opcode `0x0A`) over the TBOR transport at the
//! DDI layer.
//!
//! Creates a new security domain from a caller-supplied
//! partition policy, returning the remote partition-owner-key backup together
//! with the device-local partition-owner-key and security-domain
//! masking-key backups. Runs **inside an already-open session**; the
//! request carries the active session id, which the firmware dispatcher
//! cross-checks against the SQE-carried session id. Attestation evidence
//! travels out of band (see [`super::sd_evidence`]).

use tsra_ddi::TborOobItem;
use tsra_ddi_tbor_types::*;

use super::*;

/// Issue `SdCreateRemoteBackup` (opcode `0x0A`) on the active session.
///
/// Creates a new security domain from the caller-supplied unified
/// `policy` and authorized recipient evidence. Returns a Base envelope,
/// PID-signed SdBackup report, and unchanged local backups.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `receiver_cert_chain` - The receiver key certificate chain (spec
///   `RcvrCertChain`), transmitted out of band; validated and anchored to
///   the policy SATA key, its leaf is the recipient public key unless
///   `receiver_key_report` is given.
/// * `receiver_key_report` - Optional leaf-signed key report whose attested
///   KEM key is the recipient, transmitted out of band.
/// * `receiver_evidence` - Receiver attestation evidence (cert chains and
///   report), transmitted out of band.  Verified only when the policy sets
///   `require_trusted_sa_key`; pass empty chains and an empty report
///   otherwise.
/// * `policy` - Partition policy CBOR document (`1..=`[`PART_POLICY_MAX_LEN`] bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a malformed `policy`, and surfaces DDI/device
/// failures from the round-trip.
pub(crate) fn sd_create_remote_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    receiver_cert_chain: &[HsmCert<'_>],
    receiver_key_report: Option<&[u8]>,
    receiver_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    ddi_cookie: &parking_lot::Mutex<Option<u64>>,
) -> HsmResult<HsmSdRemoteBackupResult> {
    let policy = policy_wire(policy)?;

    // Flatten the receiver cert chain and evidence into descriptors +
    // shared OOB items.  The receiver chain is pushed first so its
    // descriptor indices precede the evidence items.
    let mut report = vec![0u8; SD_BACKUP_REPORT_MAX_LEN];
    let mut oob: Vec<TborOobItem<'_>> = Vec::new();
    push_report_out(&mut report, &mut oob)?;
    let receiver_chain = push_cert_chain(receiver_cert_chain, &mut oob, EVIDENCE_CHAIN_MAX_CERTS)?;

    // The attestation evidence is verified by the firmware only when the
    // policy sets `require_trusted_sa_key`; empty evidence ships no DER
    // bytes.
    let receiver = push_evidence_if_present(receiver_evidence, &mut oob)?;
    let receiver_key_report = match receiver_key_report {
        None => Vec::new(),
        Some(report) => vec![push_report(report, &mut oob)?],
    };

    let req = TborSdCreateRemoteBackupReq {
        session_id,
        receiver_cert_chain: receiver_chain,
        receiver_key_report,
        receiver_mfgr_cert_chain: receiver.mfgr,
        receiver_owner_cert_chain: receiver.owner,
        receiver_part_owner_cert_chain: receiver.part_owner,
        receiver_report: receiver.report,
        policy,
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
    Ok(HsmSdRemoteBackupResult {
        pok_remote_backup: resp.pok_remote_backup,
        report: take_report(report, resp.report_len)?,
        pok_local_backup: resp.pok_local_backup.to_vec(),
        sd_mk_backup: resp.sd_mk_backup.to_vec(),
    })
}
