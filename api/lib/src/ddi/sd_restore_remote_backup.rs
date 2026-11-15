// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreRemoteBackup` (opcode `0x0C`) over the TBOR transport at the
//! DDI layer.
//!
//! Restores a security domain from a **remote** backup: verifies the mandatory
//! SdBackup report and target policy before Base-opening with the actual
//! recipient key, recovers `SDMK` from `prev_sd_mk_backup`, and returns the
//! device-local backups so the domain can later be restored locally without
//! the sender. Runs **inside an already-open session**; the request carries
//! the active session id, which the firmware dispatcher cross-checks against
//! the SQE-carried session id. Attestation evidence travels out of band
//! (see [`super::sd_evidence`]).

use tsra_ddi::TborOobItem;
use tsra_ddi_tbor_types::*;

use super::*;

/// Converts the wire `SdRestoreRemoteBackup` response into the owned
/// API-layer [`HsmSdRestoreResult`].
impl From<TborSdRestoreRemoteBackupResp> for HsmSdRestoreResult {
    fn from(resp: TborSdRestoreRemoteBackupResp) -> Self {
        Self {
            pok_local_backup: resp.pok_local_backup,
            sd_mk_backup: resp.sd_mk_backup,
        }
    }
}

/// Issue `SdRestoreRemoteBackup` (opcode `0x0C`) on the active session.
///
/// Verifies the operation report and bindings before Base-opening
/// `src_remote_backup` with the receiver's `masked_sealing_key`,
/// recovers `SDMK` from `prev_sd_mk_backup`, and returns the refreshed
/// device-local backups.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `masked_sealing_key` - The receiver's masked SD-sealing key (from
///   `SdSealingKeyGen`) that unseals the backup:
///   a P-384, ML-KEM-1024 or MLKEM1024-P384 masked sealing key.
/// * `sender_pid_pub_key` - Report signer PID public key: raw 96-byte
///   big-endian P-384 X || Y, or a 2592-byte encoded ML-DSA-87 key.
/// * `sender_evidence` - Required SdBackup report and optional identity chains.
///   Trusted-SA policy requires SAPOTA-authorized PID chains; otherwise
///   verification checks integrity, not authenticated SA identity.
/// * `policy` - Partition policy CBOR document (`1..=`[`PART_POLICY_MAX_LEN`] bytes).
/// * `src_remote_backup` - The remote backup to restore:
///   an SD envelope (322, 1793 or 1890 bytes, by recipient KEM).
/// * `prev_sd_mk_backup` - The previous security-domain masking-key backup,
///   exactly [`SD_MK_BACKUP_LEN`] bytes.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_sealing_key`, `sender_pid_pub_key`, `src_remote_backup`, or `prev_sd_mk_backup`, or a
/// malformed `policy`, and surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_restore_remote_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    masked_sealing_key: &[u8],
    sender_pid_pub_key: &[u8],
    sender_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    src_remote_backup: &[u8],
    prev_sd_mk_backup: &[u8],
    ddi_cookie: &parking_lot::Mutex<Option<u64>>,
) -> HsmResult<HsmSdRestoreResult> {
    let masked_sealing_key = masked_sealing_key_wire(masked_sealing_key)?;
    let src_remote_backup = remote_backup_wire(src_remote_backup)?;
    let prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN] = prev_sd_mk_backup
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = policy_wire(policy)?;
    if ![SENDER_PID_P384_LEN, SENDER_PID_MLDSA87_LEN].contains(&sender_pid_pub_key.len()) {
        return Err(HsmError::InvalidArgument);
    }
    let sender_pid_pub_key = sender_pid_pub_key.to_vec();

    // Flatten the sender cert chain and evidence into descriptors + shared
    // OOB items.  The sender chain is pushed first so its descriptor
    // indices precede the evidence items.
    let mut oob: Vec<TborOobItem<'_>> = Vec::new();

    // The report is mandatory; the device decides whether supplied identity
    // chains must establish trusted-SA authorization.
    let sender = super::sd_evidence::push_transfer_evidence(sender_evidence, &mut oob)?;

    let req = TborSdRestoreRemoteBackupReq {
        session_id,
        masked_sealing_key,
        policy,
        sender_pid_pub_key,
        sender_mfgr_cert_chain: sender.mfgr,
        sender_owner_cert_chain: sender.owner,
        sender_part_owner_cert_chain: sender.part_owner,
        sender_report: sender.report,
        src_remote_backup,
        prev_sd_mk_backup,
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    // See `part_init_ex` (`ddi/partition_ex.rs`): thread the session's
    // cookie explicitly since this call also runs outside
    // `with_session_cookie`'s scope.
    with_explicit_cookie(ddi_cookie, |cookie| {
        dev.exec_op_tbor(&req, &mut oob, cookie)
            .map(HsmSdRestoreResult::from)
            .map_err(HsmError::from)
    })
}
