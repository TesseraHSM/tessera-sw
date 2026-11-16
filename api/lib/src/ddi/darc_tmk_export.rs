// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side dispatch for the in-session `DarcTmkExport` command
//! (opcode `0x24`) at the DDI layer.
//!
//! `DarcTmkExport` seals the source's TMK to an authenticated target. The
//! handler re-hashes the supplied `policy`, validates the **target** PID
//! certificate chain against the policy `data_spki_thumbprint`, verifies the
//! target's PID-signed key report over its DARC KEX key to recover the
//! recipient public key (P-384, ML-KEM-1024 or MLKEM1024-P384), unmasks the
//! TMK, HPKE Base seals it, and returns the canonical envelope together with
//! an operation-bound PID report.
//!
//! The target certificate-chain DER and key report travel **out of band**;
//! the request carries only `(index, length)` descriptors. The firmware
//! writes the PID report to OOB item [`DARC_REPORT_OOB_INDEX`]. Runs
//! **inside an already-open** security-domain (V2) session.

use tsra_ddi::TborOobItem;
use tsra_ddi_tbor_types::*;

use super::*;

/// Maximum certificates in a DARC target certificate chain
/// (`CertDescriptor[1..=3]`, normally DATA -> PTA -> PID).
const DARC_TARGET_CERT_CHAIN_MAX_CERTS: usize = 3;

/// Issue `DarcTmkExport` (opcode `0x24`) on the active session.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `masked_tmk` - The masked TMK (from
///   [`darc_tmk_gen`](super::darc_tmk_gen)), exactly [`MASKED_TMK_LEN`]
///   bytes.
/// * `policy` - Partition policy CBOR document (`1..=`[`PART_POLICY_MAX_LEN`] bytes)
///   whose DATA key thumbprint anchors `target_cert_chain`.
/// * `target_cert_chain` - DATA-anchored target PID certificate chain
///   (1..=3 certs); DER carried out of band.
/// * `target_key_report` - The target PID's key report over its DARC KEX
///   key (from `key_report` on the masked KEX key); carried out of band.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_tmk`, malformed `policy`, an empty/oversized chain or an
/// empty/oversized key report, and surfaces DDI/device failures.
pub(crate) fn darc_tmk_export(
    session: &HsmSession,
    masked_tmk: &[u8],
    policy: &[u8],
    target_cert_chain: &[HsmCert<'_>],
    target_key_report: &[u8],
) -> HsmResult<HsmDarcTmkExportResult> {
    let masked_tmk: [u8; MASKED_TMK_LEN] = masked_tmk
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = policy_wire(policy)?;

    if target_key_report.len() > KEY_REPORT_MAX_LEN {
        return Err(HsmError::InvalidArgument);
    }

    let mut report = vec![0u8; DARC_REPORT_MAX_LEN];
    let mut oob: Vec<TborOobItem<'_>> = Vec::new();
    push_report_out(&mut report, &mut oob)?;
    let target_cert_chain = push_cert_chain(
        target_cert_chain,
        &mut oob,
        DARC_TARGET_CERT_CHAIN_MAX_CERTS,
    )?;
    let target_key_report = push_report(target_key_report, &mut oob)?;

    let req = TborDarcTmkExportReq {
        session_id: session.ex_session_id()?,
        masked_tmk,
        policy,
        target_cert_chain,
        target_key_report,
    };

    let mut cookie = None;
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, &mut oob, &mut cookie)
            .map_err(HsmError::from)
    })?;
    drop(oob);

    Ok(HsmDarcTmkExportResult {
        sealed_tmk: resp.sealed_tmk,
        report: take_report(report, resp.report_len)?,
    })
}
