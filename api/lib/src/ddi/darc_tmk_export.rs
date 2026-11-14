// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side dispatch for the in-session `DarcTmkExport` command
//! (opcode `0x24`) at the DDI layer.
//!
//! `DarcTmkExport` seals the source's TMK to an authenticated target. The
//! handler re-hashes the supplied `policy`, validates the **target**
//! certificate chain against the policy `data_spki_thumbprint` to recover the
//! target's KEX public key, unmasks the TMK, HPKE Base seals it, and returns
//! the canonical envelope together with an operation-bound PID report.
//!
//! The target certificate-chain DER travels **out of band**; the request
//! carries only `(index, length)` descriptors, built here via
//! [`push_cert_chain`]. Runs **inside an already-open** security-domain
//! (V2) session.

use tsra_ddi_tbor_types::*;

use super::*;

/// Maximum certificates in a DARC target/source certificate chain
/// (`CertDescriptor[1..=2]`).
pub(crate) const DARC_CERT_CHAIN_MAX_CERTS: usize = 2;

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
/// * `target_cert_chain` - DATA-anchored target certificate chain
///   (1..=2 certs); DER carried out of band.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_tmk`, malformed `policy`, or an
/// empty/oversized chain, and surfaces DDI/device failures.
pub(crate) fn darc_tmk_export(
    session: &HsmSession,
    masked_tmk: &[u8],
    policy: &[u8],
    target_cert_chain: &[HsmCert<'_>],
) -> HsmResult<HsmDarcTmkExportResult> {
    let masked_tmk: [u8; MASKED_TMK_LEN] = masked_tmk
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = policy_wire(policy)?;

    let mut oob: Vec<&[u8]> = Vec::new();
    let target_cert_chain =
        push_cert_chain(target_cert_chain, &mut oob, DARC_CERT_CHAIN_MAX_CERTS)?;

    let req = TborDarcTmkExportReq {
        session_id: session.ex_session_id()?,
        masked_tmk,
        policy,
        target_cert_chain,
    };

    let mut cookie = None;
    let oob_items = (!oob.is_empty()).then_some(oob.as_slice());
    let rev = session.api_rev();
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(rev, &req, oob_items, &mut cookie)
            .map_err(HsmError::from)
    })?;

    Ok(HsmDarcTmkExportResult {
        sealed_tmk: resp.sealed_tmk.to_vec(),
        report: resp.report,
    })
}
