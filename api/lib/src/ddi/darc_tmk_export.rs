// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side dispatch for the in-session `DarcTmkExport` command
//! (opcode `0x24`) at the DDI layer.
//!
//! `DarcTmkExport` seals the source's TMK to an authenticated target. The
//! handler re-hashes the supplied `policy`, validates the **target**
//! certificate chain against the policy `DATAPubKey` to recover the
//! target's KEX public key (`RcvrPub`), unmasks the source's own KEX key
//! (`SndrPriv`) and the TMK, and returns `sealed_tmk` as an HPKE-Auth seal
//! of the TMK to `RcvrPub`.
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
/// * `masked_sender_key` - The source's masked DARC KEX key (from
///   [`darc_kex_key_gen`](super::darc_kex_key_gen)), exactly
///   [`MASKED_KEX_KEY_LEN`] bytes.
/// * `masked_tmk` - The masked TMK (from
///   [`darc_tmk_gen`](super::darc_tmk_gen)), exactly [`MASKED_TMK_LEN`]
///   bytes.
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes)
///   whose `DATAPubKey` anchors `target_cert_chain`.
/// * `target_cert_chain` - DATA-anchored target certificate chain
///   (1..=2 certs); DER carried out of band.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_sender_key`/`masked_tmk`, malformed `policy`, or an
/// empty/oversized chain, and surfaces DDI/device failures.
pub(crate) fn darc_tmk_export(
    session: &HsmSession,
    masked_sender_key: &[u8],
    masked_tmk: &[u8],
    policy: &[u8],
    target_cert_chain: &[HsmCert<'_>],
) -> HsmResult<[u8; SEALED_TMK_LEN]> {
    let masked_sender_key: [u8; MASKED_KEX_KEY_LEN] = masked_sender_key
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let masked_tmk: [u8; MASKED_TMK_LEN] = masked_tmk
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = decode_policy(policy)?;

    let mut oob: Vec<&[u8]> = Vec::new();
    let target_cert_chain =
        push_cert_chain(target_cert_chain, &mut oob, DARC_CERT_CHAIN_MAX_CERTS)?;

    let req = TborDarcTmkExportReq {
        session_id: session.ex_session_id()?,
        masked_sender_key,
        masked_tmk,
        policy,
        target_cert_chain,
    };

    let mut cookie = None;
    let oob_items = (!oob.is_empty()).then_some(oob.as_slice());
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, oob_items, &mut cookie)
            .map_err(HsmError::from)
    })?;

    Ok(resp.sealed_tmk)
}
