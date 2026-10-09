// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side dispatch for the in-session `DarcTmkImport` command
//! (opcode `0x21`) at the DDI layer.
//!
//! `DarcTmkImport` opens a `sealed_tmk` on the **target**. The handler
//! re-hashes the supplied `policy`, validates the **source** certificate
//! chain against the policy `POTAPubKey` to recover the source's HPKE
//! sender public key (`SndrPub`), unmasks the target's own KEX key
//! (`RcvrPriv`), HPKE-Auth-opens `sealed_tmk` to recover the TMK, and
//! re-masks it under the partition SDMK as a `DarcTmk` masked-key blob.
//!
//! The source certificate-chain DER travels **out of band**; the request
//! carries only `(index, length)` descriptors, built here via
//! [`push_cert_chain`]. Runs **inside an already-open** security-domain
//! (V2) session.

use tsra_ddi_tbor_types::*;

use super::*;

/// Issue `DarcTmkImport` (opcode `0x21`) on the active session.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `masked_kex_key` - The target's masked DARC KEX key (from
///   [`darc_kex_key_gen`](super::darc_kex_key_gen)), exactly
///   [`MASKED_KEX_KEY_LEN`] bytes.
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes)
///   whose `POTAPubKey` anchors `remote_cert_chain`.
/// * `sealed_tmk` - The sealed TMK from
///   [`darc_tmk_export`](super::darc_tmk_export), exactly
///   [`SEALED_TMK_LEN`] bytes.
/// * `remote_cert_chain` - POTA-anchored source certificate chain
///   (1..=2 certs); DER carried out of band.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_kex_key`/`sealed_tmk`, malformed `policy`, or an
/// empty/oversized chain, and surfaces DDI/device failures.
pub(crate) fn darc_tmk_import(
    session: &HsmSession,
    masked_kex_key: &[u8],
    policy: &[u8],
    sealed_tmk: &[u8],
    remote_cert_chain: &[HsmCert<'_>],
) -> HsmResult<Vec<u8>> {
    let masked_kex_key: [u8; MASKED_KEX_KEY_LEN] = masked_kex_key
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let sealed_tmk: [u8; SEALED_TMK_LEN] = sealed_tmk
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = decode_policy(policy)?;

    let mut oob: Vec<&[u8]> = Vec::new();
    let remote_cert_chain =
        push_cert_chain(remote_cert_chain, &mut oob, DARC_CERT_CHAIN_MAX_CERTS)?;

    let req = TborDarcTmkImportReq {
        session_id: session.ex_session_id()?,
        masked_kex_key,
        policy,
        sealed_tmk,
        remote_cert_chain,
    };

    let mut cookie = None;
    let oob_items = (!oob.is_empty()).then_some(oob.as_slice());
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, oob_items, &mut cookie)
            .map_err(HsmError::from)
    })?;

    Ok(resp.masked_tmk)
}
