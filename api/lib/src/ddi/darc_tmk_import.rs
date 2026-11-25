// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side dispatch for the in-session `DarcTmkImport` command
//! (opcode `0x21`) at the DDI layer.
//!
//! `DarcTmkImport` opens a `sealed_tmk` on the **target**. The handler
//! re-hashes the supplied `policy`, validates the **source** certificate
//! chain against the policy `pota_spki_thumbprint` to authorize the reporting PID,
//! unmasks the target's KEX key, verifies the report and envelope binding,
//! HPKE Base opens `sealed_tmk` to recover the TMK, and
//! re-masks it under the partition SDMK as a `DarcTmk` masked-key blob.
//!
//! The source certificate-chain DER and the report travel **out of band**;
//! the request carries only `(index, length)` descriptors. Runs **inside an already-open** security-domain
//! (V2) session.

use tsra_ddi_tbor_types::*;

use super::*;

/// Validate a complete signed artifact's recipient/signature-dependent length.
pub(super) fn validate_sealed_tmk(sealed: &[u8]) -> HsmResult<()> {
    const ENVELOPE_OVERHEAD: usize = SEALED_TMK_LEN - 97 - 109;
    let valid = [
        97,
        SD_SEALING_MLKEM1024_PUB_KEY_LEN,
        SD_SEALING_MLKEM1024_P384_PUB_KEY_LEN,
    ]
    .iter()
    .any(|enc| {
        [109, 4641]
            .iter()
            .any(|sign1| sealed.len() == ENVELOPE_OVERHEAD + enc + sign1)
    });
    if !valid {
        return Err(HsmError::InvalidArgument);
    }
    Ok(())
}

const _: () = assert!(SEALED_TMK_MAX_LEN == SEALED_TMK_LEN - 97 - 109 + 1665 + 4641);

/// Issue `DarcTmkImport` (opcode `0x21`) on the active session.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `masked_kex_key` - The target's masked DARC KEX key (from
///   [`darc_kex_key_gen`](super::darc_kex_key_gen)), exactly
///   [`MASKED_KEX_KEY_LEN`] bytes.
/// * `policy` - Partition policy CBOR document (`1..=`[`PART_POLICY_MAX_LEN`] bytes)
///   whose POTA key thumbprint anchors `remote_cert_chain`.
/// * `sealed_tmk` - The sealed TMK from
///   [`darc_tmk_export`](super::darc_tmk_export), including its PID signature.
/// * `remote_cert_chain` - POTA-anchored source PID certificate chain
///   (1..=3 certs, normally POTA -> PTA -> PID); DER carried out of band.
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
    let masked_kex_key = masked_sealing_key_wire(masked_kex_key)?;
    validate_sealed_tmk(sealed_tmk)?;
    let policy = policy_wire(policy)?;

    let mut oob: Vec<&[u8]> = Vec::new();
    let remote_cert_chain = push_cert_chain(
        remote_cert_chain,
        &mut oob,
        DARC_SOURCE_CERT_CHAIN_MAX_CERTS,
    )?;
    let sealed_tmk = push_report(sealed_tmk, &mut oob)?;

    let req = TborDarcTmkImportReq {
        session_id: session.ex_session_id()?,
        masked_kex_key,
        policy,
        sealed_tmk,
        remote_cert_chain,
    };

    let mut cookie = None;
    let oob_items = (!oob.is_empty()).then_some(oob.as_slice());
    let rev = session.api_rev();
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(rev, &req, oob_items, &mut cookie)
            .map_err(HsmError::from)
    })?;

    Ok(resp.masked_tmk)
}
