// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side dispatch for the in-session `DarcKeyWrap` command
//! (opcode `0x25`) at the DDI layer.
//!
//! `DarcKeyWrap` exports a designated EC private key on the **source**.
//! The handler unmasks the TMK and the local masked EC key, encodes an
//! EC2 private `COSE_Key` (carrying the key's attributes), and AES-KWP
//! (RFC 5649) wraps it under the TMK to produce `wrapped_key`.
//!
//! Runs **inside an already-open** security-domain (V2) session.

use tsra_ddi_tbor_types::*;

use super::*;

/// Issue `DarcKeyWrap` (opcode `0x25`) on the active session.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `masked_tmk` - The masked TMK (from
///   [`darc_tmk_gen`](super::darc_tmk_gen) or
///   [`darc_tmk_import`](super::darc_tmk_import)), exactly
///   [`MASKED_TMK_LEN`] bytes.
/// * `masked_key` - The source's masked EC private key to export, at most
///   [`DARC_WRAP_MASKED_KEY_MAX_LEN`] bytes.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length `masked_tmk`
/// or an empty/oversized `masked_key`, and surfaces DDI/device failures.
pub(crate) fn darc_key_wrap(
    session: &HsmSession,
    masked_tmk: &[u8],
    masked_key: &[u8],
) -> HsmResult<Vec<u8>> {
    let masked_tmk: [u8; MASKED_TMK_LEN] = masked_tmk
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    if masked_key.is_empty() || masked_key.len() > DARC_WRAP_MASKED_KEY_MAX_LEN {
        return Err(HsmError::InvalidArgument);
    }

    let req = TborDarcKeyWrapReq {
        session_id: session.ex_session_id()?,
        masked_tmk,
        masked_key: masked_key.to_vec(),
    };

    let mut cookie = None;
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    Ok(resp.wrapped_key)
}
