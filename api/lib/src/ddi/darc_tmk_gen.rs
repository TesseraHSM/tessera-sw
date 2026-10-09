// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side dispatch for the in-session `DarcTmkGen` command
//! (opcode `0x23`) at the DDI layer.
//!
//! `DarcTmkGen` mints a fresh 256-bit Transfer Masking Key (TMK) from the
//! device RNG on the **source** and returns it masked under the partition
//! SDMK as a `DarcTmk` masked-key blob. The plaintext TMK never leaves the
//! device; the caller retains the masked blob and unmasks it on-use in
//! [`darc_tmk_export`](super::darc_tmk_export) /
//! [`darc_key_wrap`](super::darc_key_wrap).
//!
//! It runs **inside an already-open** security-domain (V2) session; the
//! request carries only the active session id.

use tsra_ddi_tbor_types::*;

use super::*;

/// Issue `DarcTmkGen` (opcode `0x23`) on the active session.
///
/// Returns the freshly-minted TMK masked under the partition SDMK
/// (exactly [`MASKED_TMK_GEN_LEN`] bytes). The key is not stored on-device.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
///
/// # Errors
///
/// Surfaces DDI/device failures from the round-trip.
pub(crate) fn darc_tmk_gen(session: &HsmSession) -> HsmResult<Vec<u8>> {
    let req = TborDarcTmkGenReq {
        session_id: session.ex_session_id()?,
    };

    let mut cookie = None;
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    Ok(resp.masked_tmk)
}
