// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `ApiRev` command handler.
//!
//! `ApiRev` is the bootstrap TBOR command: it advertises the range
//! of TBOR wire-protocol versions this firmware understands. The
//! wire schema lives in [`tsra_fw_ddi_tbor_types::api_rev`] —
//! the request body is empty (the derive emits a synthetic `none`
//! placeholder TOC entry), and the response carries `(min, max)`.

use tsra_fw_ddi_tbor::PROTOCOL_VERSION;
use tsra_fw_ddi_tbor_types::TborApiRevReq;
use tsra_fw_ddi_tbor_types::TborApiRevResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmResult;

/// Lowest TBOR wire-protocol version this firmware speaks.
pub(crate) const MIN_PROTOCOL_VERSION: u8 = PROTOCOL_VERSION;

/// Highest TBOR wire-protocol version this firmware speaks.
pub(crate) const MAX_PROTOCOL_VERSION: u8 = PROTOCOL_VERSION;

/// Handle a TBOR `ApiRev` request.
///
/// The caller (`dispatch`) has already structurally validated the
/// buffer via `RequestView::parse` and confirmed the opcode is
/// `API_REV`. This handler validates the typed request and encodes the
/// `(MIN_PROTOCOL_VERSION, MAX_PROTOCOL_VERSION)` response.
pub(crate) fn handle(cmd_buf: &mut HsmCmdBuf<'_>) -> HsmResult<usize> {
    TborApiRevReq::decode(cmd_buf.request())?;
    let frame = TborApiRevResp::encode(cmd_buf.buffer_mut(), 0, false)?
        .min_ver(MIN_PROTOCOL_VERSION)?
        .max_ver(MAX_PROTOCOL_VERSION)?
        .finish();
    Ok(frame.len())
}
