// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionClose` handler.
//!
//! Destroys the requested slot via
//! [`HsmSessionManager::session_destroy`](tsra_fw_hsm_pal_traits::HsmSessionManager::session_destroy).
//!
//! # Trust boundary
//!
//! `SessionClose` is destructive, so it travels on the session's
//! encrypted channel: the PAL opens the request under the session's
//! VM→HSM transport key, and the dispatcher requires the SQE session id
//! to match the body's.  A caller without the session's keys cannot
//! close it.

use tsra_fw_ddi_tbor_types::TborSessionCloseReq;
use tsra_fw_ddi_tbor_types::TborSessionCloseResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionState;
use tsra_fw_hsm_undo::UndoLog;

/// Handle a TBOR `SessionClose` request.
///
/// Routes through `pal.session_destroy` to free the slot and any
/// associated vault state.  The destroy is deferred to the commit walk
/// (after the completion posts), so the response can still be sealed
/// under the session's transport key.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
    undo: &mut UndoLog<'p>,
) -> HsmResult<usize> {
    let req = TborSessionCloseReq::decode(cmd_buf.request())?;
    let session_id: u16 = req.session_id().into();
    let id = HsmSessId::from(session_id);
    if matches!(pal.session_state(io, id), HsmSessionState::Invalid) {
        return Err(HsmError::SessionNotFound);
    }
    undo.push_session_close(id)?;
    let resp = cmd_buf.encode_response(|buf| {
        let frame = TborSessionCloseResp::encode(buf, 0, false)?.finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
