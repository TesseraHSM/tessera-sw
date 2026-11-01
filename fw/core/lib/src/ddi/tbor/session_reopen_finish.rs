// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionReopenFinish` handler — Phase 2 of session reopen.
//!
//! Runs the shared [`SessionOpenFinish`](super::session_open_finish)
//! core against a reopen-Pending slot, restoring the session's existing
//! `masking_key` from the host-supplied `bmk_session` (unwrapped under
//! `BK_SESSION = KBKDF(BK_BOOT, "SESSION_BK", seed)`) so that keys
//! masked at session scope before the reset remain usable.

use tsra_fw_ddi_tbor_types::*;
use tsra_fw_hsm_pal_traits::*;
use tsra_fw_hsm_undo::UndoLog;

use super::session_open_finish::run_finish;
use super::session_open_finish::FinishRequest;
use super::session_open_finish::MaskingKeySource;

/// Handle a TBOR `SessionReopenFinish` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
    undo: &mut UndoLog<'p>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let req = TborSessionReopenFinishReq::decode_mut(cmd_buf.request_mut())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id));
        let seed_envelope: &mut HsmDmaBuf = req.seed_envelope;
        if seed_envelope.len() != SEED_ENVELOPE_LEN {
            return Err(HsmError::InvalidArg);
        }
        let finish = FinishRequest {
            sess_id,
            mac_fin: req.mac_fin,
            seed_envelope,
        };
        let bmk_in: &mut HsmDmaBuf = req.bmk_session;
        let bmk_session = run_finish(
            pal,
            io,
            alloc,
            undo,
            finish,
            MaskingKeySource::Restore(bmk_in),
        )
        .await?;

        cmd_buf.encode_response(|buf| {
            let frame = TborSessionReopenFinishResp::encode(buf, 0, false)?
                .bmk_session(bmk_session)?
                .finish();
            Ok(frame.as_bytes().len())
        })
    })
    .await
}
