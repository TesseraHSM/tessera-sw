// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionReopenInit` handler — Phase 1 of session reopen.
//!
//! Re-runs the [`SessionOpenInit`](super::session_open_init) handshake
//! against an existing slot that needs renegotiation (e.g. after a
//! partition disable or NSSR), instead of allocating a new slot.  The
//! PSK is the one currently bound to the slot's role.  On success the
//! slot is reopen-Pending under the same session id; any failure before
//! `SessionReopenFinish` promotes it reverts the slot to
//! NeedsRenegotiation, so the session can be retried.

use tsra_fw_ddi_tbor_types::*;
use tsra_fw_hsm_pal_traits::*;
use tsra_fw_hsm_undo::UndoLog;

use super::psk_id_for_role;
use super::session_open_init::parse_type_and_suite;
use super::session_open_init::run_handshake;
use super::session_open_init::HandshakeParams;
use super::session_open_init::SlotSource;

/// Handle a TBOR `SessionReopenInit` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
    undo: &mut UndoLog<'p>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let req = TborSessionReopenInitReq::decode(cmd_buf.request())?;
        let id = HsmSessId::from(u16::from(req.session_id()));
        let role = id.role();
        let pk_init: &HsmDmaBuf = req.pk_init();
        let (session_type, suite) =
            parse_type_and_suite(role, req.session_type().0, req.suite_id().0, pk_init)?;

        let params = HandshakeParams {
            psk_id: psk_id_for_role(role),
            session_type,
            suite,
            pk_init,
        };
        let out = run_handshake(pal, io, alloc, undo, &params, SlotSource::Reopen(id)).await?;

        cmd_buf.encode_response(|buf| {
            let frame = TborSessionReopenInitResp::encode(buf, 0, false)?
                .pk_resp(out.pk_resp)?
                .mac_resp(out.mac_resp)?
                .finish();
            Ok(frame.as_bytes().len())
        })
    })
    .await
}
