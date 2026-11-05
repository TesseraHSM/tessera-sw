// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR session reopen — `SessionReopenInit` + `SessionReopenFinish`.
//!
//! Re-establishes an existing session left NeedsRenegotiation by a
//! partition reset, reusing the open handshake's Phase-1/Phase-2 crypto
//! ([`super::init`], [`super::finish`]).  Phase 2 ships the session's
//! original `seed` and its last `bmk_session` so the HSM restores the
//! session's `masking_key`.

use tsra_ddi::TsraDdi;
use tsra_ddi_interface::Ddi;
use tsra_ddi_interface::DdiDev;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_types::TborSessionReopenFinishReq;
use tsra_ddi_tbor_types::TborSessionReopenFinishResp;
use tsra_ddi_tbor_types::TborSessionReopenInitReq;
use tsra_ddi_tbor_types::TborSessionReopenInitResp;
use tsra_ddi_tbor_types::SESSION_SEED_LEN;

use super::finish::build_mac_fin;
use super::finish::run_phase2;
use super::finish::SessionHandshake;
use super::init::run_phase1;
use super::init::PendingHandshake;
use super::init::SessionOpenInitOptions;

/// Phase 1 of reopen.  `opts.psk_id` must match the role implied by
/// `session_id` (it selects the PSK used for the host-side HPKE).
pub fn session_reopen_init(
    dev: &<TsraDdi as Ddi>::Dev,
    session_id: u16,
    opts: SessionOpenInitOptions<'_>,
) -> Result<PendingHandshake, DdiError> {
    let session_type = opts.session_type;
    let suite_id = opts.suite_id;
    run_phase1(dev, opts, |pk_init| {
        let req = TborSessionReopenInitReq {
            session_id,
            session_type: session_type.to_u8(),
            suite_id,
            pk_init,
        };
        let mut cookie = None;
        let resp: TborSessionReopenInitResp = dev.exec_op_tbor(&req, None, &mut cookie)?;
        Ok((session_id, resp.pk_resp, resp.mac_resp))
    })
}

/// Phase 2 of reopen with a caller-supplied `mac_fin`.
pub fn session_reopen_finish_with_mac(
    dev: &<TsraDdi as Ddi>::Dev,
    pending: PendingHandshake,
    mac_fin: [u8; 48],
    seed: [u8; SESSION_SEED_LEN],
    bmk_session: &[u8],
) -> Result<SessionHandshake, DdiError> {
    run_phase2(
        pending,
        mac_fin,
        seed,
        |session_id, mac_fin, seed_envelope| {
            let req = TborSessionReopenFinishReq {
                session_id,
                mac_fin,
                seed_envelope,
                bmk_session: bmk_session.to_vec(),
            };
            let mut cookie = None;
            let resp: TborSessionReopenFinishResp = dev.exec_op_tbor(&req, None, &mut cookie)?;
            Ok(resp.bmk_session)
        },
    )
}

/// Phase 2 of reopen.
pub fn session_reopen_finish(
    dev: &<TsraDdi as Ddi>::Dev,
    pending: PendingHandshake,
    seed: [u8; SESSION_SEED_LEN],
    bmk_session: &[u8],
) -> Result<SessionHandshake, DdiError> {
    let mac_fin = build_mac_fin(&pending)?;
    session_reopen_finish_with_mac(dev, pending, mac_fin, seed, bmk_session)
}

/// Full reopen of `prev` using the PSK selected by `opts`.
pub fn session_reopen(
    dev: &<TsraDdi as Ddi>::Dev,
    prev: &SessionHandshake,
    psk: Option<&[u8]>,
) -> Result<SessionHandshake, DdiError> {
    let mut opts = SessionOpenInitOptions::new(prev.psk_id, prev.session_type);
    if let Some(psk) = psk {
        opts = opts.with_psk(psk);
    }
    let pending = session_reopen_init(dev, prev.session_id, opts)?;
    session_reopen_finish(dev, pending, prev.seed, &prev.bmk_session)
}
