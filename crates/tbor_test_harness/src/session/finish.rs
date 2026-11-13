// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 2 of the TBOR session handshake — `SessionOpenFinish`.
//!
//! Generates a fresh 32-byte `seed`, derives `param_key` from the
//! handshake secret, seals the seed under `param_key`, computes the host
//! confirmation `fin` from the [`PendingHandshake`] produced by
//! [`super::init::session_open_init`], ships both to the FW (encrypted
//! under the session transport keys), and folds the response into a
//! [`SessionHandshake`] carrier that downstream tests use to drive
//! in-session commands.
//!
//! Negative-path tests reach for [`build_mac_fin`] +
//! [`session_open_finish_with_mac`] to ship a tampered or otherwise
//! caller-controlled `mac_fin`.

use tsra_crypto::AesKey;
use tsra_crypto::Rng;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_types::TborSessionOpenFinishReq;
use tsra_ddi_tbor_types::TborSessionOpenFinishResp;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::SEED_ENVELOPE_LEN;
use tsra_ddi_tbor_types::SESSION_SEED_LEN;
use tsra_session_ex_crypto::seal_seed_envelope;
use tsra_session_ex_crypto::SessionSuite;
use zeroize::Zeroizing;

use super::init::PendingHandshake;
use crate::fixture::TestDev;

/// Active session state carried through downstream in-session tests.
///
/// `param_key` is the per-session AES-256 key the host uses to seal
/// per-command parameter blobs as `aead_envelope` envelopes (e.g.,
/// the new PSK in `PskChange`). `bmk_session` is the FW's wrapped
/// masking-key envelope returned by `SessionOpenFinish`; it is
/// opaque to the host today (MBOR `ReopenSession` consumes it).
pub struct SessionHandshake {
    /// Active session identifier.
    pub session_id: u16,
    /// PSK id used for the handshake (0 = CO, 1 = CU).
    pub psk_id: u8,
    /// Key-establishment suite of the handshake.
    pub suite: SessionSuite,
    /// Per-session AES-256 wrap key derived from the handshake secret.
    pub param_key: AesKey,
    /// FW-emitted wrapped masking-key blob — opaque to the host.
    pub bmk_session: Vec<u8>,
}

impl core::fmt::Debug for SessionHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `param_key` deliberately omitted — it contains key material
        // and `AesKey` does not implement Debug.
        f.debug_struct("SessionHandshake")
            .field("session_id", &self.session_id)
            .field("psk_id", &self.psk_id)
            .field("suite", &self.suite)
            .field("bmk_session_len", &self.bmk_session.len())
            .finish_non_exhaustive()
    }
}

/// Compute the host confirmation the host normally ships in `mac_fin`.
/// Exposed so negative-path tests can compute the canonical value,
/// tamper with it, and ship the result via
/// [`session_open_finish_with_mac`].
pub fn build_mac_fin(pending: &PendingHandshake) -> Result<[u8; 48], DdiError> {
    pending.keys.fin().map_err(|_| DdiError::TborDecodeError)
}

/// Run Phase 2 of the handshake. Consumes the [`PendingHandshake`]
/// so callers cannot accidentally reuse stale state for a second
/// `SessionOpenFinish` against the same Pending slot.
pub fn session_open_finish(
    dev: &TestDev,
    pending: PendingHandshake,
) -> Result<SessionHandshake, DdiError> {
    let mac_fin = build_mac_fin(&pending)?;
    session_open_finish_with_mac(dev, pending, mac_fin)
}

/// Ship a caller-supplied `mac_fin` in `SessionOpenFinish`. The
/// `PendingHandshake` is still consumed.
///
/// On a `mac_fin` mismatch the FW returns an error that surfaces here
/// as a [`DdiError`] from `exec_op_tbor`.
pub fn session_open_finish_with_mac(
    dev: &TestDev,
    pending: PendingHandshake,
    mac_fin: [u8; 48],
) -> Result<SessionHandshake, DdiError> {
    let param_key = pending
        .keys
        .param_key()
        .map_err(|_| DdiError::TborDecodeError)?;
    let mut seed = Zeroizing::new([0u8; SESSION_SEED_LEN]);
    Rng::rand_bytes(seed.as_mut_slice()).map_err(|_| DdiError::InvalidParameter)?;
    let envelope = seal_seed_envelope(&param_key, &*seed).map_err(|_| DdiError::TborDecodeError)?;
    let seed_envelope: [u8; SEED_ENVELOPE_LEN] = envelope
        .as_slice()
        .try_into()
        .map_err(|_| DdiError::TborDecodeError)?;

    let req = TborSessionOpenFinishReq {
        session_id: pending.session_id,
        mac_fin,
        seed_envelope,
    };
    // Travels encrypted under the transport registered at Phase 1.
    let mut cookie = None;
    let resp: TborSessionOpenFinishResp =
        dev.exec_op_tbor(&req, None, &mut cookie)
            .inspect_err(|err| {
                // Firmware reclaims the slot after an authentication failure.
                if matches!(err, DdiError::TborStatus(TborStatus::SessionAuthFailure)) {
                    dev.remove_session_transport(pending.session_id);
                }
            })?;

    Ok(SessionHandshake {
        session_id: pending.session_id,
        psk_id: pending.psk_id,
        suite: pending.suite,
        param_key,
        bmk_session: resp.bmk_session,
    })
}
