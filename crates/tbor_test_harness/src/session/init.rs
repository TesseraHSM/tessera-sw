// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 1 of the TBOR session handshake — `SessionOpenInit`.
//!
//! Generates the host's per-handshake KEM ephemeral, ships `pk_init`,
//! verifies the HSM's signature over the transcript and derives the
//! handshake secret. Returns a [`PendingHandshake`] that
//! [`super::finish::session_open_finish`] consumes to complete Phase 2.
//!
//! The session transport keys are registered with the [`TestDev`] as soon
//! as Phase 1 completes, so the finish (including a raw, test-built
//! `TborSessionOpenFinishReq`) and every later in-session command travel
//! encrypted.
//!
//! The convenience entry point [`session_open_init`] runs the happy
//! path with the canonical default PSK. Negative-path tests reach for
//! [`SessionOpenInitOptions`] + [`session_open_init_with_options`] to
//! override individual knobs (PSK, wire suite id).

use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborSessionOpenInitReq;
use tsra_ddi_tbor_types::TborSessionOpenInitResp;
use tsra_session_ex_crypto::default_psk;
use tsra_session_ex_crypto::SessionHandshake as HandshakeKeys;
use tsra_session_ex_crypto::SessionInitiator;
use tsra_session_ex_crypto::SessionSuite;

use super::crypto;
use crate::fixture::TestDev;

/// State carried between Phase 1 and Phase 2 of the handshake.
pub struct PendingHandshake {
    /// Reserved session identifier returned by the FW.
    pub session_id: u16,
    /// Caller-selected PSK id (0 = CO, 1 = CU).
    pub psk_id: u8,
    /// Key-establishment suite of the handshake.
    pub suite: SessionSuite,
    /// Verified handshake secret and transcript.
    pub keys: HandshakeKeys,
}

impl core::fmt::Debug for PendingHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingHandshake")
            .field("session_id", &self.session_id)
            .field("psk_id", &self.psk_id)
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

/// Override knobs for [`session_open_init_with_options`].
///
/// `None` fields use the happy-path default (partition default PSK).
/// Tests set only the fields they need to override.
pub struct SessionOpenInitOptions<'a> {
    /// PSK id (0 = CO, 1 = CU). Required.
    pub psk_id: u8,
    /// Key-establishment suite. Required.
    pub suite: SessionSuite,
    /// Wire `suite_id`. Defaults to `suite.id()`; tests that exercise
    /// the unsupported-suite negative path override it.
    pub suite_id: u8,
    /// Override the PSK bytes fed into the key schedule. Default:
    /// `DEFAULT_PSK_CO` for `psk_id=0`, `DEFAULT_PSK_CU` for `psk_id=1`.
    /// Tests that exercise a rotated PSK pass the rotated bytes here.
    pub psk: Option<&'a [u8]>,
}

impl<'a> SessionOpenInitOptions<'a> {
    /// Construct an options block with happy-path defaults for the
    /// given `psk_id` and `suite`.
    pub fn new(psk_id: u8, suite: SessionSuite) -> Self {
        Self {
            psk_id,
            suite,
            suite_id: suite.id(),
            psk: None,
        }
    }

    /// Builder shortcut: override the PSK bytes.
    pub fn with_psk(mut self, psk: &'a [u8]) -> Self {
        self.psk = Some(psk);
        self
    }

    /// Builder shortcut: override the wire `suite_id`. Used by
    /// negative tests that exercise the unsupported-suite path.
    pub fn with_suite_id(mut self, suite_id: u8) -> Self {
        self.suite_id = suite_id;
        self
    }
}

/// Convenience wrapper: happy-path `SessionOpenInit` with the partition
/// default PSK.
pub fn session_open_init(
    dev: &TestDev,
    psk_id: u8,
    suite: SessionSuite,
) -> Result<PendingHandshake, DdiError> {
    session_open_init_with_options(dev, SessionOpenInitOptions::new(psk_id, suite))
}

/// Full-control entry point. Honours every override in `opts`;
/// fills in happy-path defaults for the rest.
pub fn session_open_init_with_options(
    dev: &TestDev,
    opts: SessionOpenInitOptions<'_>,
) -> Result<PendingHandshake, DdiError> {
    let initiator =
        SessionInitiator::generate(opts.suite).map_err(|_| DdiError::InvalidParameter)?;
    let pk_hsm = crypto::fetch_pk_hsm(dev)?;

    let session_type = SessionType::Encrypted.to_u8();
    let req = TborSessionOpenInitReq {
        psk_id: opts.psk_id,
        session_type,
        suite_id: opts.suite_id,
        pk_init: initiator.pk_init().to_vec(),
    };
    let mut cookie = None;
    let resp: TborSessionOpenInitResp = dev.exec_op_tbor(&req, None, &mut cookie)?;

    let default_psk = default_psk(opts.psk_id).map_err(|_| DdiError::InvalidParameter)?;
    let psk: &[u8] = opts.psk.unwrap_or(default_psk.as_slice());
    let keys = initiator
        .complete(
            opts.psk_id,
            session_type,
            &pk_hsm,
            psk,
            &resp.enc,
            &resp.sig,
        )
        .map_err(|_| DdiError::TborDecodeError)?;

    let transport = keys.transport().map_err(|_| DdiError::TborDecodeError)?;
    dev.set_session_transport(resp.session_id, transport);

    Ok(PendingHandshake {
        session_id: resp.session_id,
        psk_id: opts.psk_id,
        suite: opts.suite,
        keys,
    })
}
