// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR (partition reset / live migration) contract: one test per TBOR
//! opcode.
//!
//! Each test resets the partition with `erase` (an NSSR on hardware, a
//! partition disable + enable on the emulator) and then checks how the
//! device answers one opcode. [`guard`] fails when an opcode declared in
//! `src/` has no row here.
//!
//! In-session opcodes are driven through [`assert_in_session_contract`]:
//!
//! 1. **Stale** — the pre-reset session id is rejected with
//!    `SessionNeedsRenegotiation`.
//! 2. **Reopened** — after `SessionReopenInit` / `SessionReopenFinish`
//!    under the reverted default PSK, the opcode is rejected with
//!    `DefaultPskMustRotate`.
//! 3. **Recovered** — after `PskChange` and re-provisioning (`PartInit` +
//!    `PartFinal` replaying the pre-reset `local_mk_backup`, then
//!    `SdRestoreLocalBackup` if the partition had a security domain), the
//!    opcode succeeds with key material created before the reset, and its
//!    output is checked against that material.
//!
//! | Module | Opcodes | Contract |
//! |---|---|---|
//! | [`no_session`] | `ApiRev`, `PartInfo`, `GetCertChainInfo`, `GetCertificate` | Answer straight after the reset |
//! | [`lifecycle`] | session open / reopen / close, `PskChange`, `PartInit`, `PartFinal` | Per-opcode, incl. a reset mid-handshake or mid-provisioning |
//! | [`keys`] | key generation and crypto | Checkpoints 1–3 |
//! | [`sd_darc`] | security domain and DARC | Checkpoints 1–3; one-shot SD commands assert their one-shot status instead |
//!
//! `keys::nssr_key_report` is expected to fail until a reopened CO session
//! can `KeyReport` again (see its docs).

mod guard;
mod keys;
mod lifecycle;
mod no_session;
mod sd_darc;

use core::fmt::Debug;

use tsra_ddi_interface::DdiError;
use tsra_ddi_interface::DdiResult;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::SEC1_PUB_LEN;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::PART_POLICY_LEN;

use crate::commands::part_init::mach_seed;
use crate::commands::part_init::part_policy_with_pota;
use crate::commands::part_init::pota_thumbprint;

/// A provisioned partition with a rotated-PSK Crypto-Officer session,
/// plus everything the host keeps to restore it after a reset.
pub(crate) struct World {
    pub(crate) ctx: TestCtx,
    pub(crate) co: SessionHandshake,
    pota: CaKey,
    policy: [u8; PART_POLICY_LEN],
    pta_pub: [u8; SEC1_PUB_LEN],
    local_mk_backup: Vec<u8>,
    /// `(pok_local_backup, sd_mk_backup)` once a security domain exists;
    /// recovery then restores it with `SdRestoreLocalBackup`.
    sd_backups: Option<(Vec<u8>, Vec<u8>)>,
}

impl World {
    /// Factory-resets the device, rotates the CO PSK and provisions the
    /// partition (`PartInit` + `PartFinal`).
    pub(crate) fn new() -> Self {
        let pota = CaKey::generate();
        let policy = part_policy_with_pota(&pota.raw_pub());
        Self::provisioned(TestCtx::new(), pota, policy)
    }

    /// As [`World::new`], under `policy` on the already-reset `ctx`.
    pub(crate) fn provisioned(ctx: TestCtx, pota: CaKey, policy: [u8; PART_POLICY_LEN]) -> Self {
        let co = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        let (pta_pub, local_mk_backup) = provision(&ctx, &co, &pota, &policy, &[]);
        Self {
            ctx,
            co,
            pota,
            policy,
            pta_pub,
            local_mk_backup,
            sd_backups: None,
        }
    }

    pub(crate) fn sid(&self) -> u16 {
        self.co.session_id
    }

    pub(crate) fn nssr(&self) {
        self.ctx.erase().expect("NSSR (erase)");
    }

    /// Reopens the CO session under the role's (reverted) default PSK.
    pub(crate) fn reopen(&mut self) {
        let reopened = self
            .ctx
            .session_reopen(&self.co, None)
            .expect("SessionReopen after NSSR");
        assert_eq!(
            reopened.session_id, self.co.session_id,
            "reopen must keep the session id"
        );
        self.co = reopened;
    }

    /// Re-rotates the CO PSK and re-provisions the partition, replaying
    /// the pre-reset `local_mk_backup` and, if any, the SD local backups.
    pub(crate) fn finish_recovery(&mut self) {
        self.ctx
            .psk_change(&self.co, &ROTATED_CO_PSK)
            .expect("re-rotate CO PSK after reopen");
        (self.pta_pub, self.local_mk_backup) = provision(
            &self.ctx,
            &self.co,
            &self.pota,
            &self.policy,
            &self.local_mk_backup,
        );
        if let Some((pok_local_backup, sd_mk_backup)) = self.sd_backups.take() {
            let resp = self
                .ctx
                .tbor(&TborSdRestoreLocalBackupReq {
                    session_id: self.sid(),
                    pok_local_backup,
                    sd_mk_backup,
                })
                .expect("SdRestoreLocalBackup");
            self.sd_backups = Some((resp.pok_local_backup, resp.sd_mk_backup));
        }
    }

    pub(crate) fn recover(&mut self) {
        self.reopen();
        self.finish_recovery();
    }
}

/// `PartInit` + `PartFinal` with the canonical inputs; returns the PTA
/// public key and the `local_mk_backup` the host persists.
pub(crate) fn provision(
    ctx: &TestCtx,
    session: &SessionHandshake,
    pota: &CaKey,
    policy: &[u8; PART_POLICY_LEN],
    prev_local_mk_backup: &[u8],
) -> ([u8; SEC1_PUB_LEN], Vec<u8>) {
    let init = ctx
        .part_init(session, &mach_seed(), policy, &pota_thumbprint())
        .expect("PartInit");
    let pta_pub = pta_pub_from_csr(&init.pta_csr);
    let chain = make_pta_chain(pota, &pta_pub);
    let local_mk_backup = ctx
        .part_final(session, policy, prev_local_mk_backup, &chain.der_items())
        .expect("PartFinal")
        .local_mk_backup;
    (pta_pub, local_mk_backup)
}

/// Asserts the three-checkpoint contract (see the module docs) for an
/// in-session opcode. `call` issues the opcode on the given session id
/// and verifies its output; it also runs once before the reset.
pub(crate) fn assert_in_session_contract<T: Debug>(
    world: &mut World,
    mut call: impl FnMut(&TestCtx, u16) -> DdiResult<T>,
) {
    call(&world.ctx, world.sid()).expect("opcode must succeed before the NSSR");
    assert_gated(world, &mut call);
    world.finish_recovery();
    call(&world.ctx, world.sid()).expect("opcode must succeed after recovery");
}

/// Resets the partition and asserts the first two checkpoints: `call` is
/// refused on the stale session, then on the session reopened under the
/// default PSK. Leaves the session reopened.
pub(crate) fn assert_gated<T: Debug>(
    world: &mut World,
    mut call: impl FnMut(&TestCtx, u16) -> DdiResult<T>,
) {
    world.nssr();
    expect_status(
        call(&world.ctx, world.sid()),
        TborStatus::SessionNeedsRenegotiation,
        "stale session after NSSR",
    );
    world.reopen();
    expect_status(
        call(&world.ctx, world.sid()),
        TborStatus::DefaultPskMustRotate,
        "session reopened under the default PSK",
    );
}

/// Asserts that `result` is a firmware rejection with `expected`.
#[track_caller]
pub(crate) fn expect_status<T: Debug>(result: DdiResult<T>, expected: TborStatus, stage: &str) {
    match result {
        Err(DdiError::TborStatus(status)) => assert_eq!(
            status, expected,
            "{stage}: expected {expected:?} (0x{:08X}), got {status:?} (0x{:08X})",
            expected.0, status.0,
        ),
        other => panic!("{stage}: expected {expected:?}, got {other:?}"),
    }
}
