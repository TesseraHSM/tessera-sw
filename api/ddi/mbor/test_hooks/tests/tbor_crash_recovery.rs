// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crash-recovery integration tests for a TBOR partition.
//!
//! Each test provisions the partition through TBOR to one lifecycle stage
//! (`Enabled`, `Initializing` after `PartInit`, or `Initialized` after
//! `PartFinal`), injects a crash with the test-hook
//! [`DdiTestAction::TriggerCrash`](tsra_ddi_mbor_test_hooks::DdiTestAction),
//! waits for the firmware and driver to recover, and then checks the
//! partition is `Enabled` with its identity kept and can be provisioned again.
//!
//! Behaviour on this firmware:
//! - Requires a **physical** device; the socket simulator and virtual devices
//!   are skipped.
//! - Requires firmware built with `tsra_test_hooks`; otherwise `TriggerCrash`
//!   returns [`DdiStatus::UnsupportedCmd`] and the case is skipped.
//! - The crash is sent as an MBOR `TestAction` on a TBOR CU session, through
//!   the same device handle that owns that session.
//! - Holds the test-hook suite's cross-process lock, so it never resets or
//!   crashes the device under another test-hook binary.

#![allow(clippy::unwrap_used)]

mod common;

use std::thread;
use std::time::Duration;
use std::time::Instant;

use common::HardwareTestLock;
use test_with_tracing::test;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::DdiTestActionCrashReqInfo;
use tsra_ddi_mbor_test_hooks::DdiTestActionCrashType;
use tsra_ddi_mbor_test_hooks::DdiTestActionSocCpuId;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_types::DdiStatus;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::PotaFixture;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::TestPolicy;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborPartInfoResp;
use tsra_ddi_tbor_types::TborSessionClosePlainReq;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_ddi_tbor_types::POLICY_THUMBPRINT_LEN;

/// Time to leave the driver alone after the crash, so no command is sent
/// while its health monitor runs the Level-2 abort.
const RECOVERY_SETTLE: Duration = Duration::from_secs(10);

/// Upper bound on the whole recovery, generous for slow or busy hosts.
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(120);

/// `PartInfo` device kind reported by physical firmware.
const DEVICE_KIND_PHYSICAL: u8 = 2;

/// `HsmPartState::Enabled` wire discriminant.
const PART_STATE_ENABLED: u8 = 2;

/// `HsmPartState::Initializing` wire discriminant.
const PART_STATE_INITIALIZING: u8 = 4;

/// `HsmPartState::Initialized` wire discriminant.
const PART_STATE_INITIALIZED: u8 = 5;

/// Filler SATA thumbprint; this test never verifies a sealing key.
const FILLER_SATA_THUMBPRINT: [u8; POLICY_THUMBPRINT_LEN] = [0x20; POLICY_THUMBPRINT_LEN];

fn mach_seed() -> [u8; MACH_SEED_LEN] {
    core::array::from_fn(|i| 0x40 + i as u8)
}

/// Partition policy bound to `pota`'s public key.
fn part_policy(pota: &PotaFixture) -> Vec<u8> {
    TestPolicy::new(pota.spki_thumbprint(), FILLER_SATA_THUMBPRINT)
        .with_info(&[0xAB; 64])
        .encode()
}

fn part_info(ctx: &TestCtx, context: &str) -> TborPartInfoResp {
    ctx.tbor(&TborPartInfoReq::new())
        .unwrap_or_else(|e| panic!("{context}: PartInfo failed: {e:?}"))
}

/// Lifecycle stage the partition is provisioned to before the crash.
#[derive(Clone, Copy, Debug)]
enum Stage {
    /// No TBOR provisioning: `Enabled`.
    Enabled,
    /// `PartInit` only: `Initializing`.
    PartInit,
    /// `PartInit` and `PartFinal`: `Initialized`.
    PartFinal,
}

/// Provision the partition to `stage` on the CO `session`, leaving it in the
/// matching state.
fn provision_partition(
    ctx: &TestCtx,
    session: &SessionHandshake,
    pota: &PotaFixture,
    stage: Stage,
    context: &str,
) {
    let expected = match stage {
        Stage::Enabled => PART_STATE_ENABLED,
        Stage::PartInit | Stage::PartFinal => {
            let policy = part_policy(pota);
            let init = ctx
                .part_init(session, &mach_seed(), &policy)
                .unwrap_or_else(|e| panic!("{context}: PartInit failed: {e:?}"));
            if let Stage::PartFinal = stage {
                let chain = pota.chain_for(&pta_pub_from_csr(&init.pta_csr));
                ctx.part_final(session, &policy, &[], &chain.der_items())
                    .unwrap_or_else(|e| panic!("{context}: PartFinal failed: {e:?}"));
                PART_STATE_INITIALIZED
            } else {
                PART_STATE_INITIALIZING
            }
        }
    };
    assert_eq!(
        part_info(ctx, context).part_state,
        expected,
        "{context}: unexpected partition state after provisioning to {stage:?}",
    );
}

/// Wait for the host's recovery (Disable then Enable) to finish.
///
/// Until it does, `PartInfo` fails: it derives the identity public key from
/// the vault, which the crash erased, and only Enable re-imports the key.
/// So a successful `PartInfo` reporting `Enabled` marks the end of recovery,
/// even when the partition was already `Enabled` before the crash.
fn wait_for_recovery(ctx: &TestCtx) -> TborPartInfoResp {
    let start = Instant::now();
    thread::sleep(RECOVERY_SETTLE);
    loop {
        let info = ctx.tbor(&TborPartInfoReq::new());
        if let Ok(info) = &info {
            if info.part_state == PART_STATE_ENABLED {
                return *info;
            }
        }
        assert!(
            start.elapsed() < RECOVERY_TIMEOUT,
            "partition not recovered after {RECOVERY_TIMEOUT:?}; last PartInfo: {info:?}",
        );
        thread::sleep(Duration::from_secs(1));
    }
}

/// Crash the Admin core with the partition provisioned to `stage`, then
/// confirm it recovers to `Enabled` with the same identity, and that the host
/// can provision it again and open CO and CU sessions.
fn crash_and_recover(stage: Stage) {
    if tsra_ddi::sock_selected() {
        println!("Skipped TBOR crash test on the socket simulator.");
        return;
    }
    let _hardware_test_lock = HardwareTestLock::acquire();
    let ctx = TestCtx::new();

    if part_info(&ctx, "before crash").device_kind != DEVICE_KIND_PHYSICAL {
        println!("Skipped TBOR crash test for virtual device.");
        return;
    }

    // Provision through TBOR with a rotated CO session. The driver allows one
    // open session per file handle, so close CO before opening the CU session
    // used to inject the crash.
    let pota = PotaFixture::generate();
    let co = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    provision_partition(&ctx, &co, &pota, stage, "before crash");
    let before = part_info(&ctx, "before crash");
    ctx.session_close(co.session_id)
        .unwrap_or_else(|e| panic!("before crash: CO session close failed: {e:?}"));
    let cu = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    // Inject the crash through the handle that owns the CU session.
    let resp = helper_test_action_cmd(
        ctx.dev(),
        cu.session_id,
        TestActionRequest::TriggerCrash(DdiTestActionCrashReqInfo {
            crash_type: DdiTestActionCrashType::HardFault,
            cpu_id: DdiTestActionSocCpuId::Admin,
        }),
    );
    if let Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) = &resp {
        println!("TriggerCrash for Admin not supported by this firmware; skipping.");
        ctx.session_close(cu.session_id)
            .unwrap_or_else(|e| panic!("skip: CU session close failed: {e:?}"));
        return;
    }
    assert!(
        resp.is_err(),
        "TriggerCrash unexpectedly succeeded: {resp:?}"
    );

    // The partition must be back to Enabled, ready to be provisioned again,
    // with its identity kept.
    let after = wait_for_recovery(&ctx);
    assert_eq!(
        after.pid, before.pid,
        "after recovery: partition ID must be unchanged"
    );
    assert_eq!(
        after.pid_pub_key, before.pid_pub_key,
        "after recovery: partition identity key must be unchanged",
    );

    // Recovery's Disable leaves the crashed CU slot renegotiating, which
    // keeps it reserved across NSSR; release it with the plaintext close
    // (a protected close is rejected for a renegotiating slot).
    ctx.tbor(&TborSessionClosePlainReq {
        session_id: cu.session_id,
    })
    .unwrap_or_else(|e| panic!("after recovery: crashed CU session close failed: {e:?}"));

    ctx.cert_chain_info()
        .unwrap_or_else(|e| panic!("after recovery: GetCertChainInfo failed: {e:?}"));

    // Repeat the full host provisioning flow on the recovered partition. The
    // driver allows one open session per file handle, so close CO before
    // opening CU.
    let co = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    provision_partition(&ctx, &co, &pota, Stage::PartFinal, "after recovery");
    ctx.session_close(co.session_id)
        .unwrap_or_else(|e| panic!("after recovery: CO session close failed: {e:?}"));

    let cu = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    ctx.session_close(cu.session_id)
        .unwrap_or_else(|e| panic!("after recovery: CU session close failed: {e:?}"));
}

/// Crash on an `Enabled` partition (no TBOR provisioning).
#[test]
fn test_tbor_crash_recovery_hard_fault_admin_enabled() {
    crash_and_recover(Stage::Enabled);
}

/// Crash on an `Initializing` partition (after `PartInit`).
#[test]
fn test_tbor_crash_recovery_hard_fault_admin_after_part_init() {
    crash_and_recover(Stage::PartInit);
}

/// Crash on an `Initialized` partition (after `PartFinal`).
#[test]
fn test_tbor_crash_recovery_hard_fault_admin_after_part_final() {
    crash_and_recover(Stage::PartFinal);
}
