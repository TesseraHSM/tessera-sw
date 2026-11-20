// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crash-recovery integration test for a TBOR-provisioned partition.
//!
//! The test provisions the partition through TBOR (rotated CO session,
//! `PartInit`, `PartFinal`), injects a crash with the test-hook
//! [`DdiTestAction::TriggerCrash`](tsra_ddi_mbor_test_hooks::DdiTestAction),
//! waits for the firmware and driver to recover, and then repeats the host
//! provisioning flow to confirm the partition is usable again.
//!
//! Behaviour on this firmware:
//! - Requires a **physical** device; virtual devices are skipped.
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
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_ddi_tbor_types::POLICY_THUMBPRINT_LEN;

/// Seconds to wait for the firmware and driver to recover after a crash.
const RECOVERY_WAIT_SECS: u64 = 10;

/// `PartInfo` device kind reported by physical firmware.
const DEVICE_KIND_PHYSICAL: u8 = 2;

/// `HsmPartState::Enabled` wire discriminant.
const PART_STATE_ENABLED: u8 = 2;

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

/// Run `PartInit` then a first-instantiation `PartFinal` on `session`,
/// leaving the partition `Initialized`.
fn provision_partition(
    ctx: &TestCtx,
    session: &SessionHandshake,
    pota: &PotaFixture,
    context: &str,
) {
    let policy = part_policy(pota);
    let init = ctx
        .part_init(session, &mach_seed(), &policy)
        .unwrap_or_else(|e| panic!("{context}: PartInit failed: {e:?}"));
    let chain = pota.chain_for(&pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy, &[], &chain.der_items())
        .unwrap_or_else(|e| panic!("{context}: PartFinal failed: {e:?}"));
    assert_eq!(
        part_info(ctx, context).part_state,
        PART_STATE_INITIALIZED,
        "{context}: partition must be Initialized after PartFinal",
    );
}

/// Crash the Admin core on a TBOR-finalized partition, then confirm the
/// host can provision the partition again and open CO and CU sessions.
#[test]
fn test_tbor_crash_recovery_hard_fault_admin() {
    let _hardware_test_lock = HardwareTestLock::acquire();
    let ctx = TestCtx::new();

    if part_info(&ctx, "before crash").device_kind != DEVICE_KIND_PHYSICAL {
        println!("Skipped TBOR crash test for virtual device.");
        return;
    }

    // Provision through TBOR: rotated CO session, PartInit, PartFinal. The
    // driver allows one open session per file handle, so close CO before
    // opening the CU session used to inject the crash.
    let pota = PotaFixture::generate();
    let co = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    provision_partition(&ctx, &co, &pota, "before crash");
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

    thread::sleep(Duration::from_secs(RECOVERY_WAIT_SECS));

    // The crashed session is gone or needs renegotiation; closing it is
    // best-effort and its result is reported rather than asserted.
    let close = ctx.session_close(cu.session_id);
    println!("Close of pre-crash CU session after recovery: {close:?}");

    // After the host's recovery (Disable then Enable) the partition must be
    // back to Enabled, ready to be provisioned again.
    assert_eq!(
        part_info(&ctx, "after recovery").part_state,
        PART_STATE_ENABLED,
        "after recovery: partition must be Enabled for re-provisioning",
    );
    ctx.cert_chain_info()
        .unwrap_or_else(|e| panic!("after recovery: GetCertChainInfo failed: {e:?}"));

    // Repeat the host provisioning flow on the recovered partition. The
    // driver allows one open session per file handle, so close CO before
    // opening CU.
    let co = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    provision_partition(&ctx, &co, &pota, "after recovery");
    ctx.session_close(co.session_id)
        .unwrap_or_else(|e| panic!("after recovery: CO session close failed: {e:?}"));

    let cu = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    ctx.session_close(cu.session_id)
        .unwrap_or_else(|e| panic!("after recovery: CU session close failed: {e:?}"));
}
