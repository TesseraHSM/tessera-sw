// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Negative pairwise consistency test (PCT) integration tests, driven through
//! `TestAction::TriggerNegativePctFailure`.
//!
//! Each test arms the partition for one PCT kind with a skip count of 0, then
//! runs the operation whose PCT that kind names. The firmware corrupts that
//! PCT, the PCT reports the key pair as inconsistent, and the module enters
//! the FIPS error state: CP1 halts with the operation in flight and the device
//! resets. The test then waits and checks that the device has recovered.
//!
//! | Test | Kind | Operation after arming | Firmware log code |
//! |---|---|---|---|
//! | `ecc_keygen_p*_sign_pct_failure` | `EccKeyGen` | `EccGenerateKeyPair`, sign/verify | `PctValidationEccGenKeyFailed` |
//! | `ecc_keygen_p*_ecdh_pct_failure` | `EccKeyGen` | `EccGenerateKeyPair`, derive | `PctValidationEccGenKeyFailed` |
//! | `unwrapping_key_pct_failure_on_get_unwrapping_key` | `UnwrappingKey` | `GetUnwrappingKey` | `PctValidationUnwrappingKeyFailed` |
//! | `partition_id_key_pct_failure_on_nssr` | `PartitionIdKey` | `erase()` (NSSR) | `PartitionIdKeyGenerationPctFailed` |
//! | `establish_cred_key_pct_failure_on_nssr` | `EstablishCredKey` | `erase()` (NSSR) | `PctValidationEstablishCredEncKeyFailed` |
//! | `session_enc_key_pct_failure_on_nssr` | `SessionEncKey` | `erase()` (NSSR) | `PctValidationSessionEncKeyFailed` |
//!
//! The host sees every failure the same way, as an aborted or failed
//! operation, so the firmware log code is what shows which PCT failed. The
//! CP1 debug log (`debuglogread`) records it as message 238 (PCT injected,
//! `arg1` = kind) followed by 242 (FIPS error state, `arg1` = log code).
//!
//! An NSSR regenerates the partition identity, establish-credential and
//! session-encryption keys, each with its PCT, so `erase()` is the operation
//! for those three kinds. Partition initialization creates the identity key
//! through the same code, so the NSSR test covers it too.
//!
//! The three NSSR tests are **manual** (`#[ignore]`). The module halts while
//! the NSSR itself is in flight, so the driver's NSSR request fails (for
//! example with `ETIMEDOUT`) and the driver does not re-attach to the device
//! after it resets. Run one with `--ignored`, confirm the 238/242 records in
//! the debug log, then reload the driver before running anything else.
//!
//! Behaviour on this firmware:
//! - Requires a **physical** device; virtual and mock devices are skipped.
//! - Requires firmware built with both `tsra_test_hooks` and
//!   `fips_validation_hooks`; otherwise arming returns
//!   [`DdiStatus::UnsupportedCmd`] and the test is skipped.
//! - Each test resets the device. Run one test per invocation, with
//!   `--test-threads 1`, and let the device recover in between.

#![allow(clippy::unwrap_used)]

mod common;

use std::thread;
use std::time::Duration;
use std::time::Instant;

use common::*;
use test_with_tracing::test;
use tsra_ddi::*;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::DdiTestActionNegativePctFailureReqInfo;
use tsra_ddi_mbor_test_hooks::DdiTestActionNegativePctKind;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_types::*;

const REV: DdiApiRev = DdiApiRev { major: 1, minor: 0 };

/// Seconds to wait for the firmware and driver to recover after the device
/// enters the FIPS error state and resets.
const RECOVERY_WAIT_SECS: u64 = 10;

/// Upper bound on waiting for the SP to publish the unwrapping key.
const UNWRAPPING_KEY_WAIT: Duration = Duration::from_secs(120);

/// Interval between `GetUnwrappingKey` retries while the key is pending.
const UNWRAPPING_KEY_RETRY: Duration = Duration::from_secs(2);

/// ECC key generation with a sign/verify key, P-256.
#[test]
fn ecc_keygen_p256_sign_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            ecc_keygen_pct_failure(dev, session_id, DdiEccCurve::P256, DdiKeyUsage::SignVerify);
        },
    );
}

/// ECC key generation with a sign/verify key, P-384.
#[test]
fn ecc_keygen_p384_sign_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            ecc_keygen_pct_failure(dev, session_id, DdiEccCurve::P384, DdiKeyUsage::SignVerify);
        },
    );
}

/// ECC key generation with a sign/verify key, P-521.
#[test]
fn ecc_keygen_p521_sign_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            ecc_keygen_pct_failure(dev, session_id, DdiEccCurve::P521, DdiKeyUsage::SignVerify);
        },
    );
}

/// ECC key generation with a key-agreement (ECDH) key, P-256.
#[test]
fn ecc_keygen_p256_ecdh_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            ecc_keygen_pct_failure(dev, session_id, DdiEccCurve::P256, DdiKeyUsage::Derive);
        },
    );
}

/// ECC key generation with a key-agreement (ECDH) key, P-384.
#[test]
fn ecc_keygen_p384_ecdh_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            ecc_keygen_pct_failure(dev, session_id, DdiEccCurve::P384, DdiKeyUsage::Derive);
        },
    );
}

/// ECC key generation with a key-agreement (ECDH) key, P-521.
#[test]
fn ecc_keygen_p521_ecdh_pct_failure() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            ecc_keygen_pct_failure(dev, session_id, DdiEccCurve::P521, DdiKeyUsage::Derive);
        },
    );
}

/// The partition's RSA unwrapping key, tested again when the host next asks
/// for it.
#[test]
fn unwrapping_key_pct_failure_on_get_unwrapping_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !is_physical(dev)
                || !arm(dev, session_id, DdiTestActionNegativePctKind::UnwrappingKey)
            {
                return;
            }

            // Until the SP has published the key, the firmware reports it pending.
            // The first request after that runs the key's PCT and fails.
            let deadline = Instant::now() + UNWRAPPING_KEY_WAIT;
            let resp = loop {
                let resp = helper_get_unwrapping_key(dev, Some(session_id), Some(REV));
                if !matches!(
                    resp,
                    Err(DdiError::DdiStatus(DdiStatus::PendingKeyGeneration))
                ) || Instant::now() >= deadline
                {
                    break resp;
                }
                thread::sleep(UNWRAPPING_KEY_RETRY);
            };
            expect_pct_halt(resp, "GetUnwrappingKey");

            verify_recovery(dev, session_id);
        },
    );
}

/// The partition identity key, regenerated by an NSSR.
#[test]
#[ignore = "needs manual intervention: the NSSR halt leaves the driver detached; reload the driver after the test"]
fn partition_id_key_pct_failure_on_nssr() {
    ddi_dev_test(common_setup, nssr_cleanup, |dev, ddi, path, session_id| {
        nssr_pct_failure(
            dev,
            ddi,
            path,
            session_id,
            DdiTestActionNegativePctKind::PartitionIdKey,
        );
    });
}

/// The establish-credential encryption key, regenerated by an NSSR.
#[test]
#[ignore = "needs manual intervention: the NSSR halt leaves the driver detached; reload the driver after the test"]
fn establish_cred_key_pct_failure_on_nssr() {
    ddi_dev_test(common_setup, nssr_cleanup, |dev, ddi, path, session_id| {
        nssr_pct_failure(
            dev,
            ddi,
            path,
            session_id,
            DdiTestActionNegativePctKind::EstablishCredKey,
        );
    });
}

/// The session encryption key, regenerated by an NSSR.
#[test]
#[ignore = "needs manual intervention: the NSSR halt leaves the driver detached; reload the driver after the test"]
fn session_enc_key_pct_failure_on_nssr() {
    ddi_dev_test(common_setup, nssr_cleanup, |dev, ddi, path, session_id| {
        nssr_pct_failure(
            dev,
            ddi,
            path,
            session_id,
            DdiTestActionNegativePctKind::SessionEncKey,
        );
    });
}

/// Arms `kind`, generates an ECC key pair of `curve` with `usage`, and checks
/// that its PCT failure halts the module.
fn ecc_keygen_pct_failure(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    curve: DdiEccCurve,
    usage: DdiKeyUsage,
) {
    if !is_physical(dev) || !arm(dev, session_id, DdiTestActionNegativePctKind::EccKeyGen) {
        return;
    }

    let resp = helper_ecc_generate_key_pair(
        dev,
        Some(session_id),
        Some(REV),
        curve,
        helper_key_properties(usage, DdiKeyAvailability::App),
    );
    expect_pct_halt(resp, "EccGenerateKeyPair");

    verify_recovery(dev, session_id);
}

/// Arms `kind`, issues an NSSR, and checks that the NSSR fails because the
/// PCT of the partition key that `kind` names halted the module.
///
/// The halt interrupts the NSSR itself, so how the failure surfaces depends
/// on the driver (typically `ETIMEDOUT`), and the driver stays detached once
/// the device has reset. Recovery therefore isn't checked here; the debug log
/// confirms which PCT failed.
///
/// The setup session is closed before the NSSR. An NSSR keeps established
/// sessions for renegotiation and the halted device then warm-resets, which
/// preserves them, so an open session would keep its slot until power-on.
fn nssr_pct_failure(
    dev: &mut <DdiTest as Ddi>::Dev,
    ddi: &DdiTest,
    path: &str,
    session_id: u16,
    kind: DdiTestActionNegativePctKind,
) {
    if !is_physical(dev) || !arm(dev, session_id, kind) {
        return;
    }

    // The arm is per partition, so it survives closing the session.
    let resp = helper_close_session(dev, Some(session_id), Some(REV));
    assert!(resp.is_ok(), "resp {:?}", resp);

    match ddi.open_dev(path).unwrap().erase() {
        Err(err) => println!("erase (NSSR) failed as expected: {err:?}"),
        Ok(()) => panic!("erase (NSSR) unexpectedly succeeded"),
    }
    println!(
        "Check debuglogread for message 238 (arg1 = {}) then 242, and reload the driver.",
        kind.0
    );
}

/// Cleanup for the NSSR tests: the test already closed its session, and the
/// driver is detached after the halt, so there is no device to erase.
fn nssr_cleanup(
    _dev: &mut <DdiTest as Ddi>::Dev,
    _ddi: &DdiTest,
    _path: &str,
    _session_to_close: Option<u16>,
) {
}

/// Whether `dev` is a physical device; prints why the test is skipped if not.
fn is_physical(dev: &mut <DdiTest as Ddi>::Dev) -> bool {
    let physical = get_device_kind(dev) == DdiDeviceKind::Physical;
    if !physical {
        println!("Negative PCT tests require a physical device; skipping.");
    }
    physical
}

/// Arms the partition so that the next PCT of `kind` fails.
///
/// Returns `false`, so the caller skips the test, when the firmware doesn't
/// support the action.
fn arm(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    kind: DdiTestActionNegativePctKind,
) -> bool {
    let resp = helper_test_action_cmd(
        dev,
        session_id,
        TestActionRequest::TriggerNegativePctFailure(DdiTestActionNegativePctFailureReqInfo {
            neg_pct_skip_cnt: 0,
            pct_kind: kind,
        }),
    );
    match resp {
        Ok(_) => true,
        Err(err) if is_unsupported_cmd(&err) => false,
        Err(err) => panic!("Arming the negative PCT failed: {err:?}"),
    }
}

/// Checks that `resp`, the result of `op`, shows that the module halted while
/// `op` was in flight.
fn expect_pct_halt<T: std::fmt::Debug>(resp: DdiResult<T>, op: &str) {
    match resp {
        Err(err) => {
            println!("{op} failed as expected: {err:?}");
            assert!(
                matches!(
                    err,
                    DdiError::DriverError(DriverError::IoAborted)
                        | DdiError::DriverError(DriverError::IoAbortInProgress)
                        | DdiError::DeviceNotReady
                ),
                "{op} failed with an unexpected error: {err:?}"
            );
        }
        Ok(resp) => panic!("{op} unexpectedly succeeded: {resp:?}"),
    }
}

/// Waits for the device to recover from the FIPS error state, then checks that
/// it serves requests again.
fn verify_recovery(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16) {
    thread::sleep(Duration::from_secs(RECOVERY_WAIT_SECS));

    // Closing the session that was open when the module halted still succeeds.
    let resp = helper_close_session(dev, Some(session_id), Some(REV));
    assert!(resp.is_ok(), "resp {:?}", resp);

    // Re-provision and open a new session.
    let _ = helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);
    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);
    let resp = helper_open_session(dev, None, Some(REV), encrypted_credential, pub_key);
    assert!(resp.is_ok(), "resp {:?}", resp);
    let new_session_id = resp.unwrap().hdr.sess_id.unwrap();

    let resp = helper_get_api_rev(dev, None, None);
    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = helper_close_session(dev, Some(new_session_id), Some(REV));
    assert!(resp.is_ok(), "resp {:?}", resp);
}
