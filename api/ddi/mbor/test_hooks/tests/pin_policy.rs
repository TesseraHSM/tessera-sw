// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native Uno qualification: override-based cases require `tsra_test_hooks` and
//! are skipped when the firmware reports `UnsupportedCmd`. Emulator/mock runs do not qualify Uno.
//! Reference sampling durations and failure counts are preserved; normal runs include real waits.

#![allow(clippy::unwrap_used)]

mod common;

use std::cell::Cell;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use common::*;
use test_with_tracing::test;
use tsra_ddi::*;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_hooks::*;
use tsra_ddi_mbor_types::*;

type Dev = <DdiTest as Ddi>::Dev;
const ATTEMPTS: u16 = 1000;
const SAMPLE_DURATION: Duration = Duration::from_secs(5 * 60);
const EXPIRY_WAIT: Duration = Duration::from_secs(60 + 2);

fn revision() -> Option<DdiApiRev> {
    Some(DdiApiRev { major: 1, minor: 0 })
}

fn config() -> DdiTestActionPinPolicyConfig {
    DdiTestActionPinPolicyConfig {
        delay_increment: None,
        state: None,
        delay: None,
        allowed_attempts: None,
        lockout_delay: None,
    }
}

fn configure(dev: &mut Dev, session: u16, value: DdiTestActionPinPolicyConfig) {
    helper_test_action_cmd(dev, session, TestActionRequest::PinPolicyOverride(value))
        .expect("Uno tsra_test_hooks PIN-policy override is required");
}

fn clear(dev: &mut Dev, session: u16) {
    helper_test_action_cmd(dev, session, TestActionRequest::PinPolicyClear)
        .expect("Uno tsra_test_hooks PIN-policy clear is required");
}

type Body = fn(&mut Dev, &DdiTest, &str, u16);

thread_local! {
    // `ddi_dev_test` takes function pointers, so the body and per-device hook
    // support are passed through thread-local state.
    static BODY: Cell<Option<Body>> = const { Cell::new(None) };
    static HOOKS_SUPPORTED: Cell<bool> = const { Cell::new(false) };
}

fn cleanup(dev: &mut Dev, ddi: &DdiTest, path: &str, session: Option<u16>) {
    let result = session
        .filter(|_| HOOKS_SUPPORTED.get())
        .map(|id| helper_test_action_cmd(dev, id, TestActionRequest::PinPolicyClear));
    // Erase even if clearing the policy failed, including after a test panic.
    common_cleanup(dev, ddi, path, session);
    if let Some(result) = result {
        result.expect("clear PIN policy before cleanup");
    }
}

/// Runs `body` only when the firmware supports the PIN-policy test actions;
/// otherwise the case is skipped, like the other test-hook suites.
fn run(body: Body) {
    BODY.set(Some(body));
    ddi_dev_test(
        |dev, ddi, path| {
            let session = common_setup(dev, ddi, path);
            let result = helper_test_action_cmd(dev, session, TestActionRequest::PinPolicyClear);
            let supported = !matches!(&result, Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)));
            HOOKS_SUPPORTED.set(supported);
            if !supported {
                println!("Firmware is not built with tsra_test_hooks.");
            } else if result.is_err() {
                common_cleanup(dev, ddi, path, Some(session));
                result.expect("clear PIN policy before test");
            }
            session
        },
        cleanup,
        |dev, ddi, path, session| {
            if HOOKS_SUPPORTED.get() {
                BODY.get().expect("PIN-policy test body")(dev, ddi, path, session);
            }
        },
    );
}

fn attempt(dev: &Dev, id: [u8; 16], pin: [u8; 16]) -> DdiResult<DdiOpenSessionCmdResp> {
    let (credential, key) = encrypt_userid_pin_for_open_session(dev, id, pin, TEST_SESSION_SEED);
    helper_open_session(dev, None, revision(), credential, key)
}

fn wrong(dev: &Dev, expected: DdiStatus) {
    let mut pin = TEST_CRED_PIN;
    pin[0] ^= 1;
    let error = attempt(dev, TEST_CRED_ID, pin).unwrap_err();
    assert!(
        matches!(error, DdiError::DdiStatus(status) if status == expected),
        "{error:?}"
    );
}

fn valid(dev: &Dev) {
    let response = attempt(dev, TEST_CRED_ID, TEST_CRED_PIN).expect("valid PIN");
    helper_close_session(dev, Some(response.data.sess_id), revision())
        .expect("close temporary session");
}

fn seed_threshold(dev: &mut Dev, session: u16) {
    configure(
        dev,
        session,
        DdiTestActionPinPolicyConfig {
            state: Some(false),
            delay: Some(0),
            allowed_attempts: Some(ATTEMPTS - 1),
            lockout_delay: Some(0),
            ..config()
        },
    );
}

#[test]
fn invalid_pin_is_rejected() {
    ddi_dev_test(common_setup, common_cleanup, |dev, _, _, session| {
        helper_close_session(dev, Some(session), revision()).expect("close setup session");
        wrong(dev, DdiStatus::InvalidAppCredentials);
    });
}

#[test]
fn invalid_pin_reaches_threshold_and_command_errors_retain_accounting() {
    run(|_, ddi, path, _| {
        let dev = ddi.open_dev(path).unwrap();
        for _ in 0..ATTEMPTS {
            wrong(&dev, DdiStatus::InvalidAppCredentials);
        }
        for _ in 0..3 {
            wrong(&dev, DdiStatus::LoginFailed);
        }
        let error = attempt(&dev, TEST_CRED_ID, TEST_CRED_PIN).unwrap_err();
        assert!(matches!(error, DdiError::DdiStatus(DdiStatus::LoginFailed)));
    });
}

#[test]
fn failed_auth_then_valid_auth_resets_context() {
    ddi_dev_test(common_setup, common_cleanup, |_, ddi, path, _| {
        let attempt_dev = ddi.open_dev(path).unwrap();
        for _ in 0..ATTEMPTS {
            wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        }
        wrong(&attempt_dev, DdiStatus::LoginFailed);
        thread::sleep(EXPIRY_WAIT);
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        thread::sleep(EXPIRY_WAIT);
        valid(&attempt_dev);
        for _ in 0..ATTEMPTS {
            wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        }
        wrong(&attempt_dev, DdiStatus::LoginFailed);
    });
}

#[test]
fn forced_expiry_then_valid_auth_resets_context() {
    run(|dev, ddi, path, session| {
        let attempt_dev = ddi.open_dev(path).unwrap();
        seed_threshold(dev, session);
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        wrong(&attempt_dev, DdiStatus::LoginFailed);
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                lockout_delay: Some(0),
                ..config()
            },
        );
        valid(&attempt_dev);
        // A successful credential must reset both counter and factor.
        for _ in 0..ATTEMPTS {
            wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        }
        wrong(&attempt_dev, DdiStatus::LoginFailed);
    });
}

#[test]
fn delay_factor_rollover_restores_free_attempts() {
    run(|dev, ddi, path, session| {
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                delay_increment: Some(1),
                state: Some(false),
                delay: Some(32),
                allowed_attempts: Some(ATTEMPTS - 2),
                lockout_delay: Some(0),
            },
        );
        let attempt_dev = ddi.open_dev(path).unwrap();
        for _ in 0..2 {
            wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
            thread::sleep(Duration::from_secs(32 + 2));
        }
        for _ in 0..ATTEMPTS - 1 {
            wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        }
        valid(&attempt_dev);
    });
}

#[test]
fn locked_open_and_reopen_do_not_consume_nonce() {
    run(|dev, ddi, path, session| {
        let attempt_dev = ddi.open_dev(path).unwrap();
        let (credential, key) = encrypt_userid_pin_for_open_session(
            &attempt_dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                state: Some(false),
                lockout_delay: Some(60),
                ..config()
            },
        );
        let error = helper_open_session(
            &attempt_dev,
            None,
            revision(),
            credential.clone(),
            key.clone(),
        )
        .unwrap_err();
        assert!(matches!(error, DdiError::DdiStatus(DdiStatus::LoginFailed)));
        let error = helper_reopen_session(
            dev,
            session,
            revision(),
            credential.clone(),
            key.clone(),
            MborByteArray::from_slice(&[]).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(error, DdiError::DdiStatus(DdiStatus::LoginFailed)));
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                lockout_delay: Some(0),
                ..config()
            },
        );
        let response = helper_open_session(&attempt_dev, None, revision(), credential, key)
            .expect("locked rejection must leave the nonce usable");
        helper_close_session(&attempt_dev, Some(response.data.sess_id), revision()).unwrap();
    });
}

#[test]
fn reopen_authentication_counts_and_success_resets_before_later_failure() {
    run(|dev, ddi, path, session| {
        seed_threshold(dev, session);
        let mut pin = TEST_CRED_PIN;
        pin[0] ^= 1;
        let (credential, key) =
            encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, pin, TEST_SESSION_SEED);
        let error = helper_reopen_session(
            dev,
            session,
            revision(),
            credential,
            key,
            MborByteArray::from_slice(&[]).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
        ));
        let attempt_dev = ddi.open_dev(path).unwrap();
        wrong(&attempt_dev, DdiStatus::LoginFailed);
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                lockout_delay: Some(0),
                ..config()
            },
        );
        let (credential, key) = encrypt_userid_pin_for_open_session(
            dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );
        // Correct credential, invalid BMK: authentication succeeds before unmasking fails.
        assert!(helper_reopen_session(
            dev,
            session,
            revision(),
            credential,
            key,
            MborByteArray::from_slice(&[]).unwrap(),
        )
        .is_err());
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
    });
}

#[test]
fn all_zero_plaintext_credentials_are_counted() {
    run(|dev, ddi, path, session| {
        let attempt_dev = ddi.open_dev(path).unwrap();
        for (id, pin) in [([0; 16], TEST_CRED_PIN), (TEST_CRED_ID, [0; 16])] {
            clear(dev, session);
            seed_threshold(dev, session);
            let error = attempt(&attempt_dev, id, pin).unwrap_err();
            assert!(matches!(
                error,
                DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
            ));
            wrong(&attempt_dev, DdiStatus::LoginFailed);
        }
    });
}

#[test]
fn pre_authentication_failures_are_not_counted() {
    run(|dev, ddi, path, session| {
        let attempt_dev = ddi.open_dev(path).unwrap();
        for mutation in 0..4 {
            clear(dev, session);
            seed_threshold(dev, session);
            let (mut credential, mut key) = encrypt_userid_pin_for_open_session(
                &attempt_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            match mutation {
                0 => credential.nonce[0] ^= 1,
                1 => credential.tag[0] ^= 1,
                2 => credential.encrypted_pin = MborByteArray::from_slice(&[]).unwrap(),
                _ => key.key_kind = DdiKeyType::Ecc256Public,
            }
            let error =
                helper_open_session(&attempt_dev, None, revision(), credential, key).unwrap_err();
            assert!(
                !matches!(
                    error,
                    DdiError::DdiStatus(DdiStatus::InvalidAppCredentials | DdiStatus::LoginFailed)
                ),
                "{error:?}"
            );
            // If the malformed request counted, this would already be locked.
            wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
            wrong(&attempt_dev, DdiStatus::LoginFailed);
        }
    });
}

#[test]
fn clear_removes_the_volatile_delay_override() {
    run(|dev, ddi, path, session| {
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                delay_increment: Some(0),
                ..config()
            },
        );
        clear(dev, session);
        seed_threshold(dev, session);
        let attempt_dev = ddi.open_dev(path).unwrap();
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        wrong(&attempt_dev, DdiStatus::LoginFailed);
    });
}

#[test]
fn invalid_overrides_leave_an_existing_lock_unchanged() {
    run(|dev, ddi, path, session| {
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                state: Some(false),
                lockout_delay: Some(60),
                ..config()
            },
        );
        for bad in [
            DdiTestActionPinPolicyConfig {
                delay: Some(33),
                ..config()
            },
            DdiTestActionPinPolicyConfig {
                allowed_attempts: Some(ATTEMPTS),
                ..config()
            },
        ] {
            let result =
                helper_test_action_cmd(dev, session, TestActionRequest::PinPolicyOverride(bad));
            assert!(result.is_err(), "{result:?}");
        }
        wrong(&ddi.open_dev(path).unwrap(), DdiStatus::LoginFailed);
    });
}

#[test]
fn malformed_override_and_nonempty_clear_do_not_mutate_policy() {
    run(|dev, ddi, path, session| {
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                state: Some(false),
                lockout_delay: Some(60),
                ..config()
            },
        );
        for action in [
            TestActionRequest::PinPolicyOverride(config()),
            TestActionRequest::PinPolicyClear,
        ] {
            let mut data = DdiTestActionReq::try_from(action).unwrap();
            let mut bytes = data.payload.as_slice().to_vec();
            bytes.push(0);
            data.payload = MborByteArray::from_slice(&bytes).unwrap();
            let request = DdiTestActionCmdReq {
                hdr: DdiReqHdr {
                    op: DDI_OP_TEST_ACTION,
                    sess_id: Some(session),
                    rev: revision(),
                },
                data,
                ext: None,
            };
            assert!(dev.exec_op_mbor(&request, &mut None).is_err());
            wrong(&ddi.open_dev(path).unwrap(), DdiStatus::LoginFailed);
        }
    });
}

#[test]
fn explicit_lockout_delay_takes_precedence_over_factor_recomputation() {
    run(|dev, ddi, path, session| {
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                delay_increment: Some(60),
                state: Some(false),
                delay: Some(1),
                lockout_delay: Some(0),
                ..config()
            },
        );
        let attempt_dev = ddi.open_dev(path).unwrap();
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        wrong(&attempt_dev, DdiStatus::LoginFailed);
    });
}

#[test]
fn concurrent_stale_nonce_requests_count_only_the_authenticated_attempt() {
    run(|dev, ddi, path, session| {
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                state: Some(false),
                allowed_attempts: Some(ATTEMPTS - 2),
                lockout_delay: Some(0),
                ..config()
            },
        );
        let mut pin = TEST_CRED_PIN;
        pin[0] ^= 1;
        let attempt_dev = ddi.open_dev(path).unwrap();
        let (credential, key) =
            encrypt_userid_pin_for_open_session(&attempt_dev, TEST_CRED_ID, pin, TEST_SESSION_SEED);
        let errors = thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let credential = credential.clone();
                    let key = key.clone();
                    scope.spawn(move || {
                        let ddi = DdiTest::default();
                        let dev = ddi.open_dev(path).unwrap();
                        helper_open_session(&dev, None, revision(), credential, key).unwrap_err()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        let mut authenticated = 0;
        for error in errors {
            match error {
                DdiError::DdiStatus(DdiStatus::InvalidAppCredentials) => authenticated += 1,
                DdiError::DdiStatus(DdiStatus::NonceMismatch) => {}
                other => panic!("unexpected concurrent response: {other:?}"),
            }
        }
        assert_eq!(authenticated, 1);
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        wrong(&attempt_dev, DdiStatus::LoginFailed);
    });
}

fn sample_factor<const FACTOR: u16>(dev: &mut Dev, ddi: &DdiTest, path: &str, session: u16) {
    configure(
        dev,
        session,
        DdiTestActionPinPolicyConfig {
            delay_increment: Some(0),
            ..config()
        },
    );
    let attempt_dev = ddi.open_dev(path).unwrap();
    for _ in 0..u32::from(FACTOR) * u32::from(ATTEMPTS) {
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
    }
    configure(
        dev,
        session,
        DdiTestActionPinPolicyConfig {
            delay_increment: Some(1),
            ..config()
        },
    );

    let sample_period = Duration::from_millis(u64::from(FACTOR) * 1000 / 2 + 50);
    let start = Instant::now();
    let mut count = 0usize;
    thread::sleep(sample_period);
    while start.elapsed() < SAMPLE_DURATION {
        let expected = if count.is_multiple_of(2) {
            DdiStatus::LoginFailed
        } else {
            DdiStatus::InvalidAppCredentials
        };
        wrong(&attempt_dev, expected);
        count += 1;
        thread::sleep(sample_period);
    }

    configure(
        dev,
        session,
        DdiTestActionPinPolicyConfig {
            lockout_delay: Some(0),
            ..config()
        },
    );
    valid(&attempt_dev);
    for _ in 0..ATTEMPTS {
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
    }
    wrong(&attempt_dev, DdiStatus::LoginFailed);
}

#[test]
fn increase_delay_factor_and_expiry() {
    run(|_, ddi, path, _| {
        let attempt_dev = ddi.open_dev(path).unwrap();
        for _ in 0..ATTEMPTS {
            wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        }
        for _ in 0..100 {
            wrong(&attempt_dev, DdiStatus::LoginFailed);
        }
        thread::sleep(EXPIRY_WAIT);
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
    });
}

#[test]
fn accelerated_factor_increase_and_expiry() {
    run(|dev, ddi, path, session| {
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                delay_increment: Some(1),
                ..config()
            },
        );
        seed_threshold(dev, session);
        let attempt_dev = ddi.open_dev(path).unwrap();
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        wrong(&attempt_dev, DdiStatus::LoginFailed);
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                allowed_attempts: Some(ATTEMPTS - 1),
                ..config()
            },
        );
        thread::sleep(Duration::from_millis(1200));
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
        thread::sleep(Duration::from_millis(1200));
        wrong(&attempt_dev, DdiStatus::LoginFailed);
        thread::sleep(Duration::from_millis(1000));
        wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
    });
}

#[test]
fn delay_factor_1() {
    run(sample_factor::<1>);
}

#[test]
fn delay_factor_2() {
    run(sample_factor::<2>);
}

#[test]
fn delay_factor_8() {
    run(sample_factor::<8>);
}

#[test]
fn delay_factor_16() {
    run(sample_factor::<16>);
}

#[test]
fn delay_factor_32() {
    run(sample_factor::<32>);
}

#[test]
#[ignore = "requires externally orchestrated compatible IDFU during observation; does not perform IDFU"]
fn one_minute_policy_during_external_idfu() {
    run(|dev, ddi, path, session| {
        configure(
            dev,
            session,
            DdiTestActionPinPolicyConfig {
                state: Some(false),
                delay: Some(1),
                allowed_attempts: Some(0),
                lockout_delay: Some(0),
                ..config()
            },
        );
        let attempt_dev = ddi.open_dev(path).unwrap();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(600) {
            wrong(&attempt_dev, DdiStatus::InvalidAppCredentials);
            wrong(&attempt_dev, DdiStatus::LoginFailed);
            thread::sleep(Duration::from_secs(62));
        }
    });
}
