// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Periodic negative self-test trigger, driven through the opaque
//! `TestAction` payload path.
//!
//! Set `TSRA_NEGATIVE_TEST_ID` to the self-test ID to fail; the test is
//! skipped when it is not set. The firmware accepts the request and runs that
//! periodic self-test shortly afterwards. Test IDs 0-4, 6 and 7 run on
//! Admin/FP; all other IDs run on the HSM.
//!
//! Behaviour on this firmware:
//! - Requires a **physical** device; virtual/mock devices are skipped.
//! - Requires firmware built with `tsra_test_hooks`; otherwise the request
//!   returns [`DdiStatus::UnsupportedCmd`] and the case is skipped.
//! - With `fips_validation_hooks` (on both CP cores) the selected self-test
//!   fails and the device enters the FIPS error state.

#![allow(clippy::unwrap_used)]

mod common;

use std::env;
use std::error::Error;
use std::thread;
use std::time::Duration;

use common::*;
use test_with_tracing::test;
use tsra_ddi::*;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_types::*;

const REV: DdiApiRev = DdiApiRev { major: 1, minor: 0 };
const MAX_NEGATIVE_TEST_ID: u32 = 76;

/// Seconds to wait for the queued self-test to run and, on validation
/// firmware, for the firmware and driver to recover from the failure.
const RECOVERY_WAIT_SECS: u64 = 20;

#[test]
fn trigger_negative_periodic_cast() {
    // Validate before the harness so a skipped run never erases the device.
    if read_neg_self_test_env_variable("TSRA_NEGATIVE_TEST_ID").is_err() {
        println!("TSRA_NEGATIVE_TEST_ID not set or invalid; skipping.");
        return;
    }

    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let test_id = read_neg_self_test_env_variable("TSRA_NEGATIVE_TEST_ID")
                .expect("TSRA_NEGATIVE_TEST_ID validated before setup");

            let resp = helper_close_session(dev, Some(session_id), Some(REV));
            assert!(resp.is_ok(), "{:?}", resp);

            send_negative_self_test(path.to_string(), test_id);
        },
    );
}

fn read_neg_self_test_env_variable(var_name: &str) -> Result<u32, Box<dyn Error>> {
    let env_var = env::var(var_name)?;
    parse_negative_self_test_id(&env_var)
}

fn parse_negative_self_test_id(input: &str) -> Result<u32, Box<dyn Error>> {
    let value: u32 = input.parse()?;
    if value > MAX_NEGATIVE_TEST_ID {
        return Err("invalid self-test ID".into());
    }
    Ok(value)
}

#[test]
fn validate_negative_self_test_id() {
    assert_eq!(parse_negative_self_test_id("0").unwrap(), 0);
    assert_eq!(parse_negative_self_test_id("76").unwrap(), 76);
    assert!(parse_negative_self_test_id("77").is_err());
    assert!(parse_negative_self_test_id("4294967295").is_err());
    assert!(parse_negative_self_test_id("invalid").is_err());
}

fn send_negative_self_test(device_path: String, test_id: u32) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();

    if get_device_kind(&mut dev) == DdiDeviceKind::Virtual {
        println!("Periodic self-test is only supported on a physical device; skipping.");
        return;
    }

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);
    let resp = helper_open_session(&dev, None, Some(REV), encrypted_credential, pub_key);
    assert!(resp.is_ok(), "{:?}", resp);
    let session_id = resp.unwrap().hdr.sess_id.unwrap();

    let resp = helper_test_action_cmd(
        &mut dev,
        session_id,
        TestActionRequest::ExecuteNegativeSelfTest(test_id),
    );
    if let Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) = &resp {
        println!("Firmware is not built with tsra_test_hooks.");
        return;
    }
    assert!(resp.is_ok(), "resp {:?}", resp);

    // The request is only queued; hold the hardware lock and defer cleanup until
    // the self-test has run and the firmware and driver have recovered.
    thread::sleep(Duration::from_secs(RECOVERY_WAIT_SECS));

    // Closing the session should still succeed after recovery.
    let resp = helper_close_session(&dev, Some(session_id), Some(REV));
    assert!(resp.is_ok(), "resp {:?}", resp);

    // Re-provision and re-open a session to prove the device is back.
    let _ = helper_common_establish_credential_no_unwrap(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);
    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);
    let resp = helper_open_session(&dev, None, Some(REV), encrypted_credential, pub_key);
    assert!(resp.is_ok(), "resp {:?}", resp);

    // Read the API revision to confirm the firmware is healthy again.
    let resp = helper_get_api_rev(&dev, None, None).unwrap();
    assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
    assert_eq!(resp.hdr.status, DdiStatus::Success);
}
