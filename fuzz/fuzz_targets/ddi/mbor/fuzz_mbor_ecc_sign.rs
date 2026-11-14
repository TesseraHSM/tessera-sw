// Copyright (C) Microsoft Corporation. All rights reserved.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use libfuzzer_sys::arbitrary::Arbitrary;
use tsra_ddi::*;
use tsra_ddi_mbor_test_helpers::helper_delete_key;
use tsra_ddi_mbor_test_helpers::helper_ecc_generate_key_pair;
use tsra_ddi_mbor_test_helpers::helper_ecc_sign;
use tsra_ddi_mbor_test_helpers::helper_key_properties;
use tsra_ddi_mbor_types::*;
use common::*;
use libfuzzer_sys::fuzz_target;

/// Fuzz input for ECC Sign DDI op.
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    // If `true`, the fuzz test will generate a valid ECC private key
    pub use_valid_key_id: bool,
    // Specifies the availability property of keys created during the test
    pub key_availability: DdiKeyAvailability,
    // Selects the elliptic curve to be used for ECC key generation
    pub curve: DdiEccCurve,
    // A fuzzed `DdiEccSignReq` structure that provides the base for request parameters for the ECC sign operation
    pub cmdreq_data: DdiEccSignReq,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_ddi_ecc_sign(input);
});

pub fn fuzz_ddi_ecc_sign(input: FuzzInput) {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();
    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    let mut dev = ddi
        .open_dev(&dev_infos[0].path)
        .expect("Failed to open device");

    cleanup(&ddi, &dev_infos[0].path, None);
    helper_common_establish_credential(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);

    let sess_id = match helper_common_open_session(&mut dev) {
        Ok(id) => id,
        Err(err) => {
            panic!("Could not open session: {}", err);
        }
    };

    let cmdreq_data = input.cmdreq_data;
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let mut key_id = cmdreq_data.key_id;

    if input.use_valid_key_id {
        let key_props = helper_key_properties(DdiKeyUsage::SignVerify, input.key_availability);
        let key_resp =
            helper_ecc_generate_key_pair(&dev, Some(sess_id), rev, input.curve, None, key_props);

        key_id = match key_resp {
            Ok(resp) => resp.data.private_key_id,
            Err(err) => {
                panic!("Could not generate ECC key pair: {}", err);
            }
        };
    }
    debug_print_control_flags(&format!(
        "Input use_valid_key_id: {}",
        input.use_valid_key_id
    ));
    static FUZZ_DDI_ECC_SIGN_INVOCATION: AtomicUsize = AtomicUsize::new(0);
    let invocation = FUZZ_DDI_ECC_SIGN_INVOCATION.fetch_add(1, Ordering::SeqCst) + 1;
    let effective_key_id = format!("Effective key_id: {:?}", key_id);
    debug_print_request_with_meta(
        "fuzz_ddi_ecc_sign",
        invocation,
        invocation,
        &cmdreq_data,
        Some(&effective_key_id),
    );

    let resp = helper_ecc_sign(
        &dev,
        Some(sess_id),
        rev,
        key_id,
        cmdreq_data.digest,
        cmdreq_data.digest_algo,
    );

    if let Err(err) = &resp {
        if matches!(err, DdiError::DriverError(_)) {
            panic!("Crash Detected: {}", err);
        } else {
            debug_print_control_flags(&format!("Other error detected: {}", err));
        }
    }

    if input.use_valid_key_id {
        helper_delete_key(&dev, Some(sess_id), rev, key_id).expect("Could not delete key");
    }

    cleanup_with_session(&dev, Some(sess_id));
}
