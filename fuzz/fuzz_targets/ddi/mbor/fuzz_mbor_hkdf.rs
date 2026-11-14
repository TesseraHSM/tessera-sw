// Copyright (C) Microsoft Corporation. All rights reserved.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use libfuzzer_sys::arbitrary::Arbitrary;
use tsra_ddi::*;
use tsra_ddi_mbor_test_helpers::helper_delete_key;
use tsra_ddi_mbor_test_helpers::helper_hkdf_derive;
use tsra_ddi_mbor_test_helpers::helper_key_properties;
use tsra_ddi_mbor_types::*;
use common::*;
use libfuzzer_sys::fuzz_target;

/// Fuzz input for HKDF Derive DDI op.
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    /// If `true`, the fuzz test will generate a valid secret key
    pub use_valid_key_id: bool,
    /// Specifies the availability property of keys created during the test
    pub key_availability: DdiKeyAvailability,
    /// Specifies the intended usage of keys created during the test
    pub key_usage: DdiKeyUsage,
    /// Selects the elliptic curve to be used for ECC key generation
    pub key_curve: DdiEccCurve,
    /// A fuzzed `DdiHkdfDeriveReq` structure that provides the base for request parameters for the HKDF derive operation
    pub cmdreq_data: DdiHkdfDeriveReq,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_ddi_hkdf_derive(input);
});

pub fn fuzz_ddi_hkdf_derive(input: FuzzInput) {
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
        let key_resp =
            create_secret_key(&dev, sess_id, rev, input.key_curve, input.key_availability);

        key_id = match key_resp {
            Ok(id) => id,
            Err(err) => {
                panic!("Could not create secret key: {}", err);
            }
        };
    }

    debug_print_control_flags(&format!(
        "Input use_valid_key_id: {}",
        input.use_valid_key_id
    ));
    let key_props = helper_key_properties(input.key_usage, input.key_availability);

    static FUZZ_DDI_HKDF_INVOCATION: AtomicUsize = AtomicUsize::new(0);
    let invocation = FUZZ_DDI_HKDF_INVOCATION.fetch_add(1, Ordering::SeqCst) + 1;
    let effective_key_id = format!("Effective key_id: {:?}", key_id);
    debug_print_request_with_meta(
        "fuzz_ddi_hkdf_derive",
        invocation,
        invocation,
        &cmdreq_data,
        Some(&effective_key_id),
    );

    let resp = helper_hkdf_derive(
        &dev,
        Some(sess_id),
        rev,
        key_id,
        cmdreq_data.hash_algorithm,
        cmdreq_data.salt,
        cmdreq_data.info,
        cmdreq_data.key_type,
        cmdreq_data.key_tag,
        key_props,
        cmdreq_data.key_length,
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
