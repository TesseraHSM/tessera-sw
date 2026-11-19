// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../mbor_common.rs"]
mod common;

use common::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi::*;
use tsra_ddi_mbor_test_helpers::helper_delete_key;
use tsra_ddi_mbor_test_helpers::helper_hkdf_derive;
use tsra_ddi_mbor_test_helpers::helper_key_properties;
use tsra_ddi_mbor_types::*;

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
    common_fuzz_test(|dev| {
        helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

        let sess_id = match helper_common_open_session(dev) {
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
                create_secret_key(dev, sess_id, rev, input.key_curve, input.key_availability);

            key_id = match key_resp {
                Ok(id) => id,
                Err(err) => {
                    panic!("Could not create secret key: {}", err);
                }
            };
        }

        let key_props = helper_key_properties(input.key_usage, input.key_availability);

        let resp = helper_hkdf_derive(
            dev,
            Some(sess_id),
            rev,
            key_id,
            cmdreq_data.hash_algorithm,
            cmdreq_data.salt,
            cmdreq_data.info,
            cmdreq_data.key_type,
            key_props,
            cmdreq_data.key_length,
        );

        check_driver_error(resp);

        if input.use_valid_key_id {
            helper_delete_key(dev, Some(sess_id), rev, key_id).expect("Could not delete key");
        }

        cleanup_with_session(dev, Some(sess_id));
    });
}
