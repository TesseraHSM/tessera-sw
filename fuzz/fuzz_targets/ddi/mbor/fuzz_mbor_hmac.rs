// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../mbor_common.rs"]
mod common;

use common::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_mbor_test_helpers::*;
use tsra_ddi_mbor_types::*;

/// Fuzz input for HMAC DDI op.
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    /// If `true`, the fuzz test will generate a valid hmac key
    pub use_valid_key_id: bool,
    /// Specifies the availability property of keys created during the test
    pub key_availability: DdiKeyAvailability,
    /// Selects the elliptic curve to be used for ECC key generation
    pub key_curve: DdiEccCurve,
    /// Specifies the type of HMAC key to create
    pub hmac_key_type: HmacKeyType,
    /// Specifies the hash algorithm to use for HMAC operations
    pub hash_algorithm: DdiHashAlgorithm,
    /// A fuzzed `DdiHmacReq` structure that provides the base for request parameters for the HMAC operation
    pub cmdreq_data: Bounded<DdiHmacReq>,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_ddi_hmac(input);
});

pub fn fuzz_ddi_hmac(input: FuzzInput) {
    common_fuzz_test(|dev| {
        helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

        let sess_id = match helper_common_open_session(dev) {
            Ok(id) => id,
            Err(err) => {
                panic!("Could not open session: {}", err);
            }
        };

        let cmdreq_data = input.cmdreq_data.0;
        let rev = Some(DdiApiRev { major: 1, minor: 0 });
        let mut key_id = cmdreq_data.key_id;

        if input.use_valid_key_id {
            let key_resp = helper_create_hmac_key(
                dev,
                sess_id,
                rev,
                input.key_availability,
                input.key_curve,
                input.hmac_key_type,
                input.hash_algorithm,
            );

            key_id = match key_resp {
                Ok(id) => id,
                Err(err) => {
                    panic!("Could not create HMAC key: {:?}", err);
                }
            };
        }

        let resp = helper_hmac(dev, Some(sess_id), rev, key_id, cmdreq_data.msg);

        check_driver_error(resp);

        if input.use_valid_key_id {
            helper_delete_key(dev, Some(sess_id), rev, key_id).expect("Could not delete key");
        }

        cleanup_with_session(dev, Some(sess_id));
    });
}
