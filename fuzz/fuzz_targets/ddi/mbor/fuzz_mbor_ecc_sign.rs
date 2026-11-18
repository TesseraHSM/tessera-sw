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
use tsra_ddi_mbor_test_helpers::helper_ecc_generate_key_pair;
use tsra_ddi_mbor_test_helpers::helper_ecc_sign;
use tsra_ddi_mbor_test_helpers::helper_key_properties;
use tsra_ddi_mbor_types::*;

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
        let curve = match input.curve {
            DdiEccCurve::P256 | DdiEccCurve::P384 | DdiEccCurve::P521 => input.curve,
            _ => DdiEccCurve::P256,
        };
        let key_props = helper_key_properties(DdiKeyUsage::SignVerify, input.key_availability);
        let key_resp = helper_ecc_generate_key_pair(&dev, Some(sess_id), rev, curve, key_props);

        key_id = match key_resp {
            Ok(resp) => resp.data.private_key_id,
            Err(err) => {
                panic!("Could not generate ECC key pair: {}", err);
            }
        };
    }

    let resp = helper_ecc_sign(
        &dev,
        Some(sess_id),
        rev,
        key_id,
        cmdreq_data.digest,
        cmdreq_data.digest_algo,
    );

    if let Err(err @ DdiError::DriverError(_)) = &resp {
        panic!("Crash Detected: {err}");
    }

    if input.use_valid_key_id {
        helper_delete_key(&dev, Some(sess_id), rev, key_id).expect("Could not delete key");
    }

    cleanup_with_session(&dev, Some(sess_id));
}
