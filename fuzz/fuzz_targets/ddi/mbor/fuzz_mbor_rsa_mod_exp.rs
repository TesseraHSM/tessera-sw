// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../mbor_common.rs"]
mod common;

use common::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand::*;
use rand::rngs::StdRng;
use tsra_ddi::*;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_helpers::*;
use tsra_ddi_mbor_types::*;

/// Fuzz input for RSA Mod Exp DDI op.
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    /// Seed for deterministic random generation
    pub rand_seed: u64,
    /// If `true`, the fuzz test will generate a valid RSA key for modular exponentiation
    pub use_valid_key_id: bool,
    /// Specifies the availability property of the RSA key created during the test
    pub key_availability: DdiKeyAvailability,
    /// Size of the RSA key to generate
    pub key_size: RsaKeySize,
    /// A fuzzed `DdiRsaModExpReq` structure (used for fields except `y`)
    pub cmdreq_data: DdiRsaModExpReq,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_ddi_rsa_mod_exp(input);
});

pub fn fuzz_ddi_rsa_mod_exp(input: FuzzInput) {
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
            let key_resp = import_rsa_key(
                dev,
                sess_id,
                input.key_availability,
                rev,
                input.key_size as u16,
            );

            key_id = key_resp.expect("Could not get RSA key ID");
        }
        let mut rng = StdRng::seed_from_u64(input.rand_seed);
        let mut y_buf = vec![0u8; usize::from(input.key_size as u16) / 8];
        rng.fill_bytes(&mut y_buf);

        let y = MborByteArray::from_slice(&y_buf).expect("Failed to create y buffer");

        let resp = helper_rsa_mod_exp(dev, Some(sess_id), rev, key_id, y, cmdreq_data.op_type);

        if let Err(err @ DdiError::DriverError(_)) = &resp {
            panic!("Crash Detected: {err}");
        }

        if input.use_valid_key_id {
            helper_delete_key(dev, Some(sess_id), rev, key_id).expect("Could not delete RSA key");
        }

        cleanup_with_session(dev, Some(sess_id));
    });
}
