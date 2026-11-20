// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../mbor_common.rs"]
mod common;

use common::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand::rngs::StdRng;
use rand::*;
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
    /// If `true`, generate a modulus-sized operand; otherwise use the fuzzed `y`
    pub use_valid_operand: bool,
    /// If `true`, import a key with permissions for the opposite operation
    pub mismatch_key_usage: bool,
    /// A fuzzed `DdiRsaModExpReq` structure
    pub cmdreq_data: Bounded<DdiRsaModExpReq>,
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

        let cmdreq_data = input.cmdreq_data.0;
        let rev = Some(DdiApiRev { major: 1, minor: 0 });
        let mut key_id = cmdreq_data.key_id;

        if input.use_valid_key_id {
            let decrypt = (cmdreq_data.op_type == DdiRsaOpType::Decrypt) ^ input.mismatch_key_usage;
            let usage = if decrypt {
                DdiKeyUsage::EncryptDecrypt
            } else {
                DdiKeyUsage::SignVerify
            };
            let key_resp = import_rsa_key(
                dev,
                sess_id,
                input.key_availability,
                rev,
                input.key_size as u16,
                usage,
            );

            key_id = key_resp.expect("Could not get RSA key ID");
        }
        let y = if input.use_valid_operand {
            let mut rng = StdRng::seed_from_u64(input.rand_seed);
            let len = usize::from(input.key_size as u16) / 8;
            let mut y_buf = vec![0u8; len];
            rng.fill_bytes(&mut y_buf);
            // Stay below the modulus in either device byte order, and above one.
            y_buf[0] &= 0x7f;
            y_buf[len - 1] &= 0x7f;
            y_buf[len / 2] |= 1;
            MborByteArray::from_slice(&y_buf).expect("Failed to create y buffer")
        } else {
            cmdreq_data.y
        };

        let resp = helper_rsa_mod_exp(dev, Some(sess_id), rev, key_id, y, cmdreq_data.op_type);

        check_driver_error(resp);

        if input.use_valid_key_id {
            helper_delete_key(dev, Some(sess_id), rev, key_id).expect("Could not delete RSA key");
        }

        cleanup_with_session(dev, Some(sess_id));
    });
}
