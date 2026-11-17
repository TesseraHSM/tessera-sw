// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../mbor_common.rs"]
mod common;

use common::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tsra_crypto::ExportableKey;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::RsaPrivateKey;
use tsra_ddi::*;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_helpers::helper_delete_key;
use tsra_ddi_mbor_test_helpers::helper_get_unwrapping_key;
use tsra_ddi_mbor_test_helpers::helper_key_properties;
use tsra_ddi_mbor_test_helpers::helper_rsa_unwrap;
use tsra_ddi_mbor_types::*;

/// Fuzz input for RSA Unwrap DDI op.
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    /// If `true`, the fuzz test will generate a valid RSA key for unwrapping
    pub use_valid_key_id: bool,
    /// If `true`, the fuzz test will generate a valid wrapped blob using the device's unwrapping key
    pub use_valid_wrapped_blob: bool,
    /// Seed used to deterministically generate an invalid wrapped blob when `use_valid_wrapped_blob` is false
    pub wrapped_blob_seed: u64,
    /// Specifies the availability property of the RSA key created during the test
    pub key_availability: DdiKeyAvailability,
    /// Specifies the intended usage of keys created during the test
    pub key_usage: DdiKeyUsage,
    /// Size of the RSA key to generate
    pub key_size: RsaKeySize,
    /// A fuzzed `DdiRsaUnwrapReq` structure that provides the base for request parameters for the RSA unwrap operation
    pub cmdreq_data: DdiRsaUnwrapReq,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_ddi_rsa_unwrap(input);
});

pub fn fuzz_ddi_rsa_unwrap(input: FuzzInput) {
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

    let mut cmdreq_data = input.cmdreq_data;
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let mut key_id = cmdreq_data.key_id;

    if input.use_valid_key_id || input.use_valid_wrapped_blob {
        let unwrapping_resp = helper_get_unwrapping_key(&dev, Some(sess_id), rev)
            .expect("Could not get unwrapping key");

        if input.use_valid_key_id {
            key_id = unwrapping_resp.data.key_id;
        }

        if input.use_valid_wrapped_blob {
            let unwrap_pub_key_der = unwrapping_resp.data.pub_key.der.as_slice();

            let private_key = RsaPrivateKey::generate(input.key_size as usize)
                .expect("Could not generate RSA private key");

            let private_key_der = private_key
                .to_vec()
                .expect("Could not serialize RSA private key DER");

            let wrapped_blob = wrap_data(unwrap_pub_key_der, private_key_der.as_slice())
                .expect("Could not create valid wrapped blob");

            cmdreq_data.wrapped_blob = MborByteArray::from_slice(&wrapped_blob)
                .expect("Could not convert valid wrapped blob to request buffer");
            cmdreq_data.wrapped_blob_key_class = DdiKeyClass::Rsa;
            cmdreq_data.wrapped_blob_padding = DdiRsaCryptoPadding::Oaep;
            cmdreq_data.wrapped_blob_hash_algorithm = DdiHashAlgorithm::Sha256;
        }
    }

    if !input.use_valid_wrapped_blob {
        let mut rng = StdRng::seed_from_u64(input.wrapped_blob_seed);
        let mut invalid_blob = [0u8; 3072];
        rng.fill_bytes(&mut invalid_blob);

        cmdreq_data.wrapped_blob = MborByteArray::new(invalid_blob, invalid_blob.len())
            .expect("Failed to create randomized wrapped blob");
    }

    let key_props = helper_key_properties(input.key_usage, input.key_availability);

    let resp = helper_rsa_unwrap(
        &dev,
        Some(sess_id),
        rev,
        key_id,
        cmdreq_data.wrapped_blob,
        cmdreq_data.wrapped_blob_key_class,
        cmdreq_data.wrapped_blob_padding,
        cmdreq_data.wrapped_blob_hash_algorithm,
        key_props,
    );

    if let Ok(resp) = resp {
        let rsa_unwrapped_key_id = resp.data.key_id;
        // Clean up the unwrapped key if it was created successfully
        helper_delete_key(&dev, Some(sess_id), rev, rsa_unwrapped_key_id)
            .expect("Could not delete unwrapped key");
    } else if let Err(err @ DdiError::DriverError(_)) = &resp {
        panic!("Crash Detected: {err}");
    }

    cleanup_with_session(&dev, Some(sess_id));
}
