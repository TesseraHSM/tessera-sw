// Copyright (C) Microsoft Corporation. All rights reserved.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use libfuzzer_sys::arbitrary::Arbitrary;
use tsra_ddi::*;
use tsra_ddi_mbor_test_helpers::helper_aes_encrypt_decrypt;
use tsra_ddi_mbor_test_helpers::helper_aes_generate;
use tsra_ddi_mbor_test_helpers::helper_delete_key;
use tsra_ddi_mbor_test_helpers::helper_key_properties;
use tsra_ddi_mbor_types::*;
use common::*;
use libfuzzer_sys::fuzz_target;

/// Fuzz input for AES Encrypt/Decrypt DDI op.
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    // If `true`, the fuzz test will generate a valid AES key
    pub use_valid_key_id: bool,
    // Specifies the availability property of keys created during the test
    pub key_availability: DdiKeyAvailability,
    // Specifies the size of the AES key to be generated
    pub key_size: DdiAesKeySize,
    // A fuzzed `DdiAesEncryptDecryptReq` structure that provides the base for request parameters for the AES operation
    pub cmdreq_data: DdiAesEncryptDecryptReq,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_ddi_aes_encrypt_decrypt(input);
});

pub fn fuzz_ddi_aes_encrypt_decrypt(input: FuzzInput) {
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
        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, input.key_availability);
        let key_resp =
            helper_aes_generate(&dev, Some(sess_id), rev, input.key_size, None, key_props);

        key_id = match key_resp {
            Ok(resp) => resp.data.key_id,
            Err(err) => {
                panic!("Could not generate AES key: {}", err);
            }
        };
    }

    debug_print_control_flags(&format!(
        "Input use_valid_key_id: {}",
        input.use_valid_key_id
    ));
    static FUZZ_DDI_AES_INVOCATION: AtomicUsize = AtomicUsize::new(0);
    let invocation = FUZZ_DDI_AES_INVOCATION.fetch_add(1, Ordering::SeqCst) + 1;
    let effective_key_id = format!("Effective key_id: {:?}", key_id);
    debug_print_request_with_meta(
        "fuzz_ddi_aes_encrypt_decrypt",
        invocation,
        invocation,
        &cmdreq_data,
        Some(&effective_key_id),
    );

    let resp = helper_aes_encrypt_decrypt(
        &dev,
        Some(sess_id),
        rev,
        key_id,
        cmdreq_data.op,
        cmdreq_data.msg,
        cmdreq_data.iv,
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
