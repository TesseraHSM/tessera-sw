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
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_helpers::helper_establish_credential;
use tsra_ddi_mbor_types::*;

/// Fuzz input for Establish Credential DDI op.
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    /// If `true`, the fuzz test will generate a valid pub key
    pub use_valid_pub_key: bool,
    /// If 'true', the fuzz test will generate a valid value for the masked_bk3 field
    pub use_valid_masked_bk3: bool,
    /// If 'true', the fuzz test will generate a valid value for pota_pub_key field
    pub use_valid_pota_pub_key: bool,
    /// If 'true', the fuzz test will generate a valid value for encrypted_credential field
    pub use_valid_encrypted_credential: bool,
    /// If 'true', the fuzz test will generate a valid value for pota_sig field
    pub use_valid_pota_sig: bool,
    /// A fuzzed `DdiEstablishCredentialReq` structure that provides the base for request parameters for the Establish Credential operation
    pub cmdreq_data: DdiEstablishCredentialReq,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_ddi_establish_credential(input);
});

pub fn fuzz_ddi_establish_credential(input: FuzzInput) {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();
    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    let dev = ddi
        .open_dev(&dev_infos[0].path)
        .expect("Failed to open device");

    cleanup(&ddi, &dev_infos[0].path, None);

    // Note: This test case to fuzz "EstablishCredential" does not need prior credential

    let mut cmdreq_data = input.cmdreq_data;
    let rev = Some(DdiApiRev { major: 1, minor: 0 });

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_establish_cred(&dev, TEST_CRED_ID, TEST_CRED_PIN);

    if input.use_valid_pub_key {
        cmdreq_data.pub_key = pub_key;
    }

    if input.use_valid_encrypted_credential {
        cmdreq_data.encrypted_credential = encrypted_credential;
    }

    if input.use_valid_masked_bk3 {
        cmdreq_data.masked_bk3 = helper_get_or_init_bk3(&dev);
    }

    let (signature, pota_pub_key) = get_pota_endorsement(&dev);
    if input.use_valid_pota_pub_key {
        cmdreq_data.pota_pub_key = DdiDerPublicKey {
            der: MborByteArray::from_slice(&pota_pub_key)
                .expect("Failed to create MborByteArray from POTA ECC public key"),
            key_kind: DdiKeyType::Ecc384Public,
        };
    }

    if input.use_valid_pota_sig {
        cmdreq_data.pota_sig = MborByteArray::from_slice(&signature)
            .expect("Failed to create MborByteArray from POTA signature");
    }

    let resp = helper_establish_credential(
        &dev,
        None,
        rev,
        cmdreq_data.encrypted_credential,
        cmdreq_data.pub_key,
        cmdreq_data.masked_bk3,
        cmdreq_data.bmk,
        cmdreq_data.masked_unwrapping_key,
        cmdreq_data.pota_sig,
        cmdreq_data.pota_pub_key,
    );

    if let Err(err @ DdiError::DriverError(_)) = &resp {
        panic!("Crash Detected: {err}");
    }
}
