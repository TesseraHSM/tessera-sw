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
use tsra_ddi_mbor_test_helpers::helper_aes_generate;
use tsra_ddi_mbor_test_helpers::helper_delete_key;
use tsra_ddi_mbor_test_helpers::helper_ecc_generate_key_pair;
use tsra_ddi_mbor_test_helpers::helper_get_unwrapping_key;
use tsra_ddi_mbor_test_helpers::helper_key_properties;
use tsra_ddi_mbor_types::*;

#[derive(Arbitrary, Debug)]
pub enum KeySource {
    EccGenerated,
    BuiltInUnwrappingKey,
    ImportedRsaKey,
    GeneratedAesKey,
    HmacKey,
    GeneratedSecretKey,
}

#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    /// If `true`, the fuzz test will generate a valid key ID based on the specified `key_source`
    pub use_valid_key_id: bool,
    /// Specifies the source/type of key to be used for the AttestKey operation when `use_valid_key_id` is `true`
    pub key_source: KeySource,
    /// Specifies the availability property of keys created during the test
    pub key_availability: DdiKeyAvailability,
    /// Selects the elliptic curve to be used for ECC key generation
    pub key_curve: DdiEccCurve,
    /// Specifies the type of HMAC key to create
    pub hmac_key_type: HmacKeyType,
    /// Specifies the hash algorithm to use for HMAC operations
    pub hash_algorithm: DdiHashAlgorithm,
    /// Specifies the RSA key size to be used when importing an RSA key
    pub key_size: RsaKeySize,
    /// A fuzzed `DdiAttestKeyReq` structure that provides the base for request parameters for the Attest Key operation
    pub cmdreq_data: Bounded<DdiAttestKeyReq>,
    /// Specifies the AES key size to be used when generating an AES key for testing (used only if `key_source` is `GeneratedAesKey`)
    pub aes_key_size: DdiAesKeySize,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_ddi_attest_key(input);
});

pub fn fuzz_ddi_attest_key(input: FuzzInput) {
    common_fuzz_test(|dev| {
        helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

        let sess_id = match helper_common_open_session(dev) {
            Ok(id) => id,
            Err(err) => {
                check_driver_error::<()>(Err(err));
                return;
            }
        };
        let mut cmdreq_data = input.cmdreq_data.0;
        let rev = Some(DdiApiRev { major: 1, minor: 0 });
        let mut key_id = cmdreq_data.key_id;

        if input.use_valid_key_id {
            key_id = match input.key_source {
                KeySource::EccGenerated => {
                    let key_props =
                        helper_key_properties(DdiKeyUsage::Derive, input.key_availability);
                    let key_resp = helper_ecc_generate_key_pair(
                        dev,
                        Some(sess_id),
                        rev,
                        input.key_curve,
                        key_props,
                    );
                    match key_resp {
                        Ok(resp) => resp.data.private_key_id,
                        Err(err) => {
                            check_driver_error::<()>(Err(err));
                            cleanup_with_session(dev, Some(sess_id));
                            return;
                        }
                    }
                }
                KeySource::BuiltInUnwrappingKey => {
                    let resp = helper_get_unwrapping_key(dev, Some(sess_id), rev);
                    match resp {
                        Ok(resp) => resp.data.key_id,
                        Err(err) => {
                            check_driver_error::<()>(Err(err));
                            cleanup_with_session(dev, Some(sess_id));
                            return;
                        }
                    }
                }
                KeySource::ImportedRsaKey => {
                    match import_rsa_key(
                        dev,
                        sess_id,
                        input.key_availability,
                        rev,
                        input.key_size as u16,
                        DdiKeyUsage::SignVerify,
                    ) {
                        Ok(id) => id,
                        Err(err) => {
                            check_driver_error::<()>(Err(err));
                            cleanup_with_session(dev, Some(sess_id));
                            return;
                        }
                    }
                }
                KeySource::GeneratedAesKey => {
                    let key_props =
                        helper_key_properties(DdiKeyUsage::EncryptDecrypt, input.key_availability);
                    let resp =
                        helper_aes_generate(dev, Some(sess_id), rev, input.aes_key_size, key_props);
                    match resp {
                        Ok(resp) => resp.data.key_id,
                        Err(err) => {
                            check_driver_error::<()>(Err(err));
                            cleanup_with_session(dev, Some(sess_id));
                            return;
                        }
                    }
                }
                KeySource::HmacKey => {
                    match helper_create_hmac_key(
                        dev,
                        sess_id,
                        rev,
                        input.key_availability,
                        input.key_curve,
                        input.hmac_key_type,
                        input.hash_algorithm,
                    ) {
                        Ok(id) => id,
                        Err(err) => {
                            check_driver_error::<()>(Err(err));
                            cleanup_with_session(dev, Some(sess_id));
                            return;
                        }
                    }
                }
                KeySource::GeneratedSecretKey => {
                    match create_secret_key(
                        dev,
                        sess_id,
                        rev,
                        input.key_curve,
                        input.key_availability,
                    ) {
                        Ok(id) => id,
                        Err(err) => {
                            check_driver_error::<()>(Err(err));
                            cleanup_with_session(dev, Some(sess_id));
                            return;
                        }
                    }
                }
            };
        }

        cmdreq_data.key_id = key_id;
        let req = DdiAttestKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::AttestKey,
                sess_id: Some(sess_id),
                rev,
            },
            data: cmdreq_data,
            ext: None,
        };
        let resp = dev.exec_op_mbor(&req, &mut None);

        check_driver_error(resp);

        if input.use_valid_key_id && !matches!(input.key_source, KeySource::BuiltInUnwrappingKey) {
            check_driver_error(helper_delete_key(dev, Some(sess_id), rev, key_id));
        }

        cleanup_with_session(dev, Some(sess_id));
    });
}
