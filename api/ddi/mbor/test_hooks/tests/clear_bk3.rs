// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ClearBk3 validation against a physical device with fips_validation_hooks.
//!
//! Run after secure BK3 provisioning/sealing on a dedicated test device.
//! ClearBk3 zeroizes BK_BOOT, sealed BK3 and the derived session key, and
//! resets provisioning. The next init regenerates BK_BOOT without reallocating.
//! Firmware without the FIPS-validation action returns UnsupportedCmd.

#![allow(clippy::unwrap_used)]

mod common;

use common::common_cleanup;
use common::common_setup;
use common::ddi_dev_test;
use common::helper_common_establish_credential_no_unwrap;
use common::helper_get_establish_cred_encryption_key;
use common::helper_get_sealed_bk3;
use common::helper_secure_init_bk3;
use common::helper_set_init_bk3_pin;
use common::helper_set_sealed_bk3;
use common::TEST_CRED_ID;
use common::TEST_CRED_PIN;
use common::TEST_ECC_384_PRIVATE_KEY;
use test_with_tracing::test;
use tsra_cred_encrypt::DeviceCredKey;
use tsra_crypto::Rng;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_test_hooks::DDI_OP_TEST_ACTION;
use tsra_ddi_mbor_types::DdiApiRev;
use tsra_ddi_mbor_types::DdiStatus;

/// Requires mock sealing; TPM-backed provisioning is not supported.
#[test]
fn test_clear_bk3() {
    if std::env::var_os("TSRA_USE_TPM").is_some() {
        eprintln!("Skipping ClearBk3: this test requires mock sealing");
        return;
    }
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let before = helper_get_sealed_bk3(dev).expect("BK3 must be provisioned and sealed");
            assert!(!before.data.sealed_bk3.is_empty());

            let resp = helper_test_action_cmd(dev, session_id, TestActionRequest::ClearBk3);
            if matches!(&resp, Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))) {
                println!("Firmware is not built with fips_validation_hooks.");
                return;
            }
            let resp = resp.expect("ClearBk3");
            assert_eq!(resp.hdr.op, DDI_OP_TEST_ACTION);
            assert_eq!(resp.hdr.sess_id, Some(session_id));
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert!(resp.data.result.is_none());

            assert!(matches!(
                helper_get_sealed_bk3(dev),
                Err(DdiError::DdiStatus(DdiStatus::Bk3NotSecurelyProvisioned))
            ));
            // Clear retains the active credential; NSSR removes it while
            // preserving the allocation and cleared state until the next init.
            common_cleanup(dev, ddi, path, Some(session_id));
            let phase_one = helper_get_establish_cred_encryption_key(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
            )
            .expect("key fetch after ClearBk3 and NSSR");
            let (key, pub_key) = DeviceCredKey::new(&phase_one.data.pub_key, phase_one.data.nonce)
                .expect("PIN tunnel")
                .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
                .expect("PIN tunnel key");
            let credential = key
                .encrypt_establish_credential(TEST_CRED_ID, TEST_CRED_PIN, phase_one.data.nonce)
                .expect("encrypted provisioning credential");
            helper_set_init_bk3_pin(dev, credential, pub_key).expect("PIN after ClearBk3");

            let phase_two = helper_get_establish_cred_encryption_key(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
            )
            .expect("replacement BK3 tunnel");
            let (key, pub_key) = DeviceCredKey::new(&phase_two.data.pub_key, phase_two.data.nonce)
                .expect("BK3 tunnel")
                .create_bk3_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
                .expect("BK3 tunnel key");
            let mut bk3 = [0; 48];
            Rng::rand_bytes(&mut bk3).expect("fresh BK3");
            let encrypted = key
                .encrypt_bk3(&bk3, TEST_CRED_ID, TEST_CRED_PIN, phase_two.data.nonce)
                .expect("encrypted BK3");
            let provisioned = helper_secure_init_bk3(dev, encrypted, pub_key)
                .expect("reprovision after ClearBk3");
            let masked = provisioned.data.masked_bk3.as_slice().to_vec();
            helper_set_sealed_bk3(dev, masked.clone()).expect("reseal after ClearBk3");
            assert_eq!(
                helper_get_sealed_bk3(dev)
                    .expect("read reprovisioned BK3")
                    .data
                    .sealed_bk3
                    .as_slice(),
                masked.as_slice()
            );
            helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN)
                .expect("establish with reprovisioned BK3");
        },
    );
}
