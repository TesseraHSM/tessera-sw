// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test for the `ClearUserCredentials` test-hook action.
//!
//! Drives `DdiTestAction::ClearUserCredentials` (DdiOp 2004) against an
//! open session and asserts the platform handler reports success. The
//! action needs no request-specific payload.
//!
//! Requires a device whose firmware is built with `tsra_test_hooks`.

#![allow(clippy::unwrap_used)]

mod common;

use common::common_cleanup;
use common::common_setup;
use common::ddi_dev_test;
use common::helper_common_establish_credential_no_unwrap;
use common::TEST_CRED_ID;
use common::TEST_CRED_PIN;
use test_with_tracing::test;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_types::DdiAesKeySize;
use tsra_ddi_mbor_types::DdiApiRev;
use tsra_ddi_mbor_types::DdiKeyAvailability;
use tsra_ddi_mbor_types::DdiKeyUsage;
use tsra_ddi_mbor_types::DdiStatus;

#[test]
fn test_part_prov_only_once() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_properties =
                common::helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
            let resp = common::helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_properties,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp =
                helper_test_action_cmd(dev, session_id, TestActionRequest::ClearUserCredentials);

            if matches!(&resp, Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))) {
                println!("Firmware is not built with tsra_test_hooks.");
                return;
            }

            let resp = resp.unwrap();
            assert_eq!(resp.hdr.sess_id, Some(session_id));
            assert_eq!(resp.hdr.status, DdiStatus::Success);

            let resp = common::helper_get_session_encryption_key(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::CredentialsNotEstablished))
            ));

            let resp =
                helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);
            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::PartitionAlreadyProvisioned))
            ));
        },
    );
}
