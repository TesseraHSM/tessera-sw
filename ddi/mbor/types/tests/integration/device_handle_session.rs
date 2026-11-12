// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use test_with_tracing::test;
use tsra_ddi::*;
use tsra_ddi_mbor_types::*;

use super::common::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // Return incorrect session id
    25
}

#[test]
fn test_device_handle_session_no_session() {
    // Test for verifying that a NoSession command
    // fails if provided a session id
    // And it passes if provided a None for session id
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let resp = helper_get_api_rev(dev, Some(20), None);

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));

            let resp = helper_get_api_rev(dev, None, None);

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_device_handle_session_open_session_twice() {
    // Not applicable to the socket transport: a socket connection may hold
    // several sessions, so the one-session-per-handle limit doesn't apply.
    if tsra_ddi::sock_selected() {
        return;
    }
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert!(resp.hdr.sess_id.is_some());
            assert_eq!(resp.hdr.op, DdiOp::OpenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert_eq!(resp.hdr.rev.unwrap().major, 1);
            assert_eq!(resp.hdr.rev.unwrap().minor, 0);

            // now try to open another session on the same device handle
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionLimitReached)
            ));
        },
    );
}

#[test]
fn test_socket_sessions_are_owned_by_connection() {
    // Only applicable to the socket transport: hardware limits each device
    // handle to one session.
    if !tsra_ddi::sock_selected() {
        return;
    }
    ddi_dev_test(setup, common_cleanup, |dev, ddi, path, _| {
        helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);
        let mut sessions = Vec::new();
        for _ in 0..2 {
            let (credential, public_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            sessions.push(
                helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    credential,
                    public_key,
                )
                .expect("open another session on the same connection")
                .data
                .sess_id,
            );
        }
        assert_ne!(sessions[0], sessions[1]);
        let owner = dev.clone();
        let foreign = ddi.open_dev(path).expect("another connection");
        let props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
        for session in sessions {
            let error = helper_aes_generate(
                &foreign,
                Some(session),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                props,
            )
            .expect_err("another connection cannot use this session");
            assert!(matches!(
                error,
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
            helper_aes_generate(
                &owner,
                Some(session),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                props,
            )
            .expect("the owner's clone can use this session");
            helper_close_session(
                &owner,
                Some(session),
                Some(DdiApiRev { major: 1, minor: 0 }),
            )
            .expect("close only this session");
        }
    });
}
