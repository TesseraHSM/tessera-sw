// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Physical Uno firmware with `tsra_test_hooks` and exclusive partition access.
//! Simulates migration with NSSR, preserving both native handles and session IDs.
//!
//! Test flow:
//! 1. Provision the partition and open control and target sessions on separate
//!    handles with distinct seeds. Retain partition and session recovery blobs.
//! 2. Simulate migration with NSSR and restore provisioning using the saved
//!    partition material, keeping both original handles and logical session IDs.
//! 3. Reopen the control session, arm TriggerIoFailure, and close that session.
//!    Reopen the target using its original seed and session BMK; expect
//!    InvalidKeyType after recreation.
//! 4. Probe the target with a session-scoped AES request and expect
//!    SessionNeedsRenegotiation, confirming rollback restored its prior state.
//!    Verify the nonce changed and replaying the failed reopen returns NonceMismatch.
//! 5. Retry with fresh credentials but the same seed, session BMK, and logical ID.
//!    Require a successful reopen with that original ID and a nonempty BMK.
//! 6. Close remaining sessions, also attempting cleanup if an assertion panics.

#[allow(clippy::unwrap_used)]
mod common;

use std::panic::AssertUnwindSafe;

use common::*;
use test_with_tracing::test;
use tsra_cred_encrypt::DeviceCredKey;
use tsra_ddi::Ddi;
use tsra_ddi::DdiDev;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_types::*;

fn establish_with_bmk(
    dev: &<DdiTest as Ddi>::Dev,
    masked_bk3: MborByteArray<1024>,
    bmk: MborByteArray<1024>,
) -> MborByteArray<1024> {
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let key = helper_get_establish_cred_encryption_key(dev, None, rev)
        .expect("get provisioning encryption key");
    let nonce = key.data.nonce;
    let transport = DeviceCredKey::new(&key.data.pub_key, nonce).expect("credential transport");
    let (encryption_key, public) = transport
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .expect("credential encryption key");
    let encrypted = encryption_key
        .encrypt_establish_credential(TEST_CRED_ID, TEST_CRED_PIN, nonce)
        .expect("encrypt provisioning credential");
    let (signature, pota_public) = helper_get_pota_endorsement(dev);
    helper_establish_credential(
        dev,
        None,
        rev,
        encrypted,
        public,
        masked_bk3,
        bmk,
        MborByteArray::from_slice(&[]).expect("empty unwrapping key"),
        MborByteArray::from_slice(&signature).expect("POTA signature"),
        DdiDerPublicKey {
            der: MborByteArray::from_slice(&pota_public).expect("POTA public key"),
            key_kind: DdiKeyType::Ecc384Public,
        },
    )
    .expect("establish or restore provisioning")
    .data
    .bmk
}

#[test]
fn test_reopen_session_with_rollback_after_migration() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("ReopenSession rollback migration test requires a physical device.");
                return;
            }
            common_cleanup(dev, ddi, path, None);
            let dev2 = ddi.open_dev(path).expect("open second native handle");
            let setup_dev = ddi.open_dev(path).expect("open provisioning handle");
            let rev = Some(DdiApiRev { major: 1, minor: 0 });
            let mut first_id = None;
            let mut second_id = None;
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let masked_bk3 = helper_get_or_init_bk3(&setup_dev);
                let partition_bmk = establish_with_bmk(
                    &setup_dev,
                    masked_bk3,
                    MborByteArray::from_slice(&[]).expect("empty initial BMK"),
                );
                let first_seed = TEST_SESSION_SEED;
                let mut second_seed = first_seed;
                second_seed[0] ^= 1;
                let (credential, public) = encrypt_userid_pin_for_open_session(
                    &setup_dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    first_seed,
                );
                let first = helper_open_session(dev, None, rev, credential, public)
                    .expect("open control session");
                first_id = Some(first.data.sess_id);
                let (credential, public) = encrypt_userid_pin_for_open_session(
                    &setup_dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    second_seed,
                );
                let second = helper_open_session(&dev2, None, rev, credential, public)
                    .expect("open target session");
                second_id = Some(second.data.sess_id);
                assert_ne!(first_id, second_id);

                dev.erase().expect("simulate migration with NSSR");
                let _ = establish_with_bmk(dev, masked_bk3, partition_bmk);
                let (credential, public) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    first_seed,
                );
                let control = helper_reopen_session(
                    dev,
                    first.data.sess_id,
                    rev,
                    credential,
                    public,
                    first.data.bmk_session,
                )
                .expect("reopen control session");
                assert_eq!(control.hdr.sess_id, first_id);
                assert_eq!(control.hdr.op, DdiOp::ReopenSession);
                assert_eq!(control.hdr.status, DdiStatus::Success);
                assert!(!control.data.bmk_session.is_empty());

                match helper_test_action_cmd(
                    dev,
                    first.data.sess_id,
                    TestActionRequest::TriggerIoFailure,
                ) {
                    Ok(resp) => assert_eq!(resp.hdr.status, DdiStatus::Success),
                    Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                        println!("Firmware requires tsra_test_hooks for rollback injection.");
                        return;
                    }
                    Err(err) => panic!("arm rollback injection: {err:?}"),
                }
                helper_close_session(dev, first_id, rev).expect("close control session");
                first_id = None;

                let (credential, public) = encrypt_userid_pin_for_open_session(
                    &dev2,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    second_seed,
                );
                let nonce = credential.nonce;
                let failed = helper_reopen_session(
                    &dev2,
                    second.data.sess_id,
                    rev,
                    credential.clone(),
                    public.clone(),
                    second.data.bmk_session,
                );
                assert!(
                    matches!(failed, Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType))),
                    "expected failure after recreation, got {failed:?}"
                );
                let session_probe = helper_aes_generate(
                    &dev2,
                    second_id,
                    rev,
                    DdiAesKeySize::Aes256,
                    None,
                    helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session),
                );
                assert!(
                    matches!(
                        session_probe,
                        Err(DdiError::DdiStatus(DdiStatus::SessionNeedsRenegotiation))
                    ),
                    "rollback must restore the session to NeedsRenegotiation: {session_probe:?}"
                );
                let next_nonce = helper_get_session_encryption_key(&dev2, None, rev)
                    .expect("nonce after rollback")
                    .data
                    .nonce;
                assert_ne!(next_nonce, nonce, "rollback must not restore the nonce");
                let replay = helper_reopen_session(
                    &dev2,
                    second.data.sess_id,
                    rev,
                    credential,
                    public,
                    second.data.bmk_session,
                );
                assert!(
                    matches!(replay, Err(DdiError::DdiStatus(DdiStatus::NonceMismatch))),
                    "consumed credentials must not be replayable: {replay:?}"
                );

                let (credential, public) = encrypt_userid_pin_for_open_session(
                    &dev2,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    second_seed,
                );
                let recovered = helper_reopen_session(
                    &dev2,
                    second.data.sess_id,
                    rev,
                    credential,
                    public,
                    second.data.bmk_session,
                )
                .expect("fresh-nonce retry with original seed, BMK and logical ID");
                assert_eq!(recovered.hdr.sess_id, second_id);
                assert_eq!(recovered.data.sess_id, second.data.sess_id);
                assert_eq!(recovered.hdr.op, DdiOp::ReopenSession);
                assert_eq!(recovered.hdr.status, DdiStatus::Success);
                assert!(!recovered.data.bmk_session.is_empty());
            }));

            let mut cleanup_errors = Vec::new();
            if let Some(id) = first_id {
                if let Err(err) = helper_close_session(dev, Some(id), rev) {
                    cleanup_errors.push(err);
                }
            }
            if let Some(id) = second_id {
                if let Err(err) = helper_close_session(&dev2, Some(id), rev) {
                    cleanup_errors.push(err);
                }
            }
            if let Err(payload) = outcome {
                std::panic::resume_unwind(payload);
            }
            assert!(
                cleanup_errors.is_empty(),
                "Session cleanup: {cleanup_errors:?}"
            );
        },
    );
}
