// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Requires Uno firmware with `tsra_test_hooks` and exclusive partition access.
//! Uses separate native handles; capacity is checked before session cleanup.
//!
//! Test flow:
//! 1. Establish a fresh credential, open a control session, and create a
//!    session-scoped AES key to check the existing session remains usable.
//! 2. Open sessions on independent handles until capacity is exhausted. Measure
//!    remaining AES-key capacity, then close one session and its backing key.
//! 3. Prepare credentials on the session-less target handle, arm TriggerIoFailure
//!    through the control session, and expect InvalidKeyType from OpenSession.
//! 4. Verify the consumed nonce changed and replaying the failed request returns
//!    NonceMismatch. Retry with fresh credentials on the same target handle.
//! 5. Confirm the retry succeeds but another handle still sees the original
//!    capacity error. Re-measure AES-key capacity to detect backing-key leaks,
//!    and encrypt/decrypt with the original session's AES key.
//! 6. Delete the baseline key and close opened sessions, also attempting cleanup
//!    if an assertion panics.

#[allow(clippy::unwrap_used)]
mod common;
#[path = "helper/rollback.rs"]
mod rollback;

use std::panic::AssertUnwindSafe;

use common::*;
use test_with_tracing::test;
use tsra_ddi::Ddi;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_types::*;

fn open_fresh(dev: &<DdiTest as Ddi>::Dev) -> Result<DdiOpenSessionCmdResp, DdiError> {
    let (credential, public) =
        encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);
    helper_open_session(
        dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        credential,
        public,
    )
}

#[test]
fn test_open_session_with_rollback_after_exhaust_sessions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });
            let mut sessions = Vec::new();
            let mut target = None;
            let mut baseline_key = None;
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                baseline_key = Some(
                    helper_aes_generate(
                        dev,
                        Some(session_id),
                        rev,
                        DdiAesKeySize::Aes256,
                        helper_key_properties(
                            DdiKeyUsage::EncryptDecrypt,
                            DdiKeyAvailability::Session,
                        ),
                    )
                    .expect("create existing session's AES key")
                    .data
                    .key_id,
                );
                let mut exhaustion = None;
                for _ in 0..=u16::MAX {
                    let candidate = ddi.open_dev(path).expect("open independent session handle");
                    match open_fresh(&candidate) {
                        Ok(resp) => sessions.push((candidate, resp.data.sess_id)),
                        Err(DdiError::DdiStatus(
                            status @ (DdiStatus::VaultSessionLimitReached
                            | DdiStatus::NotEnoughSpace),
                        )) => {
                            exhaustion = Some(status);
                            target = Some((candidate, None));
                            break;
                        }
                        Err(err) => panic!("Unexpected OpenSession error: {err:?}"),
                    }
                }
                let exhaustion = exhaustion.expect("sessions must reach a capacity limit");
                let baseline_capacity = rollback::measure_aes_capacity(dev, session_id);
                let (released_dev, released_id) = sessions.last().expect("reclaimable session");
                helper_close_session(released_dev, Some(*released_id), rev)
                    .expect("free one session and its backing key");
                sessions.pop();

                let (target_dev, target_session) =
                    target.as_mut().expect("session-less target handle");
                let (credential, public) = encrypt_userid_pin_for_open_session(
                    target_dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );
                let nonce = credential.nonce;
                let armed =
                    helper_test_action_cmd(dev, session_id, TestActionRequest::TriggerIoFailure)
                        .expect("TriggerIoFailure requires firmware built with tsra_test_hooks");
                assert_eq!(armed.hdr.status, DdiStatus::Success);
                let failed =
                    helper_open_session(target_dev, None, rev, credential.clone(), public.clone());
                if let Ok(resp) = &failed {
                    *target_session = Some(resp.data.sess_id);
                }
                assert!(
                    matches!(failed, Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType))),
                    "Expected post-create injected failure, got {failed:?}"
                );
                let next_nonce = helper_get_session_encryption_key(target_dev, None, rev)
                    .expect("get nonce after rollback")
                    .data
                    .nonce;
                assert_ne!(
                    next_nonce, nonce,
                    "rollback must not restore a consumed nonce"
                );
                let replay = helper_open_session(target_dev, None, rev, credential, public);
                if let Ok(resp) = &replay {
                    *target_session = Some(resp.data.sess_id);
                }
                assert!(
                    matches!(replay, Err(DdiError::DdiStatus(DdiStatus::NonceMismatch))),
                    "Consumed credential must not open a session, got {replay:?}"
                );
                let recovered = open_fresh(target_dev)
                    .expect("rollback must reclaim the session and allow a fresh-nonce retry");
                *target_session = Some(recovered.data.sess_id);

                let probe = ddi.open_dev(path).expect("open capacity probe handle");
                let full_again = open_fresh(&probe);
                if let Ok(resp) = &full_again {
                    sessions.push((probe, resp.data.sess_id));
                }
                assert!(
                    matches!(full_again, Err(DdiError::DdiStatus(status)) if status == exhaustion),
                    "Expected exactly one reclaimed session, got {full_again:?}"
                );
                assert_eq!(
                    rollback::measure_aes_capacity(dev, session_id),
                    baseline_capacity,
                    "rollback must also reclaim the session's backing vault allocation"
                );
                rollback::assert_aes_key(
                    dev,
                    session_id,
                    baseline_key.expect("existing session AES key"),
                );
            }));

            let mut cleanup_errors = Vec::new();
            if let Some(key_id) = baseline_key {
                if let Err(err) = helper_delete_key(dev, Some(session_id), rev, key_id) {
                    cleanup_errors.push(err);
                }
            }
            if let Some((target_dev, Some(target_session))) = target {
                sessions.push((target_dev, target_session));
            }
            for (session_dev, id) in sessions {
                if let Err(err) = helper_close_session(&session_dev, Some(id), rev) {
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
