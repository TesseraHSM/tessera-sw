// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR rows for the session lifecycle opcodes.

#![cfg(test)]

use test_with_tracing::test;

use super::*;

/// Any in-session op that needs no key.
fn sha(dev: &Dev, sid: u16) -> Result<DdiShaDigestCmdResp, DdiError> {
    helper_sha_digest(
        dev,
        Some(sid),
        REV,
        MborByteArray::from_slice(&MSG).expect("message"),
        DdiHashAlgorithm::Sha256,
    )
}

#[test]
fn nssr_open_session() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let dev2 = ddi.open_dev(path).expect("second handle");
            let credential = || {
                encrypt_userid_pin_for_open_session(
                    &dev2,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                )
            };
            let open =
                |(credential, pub_key)| helper_open_session(&dev2, None, REV, credential, pub_key);
            let stale = credential();
            nssr(dev);
            assert_status(
                open(stale.clone()),
                DdiStatus::CredentialsNotEstablished,
                "before re-establishing the credential",
            );
            lm.reestablish_credential(dev);
            assert_status(open(stale), DdiStatus::NonceMismatch, "pre-NSSR payload");
            let sid2 = open(credential()).expect("OpenSession").data.sess_id;
            assert_ne!(
                sid2,
                lm.sid(),
                "the migrated slot stays reserved for reopen"
            );
            assert_stale_session(sha(dev, lm.sid()));
            lm.reopen(dev).expect("the migrated slot still reopens");
            helper_close_session(&dev2, Some(sid2), REV).expect("CloseSession");
        },
    );
}

#[test]
fn nssr_close_session() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            nssr(dev);
            // The gate lets CloseSession through on a migrated slot, even
            // before the credential is re-established.
            helper_close_session(dev, Some(lm.sid()), REV).expect("CloseSession after NSSR");
            assert_status(
                sha(dev, lm.sid()),
                DdiStatus::FileHandleSessionIdDoesNotMatch,
                "in-session op on the closed slot",
            );
            lm.reestablish_credential(dev);
            // The transport drops the closed slot's ownership, so it answers
            // before firmware would (`SessionNotFound`).
            assert_status(
                lm.reopen(dev),
                DdiStatus::FileHandleSessionIdDoesNotMatch,
                "reopen of the closed slot",
            );
            let (credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            let sid = helper_open_session(dev, None, REV, credential, pub_key)
                .expect("a fresh OpenSession on the same handle")
                .data
                .sess_id;
            sha(dev, sid).expect("the fresh session works");
        },
    );
}

#[test]
fn nssr_reopen_session() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            assert_status(
                lm.reopen(dev),
                DdiStatus::ProcessedIoEventInInvalidState,
                "reopen of an active slot",
            );
            let stale = lm.reopen_credential(dev);
            nssr(dev);
            // ReopenSession is exempt from the session gate but needs the
            // partition provisioned again.
            assert_status(
                lm.reopen_with(dev, stale),
                DdiStatus::PartitionNotProvisioned,
                "before re-establishing the credential",
            );
            lm.reestablish_credential(dev);
            let resp = lm.reopen(dev).expect("ReopenSession after recovery");
            assert!(!resp.bmk_session.is_empty());
            sha(dev, lm.sid()).expect("the reopened session works");
            assert_status(
                lm.reopen(dev),
                DdiStatus::ProcessedIoEventInInvalidState,
                "reopen of the re-keyed slot",
            );
            sha(dev, lm.sid()).expect("a rejected reopen leaves the slot active");
        },
    );
}
