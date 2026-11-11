// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Physical firmware with `tsra_test_hooks` and exclusive partition access.
//! The retained-control-session fixture requires ClearUserCredentials,
//! ClearProvisioningState and TriggerIoFailure; unsupported hooks fail the test.
//! BMK recovery and optional UK import are covered by the core CQE tests.
//!
//! Test flow:
//! 1. Provision the partition and retain a control session for test-hook commands.
//! 2. Clear credentials and provisioning state without resetting that session,
//!    obtain an establishment transport key, and inject a post-mutation IO failure.
//! 3. Attempt EstablishCredential and verify the injected error, then probe for
//!    CredentialsNotEstablished and PartitionNotProvisioned to confirm rollback.
//! 4. Replay the failed request and expect NonceMismatch: rollback must not restore
//!    the consumed nonce.
//! 5. Query a fresh transport key, verify both key and nonce changed, and retry
//!    establishment successfully without a partition reset.
//! 6. Open a session with the new credentials to confirm usability, then close
//!    both sessions (also attempting cleanup if an assertion fails).

#[allow(clippy::unwrap_used)]
mod common;

use std::panic::AssertUnwindSafe;

use common::*;
use test_with_tracing::test;
use tsra_cred_encrypt::DeviceCredKey;
use tsra_ddi::Ddi;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_types::*;

struct ProvisioningInput {
    masked_bk3: MborByteArray<1024>,
    signature: MborByteArray<1024>,
    pota_public: DdiDerPublicKey,
}

fn encrypt_credential(
    key: &DdiGetEstablishCredEncryptionKeyCmdResp,
) -> (DdiEncryptedEstablishCredential, DdiDerPublicKey) {
    let nonce = key.data.nonce;
    let transport = DeviceCredKey::new(&key.data.pub_key, nonce).expect("credential transport");
    let (encryption_key, public) = transport
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .expect("credential encryption key");
    let credential = encryption_key
        .encrypt_establish_credential(TEST_CRED_ID, TEST_CRED_PIN, nonce)
        .expect("encrypt establish credential");
    (credential, public)
}

fn establish(
    dev: &<DdiTest as Ddi>::Dev,
    input: &ProvisioningInput,
    credential: DdiEncryptedEstablishCredential,
    public: DdiDerPublicKey,
) -> Result<DdiEstablishCredentialCmdResp, DdiError> {
    helper_establish_credential(
        dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        credential,
        public,
        input.masked_bk3,
        MborByteArray::from_slice(&[]).expect("empty BMK"),
        MborByteArray::from_slice(&[]).expect("empty unwrapping key"),
        input.signature,
        input.pota_public.clone(),
    )
}

fn fixture_action(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    action: TestActionRequest,
    name: &str,
) {
    let response = helper_test_action_cmd(dev, session_id, action)
        .unwrap_or_else(|err| panic!("{name} fixture action requires tsra_test_hooks: {err:?}"));
    assert_eq!(response.hdr.status, DdiStatus::Success);
}

#[test]
fn test_establish_credential_post_mutation_rollback_and_fresh_key_retry() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("EstablishCredential rollback requires a physical device.");
                return;
            }
            common_cleanup(dev, ddi, path, None);
            let mut setup_dev = ddi.open_dev(path).expect("open provisioning handle");
            let target = ddi.open_dev(path).expect("open session-less target handle");
            let rev = Some(DdiApiRev { major: 1, minor: 0 });
            let mut control_session = None;
            let mut target_session = None;
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                helper_common_establish_credential_no_unwrap(
                    &mut setup_dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                )
                .expect("initial provisioning");
                let (credential, public) = encrypt_userid_pin_for_open_session(
                    &setup_dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );
                let opened =
                    helper_open_session(dev, None, rev, credential.clone(), public.clone())
                        .expect("open retained control session");
                let control_id = opened.data.sess_id;
                control_session = Some(control_id);
                let control_credential = credential;
                let control_public = public;
                let (signature, pota_public) = helper_get_pota_endorsement(&target);
                let input = ProvisioningInput {
                    masked_bk3: helper_get_or_init_bk3(&target),
                    signature: MborByteArray::from_slice(&signature).expect("POTA signature"),
                    pota_public: DdiDerPublicKey {
                        der: MborByteArray::from_slice(&pota_public).expect("POTA public key"),
                        key_kind: DdiKeyType::Ecc384Public,
                    },
                };
                fixture_action(
                    dev,
                    control_id,
                    TestActionRequest::ClearUserCredentials,
                    "ClearUserCredentials",
                );
                fixture_action(
                    dev,
                    control_id,
                    TestActionRequest::ClearProvisioningState,
                    "ClearProvisioningState",
                );
                let key = helper_get_establish_cred_encryption_key(&target, None, rev)
                    .expect("get establishment transport key");
                let old_nonce = key.data.nonce;
                let old_public = key.data.pub_key.der.as_slice().to_vec();
                let (credential, public) = encrypt_credential(&key);
                // Arm after clearing and transport generation. A reset would
                // discard the injection and invalidate the retained session.
                fixture_action(
                    dev,
                    control_id,
                    TestActionRequest::TriggerIoFailure,
                    "TriggerIoFailure",
                );
                let failed = establish(&target, &input, credential.clone(), public.clone());
                assert!(
                    matches!(failed, Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType))),
                    "expected post-mutation injected error, got {failed:?}"
                );
                let credential_probe = helper_get_session_encryption_key(&target, None, rev);
                assert!(
                    matches!(
                        credential_probe,
                        Err(DdiError::DdiStatus(DdiStatus::CredentialsNotEstablished))
                    ),
                    "rollback must clear the attempted credential: {credential_probe:?}"
                );
                // Reopen checks partition provisioning before credentials or nonce.
                // Session-scoped AES instead uses the retained session's own MK.
                let provisioning_probe = helper_reopen_session(
                    dev,
                    control_id,
                    rev,
                    control_credential,
                    control_public,
                    opened.data.bmk_session,
                );
                assert!(
                    matches!(
                        provisioning_probe,
                        Err(DdiError::DdiStatus(DdiStatus::PartitionNotProvisioned))
                    ),
                    "rollback must clear provisioning: {provisioning_probe:?}"
                );
                let replay = establish(&target, &input, credential, public);
                assert!(
                    matches!(replay, Err(DdiError::DdiStatus(DdiStatus::NonceMismatch))),
                    "authenticated failed request must not be replayable: {replay:?}"
                );
                let next_key = helper_get_establish_cred_encryption_key(&target, None, rev)
                    .expect("regenerate consumed transport key without resetting the partition");
                assert_ne!(next_key.data.nonce, old_nonce, "nonce must stay consumed");
                assert_ne!(
                    next_key.data.pub_key.der.as_slice(),
                    old_public.as_slice(),
                    "the next key query must generate a new transport public key"
                );
                let (credential, public) = encrypt_credential(&next_key);
                let recovered =
                    establish(&target, &input, credential, public).expect("fresh credential retry");
                assert_eq!(recovered.hdr.status, DdiStatus::Success);
                assert_eq!(recovered.hdr.op, DdiOp::EstablishCredential);
                assert!(recovered.hdr.sess_id.is_none());
                assert!(!recovered.data.bmk.is_empty());
                let (credential, public) = encrypt_userid_pin_for_open_session(
                    &target,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );
                let opened = helper_open_session(&target, None, rev, credential, public)
                    .expect("open session after fresh provisioning retry");
                target_session = Some(opened.data.sess_id);
                assert_eq!(opened.hdr.status, DdiStatus::Success);
            }));

            let mut cleanup_errors = Vec::new();
            if let Some(id) = target_session {
                if let Err(err) = helper_close_session(&target, Some(id), rev) {
                    cleanup_errors.push(err);
                }
            }
            if let Some(id) = control_session {
                if let Err(err) = helper_close_session(dev, Some(id), rev) {
                    cleanup_errors.push(err);
                }
            }
            if let Err(payload) = outcome {
                std::panic::resume_unwind(payload);
            }
            assert!(
                cleanup_errors.is_empty(),
                "Native cleanup: {cleanup_errors:?}"
            );
        },
    );
}
