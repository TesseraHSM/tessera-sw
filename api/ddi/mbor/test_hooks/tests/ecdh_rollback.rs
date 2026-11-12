// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Requires Uno firmware with `tsra_test_hooks` and exclusive partition access.
//! Capacity is checked before session cleanup so teardown cannot hide a leak.
//!
//! Test flow:
//! 1. Establish a fresh credential and open a session. Generate a private input
//!    key and a peer key pair for ECDH.
//! 2. Repeatedly derive app-scoped secrets from the same input and peer public
//!    key until NotEnoughSpace, then delete one secret to free an allocation.
//! 3. Arm TriggerIoFailure and derive again. Expect InvalidKeyType after secret
//!    creation, requiring rollback of the attempt-owned secret.
//! 4. Retry with the original input keys in the same session. One derivation
//!    must succeed and the next must report NotEnoughSpace, checking allocation
//!    reclamation and preservation of the input private key.
//! 5. Delete derived secrets and both input key pairs, also attempting cleanup
//!    if an assertion panics.

#[allow(clippy::unwrap_used)]
mod common;

use std::panic::AssertUnwindSafe;

use common::*;
use test_with_tracing::test;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_types::*;

#[test]
fn test_ecdh_with_rollback_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });
            let mut input_keys = Vec::new();
            let mut secrets = Vec::new();
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let generate_input = || {
                    helper_ecc_generate_key_pair(
                        dev,
                        Some(session_id),
                        rev,
                        DdiEccCurve::P256,
                        helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App),
                    )
                    .expect("generate ECDH input key")
                };
                let input = generate_input();
                input_keys.push(input.data.private_key_id);
                let peer = generate_input();
                input_keys.push(peer.data.private_key_id);
                let derive = |dev: &<DdiTest as tsra_ddi::Ddi>::Dev| {
                    helper_ecdh_key_exchange(
                        dev,
                        Some(session_id),
                        rev,
                        input.data.private_key_id,
                        MborByteArray::from_slice(
                            &peer.data.pub_key.der.data()[..peer.data.pub_key.der.len()],
                        )
                        .expect("peer public key"),
                        DdiKeyType::Secret256,
                        helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App),
                    )
                };

                let mut full = false;
                // Key IDs are u16; exceeding their namespace is not exhaustion.
                for _ in 0..=u16::MAX {
                    match derive(dev) {
                        Ok(resp) => secrets.push(resp.data.key_id),
                        Err(DdiError::DdiStatus(DdiStatus::NotEnoughSpace)) => {
                            full = true;
                            break;
                        }
                        Err(err) => panic!("Unexpected ECDH error: {err:?}"),
                    }
                }
                assert!(full, "Vault did not reach its capacity limit");
                let released = *secrets.last().expect("need a reclaimable secret");
                helper_delete_key(dev, Some(session_id), rev, released)
                    .expect("free one ECDH allocation");
                secrets.pop();

                let armed =
                    helper_test_action_cmd(dev, session_id, TestActionRequest::TriggerIoFailure)
                        .expect("TriggerIoFailure requires firmware built with tsra_test_hooks");
                assert_eq!(armed.hdr.status, DdiStatus::Success);

                let failed = derive(dev);
                if let Ok(resp) = &failed {
                    secrets.push(resp.data.key_id);
                }
                assert!(
                    matches!(failed, Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType))),
                    "Expected post-create injected failure, got {failed:?}"
                );

                // Reusing the same ECC input also checks it survived rollback.
                let recovered = derive(dev)
                    .expect("rollback must reclaim the secret and preserve the input ECC key");
                secrets.push(recovered.data.key_id);
                let full_again = derive(dev);
                if let Ok(resp) = &full_again {
                    secrets.push(resp.data.key_id);
                }
                assert!(
                    matches!(
                        full_again,
                        Err(DdiError::DdiStatus(DdiStatus::NotEnoughSpace))
                    ),
                    "Expected exactly one reclaimed allocation, got {full_again:?}"
                );
            }));

            // Attempt every deletion even if an assertion above failed.
            let cleanup_errors: Vec<_> = secrets
                .into_iter()
                .chain(input_keys)
                .filter_map(|key_id| helper_delete_key(dev, Some(session_id), rev, key_id).err())
                .collect();
            if let Err(payload) = outcome {
                std::panic::resume_unwind(payload);
            }
            assert!(cleanup_errors.is_empty(), "Key cleanup: {cleanup_errors:?}");
        },
    );
}
