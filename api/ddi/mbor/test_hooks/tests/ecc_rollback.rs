// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Requires Uno firmware with `tsra_test_hooks` and exclusive partition access.
//! Capacity is checked before session cleanup so teardown cannot hide a leak.

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
fn test_ecc_generate_with_rollback_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });
            let generate = |dev: &<DdiTest as tsra_ddi::Ddi>::Dev| {
                helper_ecc_generate_key_pair(
                    dev,
                    Some(session_id),
                    rev,
                    DdiEccCurve::P256,
                    None,
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
                )
            };
            let mut keys = Vec::new();
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let mut full = false;
                // Key IDs are u16; exceeding their namespace is not exhaustion.
                for _ in 0..=u16::MAX {
                    match generate(dev) {
                        Ok(resp) => keys.push(resp.data.private_key_id),
                        Err(DdiError::DdiStatus(DdiStatus::NotEnoughSpace)) => {
                            full = true;
                            break;
                        }
                        Err(err) => panic!("Unexpected ECC generation error: {err:?}"),
                    }
                }
                assert!(full, "Vault did not reach its capacity limit");
                assert!(
                    keys.len() >= 2,
                    "Need a retained key and a reclaimable slot"
                );

                let released = *keys.last().expect("full vault has generated keys");
                helper_delete_key(dev, Some(session_id), rev, released)
                    .expect("free one ECC allocation");
                keys.pop();

                let armed =
                    helper_test_action_cmd(dev, session_id, TestActionRequest::TriggerIoFailure)
                        .expect("TriggerIoFailure requires firmware built with tsra_test_hooks");
                assert_eq!(armed.hdr.status, DdiStatus::Success);

                let failed = generate(dev);
                if let Ok(resp) = &failed {
                    keys.push(resp.data.private_key_id);
                }
                assert!(
                    matches!(failed, Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType))),
                    "Expected post-create injected failure, got {failed:?}"
                );

                // Without undo this fails: the injected command leaked the slot.
                let recovered = generate(dev).expect("rollback must reclaim the ECC allocation");
                keys.push(recovered.data.private_key_id);
                let full_again = generate(dev);
                if let Ok(resp) = &full_again {
                    keys.push(resp.data.private_key_id);
                }
                assert!(
                    matches!(
                        full_again,
                        Err(DdiError::DdiStatus(DdiStatus::NotEnoughSpace))
                    ),
                    "Expected exactly one reclaimed allocation, got {full_again:?}"
                );

                helper_ecc_sign(
                    dev,
                    Some(session_id),
                    rev,
                    keys[0],
                    MborByteArray::from_slice(&[0x5a; 32]).expect("SHA-256 digest"),
                    DdiHashAlgorithm::Sha256,
                )
                .expect("rollback must preserve an existing ECC key");
            }));

            // Attempt every deletion even if an assertion above failed.
            let cleanup_errors: Vec<_> = keys
                .into_iter()
                .filter_map(|key_id| helper_delete_key(dev, Some(session_id), rev, key_id).err())
                .collect();
            if let Err(payload) = outcome {
                std::panic::resume_unwind(payload);
            }
            assert!(cleanup_errors.is_empty(), "Key cleanup: {cleanup_errors:?}");
        },
    );
}
