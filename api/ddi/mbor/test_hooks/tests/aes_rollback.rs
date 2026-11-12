// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Requires Uno firmware with `tsra_test_hooks` and exclusive partition access.
//!
//! Test flow:
//! 1. Establish a fresh credential and open a session, then generate app-scoped
//!    AES keys until the vault reports NotEnoughSpace.
//! 2. Retain an existing key and delete another to free one output allocation.
//! 3. Arm TriggerIoFailure and generate again. Expect InvalidKeyType after key
//!    creation, requiring rollback of the attempt-owned key.
//! 4. Retry without session cleanup: one generation must succeed and the next
//!    must report NotEnoughSpace, proving exactly one allocation was reclaimed.
//! 5. Encrypt and decrypt with the retained and recovered keys, then delete all
//!    generated keys. Deletion is also attempted if an assertion panics.

#[allow(clippy::unwrap_used)]
mod common;
#[path = "helper/rollback.rs"]
mod rollback;

use common::*;
use test_with_tracing::test;
use tsra_ddi_mbor_types::*;

#[test]
fn test_aes_generate_with_rollback_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            rollback::check_key_rollback(
                dev,
                session_id,
                |_, _| (),
                |dev, _| {
                    helper_aes_generate(
                        dev,
                        Some(session_id),
                        Some(DdiApiRev { major: 1, minor: 0 }),
                        DdiAesKeySize::Aes256,
                        None,
                        helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
                    )
                    .map(|resp| resp.data.key_id)
                },
            );
        },
    );
}
