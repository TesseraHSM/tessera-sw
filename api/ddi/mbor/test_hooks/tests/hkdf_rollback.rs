// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Requires Uno firmware with `tsra_test_hooks` and exclusive partition access.
//!
//! Test flow:
//! 1. Establish a fresh credential and open a session. Generate two ECC key
//!    pairs and derive an ECDH secret to use as the HKDF input.
//! 2. Derive app-scoped AES keys with HKDF until NotEnoughSpace. Keep an existing
//!    output and delete another to free one output allocation.
//! 3. Arm TriggerIoFailure and derive again. Expect InvalidKeyType after output
//!    creation, requiring rollback of the attempt-owned AES key.
//! 4. Retry with the same input secret, without session cleanup. One derivation
//!    must succeed and the next must report NotEnoughSpace.
//! 5. Encrypt and decrypt with the retained and recovered AES keys, then delete
//!    outputs, the input secret, and input key pairs, even on assertion failure.

#[allow(clippy::unwrap_used)]
mod common;
#[path = "helper/rollback.rs"]
mod rollback;

use common::*;
use test_with_tracing::test;
use tsra_ddi_mbor_types::*;

#[test]
fn test_hkdf_with_rollback_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            rollback::check_key_rollback(
                dev,
                session_id,
                |dev, keys| rollback::kdf_input(dev, session_id, keys),
                |dev, key_id| {
                    helper_hkdf_derive(
                        dev,
                        Some(session_id),
                        Some(DdiApiRev { major: 1, minor: 0 }),
                        *key_id,
                        DdiHashAlgorithm::Sha256,
                        None,
                        None,
                        DdiKeyType::Aes256,
                        None,
                        helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
                        None,
                    )
                    .map(|resp| resp.data.key_id)
                },
            );
        },
    );
}
