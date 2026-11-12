// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Requires Uno firmware with `tsra_test_hooks` and exclusive partition access.
//!
//! Test flow:
//! 1. Establish a fresh credential and open a session. Generate an app-scoped
//!    AES source key and retain its masked blob.
//! 2. Unmask that blob repeatedly until NotEnoughSpace, checking the source key
//!    with an encrypt/decrypt round trip before every request.
//! 3. Keep an existing output and delete another. Arm TriggerIoFailure and
//!    unmask again; expect InvalidKeyType after output creation.
//! 4. Retry the original blob without session cleanup. One unmask must succeed
//!    and the next must report NotEnoughSpace, proving output rollback while
//!    preserving the original source key.
//! 5. Encrypt and decrypt with retained and recovered outputs, then delete all
//!    outputs and the source key, even if an assertion panics.

#[allow(clippy::unwrap_used)]
mod common;
#[path = "helper/rollback.rs"]
mod rollback;

use common::*;
use test_with_tracing::test;
use tsra_ddi_mbor_types::*;

#[test]
fn test_unmask_with_rollback_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });
            rollback::check_key_rollback(
                dev,
                session_id,
                |dev, keys| {
                    let original = helper_aes_generate(
                        dev,
                        Some(session_id),
                        rev,
                        DdiAesKeySize::Aes256,
                        None,
                        helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
                    )
                    .expect("generate masked input key");
                    keys.push(original.data.key_id);
                    (original.data.key_id, original.data.masked_key)
                },
                |dev, (original, masked)| {
                    rollback::assert_aes_key(dev, session_id, *original);
                    helper_unmask_key(dev, Some(session_id), rev, *masked)
                        .map(|resp| resp.data.key_id)
                },
            );
        },
    );
}
