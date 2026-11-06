// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Requires Uno firmware with `tsra_test_hooks` and exclusive partition access.

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
