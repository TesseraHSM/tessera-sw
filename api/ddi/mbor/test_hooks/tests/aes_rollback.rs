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
