// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[test]
fn test_open_session() {
    if crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    // Not `#[partition_test]`: its fixture would init the partition before
    // this mode check, and `#[api_test]` already holds `PARTITION_LOCK`.
    crate::utils::api::init();
    crate::utils::partition::with_partition(|part, creds| {
        let rev = part.api_rev();
        let _session = part
            .open_session(rev, &creds, None)
            .expect("Failed to open session");
    });
}
