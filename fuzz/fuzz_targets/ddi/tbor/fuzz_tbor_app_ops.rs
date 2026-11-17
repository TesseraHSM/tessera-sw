// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::assertions::assert_fw_rejects;
use tsra_ddi_tbor_test_harness::assertions::assert_session_rejects;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

const MAX_OPS: usize = 16;

#[derive(Arbitrary, Debug)]
enum TestAppOps {
    OpenSession([u8; 16], [u8; 16]),
    CloseSession(u16),
}

fuzz_target!(|ops: Vec<TestAppOps>| {
    common::common_fuzz_test(&|ctx: &TestCtx, path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let mut file_handles = Vec::new();

        for op in ops.iter().take(MAX_OPS) {
            match op {
                TestAppOps::OpenSession(user_id, pin) => {
                    // Socket connections allow multiple sessions, so the
                    // bootstrap's occupied CO slot is the limiting factor.
                    let expected_status = if tsra_ddi::sock_selected() {
                        TborStatus::VaultSessionLimitReached
                    } else {
                        TborStatus::FileHandleSessionLimitReached
                    };
                    let error = ctx
                        .session_open_init(CO_PSK_ID, SessionType::Authenticated)
                        .expect_err("a second CO session should hit the session limit");
                    assert_fw_rejects(&error, expected_status);

                    // The bootstrap occupies the single CO slot. Open the
                    // secondary session as CU so Phase 1 can reach Phase 2.
                    let secondary = TestCtx::new_with_path(path);
                    let pending =
                        match secondary.session_open_init(CU_PSK_ID, SessionType::PlainText) {
                            Ok(pending) => pending,
                            Err(DdiError::TborStatus(status))
                                if status == TborStatus::VaultSessionLimitReached =>
                            {
                                continue;
                            }
                            Err(_error) => {
                                panic!("CU SessionOpenInit with available capacity failed")
                            }
                        };
                    let pending_session_id = pending.session_id;
                    let expected_mac = build_mac_fin(&pending)
                        .expect("building a valid SessionOpenFinish MAC should succeed");

                    if user_id[0] & 1 == 0 {
                        let opened = secondary
                            .session_open_finish_with_mac(pending, expected_mac)
                            .expect("SessionOpenFinish with the valid MAC should succeed");
                        file_handles.push((secondary, opened.session_id));
                    } else {
                        let mut invalid_mac = expected_mac;
                        for (index, byte) in user_id.iter().chain(pin.iter()).enumerate() {
                            invalid_mac[index % MAC_FIN_LEN] ^= *byte;
                        }
                        invalid_mac[MAC_FIN_LEN - 1] ^= 1;

                        let finish_result =
                            secondary.session_open_finish_with_mac(pending, invalid_mac);
                        assert!(
                            matches!(
                                finish_result,
                                Err(DdiError::TborStatus(status))
                                    if status == TborStatus::SessionAuthFailure
                            ),
                            "SessionOpenFinish with a mutated MAC should fail authentication"
                        );

                        let error = secondary
                            .session_close(pending_session_id)
                            .expect_err("SessionClose on a failed handshake should fail");
                        assert_session_rejects(&error, TborStatus::SessionNotFound);
                    }
                }
                TestAppOps::CloseSession(session_id) => {
                    if let Some((file_handle, opened_session_id)) = file_handles.pop() {
                        let result = file_handle.session_close(*session_id);
                        if *session_id == opened_session_id {
                            result.expect("SessionClose for the matching session should succeed");
                        } else {
                            let error = result.expect_err(
                                "SessionClose for a different session ID should be rejected",
                            );
                            assert_session_rejects(
                                &error,
                                TborStatus::FileHandleSessionIdDoesNotMatch,
                            );
                            file_handle
                                .session_close(opened_session_id)
                                .expect("closing the tracked session should succeed");
                        }
                    }
                }
            }
        }

        for (file_handle, session_id) in file_handles {
            file_handle
                .session_close(session_id)
                .expect("closing the tracked session should succeed");
        }

        ctx.session_close(session.session_id)
            .expect("closing the bootstrap session should succeed");
    });
});
