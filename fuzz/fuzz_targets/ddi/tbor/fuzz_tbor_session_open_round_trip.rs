// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::FuzzRole;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_interface::*;
use tsra_ddi_tbor_test_harness::SessionOpenInitOptions;
use tsra_ddi_tbor_test_harness::SessionSuite;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::assertions::assert_session_rejects;
use tsra_ddi_tbor_test_harness::build_mac_fin;
use tsra_ddi_tbor_types::*;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Run a genuine handshake instead of a raw `SessionOpenInit`.
    valid_open_init: bool,
    valid_role: FuzzRole,
    /// Key-establishment suite of the genuine handshake.
    ml_kem: bool,
    /// Flip `fin[index % 48]` by `xor` before `SessionOpenFinish`;
    /// `xor == 0` keeps the genuine confirmation.
    fin_tamper: (u8, u8),

    // Raw `SessionOpenInit` fields.
    psk_id: u8,
    session_type: u8,
    suite_id: u8,
    pk_init: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        if input.valid_open_init {
            round_trip(ctx, &input);
        } else {
            raw_open_init(ctx, &input);
        }
    });
});

/// A genuine handshake whose confirmation is optionally tampered with.
fn round_trip(ctx: &TestCtx, input: &FuzzInput) {
    let suite = if input.ml_kem {
        SessionSuite::MlKem1024
    } else {
        SessionSuite::EcdhP384
    };
    let pending = ctx
        .session_open_init_with_options(SessionOpenInitOptions::new(
            input.valid_role.psk_id(),
            suite,
        ))
        .expect("SessionOpenInit with valid input must succeed");
    let session_id = pending.session_id;
    let mut mac_fin = build_mac_fin(&pending).expect("host confirmation");
    let (index, xor) = input.fin_tamper;
    mac_fin[usize::from(index) % mac_fin.len()] ^= xor;

    let finish = ctx.session_open_finish_with_mac(pending, mac_fin);
    if xor == 0 {
        finish.expect("SessionOpenFinish with valid input must succeed");
        ctx.session_close(session_id)
            .expect("SessionClose on a session opened this iteration must succeed");
    } else {
        let err = finish.expect_err("a tampered confirmation must be rejected");
        assert_session_rejects(&err, TborStatus::SessionAuthFailure);
        // The failed finish destroyed the slot and the harness dropped its
        // transport keys, so the close travels unsealed.
        let err = ctx
            .session_close(session_id)
            .expect_err("SessionClose on a session that failed to open must fail");
        ctx.assert_unknown_session_rejects(&err, TborStatus::SessionNotFound);
    }
}

/// A raw `SessionOpenInit` built from fuzz input.
///
/// The host holds no ephemeral secret for `pk_init`, so a handshake that
/// firmware accepts cannot be finished; it stays Pending until the device
/// is reset.
fn raw_open_init(ctx: &TestCtx, input: &FuzzInput) {
    let req = TborSessionOpenInitReq {
        psk_id: input.psk_id,
        session_type: input.session_type,
        suite_id: input.suite_id,
        pk_init: input.pk_init.clone(),
    };
    let result = ctx.tbor(&req);
    assert!(
        matches!(&result, Ok(_) | Err(DdiError::TborStatus(_))),
        "SessionOpenInit returned an unexpected error: {result:?}"
    );
}
