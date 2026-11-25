// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::EccCurve;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::HASH_ALGO_SHA384;
use tsra_ddi_tbor_types::HASH_ALGO_SHA512;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborEcdsaSignReq;
use tsra_ddi_tbor_types::TborEcdsaVerifyReq;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    valid: bool,
    curve: EccCurve,
    hash_selector: u8,
    message_index: u8,
    length_delta: i8,
    message: Vec<u8>,
    mutate_signature: bool,
}

fn hash_selector(value: u8) -> (u8, bool) {
    match value % 4 {
        0 => (HASH_ALGO_SHA256, true),
        1 => (HASH_ALGO_SHA384, true),
        2 => (HASH_ALGO_SHA512, true),
        _ => (HASH_ALGO_SHA512.wrapping_add(1), false),
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let response = ctx
            .tbor(&TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: common::KEY_SCOPE_SESSION,
                curve: input.curve.to_tbor(),
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            })
            .expect("valid ECC key generation");
        let mut message = input.message.clone();
        message.truncate(8192);
        let oob = if message.is_empty() {
            Vec::new()
        } else {
            vec![message.as_slice()]
        };
        let (hash_algo, supported_hash) = hash_selector(input.hash_selector);
        let signature = ctx
            .tbor_oob(
                &TborEcdsaSignReq {
                    session_id: session.session_id,
                    masked_key: response.masked_key.clone(),
                    hash_algo,
                    message_index: 0,
                    message_len: message.len() as u16,
                },
                &oob,
            )
            .ok()
            .map(|signature| signature.signature);
        let mut signature = signature.unwrap_or_else(|| vec![0; 64]);
        if input.mutate_signature && !signature.is_empty() {
            let index = usize::from(input.hash_selector) % signature.len();
            signature[index] ^= 1;
        }
        let req = TborEcdsaVerifyReq {
            session_id: session.session_id,
            masked_key: if input.valid {
                response.masked_key
            } else {
                vec![0x5A; 264]
            },
            hash_algo,
            message_index: input.message_index,
            message_len: (message.len() as i32 + i32::from(input.length_delta)).clamp(0, 8193)
                as u16,
            signature,
        };
        let result = ctx.tbor_oob(&req, &oob);
        let expect_success = input.valid
            && supported_hash
            && !input.mutate_signature
            && input.message_index == 0
            && usize::from(req.message_len) == message.len()
            && req.masked_key.len() >= 264;
        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash detected: {err}"),
            (Ok(_), true) => {}
            (Ok(_), false) => panic!("invalid ECDSA verify request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid ECDSA verify request failed: {err}"),
            (Err(_), false) => {}
        }
        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
