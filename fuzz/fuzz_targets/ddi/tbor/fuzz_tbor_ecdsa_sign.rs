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

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    valid: bool,
    curve: EccCurve,
    hash_selector: u8,
    boundary: u8,
    message_index: u8,
    length_delta: i8,
    message: Vec<u8>,
    corrupt_key: bool,
}

fn message_len(input: &FuzzInput) -> usize {
    const BOUNDARIES: [usize; 17] = [
        0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1023, 1024, 1025, 8191, 8192,
    ];
    if input.boundary & 1 == 0 {
        BOUNDARIES[usize::from(input.boundary) % BOUNDARIES.len()]
    } else {
        input.message.len().min(8193)
    }
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
        let generate_key = input.valid;
        let (mut masked_key, key_generated) = if generate_key {
            let response = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id: session.session_id,
                    scope: common::KEY_SCOPE_SESSION,
                    curve: input.curve.to_tbor(),
                    key_usage: KEY_USAGE_SIGN,
                    key_label: Vec::new(),
                })
                .expect("valid ECC key generation");
            (response.masked_key, true)
        } else {
            (vec![0xA5; 264], false)
        };
        if input.corrupt_key && key_generated {
            let index = masked_key.len() / 2;
            masked_key[index] ^= 1;
        }

        let len = message_len(&input);
        let mut message = input.message.clone();
        message.truncate(len);
        message.resize(len, 0);
        let oob = if message.is_empty() {
            Vec::new()
        } else {
            vec![message.as_slice()]
        };
        let (hash_algo, supported_hash) = hash_selector(input.hash_selector);
        let req = TborEcdsaSignReq {
            session_id: session.session_id,
            masked_key,
            hash_algo,
            message_index: input.message_index,
            message_len: (len as i32 + i32::from(input.length_delta)).clamp(0, 8193) as u16,
        };
        let result = ctx.tbor_oob(&req, &oob);
        let expect_success = input.valid
            && !input.corrupt_key
            && supported_hash
            && len <= 8192
            && input.message_index == 0
            && (req.message_len == 0 || usize::from(req.message_len) == len);
        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash detected: {err}"),
            (Ok(response), true) => {
                assert!(matches!(
                    response.signature.len(),
                    64 | 96 | 132 | 136 | 144
                ));
            }
            (Ok(_), false) => panic!("invalid ECDSA sign request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid ECDSA sign request failed: {err}"),
            (Err(_), false) => {}
        }
        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
