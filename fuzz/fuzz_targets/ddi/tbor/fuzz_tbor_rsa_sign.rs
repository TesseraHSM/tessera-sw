// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::import_rsa_private_key;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_types::*;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    key_size: u8,
    crt: bool,
    message_len: u16,
    message_seed: u8,
    padding: u8,
    hash_algo: u8,
    salt_present: bool,
    salt_len: u16,
    message_index: u8,
    masked_key: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        common::finalize_partition(ctx, &session);
        let modulus_len = [256, 384, 512][input.key_size as usize % 3];
        let (masked_key, _) = import_rsa_private_key(
            ctx,
            session.session_id,
            modulus_len,
            input.crt,
            common::KEY_SCOPE_SESSION,
            KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
            &[],
        )
        .unwrap_or_else(|err| panic!("valid RSA key import failed: {err}"));

        let message_len = usize::from(input.message_len).min(RSA_SIGN_MESSAGE_MAX_LEN);
        let message: Vec<u8> = (0..message_len)
            .map(|index| input.message_seed.wrapping_add(index as u8))
            .collect();
        let (padding, hash_algo, salt_len) = match input.padding % 2 {
            0 => (
                RSA_PADDING_PSS,
                [RSA_HASH_SHA256, RSA_HASH_SHA384, RSA_HASH_SHA512][input.hash_algo as usize % 3],
                Some(input.salt_len % 64),
            ),
            _ => (
                RSA_PADDING_PKCS1_V15,
                [RSA_HASH_SHA256, RSA_HASH_SHA384, RSA_HASH_SHA512][input.hash_algo as usize % 3],
                None,
            ),
        };
        let req = TborRsaSignReq {
            session_id: session.session_id,
            masked_key: masked_key.clone(),
            padding,
            hash_algo,
            salt_len,
            message_index: 0,
            message_len: message_len as u16,
        };
        let oob = if message.is_empty() {
            Vec::new()
        } else {
            vec![message.as_slice()]
        };
        if let Err(err @ DdiError::DriverError(_)) = ctx.tbor_oob(&req, &oob) {
            panic!("Crash Detected: {err}");
        }

        let malformed_key: Vec<u8> = input
            .masked_key
            .iter()
            .copied()
            .take(RSA_SIGN_MASKED_KEY_MAX_LEN)
            .collect();
        let malformed_req = TborRsaSignReq {
            session_id: session.session_id,
            masked_key: if malformed_key.is_empty() {
                masked_key
            } else {
                malformed_key
            },
            padding: input.padding,
            hash_algo: input.hash_algo,
            salt_len: input.salt_present.then_some(input.salt_len),
            message_index: input.message_index,
            message_len: input.message_len,
        };
        if let Err(err @ DdiError::DriverError(_)) = ctx.tbor_oob(&malformed_req, &oob) {
            panic!("Crash Detected: {err}");
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
