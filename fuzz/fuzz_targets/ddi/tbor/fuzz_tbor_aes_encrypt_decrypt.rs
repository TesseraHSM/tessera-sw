// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_types::*;

/// Fuzz input for the TBOR `AesEncryptDecrypt` command.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Generate a valid masked AES key instead of using fuzzed bytes.
    use_valid_key: bool,
    /// AES key size for a generated key.
    key_size: common::AesKeySize,
    /// Fuzzed parameters for the AES operation.
    cmdreq_data: FuzzAesEncryptDecryptReq,
}

#[derive(Arbitrary, Debug)]
struct FuzzAesEncryptDecryptReq {
    masked_key: Vec<u8>,
    op: u8,
    mode: u8,
    /// Size the IV to the mode's expected length instead of `iv_len`.
    canonical_iv: bool,
    iv_len: u8,
    iv: [u8; AES_IV_LEN],
    msg: Vec<u8>,
}

/// Expected IV length for a known `mode`, or `None` for an unknown mode.
fn mode_iv_len(mode: u8) -> Option<usize> {
    match mode {
        AES_MODE_ECB => Some(0),
        AES_MODE_CBC | AES_MODE_CFB | AES_MODE_OFB | AES_MODE_CTR => Some(AES_IV_LEN),
        _ => None,
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

        let masked_key = if input.use_valid_key {
            let key_req = TborAesGenerateKeyReq {
                session_id: session.session_id,
                scope: common::KEY_SCOPE_SESSION,
                key_size: input.key_size.to_tbor(),
                key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                key_label: Vec::new(),
            };
            ctx.tbor(&key_req)
                .expect("session-scoped AES key generation should succeed")
                .masked_key
        } else {
            input.cmdreq_data.masked_key.clone()
        };

        let msg = &input.cmdreq_data.msg;
        let op = input.cmdreq_data.op;
        let mode = input.cmdreq_data.mode;
        let iv_len = match (input.cmdreq_data.canonical_iv, mode_iv_len(mode)) {
            (true, Some(len)) => len,
            _ => usize::from(input.cmdreq_data.iv_len) % (AES_IV_LEN + 1),
        };
        let iv = input.cmdreq_data.iv[..iv_len].to_vec();
        let block_mode = mode == AES_MODE_CBC || mode == AES_MODE_ECB;
        let expect_success = input.use_valid_key
            && (op == AES_OP_ENCRYPT || op == AES_OP_DECRYPT)
            && mode_iv_len(mode) == Some(iv_len)
            && !msg.is_empty()
            && (!block_mode || msg.len().is_multiple_of(AES_IV_LEN))
            && msg.len() <= AES_MSG_MAX_LEN;

        let req = TborAesEncryptDecryptReq {
            session_id: session.session_id,
            masked_key: masked_key.clone(),
            op,
            mode,
            iv: iv.clone(),
            msg: msg.clone(),
        };
        let result = ctx.tbor(&req);

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => {
                assert_eq!(resp.msg.len(), msg.len(), "output length must match input");
                if op == AES_OP_ENCRYPT {
                    let decrypted = ctx
                        .tbor(&TborAesEncryptDecryptReq {
                            session_id: session.session_id,
                            masked_key,
                            op: AES_OP_DECRYPT,
                            mode,
                            iv: iv.clone(),
                            msg: resp.msg.clone(),
                        })
                        .expect("decrypting valid ciphertext should succeed");
                    assert_eq!(&decrypted.msg, msg, "AES round trip must recover plaintext");
                    assert_eq!(decrypted.iv, resp.iv, "decrypt chaining IV must match");
                } else {
                    // `op == AES_OP_DECRYPT`: re-encrypt the returned
                    // plaintext under the same key/IV and confirm it
                    // reproduces the original ciphertext (`msg`), so a
                    // regression that returns arbitrary same-length bytes
                    // for a decrypt can't pass on output length alone.
                    let re_encrypted = ctx
                        .tbor(&TborAesEncryptDecryptReq {
                            session_id: session.session_id,
                            masked_key,
                            op: AES_OP_ENCRYPT,
                            mode,
                            iv: iv.clone(),
                            msg: resp.msg.clone(),
                        })
                        .expect("re-encrypting decrypted plaintext should succeed");
                    assert_eq!(
                        &re_encrypted.msg, msg,
                        "AES round trip must reproduce original ciphertext"
                    );
                    assert_eq!(re_encrypted.iv, resp.iv, "encrypt chaining IV must match");
                }
            }
            (Ok(_), false) => panic!("invalid AES request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid AES request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
