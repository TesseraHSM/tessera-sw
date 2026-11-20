// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::import_rsa_private_key;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_crypto::HashAlgo;
use tsra_crypto::RsaHashSignAlgo;
use tsra_crypto::Signer;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::dev_rev;
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
    mutate_signature: bool,
    signature: Vec<u8>,
    masked_key: Vec<u8>,
}

fn reference_hash(selector: u8) -> HashAlgo {
    match selector {
        RSA_HASH_SHA384 => HashAlgo::sha384(),
        RSA_HASH_SHA512 => HashAlgo::sha512(),
        _ => HashAlgo::sha256(),
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        common::finalize_partition(ctx, &session);
        let modulus_len = [256, 384, 512][input.key_size as usize % 3];
        let (masked_key, private_key) = import_rsa_private_key(
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
        let padding = if input.padding.is_multiple_of(2) {
            RSA_PADDING_PSS
        } else {
            RSA_PADDING_PKCS1_V15
        };
        let hash_selector =
            [RSA_HASH_SHA256, RSA_HASH_SHA384, RSA_HASH_SHA512][input.hash_algo as usize % 3];
        let hash = reference_hash(hash_selector);
        let salt_len = if padding == RSA_PADDING_PSS {
            let digest_len = match hash_selector {
                RSA_HASH_SHA384 => 48,
                RSA_HASH_SHA512 => 64,
                _ => 32,
            };
            let max_salt = modulus_len - digest_len - 2;
            usize::from(input.salt_len) % (max_salt + 1)
        } else {
            0
        };
        let mut signer = if padding == RSA_PADDING_PSS {
            RsaHashSignAlgo::with_pss_padding(hash, salt_len)
        } else {
            RsaHashSignAlgo::with_pkcs1_padding(hash)
        };
        let mut signature =
            Signer::sign_vec(&mut signer, &private_key, &message).expect("reference RSA signature");
        if input.mutate_signature && !signature.is_empty() {
            signature[0] ^= 1;
        }
        let req = TborRsaVerifyReq {
            session_id: session.session_id,
            masked_key: masked_key.clone(),
            padding,
            hash_algo: hash_selector,
            salt_len: (padding == RSA_PADDING_PSS).then_some(salt_len as u16),
            message_index: 0,
            message_len: message_len as u16,
            signature: dev_rev(&signature),
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
        let malformed_signature: Vec<u8> = input
            .signature
            .iter()
            .copied()
            .take(RSA_SIGNATURE_MAX_LEN)
            .collect();
        let malformed_req = TborRsaVerifyReq {
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
            signature: malformed_signature,
        };
        if let Err(err @ DdiError::DriverError(_)) = ctx.tbor_oob(&malformed_req, &oob) {
            panic!("Crash Detected: {err}");
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
