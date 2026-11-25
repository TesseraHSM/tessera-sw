// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rejection and exact-parameter tests for TBOR `RsaVerify`.

use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::RsaHashSignAlgo;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::Signer;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborRsaVerifyReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::KEY_CLASS_RSA;
use tsra_ddi_tbor_types::KEY_USAGE_DECRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::KEY_USAGE_VERIFY;
use tsra_ddi_tbor_types::RSA_HASH_SHA256;
use tsra_ddi_tbor_types::RSA_PADDING_PKCS1_V15;
use tsra_ddi_tbor_types::RSA_PADDING_PSS;

use crate::commands::common::rev;
use crate::commands::rsa_sign::import_rsa;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap_with_usage;

#[test]
fn rsa_verify_rejects_cipher_only_keys() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let private = RsaPrivateKey::generate(256).expect("generate RSA key");
    let der = private.to_vec().expect("export RSA private key");
    let masked_key = unwrap_with_usage(
        &ctx,
        session.session_id,
        KEY_CLASS_RSA,
        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        &der,
    )
    .masked_key;
    let mut signer = RsaHashSignAlgo::with_pkcs1_padding(HashAlgo::sha256());
    let signature = Signer::sign_vec(&mut signer, &private, &[]).expect("host PKCS#1 sign");
    ctx.expect_fw_reject(
        &TborRsaVerifyReq {
            session_id: session.session_id,
            masked_key,
            padding: RSA_PADDING_PKCS1_V15,
            hash_algo: RSA_HASH_SHA256,
            signature: rev(&signature),
            ..Default::default()
        },
        TborStatus::InvalidPermissions,
    );
}

/// A wrong explicit PSS salt length is a verification failure, not success.
#[test]
fn rsa_verify_rejects_different_explicit_pss_salt_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let private = RsaPrivateKey::generate(256).expect("generate RSA key");
    let der = private.to_vec().expect("export RSA private key");
    let masked_key = unwrap_with_usage(
        &ctx,
        session.session_id,
        KEY_CLASS_RSA,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &der,
    )
    .masked_key;
    let message = b"salt length is exact";
    let mut signer = RsaHashSignAlgo::with_pss_padding(HashAlgo::sha256(), 222);
    let signature = Signer::sign_vec(&mut signer, &private, message).expect("host PSS sign");
    let req = TborRsaVerifyReq {
        session_id: session.session_id,
        masked_key,
        padding: RSA_PADDING_PSS,
        hash_algo: RSA_HASH_SHA256,
        salt_len: Some(222),
        message_index: 0,
        message_len: message.len() as u16,
        signature: rev(&signature),
    };
    ctx.tbor_oob(&req, &[message])
        .expect("maximum explicit salt length is accepted");
    let mut changed_message = message.to_vec();
    changed_message[0] ^= 1;
    ctx.expect_fw_reject_oob(&req, &[&changed_message], TborStatus::RsaVerifyFailed);
    let mut mismatched_salt = req;
    mismatched_salt.salt_len = Some(221);
    ctx.expect_fw_reject_oob(&mismatched_salt, &[message], TborStatus::RsaVerifyFailed);
}

#[test]
fn rsa_verify_accepts_all_key_sizes_forms_hashes_and_paddings() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let message = b"host reference signature\0message";
    let hashes = [
        (RSA_HASH_SHA256, HashAlgo::sha256(), 32usize),
        (
            tsra_ddi_tbor_types::RSA_HASH_SHA384,
            HashAlgo::sha384(),
            48usize,
        ),
        (
            tsra_ddi_tbor_types::RSA_HASH_SHA512,
            HashAlgo::sha512(),
            64usize,
        ),
    ];

    for modulus_len in [256, 384, 512] {
        for crt in [false, true] {
            let (masked_key, private_key, _) =
                import_rsa(&ctx, session.session_id, modulus_len, crt);
            for (hash_selector, hash, digest_len) in &hashes {
                for padding in [RSA_PADDING_PKCS1_V15, RSA_PADDING_PSS] {
                    let salt_len = (padding == RSA_PADDING_PSS).then_some(*digest_len as u16);
                    let mut signer = if padding == RSA_PADDING_PSS {
                        RsaHashSignAlgo::with_pss_padding(hash.clone(), *digest_len)
                    } else {
                        RsaHashSignAlgo::with_pkcs1_padding(hash.clone())
                    };
                    let signature =
                        Signer::sign_vec(&mut signer, &private_key, message).expect("host sign");
                    let req = TborRsaVerifyReq {
                        session_id: session.session_id,
                        masked_key: masked_key.clone(),
                        padding,
                        hash_algo: *hash_selector,
                        salt_len,
                        message_index: 0,
                        message_len: message.len() as u16,
                        signature: rev(&signature),
                    };
                    ctx.tbor_oob(&req, &[message])
                        .unwrap_or_else(|error| {
                            panic!(
                                "host signature verifies for {modulus_len}-byte key, CRT={crt}, hash={hash_selector}, padding={padding}: {error}"
                            )
                        });
                }
            }
        }
    }
}

/// The request schema preserves optional salt presence, and the handler
/// rejects selector/conditional errors before consulting the OOB descriptor.
#[test]
fn rsa_verify_rejects_invalid_selectors_and_salt_presence() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let private = RsaPrivateKey::generate(256).expect("generate RSA key");
    let der = private.to_vec().expect("export RSA private key");
    let masked_key = unwrap_with_usage(
        &ctx,
        session.session_id,
        KEY_CLASS_RSA,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &der,
    )
    .masked_key;

    let request = |padding, hash_algo, salt_len| TborRsaVerifyReq {
        session_id: session.session_id,
        masked_key: masked_key.clone(),
        padding,
        hash_algo,
        salt_len,
        message_index: 0,
        message_len: 0,
        signature: vec![0; 256],
    };
    for req in [
        request(RSA_PADDING_PSS, RSA_HASH_SHA256, None),
        request(RSA_PADDING_PKCS1_V15, RSA_HASH_SHA256, Some(0)),
        request(RSA_PADDING_PSS, RSA_HASH_SHA256, Some(223)),
        request(RSA_PADDING_PSS, 0xFF, Some(32)),
        request(0xFF, RSA_HASH_SHA256, Some(32)),
    ] {
        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }

    let mut wrong_len = request(RSA_PADDING_PSS, RSA_HASH_SHA256, Some(32));
    wrong_len.signature.pop();
    ctx.expect_fw_reject(&wrong_len, TborStatus::InvalidArg);

    let mut bad_empty_index = request(RSA_PADDING_PSS, RSA_HASH_SHA256, Some(32));
    bad_empty_index.message_index = 1;
    ctx.expect_fw_reject(&bad_empty_index, TborStatus::InvalidArg);

    let zero_signature = request(RSA_PADDING_PSS, RSA_HASH_SHA256, Some(32));
    ctx.expect_fw_reject(&zero_signature, TborStatus::RsaVerifyFailed);
    let mut all_ff_signature = zero_signature;
    all_ff_signature.signature.fill(0xFF);
    ctx.expect_fw_reject(&all_ff_signature, TborStatus::RsaVerifyFailed);
}
