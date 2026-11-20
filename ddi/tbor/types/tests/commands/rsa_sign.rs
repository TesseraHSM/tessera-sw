// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Interoperability tests for TBOR `RsaSign`.

use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaHashSignAlgo;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::RsaPublicKey;
use tsra_crypto::Signer;
use tsra_crypto::Verifier;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborRsaSignReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::KEY_CLASS_RSA;
use tsra_ddi_tbor_types::KEY_CLASS_RSA_CRT;
use tsra_ddi_tbor_types::KEY_USAGE_DECRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::KEY_USAGE_VERIFY;
use tsra_ddi_tbor_types::RSA_HASH_SHA256;
use tsra_ddi_tbor_types::RSA_PADDING_PKCS1_V15;
use tsra_ddi_tbor_types::RSA_PADDING_PSS;
use tsra_ddi_tbor_types::RSA_SIGN_MESSAGE_MAX_LEN;

use crate::commands::common::rev;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap_with_usage;

pub(super) fn import_rsa(
    ctx: &TestCtx,
    session_id: u16,
    modulus_len: usize,
    crt: bool,
) -> (Vec<u8>, RsaPrivateKey, RsaPublicKey) {
    let private = RsaPrivateKey::generate(modulus_len).expect("generate RSA key");
    let public = private.public_key().expect("derive RSA public key");
    let der = private.to_vec().expect("export RSA private key");
    let class = if crt {
        KEY_CLASS_RSA_CRT
    } else {
        KEY_CLASS_RSA
    };
    let masked = unwrap_with_usage(
        ctx,
        session_id,
        class,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &der,
    )
    .masked_key;
    (masked, private, public)
}

#[test]
fn rsa_sign_rejects_cipher_only_keys() {
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
    ctx.expect_fw_reject(
        &TborRsaSignReq {
            session_id: session.session_id,
            masked_key,
            padding: RSA_PADDING_PKCS1_V15,
            hash_algo: RSA_HASH_SHA256,
            ..Default::default()
        },
        TborStatus::InvalidPermissions,
    );
}

/// Device PSS signing hashes the raw OOB bytes once and emits a signature
/// that an independent host implementation verifies over those same bytes.
#[test]
fn rsa_sign_pss_sha256_hashes_raw_oob_message() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _, public_key) = import_rsa(&ctx, session.session_id, 256, true);
    let message = b"raw message\0with embedded zero";
    let req = TborRsaSignReq {
        session_id: session.session_id,
        masked_key,
        padding: RSA_PADDING_PSS,
        hash_algo: RSA_HASH_SHA256,
        salt_len: Some(32),
        message_index: 0,
        message_len: message.len() as u16,
    };
    let signature = ctx.tbor_oob(&req, &[message]).expect("RsaSign").signature;
    let mut algo = RsaHashSignAlgo::with_pss_padding(HashAlgo::sha256(), 32);
    assert!(
        Verifier::verify(&mut algo, &public_key, message, &rev(&signature))
            .expect("reference PSS verify"),
    );
}

/// The device verifies a host-generated signature over raw bytes, using the
/// exact explicit PSS salt length from the request.
#[test]
fn rsa_sign_device_accepts_host_pss_signature() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, private_key, _) = import_rsa(&ctx, session.session_id, 256, false);
    let message = b"host signed raw message";
    let mut signer = RsaHashSignAlgo::with_pss_padding(HashAlgo::sha256(), 32);
    let signature = Signer::sign_vec(&mut signer, &private_key, message).expect("host PSS sign");
    let req = tsra_ddi_tbor_types::TborRsaVerifyReq {
        session_id: session.session_id,
        masked_key,
        padding: RSA_PADDING_PSS,
        hash_algo: RSA_HASH_SHA256,
        salt_len: Some(32),
        message_index: 0,
        message_len: message.len() as u16,
        signature: rev(&signature),
    };
    ctx.tbor_oob(&req, &[message])
        .expect("RsaVerify accepts host PSS signature");
}

/// Empty messages are hashed without an OOB descriptor.
#[test]
fn rsa_sign_empty_message_needs_no_oob_descriptor() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _, public_key) = import_rsa(&ctx, session.session_id, 256, false);
    let req = TborRsaSignReq {
        session_id: session.session_id,
        masked_key,
        padding: RSA_PADDING_PSS,
        hash_algo: RSA_HASH_SHA256,
        salt_len: Some(0),
        message_index: 0,
        message_len: 0,
    };
    let signature = ctx
        .tbor_oob(&req, &[])
        .expect("empty-message RsaSign")
        .signature;
    let mut algo = RsaHashSignAlgo::with_pss_padding(HashAlgo::sha256(), 0);
    assert!(
        Verifier::verify(&mut algo, &public_key, &[], &rev(&signature))
            .expect("reference empty-message verify"),
    );
}

#[test]
fn rsa_sign_accepts_rfc_maximum_pss_salt() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _, public_key) = import_rsa(&ctx, session.session_id, 256, false);
    let message = b"maximum PSS salt";
    let req = TborRsaSignReq {
        session_id: session.session_id,
        masked_key,
        padding: RSA_PADDING_PSS,
        hash_algo: RSA_HASH_SHA256,
        salt_len: Some(222),
        message_index: 0,
        message_len: message.len() as u16,
    };
    let signature = ctx
        .tbor_oob(&req, &[message])
        .expect("maximum-salt RsaSign")
        .signature;
    let mut algo = RsaHashSignAlgo::with_pss_padding(HashAlgo::sha256(), 222);
    assert!(
        Verifier::verify(&mut algo, &public_key, message, &rev(&signature))
            .expect("reference maximum-salt verify"),
    );
}

/// Chunking preserves the exact raw byte stream through SHA padding and the
/// final short DMA chunk, including the inclusive 8192-byte maximum.
#[test]
fn rsa_sign_hash_chunk_and_padding_boundaries() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _, public_key) = import_rsa(&ctx, session.session_id, 256, false);
    for len in [
        55, 56, 63, 64, 65, 1023, 1024, 1025, 4095, 4096, 4097, 8191, 8192,
    ] {
        let message: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let req = TborRsaSignReq {
            session_id: session.session_id,
            masked_key: masked_key.clone(),
            padding: RSA_PADDING_PSS,
            hash_algo: RSA_HASH_SHA256,
            salt_len: Some(32),
            message_index: 0,
            message_len: len as u16,
        };
        let oob = if message.is_empty() {
            Vec::new()
        } else {
            vec![message.as_slice()]
        };
        let signature = ctx
            .tbor_oob(&req, &oob)
            .expect("boundary RsaSign")
            .signature;
        let mut algo = RsaHashSignAlgo::with_pss_padding(HashAlgo::sha256(), 32);
        assert!(
            Verifier::verify(&mut algo, &public_key, &message, &rev(&signature))
                .expect("reference boundary verify"),
            "device hashed exactly {len} bytes",
        );
        let verify = tsra_ddi_tbor_types::TborRsaVerifyReq {
            session_id: session.session_id,
            masked_key: masked_key.clone(),
            padding: RSA_PADDING_PSS,
            hash_algo: RSA_HASH_SHA256,
            salt_len: Some(32),
            message_index: 0,
            message_len: len as u16,
            signature,
        };
        ctx.tbor_oob(&verify, &oob)
            .expect("boundary RsaVerify hashes the same raw OOB bytes");
    }
}

#[test]
fn rsa_sign_supports_all_key_sizes_forms_hashes_and_paddings() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let message = &[0xA7u8; RSA_SIGN_MESSAGE_MAX_LEN][..];
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
            let (masked_key, _, public_key) =
                import_rsa(&ctx, session.session_id, modulus_len, crt);
            for (hash_selector, hash, digest_len) in &hashes {
                for padding in [RSA_PADDING_PKCS1_V15, RSA_PADDING_PSS] {
                    let salt_len = (padding == RSA_PADDING_PSS).then_some(*digest_len as u16);
                    let req = TborRsaSignReq {
                        session_id: session.session_id,
                        masked_key: masked_key.clone(),
                        padding,
                        hash_algo: *hash_selector,
                        salt_len,
                        message_index: 0,
                        message_len: message.len() as u16,
                    };
                    let signature = ctx
                        .tbor_oob(&req, &[message])
                        .expect("matrix RsaSign")
                        .signature;
                    let mut algo = if padding == RSA_PADDING_PSS {
                        RsaHashSignAlgo::with_pss_padding(hash.clone(), *digest_len)
                    } else {
                        RsaHashSignAlgo::with_pkcs1_padding(hash.clone())
                    };
                    assert!(
                        Verifier::verify(&mut algo, &public_key, message, &rev(&signature))
                            .expect("reference matrix verify"),
                        "signature verifies for {modulus_len}-byte key, CRT={crt}, hash={hash_selector}, padding={padding}",
                    );
                    let verify = tsra_ddi_tbor_types::TborRsaVerifyReq {
                        session_id: session.session_id,
                        masked_key: masked_key.clone(),
                        padding,
                        hash_algo: *hash_selector,
                        salt_len,
                        message_index: 0,
                        message_len: message.len() as u16,
                        signature,
                    };
                    ctx.tbor_oob(&verify, &[message])
                        .expect("maximum-message RsaVerify fits the existing IO heap");
                }
            }
        }
    }
}

#[test]
fn rsa_sign_rejects_missing_mismatched_and_oversized_oob_messages() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _, _) = import_rsa(&ctx, session.session_id, 256, false);
    let message = b"oob";
    let request = |message_len, message_index| TborRsaSignReq {
        session_id: session.session_id,
        masked_key: masked_key.clone(),
        padding: RSA_PADDING_PSS,
        hash_algo: RSA_HASH_SHA256,
        salt_len: Some(32),
        message_index,
        message_len,
    };

    ctx.expect_fw_reject_oob(&request(1, 0), &[], TborStatus::InvalidArg);
    ctx.expect_fw_reject_oob(&request(2, 0), &[message], TborStatus::InvalidArg);
    ctx.expect_fw_reject_oob(&request(4, 0), &[message], TborStatus::InvalidArg);
    ctx.expect_fw_reject_oob(&request(3, 1), &[message], TborStatus::InvalidArg);

    let oversized = vec![0xA5; RSA_SIGN_MESSAGE_MAX_LEN + 1];
    ctx.expect_fw_reject_oob(
        &request(oversized.len() as u16, 0),
        &[&oversized],
        TborStatus::InvalidArg,
    );
}
