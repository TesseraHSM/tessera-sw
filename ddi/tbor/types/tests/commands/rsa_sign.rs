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
use tsra_ddi_tbor_types::KEY_CLASS_RSA;
use tsra_ddi_tbor_types::KEY_CLASS_RSA_CRT;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::KEY_USAGE_VERIFY;
use tsra_ddi_tbor_types::RSA_HASH_SHA256;
use tsra_ddi_tbor_types::RSA_PADDING_PSS;

use crate::commands::common::rev;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap_with_usage;

fn import_rsa(
    ctx: &TestCtx,
    session_id: u16,
    modulus_len: usize,
    crt: bool,
) -> (Vec<u8>, RsaPrivateKey, RsaPublicKey) {
    let private = RsaPrivateKey::generate(modulus_len).expect("generate RSA key");
    let public = private.public_key().expect("derive RSA public key");
    let der = private.to_vec().expect("export RSA private key");
    let class = if crt { KEY_CLASS_RSA_CRT } else { KEY_CLASS_RSA };
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
    let signature = ctx
        .tbor_oob(&req, &[message])
        .expect("RsaSign")
        .signature;
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
    let signature = ctx.tbor_oob(&req, &[]).expect("empty-message RsaSign").signature;
    let mut algo = RsaHashSignAlgo::with_pss_padding(HashAlgo::sha256(), 0);
    assert!(
        Verifier::verify(&mut algo, &public_key, &[], &rev(&signature))
            .expect("reference empty-message verify"),
    );
}

/// Chunking preserves the exact raw byte stream through SHA padding and the
/// final short DMA chunk, including the inclusive 8192-byte maximum.
#[test]
fn rsa_sign_hash_chunk_and_padding_boundaries() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _, public_key) = import_rsa(&ctx, session.session_id, 256, false);
    for len in [55, 56, 63, 64, 65, 1023, 1024, 1025, 8191, 8192] {
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
        let signature = ctx.tbor_oob(&req, &oob).expect("boundary RsaSign").signature;
        let mut algo = RsaHashSignAlgo::with_pss_padding(HashAlgo::sha256(), 32);
        assert!(
            Verifier::verify(&mut algo, &public_key, &message, &rev(&signature))
                .expect("reference boundary verify"),
            "device hashed exactly {len} bytes",
        );
    }
}
