// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `AesEncryptDecrypt` command.
//!
//! `AesEncryptDecrypt` AES transforms (CBC / ECB / CFB / OFB / CTR) a host
//! message using a
//! caller-held **masked** AES key (from `AesGenerateKey` or imported via
//! `UnwrapKey`). The device unmasks the key on-device, runs the
//! transform, and returns the result plus the updated chaining IV.
//!
//! Coverage:
//! * Encrypt → decrypt round-trip for AES-128/192/256.
//! * Returned CBC chaining IV for AES-128/192/256.
//! * Single-block round-trip for AES-128/192/256.
//! * Deterministic output for identical inputs for AES-128/192/256.
//! * Different IVs produce different ciphertext for AES-128/192/256.
//! * Different keys produce different ciphertext for AES-128/192/256.
//! * Wrong IVs do not recover the original plaintext for AES-128/192/256.
//! * Returned IV supports continued encryption/decryption for AES-128/192/256.
//! * Tampered masked keys are rejected for AES-128/192/256.
//! * Imported AES-128/192/256 keys encrypt/decrypt successfully.
//! * Non-block-aligned encrypt/decrypt messages are rejected.
//! * NIST SP 800-38A known answers (data and IV out) for every mode.
//! * Partial-length CFB / OFB / CTR round-trips and chaining.
//! * Invalid modes and mode / IV length mismatches are rejected.

#![cfg(feature = "emu")]

use rand::RngExt;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborAesEncryptDecryptReq;
use tsra_ddi_tbor_types::TborAesEncryptDecryptResp;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::AES_KEY_SIZE_128;
use tsra_ddi_tbor_types::AES_KEY_SIZE_192;
use tsra_ddi_tbor_types::AES_KEY_SIZE_256;
use tsra_ddi_tbor_types::AES_MODE_CBC;
use tsra_ddi_tbor_types::AES_MODE_CFB;
use tsra_ddi_tbor_types::AES_MODE_CTR;
use tsra_ddi_tbor_types::AES_MODE_ECB;
use tsra_ddi_tbor_types::AES_MODE_OFB;
use tsra_ddi_tbor_types::AES_MSG_MAX_LEN;
use tsra_ddi_tbor_types::AES_OP_DECRYPT;
use tsra_ddi_tbor_types::AES_OP_ENCRYPT;
use tsra_ddi_tbor_types::KEY_CLASS_AES;

use crate::commands::aes_generate_key::generate_key;
use crate::commands::aes_generate_key::SCOPE_LOCAL;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;

/// AES block / IV length.
const IV_LEN: usize = tsra_ddi_tbor_types::AES_IV_LEN;

/// Generates a fresh random 16-byte AES IV for test use.
fn random_iv() -> Vec<u8> {
    rand::rng().random::<[u8; IV_LEN]>().to_vec()
}

/// Performs an AES-CBC transform using the supplied masked key, operation, message, and IV.
fn aes_op(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: &[u8],
    op: u8,
    msg: &[u8],
    iv: &[u8],
) -> TborAesEncryptDecryptResp {
    aes_mode_op(ctx, session_id, masked_key, op, AES_MODE_CBC, msg, iv)
}

/// Performs an AES transform in `mode` using the supplied masked key, operation, message, and IV.
fn aes_mode_op(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: &[u8],
    op: u8,
    mode: u8,
    msg: &[u8],
    iv: &[u8],
) -> TborAesEncryptDecryptResp {
    let req = TborAesEncryptDecryptReq {
        session_id,
        masked_key: masked_key.to_vec(),
        op,
        mode,
        iv: iv.to_vec(),
        msg: msg.to_vec(),
    };

    ctx.tbor(&req).expect("AesEncryptDecrypt")
}

/// Verifies the returned encryption IV equals the final ciphertext block for a key size.
fn check_chaining_iv(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x5Au8; 48];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    assert_eq!(
        enc.iv,
        enc.msg[enc.msg.len() - IV_LEN..],
        "chaining IV must equal the last ciphertext block",
    );
}

/// Verifies a single AES block encrypts and decrypts successfully for a key size.
fn check_single_block_roundtrip(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0xA5u8; IV_LEN];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    assert_eq!(enc.msg.len(), IV_LEN);
    assert_ne!(enc.msg, msg);
    assert_eq!(
        enc.iv,
        enc.msg.as_slice(),
        "single-block ciphertext must also be the chaining IV",
    );

    let dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        &enc.msg,
        &iv,
    );

    assert_eq!(dec.msg, msg);
}

/// Verifies identical key, IV, and plaintext produce identical ciphertext for a key size.
fn check_deterministic_output(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x3Cu8; 32];
    let iv = random_iv();

    let enc_a = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    let enc_b = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    assert_eq!(
        enc_a.msg, enc_b.msg,
        "identical inputs must produce identical ciphertext",
    );
    assert_eq!(
        enc_a.iv, enc_b.iv,
        "identical inputs must produce identical chaining IVs",
    );
}

/// Verifies changing the IV changes the ciphertext for a key size.
fn check_different_iv_changes_ciphertext(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x5Au8; 32];
    let iv_a = random_iv();
    let mut iv_b = random_iv();

    // Guarantee distinct IVs even in the extremely unlikely event of a collision.
    if iv_a == iv_b {
        iv_b[0] ^= 0x01;
    }

    let enc_a = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv_a);

    let enc_b = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv_b);

    assert_ne!(
        enc_a.msg, enc_b.msg,
        "changing the IV must change the ciphertext",
    );
}

/// Verifies independently generated keys produce different ciphertext for a key size.
fn check_different_keys_change_ciphertext(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key_a = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);
    let key_b = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x5Au8; 32];
    let iv = random_iv();

    let enc_a = aes_op(&ctx, session.session_id, &key_a, AES_OP_ENCRYPT, &msg, &iv);

    let enc_b = aes_op(&ctx, session.session_id, &key_b, AES_OP_ENCRYPT, &msg, &iv);

    assert_ne!(
        enc_a.msg, enc_b.msg,
        "different AES keys must produce different ciphertext",
    );
}

/// Verifies decrypting with the wrong IV does not recover the original plaintext.
fn check_wrong_iv_changes_plaintext(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x6Au8; 32];
    let iv = random_iv();
    let mut wrong_iv = random_iv();

    // Guarantee that the wrong IV differs from the encryption IV.
    if iv == wrong_iv {
        wrong_iv[0] ^= 0x01;
    }

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    let dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        &enc.msg,
        &wrong_iv,
    );

    assert_ne!(
        dec.msg, msg,
        "decrypting with the wrong IV must not recover the original plaintext",
    );
}

/// Verifies the returned IV continues AES-CBC encryption correctly for a key size.
fn check_continued_encryption(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let first = [0x11u8; IV_LEN];
    let second = [0x22u8; IV_LEN];
    let iv = random_iv();

    let mut combined = Vec::new();
    combined.extend_from_slice(&first);
    combined.extend_from_slice(&second);

    let one_shot = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_ENCRYPT,
        &combined,
        &iv,
    );

    let first_enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &first, &iv);

    let second_enc = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_ENCRYPT,
        &second,
        &first_enc.iv,
    );

    let mut split_ciphertext = Vec::new();
    split_ciphertext.extend_from_slice(&first_enc.msg);
    split_ciphertext.extend_from_slice(&second_enc.msg);

    assert_eq!(
        split_ciphertext, one_shot.msg,
        "split CBC encryption must match one-shot encryption",
    );
    assert_eq!(
        second_enc.iv, one_shot.iv,
        "final chaining IV must match one-shot encryption",
    );
}

/// Verifies the returned IV continues AES-CBC decryption correctly for a key size.
fn check_continued_decryption(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x6Bu8; 32];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    let first_ciphertext = &enc.msg[..IV_LEN];
    let second_ciphertext = &enc.msg[IV_LEN..];

    let first_dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        first_ciphertext,
        &iv,
    );

    let second_dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        second_ciphertext,
        &first_dec.iv,
    );

    let mut recovered = Vec::new();
    recovered.extend_from_slice(&first_dec.msg);
    recovered.extend_from_slice(&second_dec.msg);

    assert_eq!(
        recovered, msg,
        "split CBC decryption must recover the original plaintext",
    );
    assert_eq!(
        first_dec.iv, first_ciphertext,
        "first decrypt IV must equal the ciphertext block just consumed",
    );
    assert_eq!(
        second_dec.iv, second_ciphertext,
        "final decrypt IV must equal the final ciphertext block",
    );
}

/// Verifies tampering with a masked key causes its authentication check to fail.
fn check_tampered_key_rejected(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mut key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);
    let iv = random_iv();

    let last = key.len() - 1;
    key[last] ^= 0x01;

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: AES_OP_ENCRYPT,
        mode: AES_MODE_CBC,
        msg: vec![0u8; IV_LEN],
        iv,
    };

    ctx.expect_fw_reject(&req, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

/// Verifies an imported AES key encrypts and decrypts successfully.
fn check_unwrapped_key_roundtrip(aes_key: &[u8]) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let masked = unwrap(&ctx, session.session_id, KEY_CLASS_AES, aes_key).masked_key;

    let msg = [0x37u8; IV_LEN];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &masked, AES_OP_ENCRYPT, &msg, &iv);

    let dec = aes_op(
        &ctx,
        session.session_id,
        &masked,
        AES_OP_DECRYPT,
        &enc.msg,
        &iv,
    );

    assert_eq!(
        dec.msg, msg,
        "unwrapped AES key must encrypt/decrypt successfully",
    );
}

/// Verifies AES-CBC encrypt/decrypt round-trips for AES-128, AES-192, and AES-256 keys.
#[test]
fn aes_encrypt_decrypt_roundtrip_all_sizes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = [0xA5u8; 32];
    let iv = random_iv();

    for size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
        let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, size);

        let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

        assert_eq!(
            enc.msg.len(),
            msg.len(),
            "ciphertext length must match plaintext length",
        );
        assert_ne!(enc.msg, msg, "ciphertext must differ from plaintext");

        let dec = aes_op(
            &ctx,
            session.session_id,
            &key,
            AES_OP_DECRYPT,
            &enc.msg,
            &iv,
        );

        assert_eq!(dec.msg, msg, "decrypt must recover the plaintext");
    }
}

/// Verifies AES-128 encryption returns the final ciphertext block as the chaining IV.
#[test]
fn aes_encrypt_decrypt_chaining_iv_128() {
    check_chaining_iv(AES_KEY_SIZE_128);
}

/// Verifies AES-192 encryption returns the final ciphertext block as the chaining IV.
#[test]
fn aes_encrypt_decrypt_chaining_iv_192() {
    check_chaining_iv(AES_KEY_SIZE_192);
}

/// Verifies AES-256 encryption returns the final ciphertext block as the chaining IV.
#[test]
fn aes_encrypt_decrypt_chaining_iv_256() {
    check_chaining_iv(AES_KEY_SIZE_256);
}

/// Verifies AES-128 single-block encryption and decryption round-trip successfully.
#[test]
fn aes_encrypt_decrypt_single_block_roundtrip_128() {
    check_single_block_roundtrip(AES_KEY_SIZE_128);
}

/// Verifies AES-192 single-block encryption and decryption round-trip successfully.
#[test]
fn aes_encrypt_decrypt_single_block_roundtrip_192() {
    check_single_block_roundtrip(AES_KEY_SIZE_192);
}

/// Verifies AES-256 single-block encryption and decryption round-trip successfully.
#[test]
fn aes_encrypt_decrypt_single_block_roundtrip_256() {
    check_single_block_roundtrip(AES_KEY_SIZE_256);
}

/// Verifies identical AES-128 inputs produce identical AES-CBC output.
#[test]
fn aes_encrypt_decrypt_same_inputs_are_deterministic_128() {
    check_deterministic_output(AES_KEY_SIZE_128);
}

/// Verifies identical AES-192 inputs produce identical AES-CBC output.
#[test]
fn aes_encrypt_decrypt_same_inputs_are_deterministic_192() {
    check_deterministic_output(AES_KEY_SIZE_192);
}

/// Verifies identical AES-256 inputs produce identical AES-CBC output.
#[test]
fn aes_encrypt_decrypt_same_inputs_are_deterministic_256() {
    check_deterministic_output(AES_KEY_SIZE_256);
}

/// Verifies changing the IV changes AES-128 ciphertext.
#[test]
fn aes_encrypt_decrypt_different_iv_changes_ciphertext_128() {
    check_different_iv_changes_ciphertext(AES_KEY_SIZE_128);
}

/// Verifies changing the IV changes AES-192 ciphertext.
#[test]
fn aes_encrypt_decrypt_different_iv_changes_ciphertext_192() {
    check_different_iv_changes_ciphertext(AES_KEY_SIZE_192);
}

/// Verifies changing the IV changes AES-256 ciphertext.
#[test]
fn aes_encrypt_decrypt_different_iv_changes_ciphertext_256() {
    check_different_iv_changes_ciphertext(AES_KEY_SIZE_256);
}

/// Verifies different AES-128 keys produce different ciphertext.
#[test]
fn aes_encrypt_decrypt_different_keys_change_ciphertext_128() {
    check_different_keys_change_ciphertext(AES_KEY_SIZE_128);
}

/// Verifies different AES-192 keys produce different ciphertext.
#[test]
fn aes_encrypt_decrypt_different_keys_change_ciphertext_192() {
    check_different_keys_change_ciphertext(AES_KEY_SIZE_192);
}

/// Verifies different AES-256 keys produce different ciphertext.
#[test]
fn aes_encrypt_decrypt_different_keys_change_ciphertext_256() {
    check_different_keys_change_ciphertext(AES_KEY_SIZE_256);
}

/// Verifies decrypting AES-128 ciphertext with the wrong IV does not recover the plaintext.
#[test]
fn aes_encrypt_decrypt_wrong_iv_changes_plaintext_128() {
    check_wrong_iv_changes_plaintext(AES_KEY_SIZE_128);
}

/// Verifies decrypting AES-192 ciphertext with the wrong IV does not recover the plaintext.
#[test]
fn aes_encrypt_decrypt_wrong_iv_changes_plaintext_192() {
    check_wrong_iv_changes_plaintext(AES_KEY_SIZE_192);
}

/// Verifies decrypting AES-256 ciphertext with the wrong IV does not recover the plaintext.
#[test]
fn aes_encrypt_decrypt_wrong_iv_changes_plaintext_256() {
    check_wrong_iv_changes_plaintext(AES_KEY_SIZE_256);
}

/// Verifies the returned IV continues AES-128 CBC encryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_encryption_128() {
    check_continued_encryption(AES_KEY_SIZE_128);
}

/// Verifies the returned IV continues AES-192 CBC encryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_encryption_192() {
    check_continued_encryption(AES_KEY_SIZE_192);
}

/// Verifies the returned IV continues AES-256 CBC encryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_encryption_256() {
    check_continued_encryption(AES_KEY_SIZE_256);
}

/// Verifies the returned IV continues AES-128 CBC decryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_decryption_128() {
    check_continued_decryption(AES_KEY_SIZE_128);
}

/// Verifies the returned IV continues AES-192 CBC decryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_decryption_192() {
    check_continued_decryption(AES_KEY_SIZE_192);
}

/// Verifies the returned IV continues AES-256 CBC decryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_decryption_256() {
    check_continued_decryption(AES_KEY_SIZE_256);
}

/// Verifies a tampered AES-128 masked key is rejected.
#[test]
fn aes_encrypt_decrypt_rejects_tampered_key_128() {
    check_tampered_key_rejected(AES_KEY_SIZE_128);
}

/// Verifies a tampered AES-192 masked key is rejected.
#[test]
fn aes_encrypt_decrypt_rejects_tampered_key_192() {
    check_tampered_key_rejected(AES_KEY_SIZE_192);
}

/// Verifies a tampered AES-256 masked key is rejected.
#[test]
fn aes_encrypt_decrypt_rejects_tampered_key_256() {
    check_tampered_key_rejected(AES_KEY_SIZE_256);
}

/// Verifies an imported AES-128 key encrypts and decrypts successfully.
#[test]
fn aes_encrypt_decrypt_unwrapped_key_roundtrip_128() {
    let aes_key = rand::rng().random::<[u8; 16]>();
    check_unwrapped_key_roundtrip(&aes_key);
}

/// Verifies an imported AES-192 key encrypts and decrypts successfully.
#[test]
fn aes_encrypt_decrypt_unwrapped_key_roundtrip_192() {
    let aes_key = rand::rng().random::<[u8; 24]>();
    check_unwrapped_key_roundtrip(&aes_key);
}

/// Verifies an imported AES-256 key encrypts and decrypts successfully.
#[test]
fn aes_encrypt_decrypt_unwrapped_key_roundtrip_256() {
    let aes_key = rand::rng().random::<[u8; 32]>();
    check_unwrapped_key_roundtrip(&aes_key);
}

/// Verifies encryption rejects plaintext that is not an integral number of AES blocks.
#[test]
fn aes_encrypt_decrypt_rejects_bad_msg_len() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let iv = random_iv();

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: AES_OP_ENCRYPT,
        mode: AES_MODE_CBC,
        msg: vec![0u8; 20],
        iv,
    };

    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Verifies decryption rejects ciphertext that is not an integral number of AES blocks.
#[test]
fn aes_encrypt_decrypt_rejects_bad_decrypt_msg_len() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let iv = random_iv();

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: AES_OP_DECRYPT,
        mode: AES_MODE_CBC,
        msg: vec![0u8; 31],
        iv,
    };

    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Verifies encryption rejects an empty AES-CBC message.
#[test]
fn aes_encrypt_decrypt_rejects_empty_encrypt_msg() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: AES_OP_ENCRYPT,
        mode: AES_MODE_CBC,
        msg: Vec::new(),
        iv: random_iv(),
    };

    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Verifies decryption rejects an empty AES-CBC message.
#[test]
fn aes_encrypt_decrypt_rejects_empty_decrypt_msg() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: AES_OP_DECRYPT,
        mode: AES_MODE_CBC,
        msg: Vec::new(),
        iv: random_iv(),
    };

    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Verifies unsupported AES operation discriminants are rejected.
#[test]
fn aes_encrypt_decrypt_rejects_invalid_ops() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for op in [0, AES_OP_DECRYPT + 1, u8::MAX] {
        let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

        let req = TborAesEncryptDecryptReq {
            session_id: session.session_id,
            masked_key: key,
            op,
            mode: AES_MODE_CBC,
            msg: vec![0u8; IV_LEN],
            iv: random_iv(),
        };

        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }
}

/// Verifies an invalid AES operation is rejected before message-length validation.
#[test]
fn aes_encrypt_decrypt_invalid_op_precedes_bad_msg_len() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: 0,
        mode: AES_MODE_CBC,
        msg: vec![0u8; 20],
        iv: random_iv(),
    };

    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Verifies the encrypt operation independently produces ciphertext and the expected chaining IV.
#[test]
fn aes_encrypt_decrypt_encrypt_op_semantics() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

    let msg = [0x5Au8; 32];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    assert_ne!(
        enc.msg, msg,
        "encrypt operation must produce ciphertext different from plaintext",
    );

    assert_eq!(
        enc.msg.len(),
        msg.len(),
        "encrypt operation must preserve message length",
    );

    assert_eq!(
        enc.iv,
        enc.msg[enc.msg.len() - IV_LEN..],
        "encrypt operation must return the final ciphertext block as the chaining IV",
    );
}

/// Verifies the decrypt operation independently recovers plaintext and returns the consumed ciphertext block as the IV.
#[test]
fn aes_encrypt_decrypt_decrypt_op_semantics() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

    let msg = [0x5Au8; 32];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    let dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        &enc.msg,
        &iv,
    );

    assert_eq!(
        dec.msg, msg,
        "decrypt operation must recover the original plaintext",
    );

    assert_eq!(
        dec.iv,
        enc.msg[enc.msg.len() - IV_LEN..],
        "decrypt operation must return the final ciphertext block as the chaining IV",
    );
}

/// Verifies AES-CBC accepts and round-trips the maximum supported message length.
#[test]
fn aes_encrypt_decrypt_max_msg_len_roundtrip() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

    let msg = vec![0xA5u8; AES_MSG_MAX_LEN];
    let iv = random_iv();

    assert_eq!(
        msg.len() % IV_LEN,
        0,
        "maximum message length must be AES-block aligned",
    );

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    assert_eq!(
        enc.msg.len(),
        AES_MSG_MAX_LEN,
        "maximum-length encryption must preserve message length",
    );

    assert_eq!(
        enc.iv,
        enc.msg[enc.msg.len() - IV_LEN..],
        "maximum-length encryption must return the final ciphertext block as the IV",
    );

    let dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        &enc.msg,
        &iv,
    );

    assert_eq!(
        dec.msg, msg,
        "maximum-length AES-CBC message must round-trip",
    );
}

/// Verifies the maximum-length decrypt operation returns the final ciphertext block as the chaining IV.
#[test]
fn aes_encrypt_decrypt_max_msg_len_decrypt_iv() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

    let msg = vec![0x5Au8; AES_MSG_MAX_LEN];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    let dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        &enc.msg,
        &iv,
    );

    assert_eq!(
        dec.msg, msg,
        "maximum-length decrypt must recover the plaintext",
    );

    assert_eq!(
        dec.iv,
        enc.msg[enc.msg.len() - IV_LEN..],
        "maximum-length decrypt must return the final ciphertext block as the chaining IV",
    );
}

/// Verifies AES-CBC rejects a nonexistent session.
#[test]
fn aes_encrypt_decrypt_rejects_invalid_session() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

    let req = TborAesEncryptDecryptReq {
        session_id: u16::MAX,
        masked_key: key,
        op: AES_OP_ENCRYPT,
        mode: AES_MODE_CBC,
        msg: vec![0u8; IV_LEN],
        iv: random_iv(),
    };

    ctx.expect_fw_reject(&req, TborStatus::FileHandleSessionIdDoesNotMatch);
}

/// Decodes a hex string into bytes.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// NIST SP 800-38A AES-128 key.
const SP800_38A_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// NIST SP 800-38A plaintext (first two blocks).
const SP800_38A_PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
/// NIST SP 800-38A IV for CBC / CFB / OFB.
const SP800_38A_IV: &str = "000102030405060708090a0b0c0d0e0f";
/// NIST SP 800-38A initial counter block for CTR.
const SP800_38A_CTR: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/// Verifies every mode against NIST SP 800-38A F.1.1 / F.2.1 / F.3.13 /
/// F.4.1 / F.5.1 (data and returned IV), in both directions.
#[test]
fn aes_encrypt_decrypt_all_modes_match_sp800_38a() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let masked = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &hex(SP800_38A_KEY)).masked_key;
    let pt = hex(SP800_38A_PT);
    let cases = [
        (
            AES_MODE_CBC,
            SP800_38A_IV,
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2",
            "5086cb9b507219ee95db113a917678b2",
        ),
        (
            AES_MODE_ECB,
            "",
            "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf",
            "",
        ),
        (
            AES_MODE_CFB,
            SP800_38A_IV,
            "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b",
            "c8a64537a0b3a93fcde3cdad9f1ce58b",
        ),
        (
            AES_MODE_OFB,
            SP800_38A_IV,
            "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825",
            "d9a4dada0892239f6b8b3d7680e15674",
        ),
        (
            AES_MODE_CTR,
            SP800_38A_CTR,
            "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff01",
        ),
    ];

    for (mode, iv, ct, iv_out) in cases {
        let (iv, ct, iv_out) = (hex(iv), hex(ct), hex(iv_out));
        let enc = aes_mode_op(
            &ctx,
            session.session_id,
            &masked,
            AES_OP_ENCRYPT,
            mode,
            &pt,
            &iv,
        );
        assert_eq!(enc.msg, ct, "mode {mode} ciphertext");
        assert_eq!(enc.iv, iv_out, "mode {mode} encrypt IV out");

        let dec = aes_mode_op(
            &ctx,
            session.session_id,
            &masked,
            AES_OP_DECRYPT,
            mode,
            &ct,
            &iv,
        );
        assert_eq!(dec.msg, pt, "mode {mode} plaintext");
        assert_eq!(dec.iv.len(), iv.len(), "mode {mode} decrypt IV out length");
    }
}

/// Verifies CFB / OFB / CTR accept non-block-aligned messages and that
/// block-aligned calls chain through the returned IV.
#[test]
fn aes_encrypt_decrypt_stream_modes_partial_and_chained() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let msg: Vec<u8> = (0..53u8).collect();

    for mode in [AES_MODE_CFB, AES_MODE_OFB, AES_MODE_CTR] {
        let iv = random_iv();
        let one_shot = aes_mode_op(
            &ctx,
            session.session_id,
            &key,
            AES_OP_ENCRYPT,
            mode,
            &msg,
            &iv,
        );
        assert_eq!(one_shot.msg.len(), msg.len(), "mode {mode}");
        assert_eq!(one_shot.iv.len(), IV_LEN, "mode {mode}");

        let dec = aes_mode_op(
            &ctx,
            session.session_id,
            &key,
            AES_OP_DECRYPT,
            mode,
            &one_shot.msg,
            &iv,
        );
        assert_eq!(dec.msg, msg, "mode {mode} round-trip");

        let first = aes_mode_op(
            &ctx,
            session.session_id,
            &key,
            AES_OP_ENCRYPT,
            mode,
            &msg[..32],
            &iv,
        );
        let second = aes_mode_op(
            &ctx,
            session.session_id,
            &key,
            AES_OP_ENCRYPT,
            mode,
            &msg[32..],
            &first.iv,
        );
        assert_eq!(
            [first.msg, second.msg].concat(),
            one_shot.msg,
            "mode {mode} chained output must match one-shot",
        );
        assert_eq!(second.iv, one_shot.iv, "mode {mode} chained IV out");
    }
}

/// Verifies unknown modes and per-mode IV / message length violations are rejected.
#[test]
fn aes_encrypt_decrypt_rejects_bad_mode_and_iv() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let cases: [(u8, Vec<u8>, usize); 7] = [
        (AES_MODE_CTR + 1, random_iv(), IV_LEN),
        (u8::MAX, random_iv(), IV_LEN),
        (AES_MODE_ECB, random_iv(), IV_LEN),
        (AES_MODE_ECB, Vec::new(), 17),
        (AES_MODE_CBC, Vec::new(), IV_LEN),
        (AES_MODE_CTR, vec![0u8; IV_LEN - 1], IV_LEN),
        (AES_MODE_OFB, random_iv(), 0),
    ];

    for (mode, iv, msg_len) in cases {
        let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_128);
        let req = TborAesEncryptDecryptReq {
            session_id: session.session_id,
            masked_key: key,
            op: AES_OP_ENCRYPT,
            mode,
            iv,
            msg: vec![0u8; msg_len],
        };

        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }
}
