// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests for padded RSA with caller-held masked private keys.

use tsra_crypto::DecryptOp;
use tsra_crypto::EccCurve;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EncryptOp;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::Key;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaEncryptAlgo;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::RsaPublicKey;
use tsra_ddi_tbor_test_harness::dev_rev;
use tsra_ddi_tbor_test_harness::SessionSuite;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID;
use tsra_ddi_tbor_types::TborRsaEncryptDecryptReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::HASH_ALGO_SHA384;
use tsra_ddi_tbor_types::HASH_ALGO_SHA512;
use tsra_ddi_tbor_types::KEY_CLASS_ECC;
use tsra_ddi_tbor_types::KEY_CLASS_RSA;
use tsra_ddi_tbor_types::KEY_CLASS_RSA_CRT;
use tsra_ddi_tbor_types::KEY_USAGE_DECRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::KEY_USAGE_VERIFY;
use tsra_ddi_tbor_types::RSA_ENCRYPT_DECRYPT_OP_DECRYPT;
use tsra_ddi_tbor_types::RSA_ENCRYPT_DECRYPT_OP_ENCRYPT;
use tsra_ddi_tbor_types::RSA_ENCRYPT_PADDING_OAEP;
use tsra_ddi_tbor_types::RSA_ENCRYPT_PADDING_PKCS1V15;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap_with_usage;

fn import_rsa(
    ctx: &TestCtx,
    session_id: u16,
    modulus_len: usize,
    crt: bool,
    usage: u64,
) -> (Vec<u8>, RsaPrivateKey, RsaPublicKey) {
    let private = RsaPrivateKey::generate(modulus_len).expect("generate RSA key");
    let der = private.to_vec().expect("export private key");
    let class = if crt {
        KEY_CLASS_RSA_CRT
    } else {
        KEY_CLASS_RSA
    };
    let masked = unwrap_with_usage(ctx, session_id, class, usage, &der).masked_key;
    let public = private.public_key().expect("derive public key");
    (masked, private, public)
}

fn request(
    session_id: u16,
    masked_key: &[u8],
    op: u8,
    padding: u8,
    hash_algo: Option<u8>,
    label: &[u8],
    input: &[u8],
) -> TborRsaEncryptDecryptReq {
    TborRsaEncryptDecryptReq {
        session_id,
        op,
        padding,
        hash_algo,
        label: label.to_vec(),
        input: input.to_vec(),
        masked_key: masked_key.to_vec(),
    }
}

fn host_encrypt(
    public: &RsaPublicKey,
    padding: u8,
    hash: Option<HashAlgo>,
    label: &[u8],
    message: &[u8],
) -> Vec<u8> {
    let mut ciphertext = vec![0u8; public.size()];
    let written = match padding {
        RSA_ENCRYPT_PADDING_PKCS1V15 => {
            let mut algorithm = RsaEncryptAlgo::with_pkcs1_padding();
            algorithm
                .encrypt(public, message, Some(&mut ciphertext))
                .expect("host PKCS#1 v1.5 encrypt")
        }
        RSA_ENCRYPT_PADDING_OAEP => {
            let mut algorithm =
                RsaEncryptAlgo::with_oaep_padding(hash.expect("OAEP hash"), Some(label));
            algorithm
                .encrypt(public, message, Some(&mut ciphertext))
                .expect("host OAEP encrypt")
        }
        _ => panic!("test requested unsupported padding"),
    };
    ciphertext.truncate(written);
    ciphertext
}

fn host_decrypt(
    private: &RsaPrivateKey,
    padding: u8,
    hash: Option<HashAlgo>,
    label: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut message = vec![0u8; private.size()];
    let written = match padding {
        RSA_ENCRYPT_PADDING_PKCS1V15 => {
            let mut algorithm = RsaEncryptAlgo::with_pkcs1_padding();
            algorithm
                .decrypt(private, ciphertext, Some(&mut message))
                .expect("host PKCS#1 v1.5 decrypt")
        }
        RSA_ENCRYPT_PADDING_OAEP => {
            let mut algorithm =
                RsaEncryptAlgo::with_oaep_padding(hash.expect("OAEP hash"), Some(label));
            algorithm
                .decrypt(private, ciphertext, Some(&mut message))
                .expect("host OAEP decrypt")
        }
        _ => panic!("test requested unsupported padding"),
    };
    message.truncate(written);
    message
}

#[test]
fn rsa_encrypt_decrypt_pkcs1_independent_interop_all_sizes_and_layouts() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let message = [0x00, 0x11, 0x00, 0x83, 0xA7, 0x00, 0xFE];

    for modulus_len in [256, 384, 512] {
        for crt in [false, true] {
            let (masked, private, public) = import_rsa(
                &ctx,
                session.session_id,
                modulus_len,
                crt,
                KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
            );

            let encrypted = ctx
                .tbor(&request(
                    session.session_id,
                    &masked,
                    RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
                    RSA_ENCRYPT_PADDING_PKCS1V15,
                    None,
                    &[],
                    &message,
                ))
                .expect("device PKCS#1 v1.5 encrypt");
            let host_ciphertext = dev_rev(&encrypted.output);
            assert_eq!(
                host_decrypt(
                    &private,
                    RSA_ENCRYPT_PADDING_PKCS1V15,
                    None,
                    &[],
                    &host_ciphertext,
                ),
                message,
            );

            let host_ciphertext =
                host_encrypt(&public, RSA_ENCRYPT_PADDING_PKCS1V15, None, &[], &message);
            let device_ciphertext = dev_rev(&host_ciphertext);
            let decrypted = ctx
                .tbor(&request(
                    session.session_id,
                    &masked,
                    RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
                    RSA_ENCRYPT_PADDING_PKCS1V15,
                    None,
                    &[],
                    &device_ciphertext,
                ))
                .expect("device PKCS#1 v1.5 decrypt");
            assert_eq!(decrypted.output, message);
        }
    }
}

#[test]
fn rsa_encrypt_decrypt_oaep_independent_interop_all_sizes_and_layouts() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for modulus_len in [256, 384, 512] {
        for crt in [false, true] {
            let (masked, private, public) = import_rsa(
                &ctx,
                session.session_id,
                modulus_len,
                crt,
                KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
            );
            let max_len = modulus_len - 2 * 32 - 2;
            let message = (0..max_len)
                .map(|index| (index as u8).wrapping_mul(53))
                .collect::<Vec<_>>();
            let label = [0x00, 0xD4, 0x00, 0x27];
            let encrypted = ctx
                .tbor(&request(
                    session.session_id,
                    &masked,
                    RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
                    RSA_ENCRYPT_PADDING_OAEP,
                    Some(HASH_ALGO_SHA256),
                    &label,
                    &message,
                ))
                .expect("device OAEP encrypt at maximum");
            assert_eq!(encrypted.output.len(), modulus_len);
            assert_eq!(
                host_decrypt(
                    &private,
                    RSA_ENCRYPT_PADDING_OAEP,
                    Some(HashAlgo::sha256()),
                    &label,
                    &dev_rev(&encrypted.output),
                ),
                message,
            );

            let host_ciphertext = host_encrypt(
                &public,
                RSA_ENCRYPT_PADDING_OAEP,
                Some(HashAlgo::sha256()),
                &label,
                &message,
            );
            let decrypted = ctx
                .tbor(&request(
                    session.session_id,
                    &masked,
                    RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
                    RSA_ENCRYPT_PADDING_OAEP,
                    Some(HASH_ALGO_SHA256),
                    &label,
                    &dev_rev(&host_ciphertext),
                ))
                .expect("device decrypts host OAEP ciphertext");
            assert_eq!(decrypted.output, message);
        }
    }
}

#[test]
fn rsa_encrypt_decrypt_oaep_hashes_labels_and_boundaries() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked, private, public) = import_rsa(
        &ctx,
        session.session_id,
        256,
        true,
        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
    );
    let hashes = [
        (HASH_ALGO_SHA256, HashAlgo::sha256(), 32),
        (HASH_ALGO_SHA384, HashAlgo::sha384(), 48),
        (HASH_ALGO_SHA512, HashAlgo::sha512(), 64),
    ];

    for (wire_hash, host_hash, digest_len) in hashes {
        let max_len = 256 - 2 * digest_len - 2;
        let message = (0..max_len)
            .map(|index| (index as u8).wrapping_mul(37))
            .collect::<Vec<_>>();
        let label = if wire_hash == HASH_ALGO_SHA512 {
            vec![0xA5; 256]
        } else {
            vec![0x00, 0x31, 0x00, wire_hash]
        };
        let encrypted = ctx
            .tbor(&request(
                session.session_id,
                &masked,
                RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
                RSA_ENCRYPT_PADDING_OAEP,
                Some(wire_hash),
                &label,
                &message,
            ))
            .expect("device OAEP encrypt at maximum");
        assert_eq!(
            host_decrypt(
                &private,
                RSA_ENCRYPT_PADDING_OAEP,
                Some(host_hash.clone()),
                &label,
                &dev_rev(&encrypted.output),
            ),
            message,
        );

        let host_ciphertext = host_encrypt(
            &public,
            RSA_ENCRYPT_PADDING_OAEP,
            Some(host_hash.clone()),
            &label,
            &message,
        );
        let decrypted = ctx
            .tbor(&request(
                session.session_id,
                &masked,
                RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
                RSA_ENCRYPT_PADDING_OAEP,
                Some(wire_hash),
                &label,
                &dev_rev(&host_ciphertext),
            ))
            .expect("device OAEP decrypt");
        assert_eq!(decrypted.output, message);

        let too_long = vec![0x5C; max_len + 1];
        ctx.expect_fw_reject(
            &request(
                session.session_id,
                &masked,
                RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
                RSA_ENCRYPT_PADDING_OAEP,
                Some(wire_hash),
                &label,
                &too_long,
            ),
            TborStatus::InvalidArg,
        );
    }

    for (wire_hash, host_hash, label) in [
        (HASH_ALGO_SHA256, HashAlgo::sha256(), &[][..]),
        (HASH_ALGO_SHA512, HashAlgo::sha512(), &b"label"[..]),
    ] {
        let message = [];
        let ciphertext = host_encrypt(
            &public,
            RSA_ENCRYPT_PADDING_OAEP,
            Some(host_hash),
            label,
            &message,
        );
        let decrypted = ctx
            .tbor(&request(
                session.session_id,
                &masked,
                RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
                RSA_ENCRYPT_PADDING_OAEP,
                Some(wire_hash),
                label,
                &dev_rev(&ciphertext),
            ))
            .expect("device accepts valid empty plaintext");
        assert!(decrypted.output.is_empty());
    }
}

#[test]
fn rsa_encrypt_decrypt_rejects_invalid_parameters_and_padding_then_recovers() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked, private, public) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
    );
    let input = [0x62, 0x00, 0x83];

    for (padding, hash, label) in [
        (RSA_ENCRYPT_PADDING_OAEP, None, &[][..]),
        (
            RSA_ENCRYPT_PADDING_PKCS1V15,
            Some(HASH_ALGO_SHA256),
            &[][..],
        ),
        (RSA_ENCRYPT_PADDING_PKCS1V15, None, &b"not-empty"[..]),
    ] {
        ctx.expect_fw_reject(
            &request(
                session.session_id,
                &masked,
                RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
                padding,
                hash,
                label,
                &input,
            ),
            TborStatus::InvalidArg,
        );
    }
    for (op, padding) in [
        (0, RSA_ENCRYPT_PADDING_PKCS1V15),
        (RSA_ENCRYPT_DECRYPT_OP_ENCRYPT, 0),
        (RSA_ENCRYPT_DECRYPT_OP_DECRYPT, 3),
    ] {
        ctx.expect_fw_reject(
            &request(session.session_id, &masked, op, padding, None, &[], &input),
            TborStatus::InvalidArg,
        );
    }

    let oaep_ciphertext = host_encrypt(
        &public,
        RSA_ENCRYPT_PADDING_OAEP,
        Some(HashAlgo::sha256()),
        b"right label",
        &input,
    );
    for (wire_hash, label) in [
        (HASH_ALGO_SHA256, &b"wrong label"[..]),
        (HASH_ALGO_SHA384, &b"right label"[..]),
    ] {
        ctx.expect_fw_reject(
            &request(
                session.session_id,
                &masked,
                RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
                RSA_ENCRYPT_PADDING_OAEP,
                Some(wire_hash),
                label,
                &dev_rev(&oaep_ciphertext),
            ),
            TborStatus::RsaDecryptFailed,
        );
    }

    let invalid_padding = vec![0x41; private.size()];
    let invalid_ciphertext = {
        let mut algorithm = RsaEncryptAlgo::with_no_padding();
        let mut ciphertext = vec![0; private.size()];
        algorithm
            .encrypt(&public, &invalid_padding, Some(&mut ciphertext))
            .expect("construct invalid encoded message");
        dev_rev(&ciphertext)
    };
    ctx.expect_fw_reject(
        &request(
            session.session_id,
            &masked,
            RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            &invalid_ciphertext,
        ),
        TborStatus::RsaDecryptFailed,
    );

    let wrong_lengths = [
        Vec::new(),
        vec![0x7D; private.size() - 1],
        vec![0x7D; private.size() + 1],
    ];
    for ciphertext in wrong_lengths {
        ctx.expect_fw_reject(
            &request(
                session.session_id,
                &masked,
                RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
                RSA_ENCRYPT_PADDING_PKCS1V15,
                None,
                &[],
                &ciphertext,
            ),
            TborStatus::InvalidArg,
        );
    }

    let valid_ciphertext = host_encrypt(&public, RSA_ENCRYPT_PADDING_PKCS1V15, None, &[], &input);
    let recovered = ctx
        .tbor(&request(
            session.session_id,
            &masked,
            RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            &dev_rev(&valid_ciphertext),
        ))
        .expect("masked key remains reusable after rejection");
    assert_eq!(recovered.output, input);

    let mut tampered = masked.clone();
    let tag_offset = tampered.len() - 1;
    tampered[tag_offset] ^= 0x80;
    ctx.expect_fw_reject(
        &request(
            session.session_id,
            &tampered,
            RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            &input,
        ),
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
    assert_eq!(
        ctx.tbor(&request(
            session.session_id,
            &masked,
            RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            &input,
        ))
        .expect("valid key remains usable after envelope tampering")
        .output
        .len(),
        private.size(),
    );
}

#[test]
fn rsa_encrypt_decrypt_signing_keys_are_not_encryption_keys() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked, _, _) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );
    ctx.expect_fw_reject(
        &request(
            session.session_id,
            &masked,
            RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            b"message",
        ),
        TborStatus::InvalidPermissions,
    );
    ctx.expect_fw_reject(
        &request(
            session.session_id,
            &masked,
            RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            &[],
        ),
        TborStatus::InvalidPermissions,
    );
}

#[test]
fn rsa_encrypt_decrypt_rejects_non_rsa_private_keys() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ecc = EccPrivateKey::from_curve(EccCurve::P256).expect("generate ECC key");
    let der = ecc.to_vec().expect("export ECC key");
    let masked = unwrap_with_usage(
        &ctx,
        session.session_id,
        KEY_CLASS_ECC,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &der,
    )
    .masked_key;

    ctx.expect_fw_reject(
        &request(
            session.session_id,
            &masked,
            RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            b"message",
        ),
        TborStatus::InvalidKeyType,
    );
}

#[test]
fn rsa_encrypt_decrypt_default_psk_is_gated() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO_PSK_ID, SessionSuite::EcdhP384)
        .expect("open default-PSK CO session");
    let placeholder_key = vec![0; 264];
    ctx.expect_fw_reject(
        &request(
            session.session_id(),
            &placeholder_key,
            RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            &[],
        ),
        TborStatus::DefaultPskMustRotate,
    );
}

#[test]
fn rsa_encrypt_decrypt_closed_session_is_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked, _, _) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
    );
    ctx.session_close(session.session_id)
        .expect("close CO session");
    ctx.expect_session_reject(
        &request(
            session.session_id,
            &masked,
            RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            b"message",
        ),
        TborStatus::SessionNotFound,
    );
}

#[test]
fn rsa_encrypt_decrypt_pkcs1_plaintext_boundaries() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked, private, public) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
    );
    for message in [Vec::new(), vec![0x00], vec![0x00; 245]] {
        let encrypted = ctx
            .tbor(&request(
                session.session_id,
                &masked,
                RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
                RSA_ENCRYPT_PADDING_PKCS1V15,
                None,
                &[],
                &message,
            ))
            .expect("PKCS#1 v1.5 accepts plaintext through exact maximum");
        assert_eq!(
            host_decrypt(
                &private,
                RSA_ENCRYPT_PADDING_PKCS1V15,
                None,
                &[],
                &dev_rev(&encrypted.output),
            ),
            message,
        );
    }
    ctx.expect_fw_reject(
        &request(
            session.session_id,
            &masked,
            RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            &[0xA6; 246],
        ),
        TborStatus::InvalidArg,
    );

    let host_ciphertext = host_encrypt(&public, RSA_ENCRYPT_PADDING_PKCS1V15, None, &[], &[]);
    let decrypted = ctx
        .tbor(&request(
            session.session_id,
            &masked,
            RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
            RSA_ENCRYPT_PADDING_PKCS1V15,
            None,
            &[],
            &dev_rev(&host_ciphertext),
        ))
        .expect("empty plaintext decrypts successfully");
    assert!(decrypted.output.is_empty());
}
