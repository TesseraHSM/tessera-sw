// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_crypto::AesKey;
use tsra_crypto::AesKeyWrapPadAlgo;
use tsra_crypto::DecryptOp;
use tsra_crypto::EncryptOp;
use tsra_crypto::Encrypter;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::ImportableKey;
use tsra_crypto::Key;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaEncryptAlgo;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::RsaPublicKey;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::assertions::assert_fw_rejects;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::dev_rev;
use tsra_ddi_tbor_test_harness::device_is_little_endian;
use tsra_ddi_tbor_types::*;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    key_size: u8,
    crt: bool,
    signing_permissions: bool,
    op: u8,
    padding: u8,
    hash: Option<u8>,
    label: Vec<u8>,
    message: Vec<u8>,
    tamper_key: bool,
}

fn reverse_integer_if_needed(bytes: &[u8]) -> Vec<u8> {
    if device_is_little_endian() {
        dev_rev(bytes)
    } else {
        bytes.to_vec()
    }
}

fn import_rsa_key(
    ctx: &TestCtx,
    session_id: u16,
    key: &RsaPrivateKey,
    crt: bool,
    signing_permissions: bool,
) -> Vec<u8> {
    let unwrapping_key = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .expect("get RSA unwrapping key")
        .pub_key;
    assert_eq!(unwrapping_key.len(), 260);
    let mut public_key_be = reverse_integer_if_needed(&unwrapping_key[..256]);
    public_key_be.extend(reverse_integer_if_needed(&unwrapping_key[256..]));
    let public_key =
        RsaPublicKey::from_hsm_bytes(&public_key_be).expect("parse RSA unwrapping key");
    let kek = [0xA7u8; 32];
    let encrypted_kek = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &public_key,
        &kek,
    )
    .expect("wrap AES key");
    let kek = AesKey::from_bytes(&kek).expect("construct AES key");
    let private_der = key.to_vec().expect("export private key");
    let encrypted_private_key =
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, &private_der)
            .expect("wrap RSA private key");
    let mut wrapped_blob = dev_rev(&encrypted_kek);
    wrapped_blob.extend(encrypted_private_key);
    ctx.tbor(&TborUnwrapKeyReq {
        session_id,
        scope: common::KEY_SCOPE_SESSION,
        key_class: if crt {
            KEY_CLASS_RSA_CRT
        } else {
            KEY_CLASS_RSA
        },
        key_usage: if signing_permissions {
            KEY_USAGE_SIGN | KEY_USAGE_VERIFY
        } else {
            KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT
        },
        oaep_hash_algo: HASH_ALGO_SHA256,
        wrapped_blob,
        key_label: Vec::new(),
    })
    .expect("import RSA key")
    .masked_key
}

fn host_hash(value: u8) -> Option<HashAlgo> {
    match value {
        HASH_ALGO_SHA256 => Some(HashAlgo::sha256()),
        HASH_ALGO_SHA384 => Some(HashAlgo::sha384()),
        HASH_ALGO_SHA512 => Some(HashAlgo::sha512()),
        _ => None,
    }
}

fn host_encrypt(public: &RsaPublicKey, hash: HashAlgo, label: &[u8], message: &[u8]) -> Vec<u8> {
    let mut ciphertext = vec![0u8; public.size()];
    RsaEncryptAlgo::with_oaep_padding(hash, Some(label))
        .encrypt(public, message, Some(&mut ciphertext))
        .expect("host OAEP encrypt");
    ciphertext
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        common::finalize_partition(ctx, &session);

        let modulus_len = [256, 384, 512][input.key_size as usize % 3];
        let private = RsaPrivateKey::generate(modulus_len).expect("generate RSA key");
        let public = private.public_key().expect("derive RSA public key");
        let masked = import_rsa_key(
            ctx,
            session.session_id,
            &private,
            input.crt,
            input.signing_permissions,
        );
        let label = &input.label[..input.label.len().min(RSA_OAEP_LABEL_MAX_LEN)];
        let hash = input.hash.and_then(host_hash);
        let padding_valid = matches!(
            input.padding,
            RSA_ENCRYPT_PADDING_OAEP | RSA_ENCRYPT_PADDING_PKCS1V15
        );
        let hash_valid = match input.padding {
            RSA_ENCRYPT_PADDING_OAEP => hash.is_some(),
            RSA_ENCRYPT_PADDING_PKCS1V15 => input.hash.is_none(),
            _ => false,
        };
        let label_valid = input.padding != RSA_ENCRYPT_PADDING_PKCS1V15 || label.is_empty();
        let op_valid = matches!(
            input.op,
            RSA_ENCRYPT_DECRYPT_OP_ENCRYPT | RSA_ENCRYPT_DECRYPT_OP_DECRYPT
        );
        let permitted = !input.signing_permissions;
        let valid = padding_valid && hash_valid && label_valid && op_valid && permitted;
        let max_plaintext = match (input.padding, hash.as_ref()) {
            (RSA_ENCRYPT_PADDING_PKCS1V15, _) => modulus_len - 11,
            (RSA_ENCRYPT_PADDING_OAEP, Some(_)) => {
                let digest_len = match input.hash {
                    Some(HASH_ALGO_SHA256) => 32,
                    Some(HASH_ALGO_SHA384) => 48,
                    Some(HASH_ALGO_SHA512) => 64,
                    _ => unreachable!(),
                };
                modulus_len - 2 * digest_len - 2
            }
            _ => 0,
        };
        let message = &input.message[..input.message.len().min(max_plaintext)];
        let mut ciphertext = vec![0u8; modulus_len];
        let result = if valid {
            match input.padding {
                RSA_ENCRYPT_PADDING_PKCS1V15 => {
                    let mut algo = RsaEncryptAlgo::with_pkcs1_padding();
                    algo.encrypt(&public, message, Some(&mut ciphertext))
                        .expect("host PKCS#1 encrypt");
                }
                RSA_ENCRYPT_PADDING_OAEP => {
                    let mut algo = RsaEncryptAlgo::with_oaep_padding(
                        hash.clone().expect("validated OAEP hash"),
                        Some(label),
                    );
                    algo.encrypt(&public, message, Some(&mut ciphertext))
                        .expect("host OAEP encrypt");
                }
                _ => unreachable!(),
            };
            let request_input = if input.op == RSA_ENCRYPT_DECRYPT_OP_DECRYPT {
                dev_rev(&ciphertext)
            } else {
                message.to_vec()
            };
            ctx.tbor(&TborRsaEncryptDecryptReq {
                session_id: session.session_id,
                op: input.op,
                padding: input.padding,
                hash_algo: input.hash,
                label: label.to_vec(),
                input: request_input,
                masked_key: if input.tamper_key {
                    let mut tampered = masked.clone();
                    let last = tampered.len() - 1;
                    tampered[last] ^= 0x80;
                    tampered
                } else {
                    masked.clone()
                },
            })
        } else {
            ctx.tbor(&TborRsaEncryptDecryptReq {
                session_id: session.session_id,
                op: input.op,
                padding: input.padding,
                hash_algo: input.hash,
                label: label.to_vec(),
                input: message.to_vec(),
                masked_key: masked.clone(),
            })
        };

        match (result, valid && !input.tamper_key) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash detected: {err}"),
            (Ok(response), true) if input.op == RSA_ENCRYPT_DECRYPT_OP_ENCRYPT => {
                assert_eq!(response.output.len(), modulus_len);
                let ciphertext_be = dev_rev(&response.output);
                let mut plaintext = vec![0u8; modulus_len];
                let mut algo = match input.padding {
                    RSA_ENCRYPT_PADDING_PKCS1V15 => RsaEncryptAlgo::with_pkcs1_padding(),
                    _ => RsaEncryptAlgo::with_oaep_padding(
                        hash.clone().expect("validated OAEP hash"),
                        Some(label),
                    ),
                };
                let written = algo
                    .decrypt(&private, &ciphertext_be, Some(&mut plaintext))
                    .expect("device encryption must be host-decryptable");
                assert_eq!(&plaintext[..written], message);
            }
            (Ok(response), true) => assert_eq!(response.output, message),
            (Ok(_), false) => panic!("invalid RSA encrypt/decrypt request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid RSA encrypt/decrypt request failed: {err}"),
            (Err(error), false) => {
                // Only valid requests have their keys tampered; parameter checks precede permissions.
                let expected = if valid {
                    TborStatus::AesGcmDecryptTagDoesNotMatch
                } else if padding_valid && hash_valid && label_valid && op_valid {
                    TborStatus::InvalidPermissions
                } else {
                    TborStatus::InvalidArg
                };
                assert_fw_rejects(&error, expected);
            }
        }

        if !input.signing_permissions {
            let invalid_encoded = vec![0x41; modulus_len];
            let mut invalid_ciphertext = vec![0u8; modulus_len];
            RsaEncryptAlgo::with_no_padding()
                .encrypt(&public, &invalid_encoded, Some(&mut invalid_ciphertext))
                .expect("construct invalid encoded message");
            let invalid_ciphertext = dev_rev(&invalid_ciphertext);
            for (padding, hash_algo) in [
                (RSA_ENCRYPT_PADDING_PKCS1V15, None),
                (RSA_ENCRYPT_PADDING_OAEP, Some(HASH_ALGO_SHA256)),
            ] {
                ctx.expect_fw_reject(
                    &TborRsaEncryptDecryptReq {
                        session_id: session.session_id,
                        op: RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
                        padding,
                        hash_algo,
                        label: Vec::new(),
                        input: invalid_ciphertext.clone(),
                        masked_key: masked.clone(),
                    },
                    TborStatus::RsaDecryptFailed,
                );
            }

            if input.padding == RSA_ENCRYPT_PADDING_OAEP
                && let Some(hash) = hash.clone()
            {
                let ciphertext = host_encrypt(&public, hash, label, message);
                let mut wrong_label = label.to_vec();
                wrong_label.push(0x01);
                if wrong_label.len() > RSA_OAEP_LABEL_MAX_LEN {
                    wrong_label[0] ^= 0x80;
                    wrong_label.pop();
                }
                ctx.expect_fw_reject(
                    &TborRsaEncryptDecryptReq {
                        session_id: session.session_id,
                        op: RSA_ENCRYPT_DECRYPT_OP_DECRYPT,
                        padding: RSA_ENCRYPT_PADDING_OAEP,
                        hash_algo: input.hash,
                        label: wrong_label,
                        input: dev_rev(&ciphertext),
                        masked_key: masked.clone(),
                    },
                    TborStatus::RsaDecryptFailed,
                );
            }
        }

        if input.tamper_key && !input.signing_permissions {
            let recovered = ctx
                .tbor(&TborRsaEncryptDecryptReq {
                    session_id: session.session_id,
                    op: RSA_ENCRYPT_DECRYPT_OP_ENCRYPT,
                    padding: RSA_ENCRYPT_PADDING_PKCS1V15,
                    hash_algo: None,
                    label: Vec::new(),
                    input: Vec::new(),
                    masked_key: masked,
                })
                .expect("valid key must remain usable after tamper rejection");
            assert_eq!(recovered.output.len(), modulus_len);
        }
        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
