// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! KBKDF execution is legacy-only. In EX builds, success-path tests expect the
//! explicit unsupported-operation failure, while host property guards remain shared.

use tsra_api::*;
use tsra_api_tests_macro::*;
use tsra_crypto as crypto;
use tsra_crypto::ImportableKey;
use tsra_crypto::Rng;

use crate::algo::rsa::get_rsa_unwrapping_key_pair;

// ================================
// Helper functions
// ================================

/// Generates a random IV of the given size.
pub fn test_iv(size: usize) -> Vec<u8> {
    Rng::rand_vec(size).expect("RNG failure generating IV")
}

/// Returns the KBKDF HMAC hash algorithms covered by the C++ matrix tests.
fn supported_kbkdf_hash_algos() -> &'static [HsmHashAlgo] {
    &[
        HsmHashAlgo::Sha1,
        HsmHashAlgo::Sha256,
        HsmHashAlgo::Sha384,
        HsmHashAlgo::Sha512,
    ]
}

/// Creates a KBKDF SP 800-108 Counter Mode algorithm instance.
fn kbkdf_counter_algo(
    hash: HsmHashAlgo,
    label: Option<&[u8]>,
    context: Option<&[u8]>,
) -> HsmKbkdfAlgo {
    HsmKbkdfAlgo::new(hash, label, context).expect("Failed KBKDF Counter Mode algo creation")
}

fn import_generic_secret(
    session: &HsmSession,
    material: &[u8],
    props: HsmKeyProps,
) -> HsmResult<HsmGenericSecretKey> {
    let (private, public) = get_rsa_unwrapping_key_pair(session);
    let mut wrap = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap, &public, material)?;
    let mut unwrap = HsmGenericSecretKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    HsmKeyManager::unwrap_key(&mut unwrap, &private, &wrapped, props)
}

fn generic_secret_props(bits: u32, is_session: bool) -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::GenericSecret)
        .bits(bits)
        .can_derive(true)
        .is_session(is_session)
        .build()
        .expect("Generic-secret properties")
}

/// Imports the same externally supplied material into two independent keys.
fn import_generic_secrets(
    session: &HsmSession,
    key_len: usize,
) -> (HsmGenericSecretKey, HsmGenericSecretKey) {
    let material = Rng::rand_vec(key_len).expect("Generic-secret test material");
    let props = generic_secret_props((key_len * 8) as u32, false);
    let a =
        import_generic_secret(session, &material, props.clone()).expect("Import generic secret");
    let b = import_generic_secret(session, &material, props).expect("Import generic secret");
    (a, b)
}

/// Derives an AES key from a imported generic secret using KBKDF with the given parameters.
fn derive_aes_key_from_generic_secret(
    session: &HsmSession,
    kbkdf_algo: &mut HsmKbkdfAlgo,
    generic_secret: &HsmGenericSecretKey,
    bits: u32,
) -> HsmAesKey {
    let aes_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build AES key props");

    let derived_key = HsmKeyManager::derive_key(session, kbkdf_algo, generic_secret, aes_key_props)
        .expect("Failed to derive AES key");

    assert_eq!(derived_key.kind(), HsmKeyKind::Aes);
    assert_eq!(derived_key.bits(), bits);
    derived_key
        .try_into()
        .expect("Derived key was not an AES key")
}

/// Verifies AES-CBC encryption and decryption roundtrip correctness.
fn assert_aes_cbc_roundtrip(enc_key: &HsmAesKey, dec_key: &HsmAesKey, plaintext: &[u8]) {
    let iv = test_iv(16);

    let mut enc =
        HsmAesCbcAlgo::with_padding(iv.clone()).expect("AES-CBC algo creation failed (enc)");

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut enc, enc_key, plaintext).expect("AES-CBC encryption failed");

    let mut dec = HsmAesCbcAlgo::with_padding(iv).expect("AES-CBC algo creation failed (dec)");

    let decrypted = HsmDecrypter::decrypt_vec(&mut dec, dec_key, &ciphertext)
        .expect("AES-CBC decryption failed");

    assert_eq!(decrypted, plaintext, "AES-CBC roundtrip mismatch");
}

/// Verifies two AES-CBC keys do not recover the same plaintext.
fn assert_aes_cbc_roundtrip_does_not_recover_plaintext(
    enc_key: &HsmAesKey,
    dec_key: &HsmAesKey,
    plaintext: &[u8],
) {
    let iv = [0u8; 16];

    let mut enc =
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo creation failed (enc)");

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut enc, enc_key, plaintext).expect("AES-CBC encryption failed");

    let mut dec =
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo creation failed (dec)");

    if let Ok(decrypted) = HsmDecrypter::decrypt_vec(&mut dec, dec_key, &ciphertext) {
        assert_ne!(
            decrypted, plaintext,
            "mismatched KBKDF-derived key recovered original plaintext"
        );
    }
}

/// Derives with custom output key properties and returns only success/failure.
fn kbkdf_derive_with_props(
    session: &HsmSession,
    hash: HsmHashAlgo,
    props: HsmKeyProps,
) -> Result<(), HsmError> {
    let (secret, _) = import_generic_secrets(session, 32);
    let mut kbkdf = kbkdf_counter_algo(hash, Some(b"failure-label"), Some(b"failure-context"));

    HsmKeyManager::derive_key(session, &mut kbkdf, &secret, props).map(|_| ())
}

/// Runs the KBKDF matrix across HMAC hashes and AES key sizes for a key_len.
fn run_kbkdf_counter_matrix_for_key_len(session: &HsmSession, key_len: usize) {
    let (generic_secret_a, generic_secret_b) = import_generic_secrets(session, key_len);

    for &hash_algo in supported_kbkdf_hash_algos() {
        for &bits in &[128u32, 192u32, 256u32] {
            let label = format!("kbkdf-label-{key_len:?}-{hash_algo:?}-{bits}");
            let context = format!("kbkdf-context-{key_len:?}-{hash_algo:?}-{bits}");

            let mut kbkdf_a =
                kbkdf_counter_algo(hash_algo, Some(label.as_bytes()), Some(context.as_bytes()));
            let mut kbkdf_b =
                kbkdf_counter_algo(hash_algo, Some(label.as_bytes()), Some(context.as_bytes()));

            let key_a =
                derive_aes_key_from_generic_secret(session, &mut kbkdf_a, &generic_secret_a, bits);
            let key_b =
                derive_aes_key_from_generic_secret(session, &mut kbkdf_b, &generic_secret_b, bits);

            let plaintext = format!("KBKDF key_len={key_len:?} hash={hash_algo:?} aes_bits={bits}")
                .into_bytes();
            assert_aes_cbc_roundtrip(&key_a, &key_b, &plaintext);
        }
    }
}

/// Verifies label-only KBKDF derives interoperable AES keys.
fn run_kbkdf_label_only_roundtrip(session: &HsmSession) {
    let (secret_a, secret_b) = import_generic_secrets(session, 32);

    let mut kbkdf_a = kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"label-only"), None);
    let mut kbkdf_b = kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"label-only"), None);

    let key_a = derive_aes_key_from_generic_secret(session, &mut kbkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_generic_secret(session, &mut kbkdf_b, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"label only");
}

/// Verifies context-only KBKDF derives interoperable AES keys.
fn run_kbkdf_context_only_roundtrip(session: &HsmSession) {
    let (secret_a, secret_b) = import_generic_secrets(session, 32);

    let mut kbkdf_a = kbkdf_counter_algo(HsmHashAlgo::Sha256, None, Some(b"context-only"));
    let mut kbkdf_b = kbkdf_counter_algo(HsmHashAlgo::Sha256, None, Some(b"context-only"));

    let key_a = derive_aes_key_from_generic_secret(session, &mut kbkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_generic_secret(session, &mut kbkdf_b, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"context only");
}

/// Verifies a specific KBKDF hash algorithm works with label and context.
fn run_kbkdf_hash_label_context_roundtrip(session: &HsmSession, hash: HsmHashAlgo, msg: &[u8]) {
    let (secret_a, secret_b) = import_generic_secrets(session, 32);

    let mut kbkdf_a =
        kbkdf_counter_algo(hash, Some(b"kbkdf-hash-label"), Some(b"kbkdf-hash-context"));
    let mut kbkdf_b =
        kbkdf_counter_algo(hash, Some(b"kbkdf-hash-label"), Some(b"kbkdf-hash-context"));

    let key_a = derive_aes_key_from_generic_secret(session, &mut kbkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_generic_secret(session, &mut kbkdf_b, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, msg);
}

/// Verifies KBKDF derives a specific AES key size.
fn run_kbkdf_aes_size_roundtrip(session: &HsmSession, bits: u32) {
    let (secret_a, secret_b) = import_generic_secrets(session, 32);

    let label = format!("aes-{bits}-label");
    let context = format!("aes-{bits}-context");

    let mut kbkdf_a = kbkdf_counter_algo(
        HsmHashAlgo::Sha256,
        Some(label.as_bytes()),
        Some(context.as_bytes()),
    );
    let mut kbkdf_b = kbkdf_counter_algo(
        HsmHashAlgo::Sha256,
        Some(label.as_bytes()),
        Some(context.as_bytes()),
    );

    let key_a = derive_aes_key_from_generic_secret(session, &mut kbkdf_a, &secret_a, bits);
    let key_b = derive_aes_key_from_generic_secret(session, &mut kbkdf_b, &secret_b, bits);

    let msg = format!("kbkdf aes {bits}").into_bytes();
    assert_aes_cbc_roundtrip(&key_a, &key_b, &msg);
}

/// Verifies identical imported generic secret and identical KBKDF parameters derive compatible keys.
fn run_kbkdf_same_secret_same_params_roundtrip(session: &HsmSession) {
    let (secret, _) = import_generic_secrets(session, 32);

    let mut kbkdf_a = kbkdf_counter_algo(
        HsmHashAlgo::Sha256,
        Some(b"same-secret-label"),
        Some(b"same-secret-context"),
    );
    let mut kbkdf_b = kbkdf_counter_algo(
        HsmHashAlgo::Sha256,
        Some(b"same-secret-label"),
        Some(b"same-secret-context"),
    );

    let key_a = derive_aes_key_from_generic_secret(session, &mut kbkdf_a, &secret, 256);
    let key_b = derive_aes_key_from_generic_secret(session, &mut kbkdf_b, &secret, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"same secret same params");
}

// ================================
// Test cases
// ================================

/// Verifies KBKDF Counter Mode matrix coverage for 32-byte input keys.
#[session_test]
fn test_kbkdf_matrix_32_bytes(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            run_kbkdf_counter_matrix_for_key_len(&session, 32);
        },
    );
}

/// Verifies KBKDF Counter Mode matrix coverage for 48-byte input keys.
#[session_test]
fn test_kbkdf_matrix_48_bytes(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            run_kbkdf_counter_matrix_for_key_len(&session, 48);
        },
    );
}

/// Verifies KBKDF Counter Mode matrix coverage for 64-byte input keys.
#[session_test]
fn test_kbkdf_matrix_64_bytes(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            run_kbkdf_counter_matrix_for_key_len(&session, 64);
        },
    );
}

/// Verifies KBKDF rejects deriving an AES-GCM key.
#[session_test]
fn test_kbkdf_derive_aes_gcm_key_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build AES-GCM key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject AES-GCM output key kind");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF rejects deriving a SharedSecret key.
#[session_test]
fn test_kbkdf_derive_unsupported_key_kind_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(true)
        .build()
        .expect("Failed to build shared-secret key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject SharedSecret output key kind");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF rejects deriving with zero output bit length.
#[session_test]
fn test_kbkdf_derive_zero_bit_len_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(0)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build zero-bit AES key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject zero-bit AES output");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF works when only a label is supplied.
#[session_test]
fn test_kbkdf_label_only_roundtrip(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            run_kbkdf_label_only_roundtrip(&session);
        },
    );
}

/// Verifies KBKDF works when only a context is supplied.
#[session_test]
fn test_kbkdf_context_only_roundtrip(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            run_kbkdf_context_only_roundtrip(&session);
        },
    );
}

/// Verifies KBKDF roundtrip with HMAC-SHA512 label/context parameters.
#[session_test]
fn test_kbkdf_hmac_sha512_label_context_roundtrip(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            run_kbkdf_hash_label_context_roundtrip(
                &session,
                HsmHashAlgo::Sha512,
                b"kbkdf hmac sha512",
            );
        },
    );
}

/// Verifies KBKDF roundtrip with HMAC-SHA384 label/context parameters.
#[session_test]
fn test_kbkdf_hmac_sha384_label_context_roundtrip(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            run_kbkdf_hash_label_context_roundtrip(
                &session,
                HsmHashAlgo::Sha384,
                b"kbkdf hmac sha384",
            );
        },
    );
}

/// Verifies KBKDF can derive a 128-bit AES key.
#[session_test]
fn test_kbkdf_derive_aes_128_roundtrip(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            run_kbkdf_aes_size_roundtrip(&session, 128);
        },
    );
}

/// Verifies KBKDF can derive a 192-bit AES key.
#[session_test]
fn test_kbkdf_derive_aes_192_roundtrip(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            run_kbkdf_aes_size_roundtrip(&session, 192);
        },
    );
}

/// Verifies KBKDF rejects AES output keys without encrypt/decrypt usage flags.
#[session_test]
fn test_kbkdf_derive_aes_without_usage_flags_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .build()
        .expect("Failed to build AES key props without usage flags");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject AES key without usage flags");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF rejects unsupported AES key sizes.
#[session_test]
fn test_kbkdf_derive_invalid_aes_key_size_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(129)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build invalid-size AES key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject unsupported AES key size");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF rejects non-secret output key classes.
#[session_test]
fn test_kbkdf_derive_non_secret_key_class_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build public AES key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject non-secret output key class");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF derives compatible keys from the same imported generic secret and parameters.
#[session_test]
fn test_kbkdf_same_secret_same_params_roundtrip(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            run_kbkdf_same_secret_same_params_roundtrip(&session);
        },
    );
}

/// Verifies changing KBKDF label changes the derived key material.
#[session_test]
fn test_kbkdf_different_label_produces_non_interoperable_key(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            let (secret_a, secret_b) = import_generic_secrets(&session, 32);

            let mut kbkdf_a =
                kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"label-a"), Some(b"same-context"));

            let mut kbkdf_b =
                kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"label-b"), Some(b"same-context"));

            let key_a = derive_aes_key_from_generic_secret(&session, &mut kbkdf_a, &secret_a, 256);
            let key_b = derive_aes_key_from_generic_secret(&session, &mut kbkdf_b, &secret_b, 256);

            assert_aes_cbc_roundtrip_does_not_recover_plaintext(
                &key_a,
                &key_b,
                b"different KBKDF label should not interoperate",
            );
        },
    );
}

/// Verifies changing KBKDF context changes the derived key material.
#[session_test]
fn test_kbkdf_different_context_produces_non_interoperable_key(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || {
            let (secret_a, secret_b) = import_generic_secrets(&session, 32);

            let mut kbkdf_a =
                kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"same-label"), Some(b"context-a"));

            let mut kbkdf_b =
                kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"same-label"), Some(b"context-b"));

            let key_a = derive_aes_key_from_generic_secret(&session, &mut kbkdf_a, &secret_a, 256);
            let key_b = derive_aes_key_from_generic_secret(&session, &mut kbkdf_b, &secret_b, 256);

            assert_aes_cbc_roundtrip_does_not_recover_plaintext(
                &key_a,
                &key_b,
                b"different KBKDF context should not interoperate",
            );
        },
    );
}

/// Verifies KBKDF rejects AES output keys with only encrypt usage enabled.
#[session_test]
fn test_kbkdf_derive_aes_encrypt_only_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .build()
        .expect("Failed to build AES encrypt-only key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject AES encrypt-only output key");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF rejects AES output keys with only decrypt usage enabled.
#[session_test]
fn test_kbkdf_derive_aes_decrypt_only_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_decrypt(true)
        .build()
        .expect("Failed to build AES decrypt-only key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject AES decrypt-only output key");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

#[session_test]
fn test_generic_secret_import_unmask_boundaries(session: HsmSession) {
    for key_len in [16, 17, 20, 32, 48, 64, 127, 128] {
        for is_session in [false, true] {
            let material = vec![0x5a; key_len];
            let bits = (key_len * 8) as u32;
            let key =
                import_generic_secret(&session, &material, generic_secret_props(bits, is_session))
                    .expect("Import generic secret");
            let masked = key.masked_key_vec().expect("Masked generic secret");
            assert_eq!(key.kind(), HsmKeyKind::GenericSecret);
            assert_eq!(key.bits(), bits);
            assert!(!key.is_local());
            assert!(key.can_derive());
            assert!(!key.can_sign());
            HsmKeyManager::delete_key(key).expect("Delete imported key");

            let restored = HsmKeyManager::unmask_key(
                &session,
                &mut HsmGenericSecretKeyUnmaskAlgo::default(),
                &masked,
            )
            .expect("Restore generic secret");
            assert_eq!(restored.bits(), bits);
            assert_eq!(restored.is_session(), is_session);
            assert!(!restored.is_local());
            assert!(
                HsmKeyManager::unmask_key(
                    &session,
                    &mut HsmSharedSecretKeyUnmaskAlgo::default(),
                    &masked,
                )
                .is_err()
            );
            let mut corrupted = masked;
            let last = corrupted.len() - 1;
            corrupted[last] ^= 1;
            assert!(
                HsmKeyManager::unmask_key(
                    &session,
                    &mut HsmGenericSecretKeyUnmaskAlgo::default(),
                    &corrupted,
                )
                .is_err()
            );
        }
    }
}

#[session_test]
fn test_generic_secret_import_rejects_recovered_length_mismatch(session: HsmSession) {
    for (actual, requested_bits) in [(15, 128), (129, 1024), (31, 256), (33, 256)] {
        assert!(
            import_generic_secret(
                &session,
                &vec![0x5a; actual],
                generic_secret_props(requested_bits, false),
            )
            .is_err()
        );
    }
}

#[session_test]
fn test_kbkdf_matrix_20_bytes(session: HsmSession) {
    crate::utils::session::panics_from_api_rev_1_1(
        "Failed to derive AES key: UnsupportedKeyOperation",
        || run_kbkdf_counter_matrix_for_key_len(&session, 20),
    );
}

#[session_test]
fn test_kbkdf_rejects_generic_secret_output(session: HsmSession) {
    let result = kbkdf_derive_with_props(
        &session,
        HsmHashAlgo::Sha256,
        generic_secret_props(256, false),
    );
    assert_eq!(result, Err(HsmError::InvalidKeyProps));
}

#[session_test]
fn test_ecdh_cannot_create_generic_secret(session: HsmSession) {
    let (private, public) = crate::algo::ecc::generate_ecc_keypair_with_derive(
        session.clone(),
        HsmEccCurve::P256,
        true,
    )
    .expect("ECDH test key");
    let der = public.pub_key_der_vec().expect("ECDH public key");
    let result = HsmKeyManager::derive_key(
        &session,
        &mut EcdhAlgo::new(&der),
        &private,
        generic_secret_props(256, false),
    );
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[test]
fn test_generic_secret_unmask_rejects_other_session() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = crate::utils::partition_ex_helpers::PARTITION_LOCK.lock();
    let (partition, revision, session) = crate::utils::sd_provision::finalized_co_partition();
    let key = import_generic_secret(&session, &[0x5a; 32], generic_secret_props(256, true))
        .expect("Session-scoped generic secret");
    let masked = key.masked_key_vec().expect("Masked generic secret");
    let other_partition = HsmPartitionManager::open_partition(&partition.path(), revision)
        .expect("Open another partition handle");
    let other = other_partition
        .open_session_ex(
            revision,
            HsmSessionPsk::new(HsmPskId::CU),
            HsmSessionExType::PlainText,
        )
        .expect("Another session");
    other
        .change_psk(&[0x5a; PSK_LEN])
        .expect("Rotate target PSK");
    let result = HsmKeyManager::unmask_key(
        &other,
        &mut HsmGenericSecretKeyUnmaskAlgo::default(),
        &masked,
    );
    assert!(matches!(
        result,
        Err(HsmError::MaskedKeyAuthenticationFailed)
    ));
}

#[session_test]
fn test_kbkdf_imported_key_known_answers(session: HsmSession) {
    if crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    // Independent HMAC counter-mode answers, including the production [L] field.
    let cases = [
        (
            HsmHashAlgo::Sha1,
            20,
            [
                0x19, 0x15, 0x75, 0xb1, 0x13, 0xc9, 0x29, 0xfc, 0x26, 0xee, 0xc4, 0x16, 0x5c, 0x0f,
                0xf4, 0xba, 0x89, 0x51, 0x27, 0x0f, 0x52, 0xd6, 0xca, 0xdc, 0xd7, 0x91, 0xc1, 0x8a,
                0x4b, 0x05, 0x34, 0x96,
            ],
        ),
        (
            HsmHashAlgo::Sha256,
            32,
            [
                0x4c, 0x04, 0xaf, 0xca, 0xc8, 0x64, 0x75, 0xcb, 0xe6, 0x74, 0xb5, 0xba, 0x91, 0x62,
                0x14, 0x0d, 0xf9, 0xbc, 0xc7, 0xc3, 0x51, 0x66, 0x34, 0xe2, 0x4a, 0xe5, 0x8a, 0x39,
                0x69, 0x74, 0xcf, 0x9f,
            ],
        ),
        (
            HsmHashAlgo::Sha384,
            48,
            [
                0xe5, 0xd4, 0x24, 0xdb, 0x22, 0x2e, 0xca, 0x4c, 0x70, 0xaf, 0x66, 0xa9, 0x68, 0x95,
                0xe0, 0x56, 0x2e, 0xe0, 0x09, 0x2a, 0x1a, 0x72, 0x9a, 0x23, 0xbb, 0x8b, 0xe1, 0x4d,
                0x2e, 0x1f, 0xc3, 0xa6,
            ],
        ),
        (
            HsmHashAlgo::Sha512,
            64,
            [
                0xf7, 0x90, 0xf6, 0x19, 0xd7, 0x51, 0x3a, 0xc6, 0x15, 0xdc, 0x86, 0x2c, 0x16, 0xf2,
                0x5c, 0x0a, 0x1a, 0x0c, 0x5f, 0x43, 0x7e, 0xd5, 0x2b, 0x85, 0x74, 0xb3, 0x2b, 0x49,
                0x30, 0x6c, 0xcd, 0x64,
            ],
        ),
    ];
    let data = [0xa5; 32];
    for (hash, input_len, expected) in cases {
        let material: Vec<u8> = (0..input_len).collect();
        let secret = import_generic_secret(
            &session,
            &material,
            generic_secret_props(u32::from(input_len) * 8, false),
        )
        .expect("Import known input");
        let mut algo = kbkdf_counter_algo(hash, Some(b"generic-secret-kat"), Some(b"imported"));
        let aes = derive_aes_key_from_generic_secret(&session, &mut algo, &secret, 256);
        let actual = HsmEncrypter::encrypt_vec(
            &mut HsmAesCbcAlgo::with_no_padding(vec![0; 16]).expect("CBC algorithm"),
            &aes,
            &data,
        )
        .expect("Derived AES encryption");
        let expected_ciphertext = crypto::Encrypter::encrypt_vec(
            &mut crypto::AesCbcAlgo::with_no_padding(&[0; 16]),
            &crypto::AesKey::from_bytes(&expected).expect("Expected AES key"),
            &data,
        )
        .expect("Reference AES encryption");
        assert_eq!(actual, expected_ciphertext, "KBKDF {hash:?} AES output");

        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::HmacSha256)
            .bits(256)
            .can_sign(true)
            .can_verify(true)
            .build()
            .expect("HMAC output properties");
        let hmac: HsmHmacKey = HsmKeyManager::derive_key(&session, &mut algo, &secret, props)
            .expect("Derive HMAC")
            .try_into()
            .expect("HMAC wrapper");
        let actual =
            HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &hmac, &data).expect("Derived HMAC");
        let expected_tag = crypto::Signer::sign_vec(
            &mut crypto::HmacAlgo::new(crypto::HashAlgo::sha256()),
            &crypto::HmacKey::from_bytes(&expected).expect("Expected HMAC key"),
            &data,
        )
        .expect("Reference HMAC");
        assert_eq!(actual, expected_tag, "KBKDF {hash:?} HMAC output");
    }
}
