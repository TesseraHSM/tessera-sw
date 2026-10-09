// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for ML-KEM encapsulation and decapsulation via [`EncapsulateOp`] /
//! [`DecapsulateOp`].

use super::*;

/// Builds a key pair and an encapsulation engine for `variant`.
fn setup(variant: MlKemVariant, m_tag: u8) -> (MlKemPrivateKey, MlKemPublicKey, MlKemAlgo) {
    let dk = MlKemPrivateKey::from_seed(variant, &filler(9, MLKEM_SEED_LEN)).unwrap();
    let ek = dk.public_key().unwrap();
    let algo = MlKemAlgo::with_message(msg(m_tag));
    (dk, ek, algo)
}

/// Encapsulates with `algo`, returning the ciphertext and shared secret.
fn encapsulate(algo: &mut MlKemAlgo, ek: &MlKemPublicKey) -> (Vec<u8>, Vec<u8>) {
    let (ct_len, ss_len) = algo.encapsulate(ek, None, None).unwrap();
    let mut ct = vec![0u8; ct_len];
    let mut ss = vec![0u8; ss_len];
    algo.encapsulate(ek, Some(&mut ct), Some(&mut ss)).unwrap();
    (ct, ss)
}

/// Decapsulates `ct`, returning the shared secret.
fn decapsulate(dk: &MlKemPrivateKey, ct: &[u8]) -> Vec<u8> {
    let mut algo = MlKemAlgo::new();
    let len = algo.decapsulate(dk, ct, None).unwrap();
    let mut ss = vec![0u8; len];
    algo.decapsulate(dk, ct, Some(&mut ss)).unwrap();
    ss
}

/// The basic contract: both sides derive the same secret.
#[test]
fn encapsulate_decapsulate_roundtrip() {
    for variant in VARIANTS {
        let (dk, ek, mut algo) = setup(variant, 10);
        let (ct, ss) = encapsulate(&mut algo, &ek);
        assert_eq!(ct.len(), variant.ciphertext_len());
        assert_eq!(ss.len(), MLKEM_SHARED_SECRET_LEN);
        assert_eq!(decapsulate(&dk, &ct), ss);
    }
}

/// Encapsulation is deterministic in the message, which is what makes the
/// known-answer vectors checkable.
#[test]
fn encapsulation_is_deterministic_in_the_message() {
    for variant in VARIANTS {
        let (_, ek, mut a) = setup(variant, 11);
        let mut b = MlKemAlgo::with_message(msg(11));
        assert_eq!(encapsulate(&mut a, &ek), encapsulate(&mut b, &ek));
    }
}

/// Different messages must give different ciphertexts and secrets; otherwise
/// the message is not reaching the algorithm.
#[test]
fn distinct_messages_give_distinct_results() {
    for variant in VARIANTS {
        let (_, ek, mut a) = setup(variant, 12);
        let mut b = MlKemAlgo::with_message(msg(13));
        let (ct_a, ss_a) = encapsulate(&mut a, &ek);
        let (ct_b, ss_b) = encapsulate(&mut b, &ek);
        assert_ne!(ct_a, ct_b);
        assert_ne!(ss_a, ss_b);
    }
}

/// A tampered ciphertext must not yield the original secret. FIPS 203 rejects
/// implicitly, so this is a different secret rather than an error — which is
/// exactly what stops the caller being used as a decryption oracle.
#[test]
fn a_tampered_ciphertext_rejects_implicitly() {
    for variant in VARIANTS {
        let (dk, ek, mut algo) = setup(variant, 14);
        let (mut ct, ss) = encapsulate(&mut algo, &ek);
        ct[0] ^= 0x01;

        let rejected = decapsulate(&dk, &ct);
        assert_eq!(rejected.len(), MLKEM_SHARED_SECRET_LEN);
        assert_ne!(rejected, ss, "a tampered ciphertext recovered the secret");
    }
}

/// Implicit rejection is deterministic: the same bad ciphertext always yields
/// the same secret, so repetition leaks nothing either.
#[test]
fn implicit_rejection_is_deterministic() {
    for variant in VARIANTS {
        let (dk, ek, mut algo) = setup(variant, 15);
        let (mut ct, _) = encapsulate(&mut algo, &ek);
        ct[1] ^= 0xFF;
        assert_eq!(decapsulate(&dk, &ct), decapsulate(&dk, &ct));
    }
}

/// Decapsulating under the wrong key must not recover the secret.
#[test]
fn decapsulation_under_a_different_key_does_not_recover_the_secret() {
    for variant in VARIANTS {
        let (_, ek, mut algo) = setup(variant, 16);
        let (ct, ss) = encapsulate(&mut algo, &ek);

        let other = MlKemPrivateKey::from_seed(variant, &filler(17, MLKEM_SEED_LEN)).unwrap();
        assert_ne!(decapsulate(&other, &ct), ss);
    }
}

/// A ciphertext of the wrong length is a malformed input and is reported as an
/// error, unlike one that merely fails to decrypt.
#[test]
fn decapsulation_rejects_a_wrong_length_ciphertext() {
    for variant in VARIANTS {
        let dk = MlKemPrivateKey::from_seed(variant, &filler(18, MLKEM_SEED_LEN)).unwrap();
        let mut algo = MlKemAlgo::new();
        let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
        for len in [
            0,
            variant.ciphertext_len() - 1,
            variant.ciphertext_len() + 1,
        ] {
            assert!(matches!(
                algo.decapsulate(&dk, &filler(19, len), Some(&mut ss)),
                Err(CryptoError::MlKemDecapsError)
            ));
        }
    }
}

/// `None` queries the required sizes without doing the work, per the crate's
/// buffer contract.
#[test]
fn operations_report_required_sizes() {
    for variant in VARIANTS {
        let (dk, ek, mut algo) = setup(variant, 20);
        assert_eq!(
            algo.encapsulate(&ek, None, None).unwrap(),
            (variant.ciphertext_len(), MLKEM_SHARED_SECRET_LEN)
        );

        let mut decaps = MlKemAlgo::new();
        assert_eq!(
            decaps.decapsulate(&dk, &[], None).unwrap(),
            MLKEM_SHARED_SECRET_LEN
        );
    }
}

/// Short output buffers are errors, not truncated results.
#[test]
fn operations_reject_short_buffers() {
    for variant in VARIANTS {
        let (dk, ek, mut algo) = setup(variant, 21);
        let (ct, _) = encapsulate(&mut algo, &ek);

        let mut short_ct = vec![0u8; variant.ciphertext_len() - 1];
        let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
        assert!(matches!(
            algo.encapsulate(&ek, Some(&mut short_ct), Some(&mut ss)),
            Err(CryptoError::MlKemBufferTooSmall)
        ));

        let mut full_ct = vec![0u8; variant.ciphertext_len()];
        let mut short_ss = [0u8; MLKEM_SHARED_SECRET_LEN - 1];
        assert!(matches!(
            algo.encapsulate(&ek, Some(&mut full_ct), Some(&mut short_ss)),
            Err(CryptoError::MlKemBufferTooSmall)
        ));

        let mut decaps = MlKemAlgo::new();
        assert!(matches!(
            decaps.decapsulate(&dk, &ct, Some(&mut short_ss)),
            Err(CryptoError::MlKemBufferTooSmall)
        ));
    }
}

/// An engine built with [`MlKemAlgo::new`] draws a fresh message for every
/// encapsulation, so encapsulating twice to one key gives two different
/// ciphertexts and secrets, each of which still decapsulates correctly. This
/// is the default path, and the property that makes it safe to reuse an
/// engine.
#[test]
fn a_drawn_message_engine_rerandomises_every_encapsulation() {
    for variant in VARIANTS {
        let (dk, ek, _) = setup(variant, 22);
        let mut algo = MlKemAlgo::new();

        let (ct_a, ss_a) = encapsulate(&mut algo, &ek);
        let (ct_b, ss_b) = encapsulate(&mut algo, &ek);
        assert_ne!(ct_a, ct_b, "engine reused the same message");
        assert_ne!(ss_a, ss_b);

        assert_eq!(decapsulate(&dk, &ct_a), ss_a);
        assert_eq!(decapsulate(&dk, &ct_b), ss_b);
    }
}

/// A pinned message does the opposite: the same engine reproduces one
/// ciphertext, which is what the known-answer vectors rely on.
#[test]
fn a_pinned_message_engine_repeats_its_ciphertext() {
    for variant in VARIANTS {
        let (_, ek, mut algo) = setup(variant, 23);
        assert_eq!(encapsulate(&mut algo, &ek), encapsulate(&mut algo, &ek));
    }
}

/// A ciphertext from one parameter set must not decapsulate under another: the
/// variant travels with the key, so the length mismatch is caught rather than
/// silently reinterpreted.
#[test]
fn parameter_sets_do_not_interoperate() {
    let (_, ek, mut algo) = setup(MlKemVariant::MlKem512, 24);
    let (ct, _) = encapsulate(&mut algo, &ek);

    for variant in [MlKemVariant::MlKem768, MlKemVariant::MlKem1024] {
        let dk = MlKemPrivateKey::from_seed(variant, &filler(9, MLKEM_SEED_LEN)).unwrap();
        let mut decaps = MlKemAlgo::new();
        let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
        assert!(matches!(
            decaps.decapsulate(&dk, &ct, Some(&mut ss)),
            Err(CryptoError::MlKemDecapsError)
        ));
    }
}
