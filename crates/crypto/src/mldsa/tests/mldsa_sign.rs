// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for ML-DSA signing and verification via [`SignOp`] / [`VerifyOp`].

use super::*;

/// Builds a key pair and a signing engine for `variant`.
fn setup(variant: MlDsaVariant, ctx: &[u8]) -> (MlDsaPrivateKey, MlDsaPublicKey, MlDsaAlgo) {
    let sk = MlDsaPrivateKey::from_seed(variant, &filler(9, MLDSA_SEED_LEN)).unwrap();
    let pk = sk.public_key().unwrap();
    let algo = MlDsaAlgo::new(ctx).unwrap();
    (sk, pk, algo)
}

/// The basic contract: what we sign, we verify.
#[test]
fn sign_verify_roundtrip() {
    for variant in VARIANTS {
        let (sk, pk, mut algo) = setup(variant, b"roundtrip");
        let msg = filler(11, 200);
        let sig = Signer::sign_vec(&mut algo, &sk, &msg).unwrap();
        assert_eq!(sig.len(), variant.sig_len());

        let mut verifier = MlDsaAlgo::new(b"roundtrip").unwrap();
        assert!(Verifier::verify(&mut verifier, &pk, &msg, &sig).unwrap());
    }
}

/// Signing is hedged: different randomness gives a different, still-valid
/// signature. This is the property that distinguishes hedged from deterministic
/// signing, and the firmware signs hedged.
#[test]
fn signing_is_hedged() {
    for variant in VARIANTS {
        let sk = MlDsaPrivateKey::from_seed(variant, &filler(12, MLDSA_SEED_LEN)).unwrap();
        let pk = sk.public_key().unwrap();
        let msg = filler(13, 64);

        let mut a = MlDsaAlgo::new(b"").unwrap();
        let mut b = MlDsaAlgo::new(b"").unwrap();
        let sig_a = Signer::sign_vec(&mut a, &sk, &msg).unwrap();
        let sig_b = Signer::sign_vec(&mut b, &sk, &msg).unwrap();
        assert_ne!(sig_a, sig_b, "different randomness gave the same signature");

        let mut verifier = MlDsaAlgo::new(b"").unwrap();
        assert!(Verifier::verify(&mut verifier, &pk, &msg, &sig_a).unwrap());
        assert!(Verifier::verify(&mut verifier, &pk, &msg, &sig_b).unwrap());
    }
}

/// The same randomness reproduces the same signature, which is what makes the
/// known-answer vectors checkable.
#[test]
#[cfg(target_os = "linux")]
fn signing_is_deterministic_in_the_randomness() {
    for variant in VARIANTS {
        let (sk, _, _) = setup(variant, b"ctx");
        let mut a = MlDsaAlgo::with_randomness(b"ctx", rnd(10)).unwrap();
        let mut b =
            MlDsaAlgo::with_randomness(b"ctx", filler(10, MLDSA_RND_LEN).try_into().unwrap())
                .unwrap();
        let msg = filler(16, 32);
        assert_eq!(
            Signer::sign_vec(&mut a, &sk, &msg).unwrap(),
            Signer::sign_vec(&mut b, &sk, &msg).unwrap()
        );
    }
}

/// A modified message must not verify.
#[test]
fn a_tampered_message_does_not_verify() {
    for variant in VARIANTS {
        let (sk, pk, mut algo) = setup(variant, b"");
        let mut msg = filler(17, 48);
        let sig = Signer::sign_vec(&mut algo, &sk, &msg).unwrap();

        msg[0] ^= 0x01;
        let mut verifier = MlDsaAlgo::new(b"").unwrap();
        assert!(!Verifier::verify(&mut verifier, &pk, &msg, &sig).unwrap());
    }
}

/// A modified signature must not verify.
#[test]
fn a_tampered_signature_does_not_verify() {
    for variant in VARIANTS {
        let (sk, pk, mut algo) = setup(variant, b"");
        let msg = filler(18, 48);
        let mut sig = Signer::sign_vec(&mut algo, &sk, &msg).unwrap();
        sig[0] ^= 0x01;

        let mut verifier = MlDsaAlgo::new(b"").unwrap();
        assert!(!Verifier::verify(&mut verifier, &pk, &msg, &sig).unwrap());
    }
}

/// A signature of the wrong length is a failed verification, not an error: the
/// question asked was whether these bytes authenticate the message.
#[test]
fn a_malformed_signature_verifies_false_rather_than_erroring() {
    for variant in VARIANTS {
        let (_, pk, _) = setup(variant, b"");
        let mut verifier = MlDsaAlgo::new(b"").unwrap();
        for len in [0, 1, variant.sig_len() - 1, variant.sig_len() + 1] {
            assert_eq!(
                Verifier::verify(&mut verifier, &pk, b"msg", &filler(19, len)).unwrap(),
                false,
                "ML-DSA-{variant:?} should reject a {len}-byte signature as false"
            );
        }
    }
}

/// A signature made under one key must not verify under another.
#[test]
fn a_signature_does_not_verify_under_a_different_key() {
    for variant in VARIANTS {
        let (sk, _, mut algo) = setup(variant, b"");
        let msg = filler(20, 32);
        let sig = Signer::sign_vec(&mut algo, &sk, &msg).unwrap();

        let other = MlDsaPrivateKey::from_seed(variant, &filler(21, MLDSA_SEED_LEN))
            .unwrap()
            .public_key()
            .unwrap();
        let mut verifier = MlDsaAlgo::new(b"").unwrap();
        assert!(!Verifier::verify(&mut verifier, &other, &msg, &sig).unwrap());
    }
}

/// An empty message is valid input and must round-trip.
#[test]
fn an_empty_message_roundtrips() {
    for variant in VARIANTS {
        let (sk, pk, mut algo) = setup(variant, b"");
        let sig = Signer::sign_vec(&mut algo, &sk, b"").unwrap();
        let mut verifier = MlDsaAlgo::new(b"").unwrap();
        assert!(Verifier::verify(&mut verifier, &pk, b"", &sig).unwrap());
    }
}

/// `None` queries the signature size without signing, per the crate's buffer
/// contract.
#[test]
fn sign_reports_the_required_size() {
    for variant in VARIANTS {
        let (sk, _, mut algo) = setup(variant, b"");
        assert_eq!(
            Signer::sign(&mut algo, &sk, b"msg", None).unwrap(),
            variant.sig_len()
        );

        let mut buf = vec![0u8; variant.sig_len()];
        assert_eq!(
            Signer::sign(&mut algo, &sk, b"msg", Some(&mut buf)).unwrap(),
            variant.sig_len()
        );
    }
}

/// A short signature buffer is an error, not a truncated signature.
#[test]
fn sign_rejects_a_short_buffer() {
    for variant in VARIANTS {
        let (sk, _, mut algo) = setup(variant, b"");
        let mut buf = vec![0u8; variant.sig_len() - 1];
        assert!(matches!(
            Signer::sign(&mut algo, &sk, b"msg", Some(&mut buf)),
            Err(CryptoError::MlDsaBufferTooSmall)
        ));
    }
}

/// An engine built with [`MlDsaAlgo::new`] draws fresh randomness for every
/// signature, so signing the same message twice through one engine gives two
/// different — and both valid — signatures. This is the default path, and the
/// property that makes it safe to reuse an engine.
#[test]
fn a_drawn_randomness_engine_rerandomises_every_signature() {
    for variant in VARIANTS {
        let sk = MlDsaPrivateKey::from_seed(variant, &filler(22, MLDSA_SEED_LEN)).unwrap();
        let pk = sk.public_key().unwrap();
        let mut algo = MlDsaAlgo::new(b"drawn").unwrap();

        let first = Signer::sign_vec(&mut algo, &sk, b"msg").unwrap();
        let second = Signer::sign_vec(&mut algo, &sk, b"msg").unwrap();
        assert_ne!(first, second, "engine reused the same randomness");

        let mut verifier = MlDsaAlgo::new(b"drawn").unwrap();
        assert!(Verifier::verify(&mut verifier, &pk, b"msg", &first).unwrap());
        assert!(Verifier::verify(&mut verifier, &pk, b"msg", &second).unwrap());
    }
}

/// Pinned randomness does the opposite: the same engine reproduces one
/// signature, which is what the known-answer vectors rely on.
#[test]
#[cfg(target_os = "linux")]
fn a_pinned_randomness_engine_repeats_its_signature() {
    for variant in VARIANTS {
        let sk = MlDsaPrivateKey::from_seed(variant, &filler(22, MLDSA_SEED_LEN)).unwrap();
        let mut algo =
            MlDsaAlgo::with_randomness(b"", filler(23, MLDSA_RND_LEN).try_into().unwrap()).unwrap();
        assert_eq!(
            Signer::sign_vec(&mut algo, &sk, b"msg").unwrap(),
            Signer::sign_vec(&mut algo, &sk, b"msg").unwrap()
        );
    }
}

/// The context string is capped at 255 bytes by FIPS 204; a longer one is
/// rejected rather than truncated, by both constructors and regardless of
/// which direction the engine will be used in.
#[test]
fn construction_rejects_an_oversized_context() {
    let ctx = filler(25, MLDSA_CTX_MAX_LEN + 1);
    assert!(matches!(
        MlDsaAlgo::new(&ctx),
        Err(CryptoError::MlDsaInvalidContext)
    ));

    // The boundary itself is allowed.
    let ctx = filler(25, MLDSA_CTX_MAX_LEN);
    assert!(MlDsaAlgo::new(&ctx).is_ok());
}

/// A maximal context must still sign and verify, since the wire protocol
/// permits it.
#[test]
fn a_maximal_context_roundtrips() {
    let ctx = filler(26, MLDSA_CTX_MAX_LEN);
    for variant in VARIANTS {
        let (sk, pk, mut algo) = setup(variant, &ctx);
        let msg = filler(27, 16);
        let sig = Signer::sign_vec(&mut algo, &sk, &msg).unwrap();
        let mut verifier = MlDsaAlgo::new(&ctx).unwrap();
        assert!(Verifier::verify(&mut verifier, &pk, &msg, &sig).unwrap());
    }
}

/// Signing with a key of one parameter set must not produce something that
/// verifies under another: the variant travels with the key, so a mismatch is
/// caught rather than silently reinterpreted.
#[test]
fn parameter_sets_do_not_interoperate() {
    let msg = filler(28, 32);
    let mut algo = MlDsaAlgo::new(b"").unwrap();
    let sk =
        MlDsaPrivateKey::from_seed(MlDsaVariant::MlDsa44, &filler(30, MLDSA_SEED_LEN)).unwrap();
    let sig = Signer::sign_vec(&mut algo, &sk, &msg).unwrap();

    for variant in [MlDsaVariant::MlDsa65, MlDsaVariant::MlDsa87] {
        let pk = MlDsaPrivateKey::from_seed(variant, &filler(30, MLDSA_SEED_LEN))
            .unwrap()
            .public_key()
            .unwrap();
        let mut verifier = MlDsaAlgo::new(b"").unwrap();
        assert!(!Verifier::verify(&mut verifier, &pk, &msg, &sig).unwrap());
    }
}

/// Signing an external `μ` computed by [`HashAlgo::mldsa_mu`] is pure signing:
/// signatures from either interface verify under the other.
#[test]
fn external_mu_is_pure_signing_over_the_same_message() {
    for variant in VARIANTS {
        let sk = MlDsaPrivateKey::from_seed(variant, &filler(31, MLDSA_SEED_LEN)).unwrap();
        let pk = sk.public_key().unwrap();
        let (msg, ctx) = (filler(32, 100), filler(33, 17));
        let mu = Hasher::hash_vec(&mut HashAlgo::mldsa_mu(&pk, &ctx).unwrap(), &msg).unwrap();

        let (mut pure, mut external) = (MlDsaAlgo::new(&ctx).unwrap(), MlDsaAlgo::external_mu());
        let pure_sig = Signer::sign_vec(&mut pure, &sk, &msg).unwrap();
        let mu_sig = Signer::sign_vec(&mut external, &sk, &mu).unwrap();

        let mut pure = MlDsaAlgo::new(&ctx).unwrap();
        let mut external = MlDsaAlgo::external_mu();
        assert!(Verifier::verify(&mut pure, &pk, &msg, &mu_sig).unwrap());
        assert!(Verifier::verify(&mut external, &pk, &mu, &pure_sig).unwrap());

        // A different context gives a different mu, and the signature no
        // longer verifies under it.
        let other =
            Hasher::hash_vec(&mut HashAlgo::mldsa_mu(&pk, b"other").unwrap(), &msg).unwrap();
        assert!(!Verifier::verify(&mut external, &pk, &other, &mu_sig).unwrap());
    }
}

#[test]
#[cfg(target_os = "linux")]
fn external_mu_matches_pure_signing_with_the_same_randomness() {
    for variant in VARIANTS {
        let sk = MlDsaPrivateKey::from_seed(variant, &filler(31, MLDSA_SEED_LEN)).unwrap();
        let pk = sk.public_key().unwrap();
        let (msg, ctx) = (filler(32, 100), filler(33, 17));
        let mu = Hasher::hash_vec(&mut HashAlgo::mldsa_mu(&pk, &ctx).unwrap(), &msg).unwrap();
        let mut pure = MlDsaAlgo::with_randomness(&ctx, rnd(34)).unwrap();
        let mut external = MlDsaAlgo::external_mu_with_randomness(rnd(34));
        assert_eq!(
            Signer::sign_vec(&mut pure, &sk, &msg).unwrap(),
            Signer::sign_vec(&mut external, &sk, &mu).unwrap(),
            "{variant:?}: mu differs from the one pure signing computes"
        );
    }
}

#[test]
#[cfg(target_os = "windows")]
fn deterministic_required_is_rejected_without_writing() {
    for variant in VARIANTS {
        let (sk, pk, _) = setup(variant, b"ctx");
        for mut algo in [
            MlDsaAlgo::new(b"ctx").unwrap().deterministic(),
            MlDsaAlgo::external_mu().deterministic(),
        ] {
            let input = if algo.external_mu {
                vec![1; MLDSA_MU_LEN]
            } else {
                vec![1; 17]
            };
            let mut output = vec![0xA5; variant.sig_len()];
            assert_eq!(
                algo.sign(&sk, &input, Some(&mut output)),
                Err(CryptoError::MlDsaDeterministicUnsupported)
            );
            assert!(output.iter().all(|byte| *byte == 0xA5));
            assert_eq!(algo.sign(&sk, &input, None).unwrap(), variant.sig_len());
        }
        let mut hedged = MlDsaAlgo::new(b"ctx").unwrap();
        let sig = Signer::sign_vec(&mut hedged, &sk, b"message").unwrap();
        let mut verifier = MlDsaAlgo::new(b"ctx").unwrap().deterministic();
        assert!(verifier.verify(&pk, b"message", &sig).unwrap());
    }
}

/// An external `μ` is exactly 64 bytes; anything else is malformed input to
/// both directions, not a failed verification.
#[test]
fn external_mu_of_the_wrong_length_is_rejected() {
    let (sk, pk, _) = setup(MlDsaVariant::MlDsa44, b"");
    let mut algo = MlDsaAlgo::external_mu();
    let sig = Signer::sign_vec(&mut algo, &sk, &[7; MLDSA_MU_LEN]).unwrap();
    for len in [0, MLDSA_MU_LEN - 1, MLDSA_MU_LEN + 1] {
        let mu = vec![7; len];
        assert!(matches!(
            Signer::sign_vec(&mut algo, &sk, &mu),
            Err(CryptoError::MlDsaInvalidMu)
        ));
        assert!(matches!(
            Verifier::verify(&mut algo, &pk, &mu, &sig),
            Err(CryptoError::MlDsaInvalidMu)
        ));
    }
}

/// `μ` binds the context string, so it shares its 255-byte limit.
#[test]
fn mu_rejects_an_oversized_context() {
    let (_, pk, _) = setup(MlDsaVariant::MlDsa44, b"");
    assert!(matches!(
        HashAlgo::mldsa_mu(&pk, &filler(35, MLDSA_CTX_MAX_LEN + 1)),
        Err(CryptoError::MlDsaInvalidContext)
    ));
    assert!(HashAlgo::mldsa_mu(&pk, &filler(35, MLDSA_CTX_MAX_LEN)).is_ok());
}

/// `μ` is an ordinary hash of the message: streamed in any chunks, it
/// matches the one-shot result, and it reports its 64-byte length.
#[test]
fn mu_streams_like_a_one_shot_hash() {
    let (_, pk, _) = setup(MlDsaVariant::MlDsa65, b"");
    let msg = filler(36, 1000);
    let mut algo = HashAlgo::mldsa_mu(&pk, b"ctx").unwrap();
    assert_eq!(Hasher::hash(&mut algo, &msg, None).unwrap(), MLDSA_MU_LEN);
    let one_shot = Hasher::hash_vec(&mut algo, &msg).unwrap();

    // Split across SHAKE256's 136-byte rate, with an empty chunk too.
    let mut stream = Hasher::hash_init(algo).unwrap();
    for chunk in [
        &msg[..0],
        &msg[..1],
        &msg[1..136],
        &msg[136..137],
        &msg[137..],
    ] {
        stream.update(chunk).unwrap();
    }
    assert_eq!(stream.finish_vec().unwrap(), one_shot);
}
