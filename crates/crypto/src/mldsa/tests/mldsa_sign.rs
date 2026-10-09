// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for ML-DSA signing and verification via [`SignOp`] / [`VerifyOp`].

use super::*;

/// Builds a key pair and a signing engine for `variant`.
fn setup(variant: MlDsaVariant, ctx: &[u8]) -> (MlDsaPrivateKey, MlDsaPublicKey, MlDsaAlgo) {
    let sk = MlDsaPrivateKey::from_seed(variant, &filler(9, MLDSA_SEED_LEN)).unwrap();
    let pk = sk.public_key().unwrap();
    let algo = MlDsaAlgo::with_randomness(ctx, rnd(10)).unwrap();
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

        let mut a =
            MlDsaAlgo::with_randomness(b"", filler(14, MLDSA_RND_LEN).try_into().unwrap()).unwrap();
        let mut b =
            MlDsaAlgo::with_randomness(b"", filler(15, MLDSA_RND_LEN).try_into().unwrap()).unwrap();
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
fn signing_is_deterministic_in_the_randomness() {
    for variant in VARIANTS {
        let (sk, _, mut a) = setup(variant, b"ctx");
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
    let pinned = rnd(24);
    let ctx = filler(25, MLDSA_CTX_MAX_LEN + 1);
    assert!(matches!(
        MlDsaAlgo::with_randomness(&ctx, pinned),
        Err(CryptoError::MlDsaInvalidContext)
    ));
    assert!(matches!(
        MlDsaAlgo::new(&ctx),
        Err(CryptoError::MlDsaInvalidContext)
    ));

    // The boundary itself is allowed.
    let ctx = filler(25, MLDSA_CTX_MAX_LEN);
    assert!(MlDsaAlgo::with_randomness(&ctx, pinned).is_ok());
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
    let mut algo =
        MlDsaAlgo::with_randomness(b"", filler(29, MLDSA_RND_LEN).try_into().unwrap()).unwrap();
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
