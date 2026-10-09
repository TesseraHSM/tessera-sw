// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NIST ACVP known-answer tests for ML-KEM.
//!
//! These are the authoritative FIPS 203 vectors, covering all three parameter
//! sets across key generation, encapsulation, decapsulation — including the
//! implicit-rejection cases — and key validity.

use super::*;
use crate::testvectors::mlkem::MLKEM_DECAP_TEST_VECTORS;
use crate::testvectors::mlkem::MLKEM_ENCAP_TEST_VECTORS;
use crate::testvectors::mlkem::MLKEM_KEYCHECK_TEST_VECTORS;
use crate::testvectors::mlkem::MLKEM_KEYGEN_TEST_VECTORS;

/// Key generation is deterministic, so the seed must reproduce both halves of
/// NIST's key pair byte for byte.
#[test]
fn keygen_matches_nist_vectors() {
    for v in MLKEM_KEYGEN_TEST_VECTORS {
        let variant = variant_of(v.param_set);
        let dk = MlKemPrivateKey::from_seed(variant, v.seed).unwrap();
        assert_eq!(
            dk.to_vec().unwrap(),
            v.sec_key,
            "ML-KEM-{} expanded key disagrees with NIST",
            v.param_set
        );
        assert_eq!(
            dk.public_key().unwrap().to_vec().unwrap(),
            v.pub_key,
            "ML-KEM-{} encapsulation key disagrees with NIST",
            v.param_set
        );
    }
}

/// Encapsulation is deterministic in the message, so each vector must
/// reproduce NIST's ciphertext and shared secret exactly.
#[test]
fn encapsulation_matches_nist_vectors() {
    for v in MLKEM_ENCAP_TEST_VECTORS {
        let ek = MlKemPublicKey::from_bytes(v.pub_key).unwrap();
        let mut algo = MlKemAlgo::with_message(v.m.try_into().unwrap());

        let mut ct = vec![0u8; v.ciphertext.len()];
        let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
        algo.encapsulate(&ek, Some(&mut ct), Some(&mut ss)).unwrap();

        assert_eq!(
            ct, v.ciphertext,
            "ML-KEM-{} ciphertext disagrees with NIST",
            v.param_set
        );
        assert_eq!(
            ss, v.shared_secret,
            "ML-KEM-{} shared secret disagrees with NIST",
            v.param_set
        );
    }
}

/// Decapsulation must reproduce NIST's secret, including for the modified
/// ciphertexts — where the expected value is the implicit-rejection secret
/// rather than an error. That is the property that stops a caller being used
/// as a decryption oracle, and only NIST's vectors pin its exact value.
#[test]
fn decapsulation_matches_nist_vectors() {
    for v in MLKEM_DECAP_TEST_VECTORS {
        let dk = MlKemPrivateKey::from_bytes(v.sec_key).unwrap();
        let mut algo = MlKemAlgo::new();

        let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
        algo.decapsulate(&dk, v.ciphertext, Some(&mut ss)).unwrap();
        assert_eq!(
            ss, v.shared_secret,
            "ML-KEM-{} decapsulation disagrees with NIST: {}",
            v.param_set, v.reason
        );
    }
}

/// Key import must accept and reject exactly the keys NIST says it should.
/// The rejections are structural — an encapsulation key whose coefficients
/// exceed the modulus, and a decapsulation key whose embedded hash does not
/// match its public half — neither of which a length check would catch.
///
/// The two halves are validated at different points, deliberately. An
/// encapsulation key is decoded at import, so `from_bytes` rejects it. A
/// decapsulation key is only expanded when it is used, so importing one is a
/// length check alone and the structural check happens at expansion; deriving
/// the public half is the cheapest way to force that here, and mirrors what
/// any real use of the key would do.
#[test]
fn key_validation_matches_nist_vectors() {
    for v in MLKEM_KEYCHECK_TEST_VECTORS {
        let accepted = if v.is_encapsulation_key {
            MlKemPublicKey::from_bytes(v.key).is_ok()
        } else {
            MlKemPrivateKey::from_bytes(v.key)
                .and_then(|dk| dk.public_key())
                .is_ok()
        };
        assert_eq!(
            accepted,
            v.expected_valid,
            "ML-KEM-{} {} check disagrees with NIST: {}",
            v.param_set,
            if v.is_encapsulation_key { "ek" } else { "dk" },
            v.reason
        );
    }
}

/// The vectors must cover all three parameter sets and both outcomes of every
/// check. A silently truncated table would leave the tests above passing while
/// checking far less than they appear to.
#[test]
fn vectors_cover_every_parameter_set_and_outcome() {
    for param_set in [512u16, 768, 1024] {
        for (name, present) in [
            (
                "keygen",
                MLKEM_KEYGEN_TEST_VECTORS
                    .iter()
                    .any(|v| v.param_set == param_set),
            ),
            (
                "encap",
                MLKEM_ENCAP_TEST_VECTORS
                    .iter()
                    .any(|v| v.param_set == param_set),
            ),
        ] {
            assert!(present, "ML-KEM-{param_set} has no {name} vectors");
        }

        // Decapsulation must include a modified ciphertext, or implicit
        // rejection is never exercised.
        assert!(
            MLKEM_DECAP_TEST_VECTORS
                .iter()
                .any(|v| v.param_set == param_set && v.reason.contains("modified")),
            "ML-KEM-{param_set} has no implicit-rejection decap vector"
        );

        for is_ek in [true, false] {
            for expected in [true, false] {
                assert!(
                    MLKEM_KEYCHECK_TEST_VECTORS
                        .iter()
                        .any(|v| v.param_set == param_set
                            && v.is_encapsulation_key == is_ek
                            && v.expected_valid == expected),
                    "ML-KEM-{param_set} missing is_ek={is_ek} valid={expected} key check"
                );
            }
        }
    }
}
