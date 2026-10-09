// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NIST ACVP known-answer tests for ML-DSA.
//!
//! These are the authoritative FIPS 204 vectors, covering all three parameter
//! sets across key generation, signing (deterministic and hedged) and
//! verification — including NIST's tampered-signature and modified-message
//! cases, which a roundtrip test cannot produce.

use super::*;
use crate::testvectors::mldsa::MLDSA_KEYGEN_TEST_VECTORS;
use crate::testvectors::mldsa::MLDSA_SIGGEN_TEST_VECTORS;
use crate::testvectors::mldsa::MLDSA_SIGVER_SHORT_MSG_TEST_VECTORS;
use crate::testvectors::mldsa::MLDSA_SIGVER_TEST_VECTORS;

/// Key generation is deterministic, so the seed must reproduce both halves of
/// NIST's key pair byte for byte.
#[test]
fn keygen_matches_nist_vectors() {
    for v in MLDSA_KEYGEN_TEST_VECTORS {
        let variant = variant_of(v.param_set);
        let sk = MlDsaPrivateKey::from_seed(variant, v.seed).unwrap();
        assert_eq!(
            sk.to_vec().unwrap(),
            v.sec_key,
            "ML-DSA-{} expanded key disagrees with NIST",
            v.param_set
        );
        assert_eq!(
            sk.public_key().unwrap().to_vec().unwrap(),
            v.pub_key,
            "ML-DSA-{} public key disagrees with NIST",
            v.param_set
        );
    }
}

/// Signing is deterministic in `rnd`, so each vector must reproduce NIST's
/// signature exactly. This covers both the deterministic groups, where FIPS
/// 204 fixes `rnd` to zero, and the hedged groups, which carry their own.
#[test]
fn signing_matches_nist_vectors() {
    for v in MLDSA_SIGGEN_TEST_VECTORS {
        let sk = MlDsaPrivateKey::from_bytes(v.sec_key).unwrap();
        let mut algo = MlDsaAlgo::with_randomness(v.ctx, v.rnd.try_into().unwrap()).unwrap();
        assert_eq!(
            Signer::sign_vec(&mut algo, &sk, v.msg).unwrap(),
            v.sig,
            "ML-DSA-{} signature disagrees with NIST (deterministic={}, msg {} B, ctx {} B)",
            v.param_set,
            v.deterministic,
            v.msg.len(),
            v.ctx.len()
        );
    }
}

/// NIST's verification vectors must be accepted or rejected exactly as
/// specified. The negative cases tamper with distinct parts of the signature —
/// the commitment, the hint, and `z` — which a roundtrip test never exercises.
#[test]
fn verification_matches_nist_vectors() {
    for v in MLDSA_SIGVER_TEST_VECTORS
        .iter()
        .chain(MLDSA_SIGVER_SHORT_MSG_TEST_VECTORS)
    {
        let pk = MlDsaPublicKey::from_bytes(v.pub_key).unwrap();
        let mut algo = MlDsaAlgo::new(v.ctx).unwrap();
        assert_eq!(
            Verifier::verify(&mut algo, &pk, v.msg, v.sig).unwrap(),
            v.expected_pass,
            "ML-DSA-{} verification disagrees with NIST: {}",
            v.param_set,
            v.reason
        );
    }
}

/// The vectors must cover all three parameter sets, both signing modes, and
/// both verification outcomes. A silently truncated table would leave the
/// tests above passing while checking far less than they appear to.
#[test]
fn vectors_cover_every_parameter_set_and_mode() {
    for param_set in [44u16, 65, 87] {
        assert!(
            MLDSA_KEYGEN_TEST_VECTORS
                .iter()
                .any(|v| v.param_set == param_set),
            "ML-DSA-{param_set} has no keygen vectors"
        );
        for deterministic in [true, false] {
            assert!(
                MLDSA_SIGGEN_TEST_VECTORS
                    .iter()
                    .any(|v| v.param_set == param_set && v.deterministic == deterministic),
                "ML-DSA-{param_set} has no deterministic={deterministic} siggen vectors"
            );
        }
        for expected in [true, false] {
            assert!(
                MLDSA_SIGVER_TEST_VECTORS
                    .iter()
                    .any(|v| v.param_set == param_set && v.expected_pass == expected),
                "ML-DSA-{param_set} has no expected_pass={expected} sigver vectors"
            );
        }
    }
}
