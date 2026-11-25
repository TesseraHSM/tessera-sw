// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `MlDsaSign`'s `hedge`: hedged or deterministic signing, selected as
//! PKCS#11's `CK_HEDGE_TYPE` does.
//!
//! A hedged signature draws fresh randomness, so signing the same `μ` twice
//! gives two different signatures. A deterministic one fixes the randomness
//! at zero, so it gives the same signature every time. Every signature must
//! verify under an independent host implementation (`tsra_crypto`).
//!
//! The device has no key import, so its deterministic signatures cannot be
//! replayed against NIST's known answers here; `tsra_crypto`'s known-answer
//! tests cover the variant itself.

use tsra_crypto::HashAlgo;
use tsra_crypto::Hasher;
use tsra_crypto::ImportableKey;
use tsra_crypto::MlDsaAlgo;
use tsra_crypto::MlDsaPublicKey;
use tsra_crypto::VerifyOp;
use tsra_ddi_tbor_test_harness::pqc::MlDsaParams;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_44;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_65;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_87;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborMlDsaGenerateKeyReq;
use tsra_ddi_tbor_types::TborMlDsaSignReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MLDSA_HEDGE_DETERMINISTIC;
use tsra_ddi_tbor_types::MLDSA_HEDGE_PREFERRED;
use tsra_ddi_tbor_types::MLDSA_HEDGE_REQUIRED;
use tsra_ddi_tbor_types::MLDSA_MU_LEN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Every parameter set.
const PARAMS: [&MlDsaParams; 3] = [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87];

/// The message whose `μ` is signed, and the context string bound with it.
const MSG: &[u8] = b"hedge message";
const CTX: &[u8] = b"hedge context";

/// Generate a key on the device: `(masked_key, pub_key)`.
fn generate(ctx: &TestCtx, session_id: u16, p: &MlDsaParams) -> (Vec<u8>, Vec<u8>) {
    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlDsaGenerateKey({}): {e:?}", p.name));
    (key.masked_key, key.pub_key)
}

/// `MlDsaSign` on the device.
fn sign_req(session_id: u16, masked_key: &[u8], hedge: u8, mu: &[u8]) -> TborMlDsaSignReq {
    TborMlDsaSignReq {
        session_id,
        masked_key: masked_key.to_vec(),
        mu: mu.to_vec(),
        hedge,
    }
}

/// Sign on the device, returning the signature.
fn device_sign(ctx: &TestCtx, session_id: u16, masked_key: &[u8], hedge: u8, mu: &[u8]) -> Vec<u8> {
    ctx.tbor(&sign_req(session_id, masked_key, hedge, mu))
        .unwrap_or_else(|e| panic!("MlDsaSign(hedge {hedge}): {e:?}"))
        .signature
}

/// `μ` for `MSG` under `CTX` and `pub_key`, computed on the host.
fn host_mu(pub_key: &[u8]) -> Vec<u8> {
    MlDsaPublicKey::from_bytes(pub_key)
        .and_then(|pk| HashAlgo::mldsa_mu(&pk, CTX))
        .and_then(|mut algo| Hasher::hash_vec(&mut algo, MSG))
        .expect("host mu")
}

/// Pure verification of `MSG` under `CTX` on the host.
fn host_verify(pub_key: &[u8], signature: &[u8]) -> bool {
    let pk = MlDsaPublicKey::from_bytes(pub_key).expect("import device pk");
    MlDsaAlgo::new(CTX)
        .expect("mldsa engine")
        .verify(&pk, MSG, signature)
        .expect("host verify")
}

/// Hedged signing, preferred or required, draws fresh randomness: two
/// signatures over the same `μ` differ, and both verify. A device that
/// signed deterministically would still verify, so only the inequality
/// catches it.
#[test]
fn mldsa_sign_hedged_signatures_differ() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);
        for hedge in [MLDSA_HEDGE_PREFERRED, MLDSA_HEDGE_REQUIRED] {
            let sigs: Vec<Vec<u8>> = (0..2)
                .map(|_| device_sign(&ctx, sid, &masked_key, hedge, &mu))
                .collect();
            assert_ne!(
                sigs[0], sigs[1],
                "{} hedge {hedge}: two signatures over the same mu are identical",
                p.name
            );
            for sig in &sigs {
                assert!(
                    host_verify(&pub_key, sig),
                    "{} hedge {hedge}: signature does not verify",
                    p.name
                );
            }
        }
    }
}

/// Deterministic signing gives the same signature every time, and it
/// verifies.
#[test]
fn mldsa_sign_deterministic_signatures_repeat() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);

        let first = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu);
        assert!(
            host_verify(&pub_key, &first),
            "{}: deterministic signature does not verify",
            p.name
        );
        assert_eq!(
            device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu),
            first,
            "{}: deterministic signing did not repeat",
            p.name
        );
    }
}

/// Values other than PKCS#11's three hedge types are rejected.
#[test]
fn mldsa_sign_rejects_unknown_hedge() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;
    let (masked_key, _) = generate(&ctx, sid, &ML_DSA_44);

    for hedge in [3u8, 4, 0x80, 0xFF] {
        ctx.expect_fw_reject(
            &sign_req(sid, &masked_key, hedge, &[0x5A; MLDSA_MU_LEN]),
            TborStatus::InvalidArg,
        );
    }
}

/// Switching hedge modes preserves deterministic signing and fresh hedged signatures.
#[test]
fn mldsa_sign_hedge_mode_switching() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);

        let deterministic_first =
            device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu);
        let hedged_first = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_REQUIRED, &mu);
        let preferred = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_PREFERRED, &mu);
        let deterministic_second =
            device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu);
        let hedged_second = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_REQUIRED, &mu);

        assert_eq!(
            deterministic_first, deterministic_second,
            "{}: deterministic result changed after hedge switching",
            p.name
        );
        assert_ne!(
            hedged_first, hedged_second,
            "{}: required hedge reused a signature",
            p.name
        );
        assert_ne!(
            hedged_first, preferred,
            "{}: preferred hedge reused a signature",
            p.name
        );

        for sig in [
            &deterministic_first,
            &hedged_first,
            &preferred,
            &deterministic_second,
            &hedged_second,
        ] {
            assert!(
                host_verify(&pub_key, sig),
                "{}: signature failed after hedge switching",
                p.name
            );
        }
    }
}

/// Repeated hedged signing produces distinct signatures without breaking verification.
#[test]
fn mldsa_sign_hedged_many_signatures_unique() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);

        for hedge in [MLDSA_HEDGE_PREFERRED, MLDSA_HEDGE_REQUIRED] {
            let mut signatures = Vec::new();

            for i in 0..8 {
                let sig = device_sign(&ctx, sid, &masked_key, hedge, &mu);

                assert!(
                    host_verify(&pub_key, &sig),
                    "{} hedge {hedge}: signature {i} failed verification",
                    p.name
                );
                assert!(
                    !signatures.contains(&sig),
                    "{} hedge {hedge}: repeated signature at iteration {i}",
                    p.name
                );

                signatures.push(sig);
            }
        }
    }
}

/// Different device-generated keys must not validate each other's signatures.
#[test]
fn mldsa_sign_hedge_cross_key_verification() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (key_a, pub_a) = generate(&ctx, sid, p);
        let (_, pub_b) = generate(&ctx, sid, p);

        assert_ne!(pub_a, pub_b, "{}: generated public keys match", p.name);

        let mu_a = host_mu(&pub_a);

        for hedge in [
            MLDSA_HEDGE_DETERMINISTIC,
            MLDSA_HEDGE_PREFERRED,
            MLDSA_HEDGE_REQUIRED,
        ] {
            let sig = device_sign(&ctx, sid, &key_a, hedge, &mu_a);

            assert!(
                host_verify(&pub_a, &sig),
                "{} hedge {hedge}: correct key rejected signature",
                p.name
            );
            assert!(
                !host_verify(&pub_b, &sig),
                "{} hedge {hedge}: wrong key accepted signature",
                p.name
            );
        }
    }
}

/// Invalid hedge values do not corrupt the session or its signing key.
#[test]
fn mldsa_sign_hedge_recovery_after_invalid_value() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);

        let baseline = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu);

        for invalid in [3u8, 4, 0x7F, 0x80, 0xFE, 0xFF] {
            ctx.expect_fw_reject(
                &sign_req(sid, &masked_key, invalid, &mu),
                TborStatus::InvalidArg,
            );

            let recovered = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu);

            assert_eq!(
                recovered, baseline,
                "{}: deterministic result changed after invalid hedge {invalid}",
                p.name
            );
            assert!(
                host_verify(&pub_key, &recovered),
                "{}: recovery failed after invalid hedge {invalid}",
                p.name
            );
        }
    }
}

/// Invalid hedge requests do not prevent subsequent randomized signing.
#[test]
fn mldsa_sign_hedge_recovery_to_required() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);

        ctx.expect_fw_reject(
            &sign_req(sid, &masked_key, 0xFF, &mu),
            TborStatus::InvalidArg,
        );

        let first = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_REQUIRED, &mu);
        let second = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_REQUIRED, &mu);

        assert_ne!(
            first, second,
            "{}: required hedge repeated after an invalid request",
            p.name
        );
        assert!(
            host_verify(&pub_key, &first),
            "{}: first recovered signature did not verify",
            p.name
        );
        assert!(
            host_verify(&pub_key, &second),
            "{}: second recovered signature did not verify",
            p.name
        );
    }
}

/// Compute the ML-DSA message representative for an arbitrary message.
fn host_mu_for(pub_key: &[u8], msg: &[u8]) -> Vec<u8> {
    MlDsaPublicKey::from_bytes(pub_key)
        .and_then(|pk| HashAlgo::mldsa_mu(&pk, CTX))
        .and_then(|mut algo| Hasher::hash_vec(&mut algo, msg))
        .expect("host mu")
}

/// Verify an ML-DSA signature against an arbitrary message.
fn host_verify_for(pub_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    let pk = MlDsaPublicKey::from_bytes(pub_key).expect("import device pk");
    MlDsaAlgo::new(CTX)
        .expect("mldsa engine")
        .verify(&pk, msg, signature)
        .expect("host verify")
}

/// Each hedge mode signs the supplied mu rather than a previously used message.
#[test]
fn mldsa_sign_hedge_binds_message() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);

        let msg_a = b"hedge message A";
        let msg_b = b"hedge message B";
        let mu_a = host_mu_for(&pub_key, msg_a);
        let mu_b = host_mu_for(&pub_key, msg_b);

        assert_ne!(mu_a, mu_b, "{}: different messages have equal mu", p.name);

        for hedge in [
            MLDSA_HEDGE_DETERMINISTIC,
            MLDSA_HEDGE_PREFERRED,
            MLDSA_HEDGE_REQUIRED,
        ] {
            let sig_a = device_sign(&ctx, sid, &masked_key, hedge, &mu_a);
            let sig_b = device_sign(&ctx, sid, &masked_key, hedge, &mu_b);

            assert_ne!(
                sig_a, sig_b,
                "{} hedge {hedge}: different messages produced equal signatures",
                p.name
            );

            assert!(
                host_verify_for(&pub_key, msg_a, &sig_a),
                "{} hedge {hedge}: message A failed verification",
                p.name
            );
            assert!(
                host_verify_for(&pub_key, msg_b, &sig_b),
                "{} hedge {hedge}: message B failed verification",
                p.name
            );

            assert!(
                !host_verify_for(&pub_key, msg_b, &sig_a),
                "{} hedge {hedge}: signature A verified for message B",
                p.name
            );
            assert!(
                !host_verify_for(&pub_key, msg_a, &sig_b),
                "{} hedge {hedge}: signature B verified for message A",
                p.name
            );
        }
    }
}

/// Every hedge mode rejects mu lengths other than MLDSA_MU_LEN.
#[test]
fn mldsa_sign_hedge_rejects_invalid_mu_lengths() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let valid_mu = host_mu(&pub_key);

        for hedge in [
            MLDSA_HEDGE_DETERMINISTIC,
            MLDSA_HEDGE_PREFERRED,
            MLDSA_HEDGE_REQUIRED,
        ] {
            for len in [0, 1, MLDSA_MU_LEN - 1, MLDSA_MU_LEN + 1, 128] {
                ctx.expect_fw_reject(
                    &sign_req(sid, &masked_key, hedge, &vec![0x5A; len]),
                    TborStatus::TborInvalidFixedLength,
                );
            }

            let sig = device_sign(&ctx, sid, &masked_key, hedge, &valid_mu);
            assert!(
                host_verify(&pub_key, &sig),
                "{} hedge {hedge}: failed after invalid mu lengths",
                p.name
            );
        }
    }
}

/// Signatures in every hedge mode are bound to the original context.
#[test]
fn mldsa_sign_hedge_context_binding() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);
        let pk = MlDsaPublicKey::from_bytes(&pub_key).expect("public key");

        for hedge in [
            MLDSA_HEDGE_DETERMINISTIC,
            MLDSA_HEDGE_PREFERRED,
            MLDSA_HEDGE_REQUIRED,
        ] {
            let sig = device_sign(&ctx, sid, &masked_key, hedge, &mu);

            assert!(
                host_verify(&pub_key, &sig),
                "{} hedge {hedge}: correct context failed",
                p.name
            );

            let wrong_context_valid = MlDsaAlgo::new(b"wrong context")
                .expect("wrong-context engine")
                .verify(&pk, MSG, &sig)
                .expect("wrong-context verification");

            assert!(
                !wrong_context_valid,
                "{} hedge {hedge}: signature verified with wrong context",
                p.name
            );
        }
    }
}

/// Interleaved hedged operations leave deterministic signatures unchanged.
#[test]
fn mldsa_sign_deterministic_stable_after_many_hedged_calls() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);

        let baseline = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu);

        for i in 0..10 {
            let hedge = if i % 2 == 0 {
                MLDSA_HEDGE_PREFERRED
            } else {
                MLDSA_HEDGE_REQUIRED
            };

            let randomized = device_sign(&ctx, sid, &masked_key, hedge, &mu);
            assert!(
                host_verify(&pub_key, &randomized),
                "{} iteration {i}: hedged signature failed",
                p.name
            );

            let deterministic = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu);

            assert_eq!(
                deterministic, baseline,
                "{} iteration {i}: deterministic signature changed",
                p.name
            );
        }
    }
}

/// Invalid hedge values do not prevent subsequent use of any valid mode.
#[test]
fn mldsa_sign_hedge_invalid_then_all_valid_modes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);

        for invalid in [3u8, 4, 0x7F, 0x80, 0xFE, 0xFF] {
            ctx.expect_fw_reject(
                &sign_req(sid, &masked_key, invalid, &mu),
                TborStatus::InvalidArg,
            );

            for hedge in [
                MLDSA_HEDGE_DETERMINISTIC,
                MLDSA_HEDGE_PREFERRED,
                MLDSA_HEDGE_REQUIRED,
            ] {
                let sig = device_sign(&ctx, sid, &masked_key, hedge, &mu);

                assert!(
                    host_verify(&pub_key, &sig),
                    "{}: hedge {hedge} failed after invalid value {invalid}",
                    p.name
                );
            }
        }
    }
}

/// Signing a second message does not alter the first deterministic signature.
#[test]
fn mldsa_sign_deterministic_message_interleaving() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);

        let msg_a = b"message A";
        let msg_b = b"message B";

        let mu_a = host_mu_for(&pub_key, msg_a);
        let mu_b = host_mu_for(&pub_key, msg_b);

        let first_a = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu_a);
        let sig_b = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu_b);
        let second_a = device_sign(&ctx, sid, &masked_key, MLDSA_HEDGE_DETERMINISTIC, &mu_a);

        assert_eq!(
            first_a, second_a,
            "{}: deterministic signature changed after signing another message",
            p.name
        );
        assert_ne!(
            first_a, sig_b,
            "{}: different messages produced identical signatures",
            p.name
        );

        assert!(host_verify_for(&pub_key, msg_a, &first_a));
        assert!(host_verify_for(&pub_key, msg_b, &sig_b));
    }
}
