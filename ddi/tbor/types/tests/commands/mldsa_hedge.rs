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
