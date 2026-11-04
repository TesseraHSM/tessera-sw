// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `MlDsaSign`'s `hedge`: hedged or deterministic signing, selected as
//! PKCS#11's `CK_HEDGE_TYPE` does.
//!
//! A hedged signature draws fresh randomness, so signing the same input
//! twice gives two different signatures. A deterministic one fixes the
//! randomness at zero, so it gives the same signature every time, whether
//! the input is the message or its external `μ`. Every signature must
//! verify under an independent host implementation (`tsra_crypto`).
//!
//! The device has no key import, so its deterministic signatures cannot be
//! replayed against NIST's known answers here; `tsra_crypto`'s known-answer
//! tests cover the variant itself.

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
use tsra_ddi_tbor_types::MLDSA_MSG_TYPE_EXTERNAL_MU;
use tsra_ddi_tbor_types::MLDSA_MSG_TYPE_PURE;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Every parameter set.
const PARAMS: [&MlDsaParams; 3] = [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87];

/// The message signed, and the context string bound with it.
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
fn sign_req(
    session_id: u16,
    masked_key: &[u8],
    msg_type: u8,
    hedge: u8,
    message: &[u8],
    context: &[u8],
) -> TborMlDsaSignReq {
    TborMlDsaSignReq {
        session_id,
        masked_key: masked_key.to_vec(),
        msg_type,
        hedge,
        message: message.to_vec(),
        ctx: context.to_vec(),
    }
}

/// Sign on the device, returning the signature.
fn device_sign(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: &[u8],
    msg_type: u8,
    hedge: u8,
    message: &[u8],
    context: &[u8],
) -> Vec<u8> {
    ctx.tbor(&sign_req(
        session_id, masked_key, msg_type, hedge, message, context,
    ))
    .unwrap_or_else(|e| panic!("MlDsaSign(msg_type {msg_type}, hedge {hedge}): {e:?}"))
    .signature
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
/// signatures over the same input differ, and both verify. A device that
/// signed deterministically would still verify, so only the inequality
/// catches it.
#[test]
fn mldsa_sign_hedged_signatures_differ() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        for hedge in [MLDSA_HEDGE_PREFERRED, MLDSA_HEDGE_REQUIRED] {
            let sigs: Vec<Vec<u8>> = (0..2)
                .map(|_| device_sign(&ctx, sid, &masked_key, MLDSA_MSG_TYPE_PURE, hedge, MSG, CTX))
                .collect();
            assert_ne!(
                sigs[0], sigs[1],
                "{} hedge {hedge}: two signatures over the same input are identical",
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

/// Deterministic signing gives the same signature every time, over the
/// message or its external `μ` alike, and it verifies.
#[test]
fn mldsa_sign_deterministic_signatures_repeat() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = MlDsaPublicKey::from_bytes(&pub_key)
            .and_then(|pk| pk.mu(CTX, MSG))
            .expect("host mu");

        let sign = |msg_type, message: &[u8], context: &[u8]| {
            device_sign(
                &ctx,
                sid,
                &masked_key,
                msg_type,
                MLDSA_HEDGE_DETERMINISTIC,
                message,
                context,
            )
        };
        let first = sign(MLDSA_MSG_TYPE_PURE, MSG, CTX);
        assert!(
            host_verify(&pub_key, &first),
            "{}: deterministic signature does not verify",
            p.name
        );
        assert_eq!(
            sign(MLDSA_MSG_TYPE_PURE, MSG, CTX),
            first,
            "{}: deterministic signing over the message did not repeat",
            p.name
        );
        assert_eq!(
            sign(MLDSA_MSG_TYPE_EXTERNAL_MU, &mu, &[]),
            first,
            "{}: deterministic signature over mu differs from the one over the message",
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
            &sign_req(sid, &masked_key, MLDSA_MSG_TYPE_PURE, hedge, MSG, CTX),
            TborStatus::InvalidArg,
        );
    }
}
