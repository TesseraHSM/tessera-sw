// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bring-up smoke test for the TBOR `MlDsaVerify` command.
//!
//! Deliberately minimal: one host-only wire-shape check plus one
//! generate-sign-verify round-trip.  Negative verification (which must
//! surface `MlDsaVerifyFailed`) lands once the firmware handlers do.
//!
//! The command is in-session: each test brings up a finalized CO
//! session and binds the request to it, as the ECC/AES tests do.

use tsra_ddi_tbor_codec::RequestView;
use tsra_ddi_tbor_test_harness::pqc::assert_not_truncated_at_page;
use tsra_ddi_tbor_test_harness::pqc::MlDsaParams;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_44;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_65;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_87;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::SessionControlKind;
use tsra_ddi_tbor_types::TborMlDsaGenerateKeyReq;
use tsra_ddi_tbor_types::TborMlDsaSignReq;
use tsra_ddi_tbor_types::TborMlDsaVerifyReq;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::MLDSA_HEDGE_PREFERRED;
use tsra_ddi_tbor_types::MLDSA_MU_LEN;
use tsra_ddi_tbor_types::TBOR_OP_MLDSA_VERIFY;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Host-only: opcode, in-session control and TOC arity.
#[test]
fn mldsa_verify_request_wire_shape() {
    let req = TborMlDsaVerifyReq {
        session_id: 0,
        pub_key: vec![0x11; 1312],
        mu: vec![0x22; MLDSA_MU_LEN],
        signature: vec![0x33; 2420],
    };

    assert_eq!(TborMlDsaVerifyReq::OPCODE, TBOR_OP_MLDSA_VERIFY);
    assert_eq!(req.get_session_id(), Some(0));
    assert_eq!(req.session_ctrl(), SessionControlKind::InSession);

    let mut buf = [0u8; 8192];
    let bytes = req
        .encode_request(&mut buf, (1, 1))
        .expect("encode request");
    let view = RequestView::parse(bytes).expect("parse request");
    assert_eq!(view.opcode(), TBOR_OP_MLDSA_VERIFY);
    assert_eq!(view.toc_count(), 4);
}

/// Happy path: generate, sign, then verify the signature the device
/// itself produced.  A successful decode is the success signal --
/// `TborMlDsaVerifyResp` is a unit struct and failure is reported as
/// `MlDsaVerifyFailed`.
///
/// Verify carries the public key, `μ` and signature together, the largest
/// ML-DSA request.
fn verify_case(p: &MlDsaParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mu = vec![0x5A; MLDSA_MU_LEN];

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlDsaGenerateKey({}): {e:?}", p.name));

    let signed = ctx
        .tbor(&TborMlDsaSignReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            mu: mu.clone(),
            hedge: MLDSA_HEDGE_PREFERRED,
        })
        .unwrap_or_else(|e| panic!("MlDsaSign({}): {e:?}", p.name));

    assert_eq!(
        signed.signature.len(),
        p.sig_len,
        "{} signature length",
        p.name
    );
    assert_not_truncated_at_page(&signed.signature, p.name);

    ctx.tbor(&TborMlDsaVerifyReq {
        session_id: session.session_id,
        pub_key: key.pub_key,
        mu,
        signature: signed.signature,
    })
    .unwrap_or_else(|e| {
        panic!(
            "MlDsaVerify({}) rejected a signature the device just \
             produced: {e:?}",
            p.name
        )
    });
}

#[test]
fn mldsa_verify_smoke_44() {
    verify_case(&ML_DSA_44);
}

#[test]
fn mldsa_verify_smoke_65() {
    verify_case(&ML_DSA_65);
}

#[test]
fn mldsa_verify_smoke_87() {
    verify_case(&ML_DSA_87);
}

/// Generate a valid ML-DSA key and signature for verification tests.
fn with_valid_signature(
    p: &MlDsaParams,
    test: impl FnOnce(&TestCtx, u16, Vec<u8>, Vec<u8>, Vec<u8>),
) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mu = vec![0x5A; MLDSA_MU_LEN];

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlDsaGenerateKey({}): {e:?}", p.name));

    let signed = ctx
        .tbor(&TborMlDsaSignReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            mu: mu.clone(),
            hedge: MLDSA_HEDGE_PREFERRED,
        })
        .unwrap_or_else(|e| panic!("MlDsaSign({}): {e:?}", p.name));

    assert_eq!(signed.signature.len(), p.sig_len);

    test(&ctx, session.session_id, key.pub_key, mu, signed.signature);
}

/// Verify that an invalid ML-DSA request is rejected.
fn expect_verify_rejected(
    ctx: &TestCtx,
    session_id: u16,
    pub_key: &[u8],
    mu: &[u8],
    signature: &[u8],
) {
    let result = ctx.tbor(&TborMlDsaVerifyReq {
        session_id,
        pub_key: pub_key.to_vec(),
        mu: mu.to_vec(),
        signature: signature.to_vec(),
    });

    assert!(
        result.is_err(),
        "MlDsaVerify unexpectedly accepted an invalid request"
    );
}

/// Verify that a valid ML-DSA request succeeds.
fn expect_verify_success(
    ctx: &TestCtx,
    session_id: u16,
    pub_key: &[u8],
    mu: &[u8],
    signature: &[u8],
) {
    ctx.tbor(&TborMlDsaVerifyReq {
        session_id,
        pub_key: pub_key.to_vec(),
        mu: mu.to_vec(),
        signature: signature.to_vec(),
    })
    .expect("MlDsaVerify rejected a valid signature");
}

/// Reject a signature with a modified middle byte.
fn verify_tampered_signature_case(p: &MlDsaParams) {
    with_valid_signature(p, |ctx, session_id, pub_key, mu, mut signature| {
        let middle = signature.len() / 2;
        signature[middle] ^= 0x01;

        expect_verify_rejected(ctx, session_id, &pub_key, &mu, &signature);
    });
}

/// ML-DSA-44 rejects a tampered signature.
#[test]
fn mldsa_verify_rejects_tampered_signature_44() {
    verify_tampered_signature_case(&ML_DSA_44);
}

/// ML-DSA-65 rejects a tampered signature.
#[test]
fn mldsa_verify_rejects_tampered_signature_65() {
    verify_tampered_signature_case(&ML_DSA_65);
}

/// ML-DSA-87 rejects a tampered signature.
#[test]
fn mldsa_verify_rejects_tampered_signature_87() {
    verify_tampered_signature_case(&ML_DSA_87);
}

/// Reject a signature verified against a different generated public key.
fn verify_wrong_public_key_case(p: &MlDsaParams) {
    with_valid_signature(p, |ctx, session_id, pub_key, mu, signature| {
        let other_key = ctx
            .tbor(&TborMlDsaGenerateKeyReq {
                session_id,
                scope: SCOPE_LOCAL,
                key_kind: p.key_kind,
            })
            .expect("generate second ML-DSA key");

        assert_ne!(
            pub_key, other_key.pub_key,
            "independently generated public keys should differ"
        );

        expect_verify_rejected(ctx, session_id, &other_key.pub_key, &mu, &signature);

        // The original public key must still verify.
        expect_verify_success(ctx, session_id, &pub_key, &mu, &signature);
    });
}

/// ML-DSA-44 rejects verification using another public key.
#[test]
fn mldsa_verify_rejects_wrong_public_key_44() {
    verify_wrong_public_key_case(&ML_DSA_44);
}

/// ML-DSA-65 rejects verification using another public key.
#[test]
fn mldsa_verify_rejects_wrong_public_key_65() {
    verify_wrong_public_key_case(&ML_DSA_65);
}

/// ML-DSA-87 rejects verification using another public key.
#[test]
fn mldsa_verify_rejects_wrong_public_key_87() {
    verify_wrong_public_key_case(&ML_DSA_87);
}
/// Reject empty, truncated, and oversized message digests.
#[test]
fn mldsa_verify_rejects_invalid_mu_lengths_44() {
    with_valid_signature(&ML_DSA_44, |ctx, session_id, pub_key, mu, signature| {
        for len in [0, 1, MLDSA_MU_LEN - 1, MLDSA_MU_LEN + 1] {
            let bad_mu = vec![0x5A; len];

            expect_verify_rejected(ctx, session_id, &pub_key, &bad_mu, &signature);
        }

        expect_verify_success(ctx, session_id, &pub_key, &mu, &signature);
    });
}

/// Reject empty, truncated, and oversized signatures.
#[test]
fn mldsa_verify_rejects_invalid_signature_lengths_44() {
    with_valid_signature(&ML_DSA_44, |ctx, session_id, pub_key, mu, signature| {
        for len in [0, 1, signature.len() - 1, signature.len() + 1] {
            let bad_signature = vec![0u8; len];

            expect_verify_rejected(ctx, session_id, &pub_key, &mu, &bad_signature);
        }

        expect_verify_success(ctx, session_id, &pub_key, &mu, &signature);
    });
}

/// Reject empty, truncated, and oversized public keys.
#[test]
fn mldsa_verify_rejects_invalid_public_key_lengths_44() {
    with_valid_signature(&ML_DSA_44, |ctx, session_id, pub_key, mu, signature| {
        for len in [0, 1, pub_key.len() - 1, pub_key.len() + 1] {
            let bad_pub_key = vec![0u8; len];

            expect_verify_rejected(ctx, session_id, &bad_pub_key, &mu, &signature);
        }

        expect_verify_success(ctx, session_id, &pub_key, &mu, &signature);
    });
}

/// Repeated verification of the same valid signature succeeds.
#[test]
fn mldsa_verify_repeated_valid_signature_44() {
    with_valid_signature(&ML_DSA_44, |ctx, session_id, pub_key, mu, signature| {
        for _ in 0..5 {
            expect_verify_success(ctx, session_id, &pub_key, &mu, &signature);
        }
    });
}

/// Failed verification does not invalidate a working session.
#[test]
fn mldsa_verify_recovers_after_failed_verification_44() {
    with_valid_signature(&ML_DSA_44, |ctx, session_id, pub_key, mu, signature| {
        let mut bad_signature = signature.clone();
        let middle = bad_signature.len() / 2;
        bad_signature[middle] ^= 0x01;

        for _ in 0..3 {
            expect_verify_rejected(ctx, session_id, &pub_key, &mu, &bad_signature);

            expect_verify_success(ctx, session_id, &pub_key, &mu, &signature);
        }
    });
}
/// Reject a correctly sized signature containing only zeros.
#[test]
fn mldsa_verify_rejects_zeroed_signature_44() {
    with_valid_signature(&ML_DSA_44, |ctx, session_id, pub_key, mu, signature| {
        let zeroed_signature = vec![0u8; signature.len()];

        expect_verify_rejected(ctx, session_id, &pub_key, &mu, &zeroed_signature);

        expect_verify_success(ctx, session_id, &pub_key, &mu, &signature);
    });
}
