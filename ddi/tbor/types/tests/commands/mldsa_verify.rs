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
    let bytes = req.encode_request(&mut buf).expect("encode request");
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
