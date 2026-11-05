// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bring-up smoke test for the TBOR `MlDsaSign` command.
//!
//! One host-only wire-shape check, a generate-then-sign round-trip for
//! every FIPS 204 parameter set, and a check that the private key really
//! is masked.  What a signature over `μ` covers is checked in
//! `mldsa_external_mu`.
//!
//! The command is in-session: each test brings up a finalized CO
//! session and binds the request to it, as the ECC/AES tests do.

use tsra_ddi_tbor_codec::RequestView;
use tsra_ddi_tbor_test_harness::pqc::assert_not_truncated_at_page;
use tsra_ddi_tbor_test_harness::pqc::MlDsaParams;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_44;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_65;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_87;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_512;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::SessionControlKind;
use tsra_ddi_tbor_types::TborMlDsaGenerateKeyReq;
use tsra_ddi_tbor_types::TborMlDsaSignReq;
use tsra_ddi_tbor_types::TborMlKemGenerateKeyReq;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MLDSA_HEDGE_PREFERRED;
use tsra_ddi_tbor_types::MLDSA_MU_LEN;
use tsra_ddi_tbor_types::TBOR_OP_MLDSA_SIGN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Host-only: opcode, in-session control and TOC arity.
#[test]
fn mldsa_sign_request_wire_shape() {
    let req = TborMlDsaSignReq {
        session_id: 0,
        masked_key: vec![0xAA; 164],
        mu: vec![0xBB; MLDSA_MU_LEN],
        hedge: MLDSA_HEDGE_PREFERRED,
    };

    assert_eq!(TborMlDsaSignReq::OPCODE, TBOR_OP_MLDSA_SIGN);
    assert_eq!(req.get_session_id(), Some(0));
    assert_eq!(req.session_ctrl(), SessionControlKind::InSession);

    let mut buf = [0u8; 1024];
    let bytes = req.encode_request(&mut buf).expect("encode request");
    let view = RequestView::parse(bytes).expect("parse request");
    assert_eq!(view.opcode(), TBOR_OP_MLDSA_SIGN);
    assert_eq!(view.toc_count(), 4);
}

/// Happy path: generate a key, sign a `μ`, and check the signature
/// is the right length and non-trivial.
///
/// Signing re-derives the key pair from the seed on the FP core, so the
/// large parameter sets exercise a keygen plus a sign inside a single
/// operand slot -- the tightest case the FP has to handle.
fn sign_case(p: &MlDsaParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlDsaGenerateKey({}): {e:?}", p.name));

    let resp = ctx
        .tbor(&TborMlDsaSignReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            mu: vec![0x5A; MLDSA_MU_LEN],
            hedge: MLDSA_HEDGE_PREFERRED,
        })
        .unwrap_or_else(|e| panic!("MlDsaSign({}): {e:?}", p.name));

    assert_eq!(
        resp.signature.len(),
        p.sig_len,
        "{} signature length",
        p.name
    );
    assert!(
        resp.signature.iter().any(|&b| b != 0),
        "{} signature is all zeroes",
        p.name
    );
    assert_not_truncated_at_page(&resp.signature, p.name);
}

#[test]
fn mldsa_sign_smoke_44() {
    sign_case(&ML_DSA_44);
}

#[test]
fn mldsa_sign_smoke_65() {
    sign_case(&ML_DSA_65);
}

#[test]
fn mldsa_sign_smoke_87() {
    sign_case(&ML_DSA_87);
}

/// The private key really is masked, and the device really unmasks it.
///
/// Two checks, because each alone is weak: the blob is an AEAD envelope
/// rather than raw key material, and corrupting the authentication tag
/// makes signing *fail* instead of producing a signature. The second is
/// what proves the device is unmasking and authenticating rather than
/// passing bytes through — a bypass would happily sign with a blob whose
/// tag no longer matches. The envelope's size is pinned separately, by
/// the `masked_key_len` assertion in the generate-key tests.
fn masking_case(p: &MlDsaParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlDsaGenerateKey({}): {e:?}", p.name));

    assert_eq!(
        &key.masked_key[..4],
        b"AEAD",
        "{}: masked key is not an AEAD envelope",
        p.name
    );

    // Flip the last byte, which lands in the authentication tag.
    let mut tampered = key.masked_key.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let outcome = ctx.tbor(&TborMlDsaSignReq {
        session_id: session.session_id,
        masked_key: tampered,
        mu: vec![0x5A; MLDSA_MU_LEN],
        hedge: MLDSA_HEDGE_PREFERRED,
    });
    assert!(
        outcome.is_err(),
        "{}: signing accepted a masked key whose tag had been corrupted",
        p.name
    );
}

#[test]
fn mldsa_sign_rejects_a_tampered_masked_key_44() {
    masking_case(&ML_DSA_44);
}

#[test]
fn mldsa_sign_rejects_a_tampered_masked_key_65() {
    masking_case(&ML_DSA_65);
}

#[test]
fn mldsa_sign_rejects_a_tampered_masked_key_87() {
    masking_case(&ML_DSA_87);
}

/// Rejects a valid masked key of another type with `InvalidKeyType`.
///
/// The key is an ML-KEM key, which may not sign either, so this also checks
/// that the key type is checked before the key's permissions, as `EccSign`
/// does.
#[test]
fn mldsa_sign_wrong_key_class_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = ctx
        .tbor(&TborMlKemGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_KEM_512.key_kind,
        })
        .expect("MlKemGenerateKey");

    ctx.expect_fw_reject(
        &TborMlDsaSignReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            mu: vec![0x5A; MLDSA_MU_LEN],
            hedge: MLDSA_HEDGE_PREFERRED,
        },
        TborStatus::InvalidKeyType,
    );
}
