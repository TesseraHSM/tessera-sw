// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bring-up smoke test for the TBOR `MlKemDecapsulate` command.
//!
//! One host-only wire-shape check, a generate-encapsulate-decapsulate
//! round-trip, and a check that the private key really is masked —
//! including that a corrupt ciphertext is rejected *implicitly* while a
//! corrupt masking tag is not.
//!
//! The command is in-session: each test brings up a finalized CO
//! session and binds the request to it, as the ECC/AES tests do.
//!
//! Note the shared secrets are returned **masked**, so the smoke test
//! cannot compare them directly; it asserts a well-formed decapsulation
//! instead.  Agreement is checked once unmasking is available.

use tsra_ddi_tbor_codec::RequestView;
use tsra_ddi_tbor_test_harness::pqc::assert_not_truncated_at_page;
use tsra_ddi_tbor_test_harness::pqc::MlKemParams;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_1024;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_512;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_768;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::SessionControlKind;
use tsra_ddi_tbor_types::TborMlKemDecapsulateReq;
use tsra_ddi_tbor_types::TborMlKemEncapsulateReq;
use tsra_ddi_tbor_types::TborMlKemGenerateKeyReq;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::MASKED_MLKEM_SHARED_SECRET_MAX_LEN;
use tsra_ddi_tbor_types::TBOR_OP_MLKEM_DECAPSULATE;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Host-only: opcode, in-session control and TOC arity.
#[test]
fn mlkem_decapsulate_request_wire_shape() {
    let req = TborMlKemDecapsulateReq {
        session_id: 0,
        scope: SCOPE_LOCAL,
        masked_key: vec![0x11; 196],
        ciphertext: vec![0x22; 1088],
    };

    assert_eq!(TborMlKemDecapsulateReq::OPCODE, TBOR_OP_MLKEM_DECAPSULATE);
    assert_eq!(req.get_session_id(), Some(0));
    assert_eq!(req.session_ctrl(), SessionControlKind::InSession);

    let mut buf = [0u8; 4096];
    let bytes = req.encode_request(&mut buf).expect("encode request");
    let view = RequestView::parse(bytes).expect("parse request");
    assert_eq!(view.opcode(), TBOR_OP_MLKEM_DECAPSULATE);
    assert_eq!(view.toc_count(), 4);
}

/// Happy path: generate, encapsulate to the public key, then
/// decapsulate the resulting ciphertext with the masked private key.
///
/// NOTE: this does **not** prove the two sides agree on the shared
/// secret.  Both secrets leave the HSM masked under a random 12-byte
/// IV, so the blobs are not comparable byte-for-byte, and the test has
/// no way to unmask them.  Confirming agreement needs either an
/// unmasking path in the test harness or a device-side self-test; until
/// then this checks only that decapsulation runs and produces a
/// well-formed, non-trivial response.
///
/// ML-KEM decapsulation never reports failure -- FIPS 203 implicit
/// rejection returns a deterministic pseudorandom secret for a
/// malformed ciphertext -- so a negative test would look identical to
/// this one from the outside.
fn decapsulate_case(p: &MlKemParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlKemGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlKemGenerateKey({}): {e:?}", p.name));

    let encap = ctx
        .tbor(&TborMlKemEncapsulateReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            pub_key: key.pub_key,
        })
        .unwrap_or_else(|e| panic!("MlKemEncapsulate({}): {e:?}", p.name));

    assert_eq!(
        encap.ciphertext.len(),
        p.ciphertext_len,
        "{} ciphertext length",
        p.name
    );

    let resp = ctx
        .tbor(&TborMlKemDecapsulateReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key: key.masked_key,
            ciphertext: encap.ciphertext,
        })
        .unwrap_or_else(|e| panic!("MlKemDecapsulate({}): {e:?}", p.name));

    assert_eq!(
        resp.masked_shared_secret.len(),
        MASKED_MLKEM_SHARED_SECRET_MAX_LEN,
        "{} masked shared secret length",
        p.name
    );
    assert!(
        resp.masked_shared_secret.iter().any(|&b| b != 0),
        "{} masked shared secret is all zeroes",
        p.name
    );
    assert_not_truncated_at_page(&resp.masked_shared_secret, p.name);
}

#[test]
fn mlkem_decapsulate_smoke_512() {
    decapsulate_case(&ML_KEM_512);
}

#[test]
fn mlkem_decapsulate_smoke_768() {
    decapsulate_case(&ML_KEM_768);
}

#[test]
fn mlkem_decapsulate_smoke_1024() {
    decapsulate_case(&ML_KEM_1024);
}

/// The private key really is masked, and the device really unmasks it.
///
/// The same shape as the ML-DSA test, but ML-KEM makes it sharper. A
/// corrupt *ciphertext* must not fail: FIPS 203 rejects implicitly and
/// returns a pseudo-random secret, which is what stops a caller being used
/// as a decryption oracle. A corrupt *masked key* must fail, because that
/// is an authentication failure one layer up, at the AEAD envelope.
///
/// Checking both in one test is the point. Either outcome alone could be
/// explained away — a bypass would pass the ciphertext case too, and a
/// handler that erred on everything would pass the key case — but only a
/// device that genuinely unmasks and authenticates gets both right.
fn masking_case(p: &MlKemParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlKemGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlKemGenerateKey({}): {e:?}", p.name));

    assert_eq!(
        &key.masked_key[..4],
        b"AEAD",
        "{}: masked key is not an AEAD envelope",
        p.name
    );

    let encap = ctx
        .tbor(&TborMlKemEncapsulateReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            pub_key: key.pub_key,
        })
        .unwrap_or_else(|e| panic!("MlKemEncapsulate({}): {e:?}", p.name));

    // A corrupt ciphertext of the right length is implicitly rejected, not
    // failed.
    let mut bad_ct = encap.ciphertext.clone();
    bad_ct[0] ^= 0x01;
    let implicit = ctx.tbor(&TborMlKemDecapsulateReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        masked_key: key.masked_key.clone(),
        ciphertext: bad_ct,
    });
    assert!(
        implicit.is_ok(),
        "{}: a corrupt ciphertext must be rejected implicitly, not reported",
        p.name
    );

    // A corrupt authentication tag on the key must fail outright.
    let mut tampered = key.masked_key.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let outcome = ctx.tbor(&TborMlKemDecapsulateReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        masked_key: tampered,
        ciphertext: encap.ciphertext,
    });
    assert!(
        outcome.is_err(),
        "{}: decapsulation accepted a masked key whose tag had been corrupted",
        p.name
    );
}

#[test]
fn mlkem_decapsulate_rejects_a_tampered_masked_key_512() {
    masking_case(&ML_KEM_512);
}

#[test]
fn mlkem_decapsulate_rejects_a_tampered_masked_key_768() {
    masking_case(&ML_KEM_768);
}

#[test]
fn mlkem_decapsulate_rejects_a_tampered_masked_key_1024() {
    masking_case(&ML_KEM_1024);
}
