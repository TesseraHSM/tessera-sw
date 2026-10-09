// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bring-up smoke test for the TBOR `MlKemEncapsulate` command.
//!
//! Deliberately minimal: one host-only wire-shape check plus one
//! generate-then-encapsulate round-trip.  Scope sweeps and malformed
//! public-key rejection land once the firmware handlers do.
//!
//! The command is in-session: each test brings up a finalized CO
//! session and binds the request to it, as the ECC/AES tests do.

use tsra_ddi_tbor_codec::RequestView;
use tsra_ddi_tbor_test_harness::pqc::assert_not_truncated_at_page;
use tsra_ddi_tbor_test_harness::pqc::MlKemParams;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_1024;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_512;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_768;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::SessionControlKind;
use tsra_ddi_tbor_types::TborMlKemEncapsulateReq;
use tsra_ddi_tbor_types::TborMlKemGenerateKeyReq;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::MASKED_MLKEM_SHARED_SECRET_MAX_LEN;
use tsra_ddi_tbor_types::TBOR_OP_MLKEM_ENCAPSULATE;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Host-only: opcode, in-session control and TOC arity.
#[test]
fn mlkem_encapsulate_request_wire_shape() {
    let req = TborMlKemEncapsulateReq {
        session_id: 0,
        scope: SCOPE_LOCAL,
        pub_key: vec![0x11; 1184],
    };

    assert_eq!(TborMlKemEncapsulateReq::OPCODE, TBOR_OP_MLKEM_ENCAPSULATE);
    assert_eq!(req.get_session_id(), Some(0));
    assert_eq!(req.session_ctrl(), SessionControlKind::InSession);

    let mut buf = [0u8; 4096];
    let bytes = req.encode_request(&mut buf).expect("encode request");
    let view = RequestView::parse(bytes).expect("parse request");
    assert_eq!(view.opcode(), TBOR_OP_MLKEM_ENCAPSULATE);
    assert_eq!(view.toc_count(), 3);
}

/// Happy path: generate a keypair, then encapsulate to its public key.
fn encapsulate_case(p: &MlKemParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlKemGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlKemGenerateKey({}): {e:?}", p.name));

    let resp = ctx
        .tbor(&TborMlKemEncapsulateReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            pub_key: key.pub_key,
        })
        .unwrap_or_else(|e| panic!("MlKemEncapsulate({}): {e:?}", p.name));

    assert_eq!(
        resp.ciphertext.len(),
        p.ciphertext_len,
        "{} ciphertext length",
        p.name
    );
    assert_eq!(
        resp.masked_shared_secret.len(),
        MASKED_MLKEM_SHARED_SECRET_MAX_LEN,
        "{} masked shared secret length",
        p.name
    );
    assert!(
        resp.ciphertext.iter().any(|&b| b != 0),
        "{} ciphertext is all zeroes",
        p.name
    );
    assert!(
        resp.masked_shared_secret.iter().any(|&b| b != 0),
        "{} masked shared secret is all zeroes",
        p.name
    );
    assert_not_truncated_at_page(&resp.ciphertext, p.name);
    assert_not_truncated_at_page(&resp.masked_shared_secret, p.name);
}

#[test]
fn mlkem_encapsulate_smoke_512() {
    encapsulate_case(&ML_KEM_512);
}

#[test]
fn mlkem_encapsulate_smoke_768() {
    encapsulate_case(&ML_KEM_768);
}

#[test]
fn mlkem_encapsulate_smoke_1024() {
    encapsulate_case(&ML_KEM_1024);
}
