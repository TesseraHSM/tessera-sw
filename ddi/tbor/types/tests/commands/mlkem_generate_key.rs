// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bring-up smoke test for the TBOR `MlKemGenerateKey` command.
//!
//! One host-only wire-shape check plus a happy-path round-trip for
//! every FIPS 203 parameter set.  Negative cases are still to come.
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
use tsra_ddi_tbor_types::TborMlKemGenerateKeyReq;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::TBOR_OP_MLKEM_GENERATE_KEY;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Host-only: opcode, in-session control and TOC arity.
#[test]
fn mlkem_generate_key_request_wire_shape() {
    let req = TborMlKemGenerateKeyReq {
        session_id: 0,
        scope: SCOPE_LOCAL,
        key_kind: ML_KEM_768.key_kind,
    };

    assert_eq!(TborMlKemGenerateKeyReq::OPCODE, TBOR_OP_MLKEM_GENERATE_KEY);
    assert_eq!(req.get_session_id(), Some(0));
    assert_eq!(req.session_ctrl(), SessionControlKind::InSession);

    let mut buf = [0u8; 256];
    let bytes = req.encode_request(&mut buf).expect("encode request");
    let view = RequestView::parse(bytes).expect("parse request");
    assert_eq!(view.opcode(), TBOR_OP_MLKEM_GENERATE_KEY);
    assert_eq!(view.toc_count(), 3);
}

/// Happy path: generate a keypair and check the response is well
/// formed.
fn generate_key_case(p: &MlKemParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let resp = ctx
        .tbor(&TborMlKemGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlKemGenerateKey({}): {e:?}", p.name));

    assert_eq!(
        resp.pub_key.len(),
        p.pub_key_len,
        "{} encapsulation key length",
        p.name
    );
    assert_eq!(
        resp.masked_key.len(),
        p.masked_key_len,
        "{} masked key length: the blob carries the seed *and* the expanded \
         private key, so it is parameter-set dependent",
        p.name
    );
    assert!(
        resp.pub_key.iter().any(|&b| b != 0),
        "{} encapsulation key is all zeroes",
        p.name
    );
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "{} masked key is all zeroes",
        p.name
    );
    assert_not_truncated_at_page(&resp.pub_key, p.name);
    assert_not_truncated_at_page(&resp.masked_key, p.name);
}

#[test]
fn mlkem_generate_key_smoke_512() {
    generate_key_case(&ML_KEM_512);
}

#[test]
fn mlkem_generate_key_smoke_768() {
    generate_key_case(&ML_KEM_768);
}

#[test]
fn mlkem_generate_key_smoke_1024() {
    generate_key_case(&ML_KEM_1024);
}
