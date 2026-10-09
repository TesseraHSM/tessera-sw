// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bring-up smoke test for the TBOR `MlDsaGenerateKey` command.
//!
//! Deliberately minimal: one host-only wire-shape check plus one
//! happy-path round-trip, enough to prove the opcode reaches firmware
//! and returns a well-formed response.  Negative cases, parameter-set
//! sweeps and cross-command chains land once the firmware handlers do.
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
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::TBOR_OP_MLDSA_GENERATE_KEY;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Host-only: opcode, in-session control and TOC arity.
#[test]
fn mldsa_generate_key_request_wire_shape() {
    let req = TborMlDsaGenerateKeyReq {
        session_id: 0,
        scope: SCOPE_LOCAL,
        key_kind: ML_DSA_44.key_kind,
    };

    assert_eq!(TborMlDsaGenerateKeyReq::OPCODE, TBOR_OP_MLDSA_GENERATE_KEY);
    assert_eq!(req.get_session_id(), Some(0));
    assert_eq!(req.session_ctrl(), SessionControlKind::InSession);

    let mut buf = [0u8; 256];
    let bytes = req.encode_request(&mut buf).expect("encode request");
    let view = RequestView::parse(bytes).expect("parse request");
    assert_eq!(view.opcode(), TBOR_OP_MLDSA_GENERATE_KEY);
    assert_eq!(view.toc_count(), 3);
}

/// Happy path: generate a keypair and check the response is well
/// formed. The masked private key is opaque here -- only its length and
/// non-triviality can be checked without the masking key.
fn generate_key_case(p: &MlDsaParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let resp = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlDsaGenerateKey({}): {e:?}", p.name));

    assert_eq!(
        resp.pub_key.len(),
        p.pub_key_len,
        "{} public key length",
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
        "{} public key is all zeroes",
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
fn mldsa_generate_key_smoke_44() {
    generate_key_case(&ML_DSA_44);
}

#[test]
fn mldsa_generate_key_smoke_65() {
    generate_key_case(&ML_DSA_65);
}

#[test]
fn mldsa_generate_key_smoke_87() {
    generate_key_case(&ML_DSA_87);
}
