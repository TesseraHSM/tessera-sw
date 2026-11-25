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
    let bytes = req
        .encode_request(&mut buf, (1, 1))
        .expect("encode request");
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

/// Verify that repeated key generation produces unique public keys.
#[test]
fn mldsa_generate_key_repeated_generations_are_unique() {
    for p in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let mut previous_pub_key: Option<Vec<u8>> = None;

        for iteration in 0..3 {
            let resp = ctx
                .tbor(&TborMlDsaGenerateKeyReq {
                    session_id: session.session_id,
                    scope: SCOPE_LOCAL,
                    key_kind: p.key_kind,
                })
                .unwrap_or_else(|e| {
                    panic!("MlDsaGenerateKey({}) iteration {iteration}: {e:?}", p.name)
                });

            assert_eq!(resp.pub_key.len(), p.pub_key_len);
            assert_eq!(resp.masked_key.len(), p.masked_key_len);

            assert!(resp.pub_key.iter().any(|&b| b != 0));
            assert!(resp.masked_key.iter().any(|&b| b != 0));

            assert_not_truncated_at_page(&resp.pub_key, p.name);
            assert_not_truncated_at_page(&resp.masked_key, p.name);

            if let Some(previous) = &previous_pub_key {
                assert_ne!(
                    resp.pub_key.as_slice(),
                    previous.as_slice(),
                    "{} generated duplicate consecutive public keys",
                    p.name
                );
            }

            previous_pub_key = Some(resp.pub_key.clone());
        }
    }
}

/// Verify that key generation works across independent CO sessions.
#[test]
fn mldsa_generate_key_across_fresh_sessions() {
    for p in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        let mut previous_pub_key: Option<Vec<u8>> = None;

        for iteration in 0..2 {
            let ctx = TestCtx::new();
            let session = finalized_co_session(&ctx);

            let resp = ctx
                .tbor(&TborMlDsaGenerateKeyReq {
                    session_id: session.session_id,
                    scope: SCOPE_LOCAL,
                    key_kind: p.key_kind,
                })
                .unwrap_or_else(|e| {
                    panic!(
                        "MlDsaGenerateKey({}) fresh session {iteration}: {e:?}",
                        p.name
                    )
                });

            assert_eq!(resp.pub_key.len(), p.pub_key_len);
            assert_eq!(resp.masked_key.len(), p.masked_key_len);

            assert_not_truncated_at_page(&resp.pub_key, p.name);
            assert_not_truncated_at_page(&resp.masked_key, p.name);

            if let Some(previous) = &previous_pub_key {
                assert_ne!(
                    resp.pub_key.as_slice(),
                    previous.as_slice(),
                    "{} generated identical public keys across sessions",
                    p.name
                );
            }

            previous_pub_key = Some(resp.pub_key.clone());
        }
    }
}

/// Verify that alternating ML-DSA parameter sets preserves output sizes.
#[test]
fn mldsa_generate_key_interleaved_parameter_sets() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let params = [
        &ML_DSA_44, &ML_DSA_65, &ML_DSA_87, &ML_DSA_44, &ML_DSA_87, &ML_DSA_65,
    ];

    for (iteration, p) in params.iter().enumerate() {
        let resp = ctx
            .tbor(&TborMlDsaGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                key_kind: p.key_kind,
            })
            .unwrap_or_else(|e| {
                panic!("MlDsaGenerateKey({}) iteration {iteration}: {e:?}", p.name)
            });

        assert_eq!(
            resp.pub_key.len(),
            p.pub_key_len,
            "{} public key length at iteration {iteration}",
            p.name
        );

        assert_eq!(
            resp.masked_key.len(),
            p.masked_key_len,
            "{} masked key length at iteration {iteration}",
            p.name
        );

        assert!(resp.pub_key.iter().any(|&b| b != 0));
        assert!(resp.masked_key.iter().any(|&b| b != 0));

        assert_not_truncated_at_page(&resp.pub_key, p.name);
        assert_not_truncated_at_page(&resp.masked_key, p.name);
    }
}

/// Verify all supported parameter sets work in one finalized CO session.
#[test]
fn mldsa_generate_key_all_parameter_sets_in_one_session() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for p in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        let resp = ctx
            .tbor(&TborMlDsaGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                key_kind: p.key_kind,
            })
            .unwrap_or_else(|e| panic!("MlDsaGenerateKey({}): {e:?}", p.name));

        assert_eq!(resp.pub_key.len(), p.pub_key_len);
        assert_eq!(resp.masked_key.len(), p.masked_key_len);

        assert!(resp.pub_key.iter().any(|&b| b != 0));
        assert!(resp.masked_key.iter().any(|&b| b != 0));

        assert_not_truncated_at_page(&resp.pub_key, p.name);
        assert_not_truncated_at_page(&resp.masked_key, p.name);
    }
}

/// Verify request opcode, session control, and TOC for all parameter sets.
#[test]
fn mldsa_generate_key_request_wire_shape_all_params() {
    for p in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        let req = TborMlDsaGenerateKeyReq {
            session_id: 0,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        };

        assert_eq!(TborMlDsaGenerateKeyReq::OPCODE, TBOR_OP_MLDSA_GENERATE_KEY);
        assert_eq!(req.get_session_id(), Some(0));
        assert_eq!(req.session_ctrl(), SessionControlKind::InSession);

        let mut buf = [0u8; 256];
        let bytes = req
            .encode_request(&mut buf, (1, 1))
            .expect("encode ML-DSA request");

        let view = RequestView::parse(bytes).expect("parse ML-DSA request");

        assert_eq!(view.opcode(), TBOR_OP_MLDSA_GENERATE_KEY);
        assert_eq!(view.toc_count(), 3);
    }
}

/// Verify identical requests produce identical encoded wire bytes.
#[test]
fn mldsa_generate_key_request_encoding_is_deterministic() {
    for p in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        let req = TborMlDsaGenerateKeyReq {
            session_id: 0,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        };

        let mut buf1 = [0u8; 256];
        let mut buf2 = [0u8; 256];

        let encoded1 = req
            .encode_request(&mut buf1, (1, 1))
            .expect("first encoding");

        let encoded2 = req
            .encode_request(&mut buf2, (1, 1))
            .expect("second encoding");

        assert_eq!(
            encoded1, encoded2,
            "{} request encoding is not deterministic",
            p.name
        );
    }
}

/// Verify request encoding rejects an insufficient output buffer.
#[test]
fn mldsa_generate_key_request_rejects_small_buffer() {
    for p in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        let req = TborMlDsaGenerateKeyReq {
            session_id: 0,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        };

        let mut empty = [0u8; 0];
        assert!(
            req.encode_request(&mut empty, (1, 1)).is_err(),
            "{} accepted an empty output buffer",
            p.name
        );

        let mut tiny = [0u8; 1];
        assert!(
            req.encode_request(&mut tiny, (1, 1)).is_err(),
            "{} accepted a one-byte output buffer",
            p.name
        );
    }
}

/// Verify an encoding failure does not prevent a later valid encoding.
#[test]
fn mldsa_generate_key_request_encoding_recovers_after_small_buffer() {
    for p in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        let req = TborMlDsaGenerateKeyReq {
            session_id: 0,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        };

        let mut tiny = [0u8; 1];
        assert!(req.encode_request(&mut tiny, (1, 1)).is_err());

        let mut valid = [0u8; 256];
        let encoded = req
            .encode_request(&mut valid, (1, 1))
            .expect("encoding after small-buffer failure");

        let view = RequestView::parse(encoded).expect("parse request after recovery");

        assert_eq!(view.opcode(), TBOR_OP_MLDSA_GENERATE_KEY);
        assert_eq!(view.toc_count(), 3);
    }
}

/// Verify that multiple generations do not reuse public key material.
#[test]
fn mldsa_generate_key_all_generated_keys_unique() {
    for p in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let mut seen = std::collections::HashSet::new();

        for iteration in 0..10 {
            let resp = ctx
                .tbor(&TborMlDsaGenerateKeyReq {
                    session_id: session.session_id,
                    scope: SCOPE_LOCAL,
                    key_kind: p.key_kind,
                })
                .unwrap_or_else(|e| {
                    panic!("MlDsaGenerateKey({}) iteration {iteration}: {e:?}", p.name)
                });

            assert_eq!(resp.pub_key.len(), p.pub_key_len);
            assert_eq!(resp.masked_key.len(), p.masked_key_len);

            assert!(
                seen.insert(resp.pub_key.clone()),
                "{} repeated public key at iteration {iteration}",
                p.name
            );

            assert_not_truncated_at_page(&resp.pub_key, p.name);
            assert_not_truncated_at_page(&resp.masked_key, p.name);
        }
    }
}

/// Verify public keys generated with different parameter sets differ.
#[test]
fn mldsa_generate_key_public_key_differs_across_parameter_sets() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let mut keys = Vec::new();

    for p in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        let resp = ctx
            .tbor(&TborMlDsaGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                key_kind: p.key_kind,
            })
            .unwrap_or_else(|e| panic!("MlDsaGenerateKey({}): {e:?}", p.name));

        assert_eq!(resp.pub_key.len(), p.pub_key_len);
        keys.push((p.name, resp.pub_key.clone()));
    }

    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i].1, keys[j].1,
                "{} and {} returned identical public keys",
                keys[i].0, keys[j].0
            );
        }
    }
}

/// Verify encoding succeeds at the exact buffer-size boundary.
#[test]
fn mldsa_generate_key_exact_request_buffer_boundary() {
    for p in [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87] {
        let req = TborMlDsaGenerateKeyReq {
            session_id: 0,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        };

        let mut large = [0u8; 256];

        let required_len = req
            .encode_request(&mut large, (1, 1))
            .expect("encode reference request")
            .len();

        let mut exact = vec![0u8; required_len];

        let encoded = req
            .encode_request(&mut exact, (1, 1))
            .expect("exact-size buffer must succeed");

        assert_eq!(encoded.len(), required_len);

        let view = RequestView::parse(encoded).expect("parse exact-size request");

        assert_eq!(view.opcode(), TBOR_OP_MLDSA_GENERATE_KEY);
        assert_eq!(view.toc_count(), 3);

        let mut short = vec![0u8; required_len - 1];

        assert!(
            req.encode_request(&mut short, (1, 1)).is_err(),
            "{} accepted a buffer one byte too short",
            p.name
        );
    }
}
