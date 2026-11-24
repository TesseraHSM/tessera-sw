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

use crate::commands::common::assert_masked_key_layout_rejected;
use crate::commands::common::PayloadGapReq;
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
    let bytes = req
        .encode_request(&mut buf, (1, 1))
        .expect("encode request");
    let view = RequestView::parse(bytes).expect("parse request");
    assert_eq!(view.opcode(), TBOR_OP_MLDSA_SIGN);
    // Four fields plus the masked key's alignment padding entry.
    assert_eq!(view.toc_count(), 5);
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

/// Rejects an otherwise valid request whose payload data starts after a
/// non-canonical 4-byte gap.
#[test]
fn mldsa_sign_rejects_payload_gap() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .expect("MlDsaGenerateKey");
    let req = TborMlDsaSignReq {
        session_id: session.session_id,
        masked_key: key.masked_key,
        mu: vec![0x5A; MLDSA_MU_LEN],
        hedge: MLDSA_HEDGE_PREFERRED,
    };

    ctx.expect_fw_reject(&PayloadGapReq(req), TborStatus::TborNonCanonicalLayout);
}

/// Rejects a misaligned masked key and one without its padding entry.
#[test]
fn mldsa_sign_rejects_bad_masked_key_layout() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .expect("MlDsaGenerateKey");
    assert_masked_key_layout_rejected(
        &ctx,
        &TborMlDsaSignReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            mu: vec![0x5A; MLDSA_MU_LEN],
            hedge: MLDSA_HEDGE_PREFERRED,
        },
    );
}

/// Rejects empty, truncated, and oversized mu inputs.
#[test]
fn mldsa_sign_rejects_invalid_mu_lengths() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .expect("MlDsaGenerateKey");

    for len in [0, 1, MLDSA_MU_LEN - 1, MLDSA_MU_LEN + 1] {
        let result = ctx.tbor(&TborMlDsaSignReq {
            session_id: session.session_id,
            masked_key: key.masked_key.clone(),
            mu: vec![0x5A; len],
            hedge: MLDSA_HEDGE_PREFERRED,
        });

        assert!(
            result.is_err(),
            "MlDsaSign accepted invalid mu length {len}"
        );
    }

    // A rejected request must not prevent a subsequent valid sign.
    let resp = ctx
        .tbor(&TborMlDsaSignReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            mu: vec![0x5A; MLDSA_MU_LEN],
            hedge: MLDSA_HEDGE_PREFERRED,
        })
        .expect("valid sign after invalid mu lengths");

    assert_eq!(resp.signature.len(), ML_DSA_44.sig_len);
}

/// Rejects empty and truncated masked-key envelopes.
#[test]
fn mldsa_sign_rejects_truncated_masked_keys() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .expect("MlDsaGenerateKey");

    let full_len = key.masked_key.len();
    assert!(full_len > 32);

    for len in [0, 1, 4, 16, 32, full_len - 1] {
        let result = ctx.tbor(&TborMlDsaSignReq {
            session_id: session.session_id,
            masked_key: key.masked_key[..len].to_vec(),
            mu: vec![0x5A; MLDSA_MU_LEN],
            hedge: MLDSA_HEDGE_PREFERRED,
        });

        assert!(
            result.is_err(),
            "MlDsaSign accepted truncated masked key of length {len}"
        );
    }
}

/// Rejects corrupted AEAD envelope headers.
#[test]
fn mldsa_sign_rejects_corrupted_masked_key_header() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .expect("MlDsaGenerateKey");

    assert_eq!(&key.masked_key[..4], b"AEAD");

    for index in 0..4 {
        let mut corrupted = key.masked_key.clone();
        corrupted[index] ^= 0x01;

        let result = ctx.tbor(&TborMlDsaSignReq {
            session_id: session.session_id,
            masked_key: corrupted,
            mu: vec![0x5A; MLDSA_MU_LEN],
            hedge: MLDSA_HEDGE_PREFERRED,
        });

        assert!(
            result.is_err(),
            "MlDsaSign accepted corrupted AEAD header byte {index}"
        );
    }
}

/// Rejects a masked key whose authenticated payload is corrupted.
#[test]
fn mldsa_sign_rejects_corrupted_masked_key_payload() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .expect("MlDsaGenerateKey");

    let mut corrupted = key.masked_key.clone();

    // Avoid the AEAD magic and trailing authentication tag.
    let index = corrupted.len() / 2;
    corrupted[index] ^= 0x80;

    let result = ctx.tbor(&TborMlDsaSignReq {
        session_id: session.session_id,
        masked_key: corrupted,
        mu: vec![0x5A; MLDSA_MU_LEN],
        hedge: MLDSA_HEDGE_PREFERRED,
    });

    assert!(
        result.is_err(),
        "MlDsaSign accepted corrupted masked-key payload"
    );
}

/// Signs multiple messages with the same masked key.
fn repeated_sign_case(p: &MlDsaParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .expect("MlDsaGenerateKey");

    for pattern in [0x00, 0x5A, 0xFF] {
        let resp = ctx
            .tbor(&TborMlDsaSignReq {
                session_id: session.session_id,
                masked_key: key.masked_key.clone(),
                mu: vec![pattern; MLDSA_MU_LEN],
                hedge: MLDSA_HEDGE_PREFERRED,
            })
            .unwrap_or_else(|e| {
                panic!(
                    "{}: repeated sign with pattern {pattern:#04x}: {e:?}",
                    p.name
                )
            });

        assert_eq!(
            resp.signature.len(),
            p.sig_len,
            "{}: repeated signature length",
            p.name
        );

        assert!(
            resp.signature.iter().any(|&b| b != 0),
            "{}: signature is all zeroes",
            p.name
        );

        assert_not_truncated_at_page(&resp.signature, p.name);
    }
}

/// Reuses an ML-DSA-44 key for multiple signing requests.
#[test]
fn mldsa_sign_repeated_signing_44() {
    repeated_sign_case(&ML_DSA_44);
}

/// Reuses an ML-DSA-65 key for multiple signing requests.
#[test]
fn mldsa_sign_repeated_signing_65() {
    repeated_sign_case(&ML_DSA_65);
}

/// Reuses an ML-DSA-87 key for multiple signing requests.
#[test]
fn mldsa_sign_repeated_signing_87() {
    repeated_sign_case(&ML_DSA_87);
}

/// A rejected masked key does not invalidate the CO session.
#[test]
fn mldsa_sign_recovers_after_invalid_masked_key() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .expect("MlDsaGenerateKey");

    for _ in 0..3 {
        let mut corrupted = key.masked_key.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x01;

        let rejected = ctx.tbor(&TborMlDsaSignReq {
            session_id: session.session_id,
            masked_key: corrupted,
            mu: vec![0x5A; MLDSA_MU_LEN],
            hedge: MLDSA_HEDGE_PREFERRED,
        });

        assert!(
            rejected.is_err(),
            "corrupted masked key unexpectedly accepted"
        );

        let valid = ctx
            .tbor(&TborMlDsaSignReq {
                session_id: session.session_id,
                masked_key: key.masked_key.clone(),
                mu: vec![0x5A; MLDSA_MU_LEN],
                hedge: MLDSA_HEDGE_PREFERRED,
            })
            .expect("valid sign after corrupted key");

        assert_eq!(valid.signature.len(), ML_DSA_44.sig_len);
    }
}

/// Rejects an all-zero masked key with the correct envelope length.
#[test]
fn mldsa_sign_rejects_zeroed_masked_key() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .expect("MlDsaGenerateKey");

    let result = ctx.tbor(&TborMlDsaSignReq {
        session_id: session.session_id,
        masked_key: vec![0; key.masked_key.len()],
        mu: vec![0x5A; MLDSA_MU_LEN],
        hedge: MLDSA_HEDGE_PREFERRED,
    });

    assert!(result.is_err(), "MlDsaSign accepted an all-zero masked key");
}
/// Rejects a masked-key envelope with trailing bytes.
#[test]
fn mldsa_sign_rejects_oversized_masked_key() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .expect("MlDsaGenerateKey");

    let mut oversized = key.masked_key;
    oversized.extend_from_slice(&[0xAA; 16]);

    let result = ctx.tbor(&TborMlDsaSignReq {
        session_id: session.session_id,
        masked_key: oversized,
        mu: vec![0x5A; MLDSA_MU_LEN],
        hedge: MLDSA_HEDGE_PREFERRED,
    });

    assert!(
        result.is_err(),
        "MlDsaSign accepted an oversized masked key"
    );
}
