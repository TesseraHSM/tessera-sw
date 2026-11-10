// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `VerifyKey` command.
//!
//! `VerifyKey` authenticates a caller-held masked key of any kind without
//! using it: an intact blob is acknowledged, while a tampered or
//! wrong-session blob fails AEAD authentication.

use tsra_crypto::*;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::SessionOpenInitOptions;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::*;

use crate::commands::common::CO;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::get_public_key::generate_ecc;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;

fn verify_key(ctx: &TestCtx, session_id: u16, masked_key: Vec<u8>) {
    ctx.tbor(&TborVerifyKeyReq {
        session_id,
        masked_key,
    })
    .expect("VerifyKey");
}

/// Accepts intact masked keys of every class: symmetric and asymmetric.
#[test]
fn verify_key_accepts_intact_keys() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let rsa = RsaPrivateKey::generate(256).expect("generate RSA key");
    let rsa_der = rsa.to_vec().expect("RSA private DER export");
    for (class, material) in [
        (KEY_CLASS_AES, vec![0x42u8; 32]),
        (KEY_CLASS_RSA, rsa_der.clone()),
        (KEY_CLASS_RSA_CRT, rsa_der),
    ] {
        let imported = unwrap(&ctx, session.session_id, class, &material);
        verify_key(&ctx, session.session_id, imported.masked_key);
    }
    let (masked_key, _) = generate_ecc(&ctx, session.session_id, ECC_CURVE_P256);
    verify_key(&ctx, session.session_id, masked_key);
}

/// Expanded PQC envelopes larger than the RSA unwrap limit remain verifiable.
#[test]
fn verify_key_accepts_large_generated_pqc_keys() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for key_kind in [MLDSA_KEY_KIND_65_SEED, MLDSA_KEY_KIND_87_SEED] {
        let key = ctx
            .tbor(&TborMlDsaGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                key_kind,
            })
            .expect("generate ML-DSA key");
        assert!(key.masked_key.len() > UNWRAP_MASKED_KEY_MAX_LEN);
        verify_key(&ctx, session.session_id, key.masked_key);
    }
    let key = ctx
        .tbor(&TborMlKemGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            key_kind: MLKEM_KEY_KIND_1024_SEED,
        })
        .expect("generate ML-KEM-1024 key");
    assert!(key.masked_key.len() > UNWRAP_MASKED_KEY_MAX_LEN);
    verify_key(&ctx, session.session_id, key.masked_key);
}

/// Crypto-User sessions may verify keys.
#[test]
fn verify_key_allowed_on_crypto_user_session() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let (masked_key, _) = generate_ecc(&ctx, session.session_id, ECC_CURVE_P384);
    verify_key(&ctx, session.session_id, masked_key);
}

/// Flipping a byte in the tag, the cleartext metadata (AAD), or the
/// encrypted key material fails authentication.
#[test]
fn verify_key_tampered_masked_key_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let imported = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &[0x42u8; 32]);
    let len = imported.masked_key.len();
    // Envelope: header(8) ‖ iv(12) ‖ metadata(192) ‖ payload ‖ tag(16).
    for at in [len - 1, len - 17, 8 + 12 + 40] {
        let mut masked_key = imported.masked_key.clone();
        masked_key[at] ^= 0x01;
        ctx.expect_fw_reject(
            &TborVerifyKeyReq {
                session_id: session.session_id,
                masked_key,
            },
            TborStatus::AesGcmDecryptTagDoesNotMatch,
        );
    }
}

/// A session-scoped key fails authentication in a different session.
#[test]
fn verify_key_session_scoped_key_rejected_in_different_session() {
    let ctx = TestCtx::new();
    let session_a = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, _) = generate_ecc(&ctx, session_a.session_id, ECC_CURVE_P256);
    ctx.session_close(session_a.session_id)
        .expect("close originating CO session");
    let opts =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&ROTATED_CO_PSK);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open replacement CO session");
    let session_b = ctx
        .session_open_finish(pending)
        .expect("finish replacement CO session");
    ctx.expect_fw_reject(
        &TborVerifyKeyReq {
            session_id: session_b.session_id,
            masked_key,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Rejected while the CO PSK is still the default.
#[test]
fn verify_key_rejects_default_co_psk() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO session under default PSK");
    ctx.expect_fw_reject(
        &TborVerifyKeyReq {
            session_id: session.session_id(),
            masked_key: vec![0u8; 64],
        },
        TborStatus::DefaultPskMustRotate,
    );
}
