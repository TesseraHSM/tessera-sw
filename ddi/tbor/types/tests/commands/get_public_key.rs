// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `GetPublicKey` command.
//!
//! `GetPublicKey` unmasks a caller-held masked RSA / ECC private key and
//! returns its wire public key. These tests check the result against the
//! public key returned when the key was created (`EccGenerateKey` /
//! `UnwrapKey`), so both commands are pinned to the same wire format.

#![cfg(feature = "emu")]

use tsra_crypto::*;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::SessionOpenInitOptions;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::*;

use crate::commands::common::CO;
use crate::commands::common::SCOPE_SESSION;
use crate::commands::ecc_sign::ECC_CURVES;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;

/// Generate a session-scoped ECC signing key; returns `(masked, pub)`.
pub fn generate_ecc(ctx: &TestCtx, session_id: u16, curve: u8) -> (Vec<u8>, Vec<u8>) {
    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_SESSION,
            curve,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");
    (resp.masked_key, resp.pub_key)
}

fn get_public_key(ctx: &TestCtx, session_id: u16, masked_key: Vec<u8>) -> Vec<u8> {
    ctx.tbor(&TborGetPublicKeyReq {
        session_id,
        masked_key,
    })
    .expect("GetPublicKey")
    .pub_key
}

/// Returns the same public key as `EccGenerateKey` on every curve.
#[test]
fn get_public_key_matches_ecc_generate_key_all_curves() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        let (masked_key, pub_key) = generate_ecc(&ctx, session.session_id, curve);
        assert_eq!(
            get_public_key(&ctx, session.session_id, masked_key),
            pub_key,
            "curve {curve}",
        );
    }
}

/// Returns the same public key as `UnwrapKey` for imported ECC keys.
#[test]
fn get_public_key_matches_unwrapped_ecc_key() {
    for curve in [EccCurve::P256, EccCurve::P384, EccCurve::P521] {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);
        let host_key = EccPrivateKey::from_curve(curve).expect("generate host ECC key");
        let der = host_key.to_vec().expect("PKCS#8 DER export");
        let imported = unwrap(&ctx, session.session_id, KEY_CLASS_ECC, &der);
        assert_eq!(
            get_public_key(&ctx, session.session_id, imported.masked_key),
            imported.pub_key,
        );
    }
}

/// Returns the same public key as `UnwrapKey` for RSA keys, CRT and non-CRT,
/// across every supported modulus size.
#[test]
fn get_public_key_matches_unwrapped_rsa_key() {
    for modulus_bytes in [256, 384, 512] {
        let key = RsaPrivateKey::generate(modulus_bytes).expect("generate RSA key");
        let der = key.to_vec().expect("RSA private DER export");
        for class in [KEY_CLASS_RSA, KEY_CLASS_RSA_CRT] {
            let ctx = TestCtx::new();
            let session = finalized_co_session(&ctx);
            let imported = unwrap(&ctx, session.session_id, class, &der);
            let pub_key = get_public_key(&ctx, session.session_id, imported.masked_key);
            assert_eq!(pub_key.len(), modulus_bytes + 4);
            assert_eq!(pub_key, imported.pub_key, "class {class}");
        }
    }
}

/// Crypto-User sessions may query public keys.
#[test]
fn get_public_key_allowed_on_crypto_user_session() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let (masked_key, pub_key) = generate_ecc(&ctx, session.session_id, ECC_CURVE_P256);
    assert_eq!(
        get_public_key(&ctx, session.session_id, masked_key),
        pub_key
    );
}

/// Symmetric keys have no public component.
#[test]
fn get_public_key_symmetric_key_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let imported = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &[0x42u8; 32]);
    ctx.expect_fw_reject(
        &TborGetPublicKeyReq {
            session_id: session.session_id,
            masked_key: imported.masked_key,
        },
        TborStatus::InvalidKeyType,
    );
}

/// A tampered masked key fails AEAD authentication.
#[test]
fn get_public_key_tampered_masked_key_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mut masked_key, _) = generate_ecc(&ctx, session.session_id, ECC_CURVE_P384);
    let last = masked_key.len() - 1;
    masked_key[last] ^= 0x01;
    ctx.expect_fw_reject(
        &TborGetPublicKeyReq {
            session_id: session.session_id,
            masked_key,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// A session-scoped key cannot be unmasked from a different session.
#[test]
fn get_public_key_session_scoped_key_rejected_in_different_session() {
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
        &TborGetPublicKeyReq {
            session_id: session_b.session_id,
            masked_key,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Rejected while the CO PSK is still the default.
#[test]
fn get_public_key_rejects_default_co_psk() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO session under default PSK");
    ctx.expect_fw_reject(
        &TborGetPublicKeyReq {
            session_id: session.session_id(),
            masked_key: vec![0u8; 64],
        },
        TborStatus::DefaultPskMustRotate,
    );
}
