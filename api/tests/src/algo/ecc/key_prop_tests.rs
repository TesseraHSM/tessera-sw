// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_api::*;
use tsra_api_tests_macro::*;
use tsra_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;

use super::common::*;
use super::key_tests::*;

// Helper to attempt ECC key pair unwrap with given properties, using a bogus blob to exercise validation and DDI paths.
fn unwrap_ecc_with_props(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(HsmEccPrivateKey, HsmEccPublicKey), HsmError> {
    let (unwrapping_priv_key, _unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);
    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    // Deliberately invalid wrapped blob; unwrap should fail *before* DDI on invalid props.
    let bogus_wrapped_key: &[u8] = &[];

    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        bogus_wrapped_key,
        priv_key_props,
        pub_key_props,
    )
}

// Generates a valid ECC sign/verify key pair and expects keygen to succeed.
#[session_test]
fn test_ecc_key_pair_valid_sign_verify_succeeds(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let (_priv_key, _pub_key) =
        gen_ecc_key_pair(&session, priv_key_props, pub_key_props).expect("Keygen should succeed");
}

// Rejects ECC private key props when class is not Private.
#[session_test]
fn test_ecc_priv_props_invalid_class_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC private key props when key kind is not Ecc.
#[session_test]
fn test_ecc_priv_props_invalid_kind_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC private key props when curve is missing (even if bits is set).
#[session_test]
fn test_ecc_priv_props_missing_curve_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .can_sign(true)
        .bits(256)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC private key props when both SIGN and DERIVE are set.
#[session_test]
fn test_ecc_priv_props_sign_and_derive_both_set_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .can_derive(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC private key props when no usage flags are set.
#[session_test]
fn test_ecc_priv_props_no_usage_flags_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

fn assert_ecc_flag_rejected(
    session: &HsmSession,
    curve: HsmEccCurve,
    key_class: HsmKeyClass,
    can_derive: bool,
    set_flag: fn(HsmKeyPropsBuilder, bool) -> HsmKeyPropsBuilder,
) {
    assert!(matches!(
        key_class,
        HsmKeyClass::Private | HsmKeyClass::Public
    ));
    let props_with_flag = |enabled| {
        let (mut priv_builder, mut pub_builder) = ecc_key_pair_props_builders(curve, can_derive, true);
        if key_class == HsmKeyClass::Private {
            priv_builder = set_flag(priv_builder, enabled);
        } else {
            pub_builder = set_flag(pub_builder, enabled);
        }
        (
            priv_builder.build().expect("Failed to build private props"),
            pub_builder.build().expect("Failed to build public props"),
        )
    };

    let (priv_props, pub_props) = props_with_flag(false);
    let (priv_key, pub_key) = gen_ecc_key_pair(session, priv_props, pub_props)
        .expect("Control template must succeed with the forbidden flag unset");
    assert_eq!(priv_key.ecc_curve(), Some(curve));
    assert_eq!(pub_key.ecc_curve(), Some(curve));
    assert_eq!(priv_key.bits(), curve.key_size_bits() as u32);
    assert_eq!(pub_key.bits(), curve.key_size_bits() as u32);
    HsmKeyManager::delete_key(priv_key).expect("Failed to delete control private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete control public key");

    let (priv_props, pub_props) = props_with_flag(true);
    let result = gen_ecc_key_pair(session, priv_props, pub_props);
    assert_eq!(
        result.err(),
        Some(HsmError::InvalidKeyProps),
        "Changing only the forbidden flag must reject {key_class:?} {curve:?} props with derive={can_derive}"
    );
}

macro_rules! ecc_flag_tests {
    ($name:ident, $key_class:expr, $can_derive:expr, $set_flag:path $(,)?) => {
        mod $name {
            use super::*;

            #[session_test]
            fn p256(session: HsmSession) {
                assert_ecc_flag_rejected(
                    &session,
                    HsmEccCurve::P256,
                    $key_class,
                    $can_derive,
                    $set_flag,
                );
            }

            #[session_test]
            fn p384(session: HsmSession) {
                assert_ecc_flag_rejected(
                    &session,
                    HsmEccCurve::P384,
                    $key_class,
                    $can_derive,
                    $set_flag,
                );
            }

            #[session_test]
            fn p521(session: HsmSession) {
                assert_ecc_flag_rejected(
                    &session,
                    HsmEccCurve::P521,
                    $key_class,
                    $can_derive,
                    $set_flag,
                );
            }
        }
    };
}

ecc_flag_tests!(
    test_ecc_priv_sign_wrap_fails,
    HsmKeyClass::Private,
    false,
    HsmKeyPropsBuilder::can_wrap,
);

ecc_flag_tests!(
    test_ecc_priv_derive_wrap_fails,
    HsmKeyClass::Private,
    true,
    HsmKeyPropsBuilder::can_wrap,
);

ecc_flag_tests!(
    test_ecc_priv_sign_encrypt_fails,
    HsmKeyClass::Private,
    false,
    HsmKeyPropsBuilder::can_encrypt,
);

ecc_flag_tests!(
    test_ecc_priv_derive_encrypt_fails,
    HsmKeyClass::Private,
    true,
    HsmKeyPropsBuilder::can_encrypt,
);

ecc_flag_tests!(
    test_ecc_priv_sign_decrypt_fails,
    HsmKeyClass::Private,
    false,
    HsmKeyPropsBuilder::can_decrypt,
);

ecc_flag_tests!(
    test_ecc_priv_derive_decrypt_fails,
    HsmKeyClass::Private,
    true,
    HsmKeyPropsBuilder::can_decrypt,
);

ecc_flag_tests!(
    test_ecc_priv_sign_unwrap_fails,
    HsmKeyClass::Private,
    false,
    HsmKeyPropsBuilder::can_unwrap,
);

ecc_flag_tests!(
    test_ecc_priv_derive_unwrap_fails,
    HsmKeyClass::Private,
    true,
    HsmKeyPropsBuilder::can_unwrap,
);

ecc_flag_tests!(
    test_ecc_priv_sign_verify_fails,
    HsmKeyClass::Private,
    false,
    HsmKeyPropsBuilder::can_verify,
);

ecc_flag_tests!(
    test_ecc_priv_derive_verify_fails,
    HsmKeyClass::Private,
    true,
    HsmKeyPropsBuilder::can_verify,
);

ecc_flag_tests!(
    test_ecc_pub_verify_wrap_fails,
    HsmKeyClass::Public,
    false,
    HsmKeyPropsBuilder::can_wrap,
);

ecc_flag_tests!(
    test_ecc_pub_derive_wrap_fails,
    HsmKeyClass::Public,
    true,
    HsmKeyPropsBuilder::can_wrap,
);

ecc_flag_tests!(
    test_ecc_pub_verify_encrypt_fails,
    HsmKeyClass::Public,
    false,
    HsmKeyPropsBuilder::can_encrypt,
);

ecc_flag_tests!(
    test_ecc_pub_derive_encrypt_fails,
    HsmKeyClass::Public,
    true,
    HsmKeyPropsBuilder::can_encrypt,
);

ecc_flag_tests!(
    test_ecc_pub_verify_decrypt_fails,
    HsmKeyClass::Public,
    false,
    HsmKeyPropsBuilder::can_decrypt,
);

ecc_flag_tests!(
    test_ecc_pub_derive_decrypt_fails,
    HsmKeyClass::Public,
    true,
    HsmKeyPropsBuilder::can_decrypt,
);

ecc_flag_tests!(
    test_ecc_pub_verify_unwrap_fails,
    HsmKeyClass::Public,
    false,
    HsmKeyPropsBuilder::can_unwrap,
);

ecc_flag_tests!(
    test_ecc_pub_derive_unwrap_fails,
    HsmKeyClass::Public,
    true,
    HsmKeyPropsBuilder::can_unwrap,
);

ecc_flag_tests!(
    test_ecc_pub_verify_sign_fails,
    HsmKeyClass::Public,
    false,
    HsmKeyPropsBuilder::can_sign,
);

ecc_flag_tests!(
    test_ecc_pub_derive_sign_fails,
    HsmKeyClass::Public,
    true,
    HsmKeyPropsBuilder::can_sign,
);

// Rejects ECC public key props with both VERIFY and DERIVE usage.
#[session_test]
fn test_ecc_pub_props_verify_and_derive_fail(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .can_derive(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap fails fast when private key props are invalid.
#[session_test]
fn test_ecc_unwrap_invalid_priv_props_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let result = unwrap_ecc_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap validates props first and reaches the DDI layer with valid props.
#[session_test]
fn test_ecc_unwrap_valid_props(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    // With a bogus wrapped blob we expect the call to reach the DDI layer and fail there.
    let result = unwrap_ecc_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(
        result,
        Err(HsmError::DdiCmdFailure) | Err(HsmError::InvalidArgument)
    ));
}

// Rejects ECC public key props when class is not Public.
#[session_test]
fn test_ecc_pub_props_invalid_class_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private) // invalid
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC public key props when key kind is not Ecc.
#[session_test]
fn test_ecc_pub_props_invalid_kind_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa) // invalid
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC public key props when curve is missing (builder-level validation).
#[session_test]
fn test_ecc_pub_props_missing_curve_fails(_session: HsmSession) {
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .can_verify(true)
        .build();

    // Builder should fail before reaching keygen
    assert!(matches!(pub_props, Err(HsmError::PropertyNotPresent)));
}

#[session_test]
fn test_ecc_pub_props_missing_curve_with_bits_fails(session: HsmSession) {
    for curve in [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521] {
        let priv_props = ecc_priv_props(curve, true, false);
        let pub_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Public)
            .key_kind(HsmKeyKind::Ecc)
            .bits(curve.key_size_bits() as u32)
            .can_verify(true)
            .build()
            .expect("Bits should allow building props without a curve");
        let result = gen_ecc_key_pair(&session, priv_props, pub_props);

        assert_eq!(
            result.err(),
            Some(HsmError::InvalidKeyProps),
            "Public key props without a curve must be rejected for {curve:?}"
        );
    }
}

// Rejects ECC public key props when no usage flags are set.
#[session_test]
fn test_ecc_pub_props_no_usage_flags_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects keygen when private/public curves mismatch.
#[session_test]
fn test_ecc_key_pair_curve_mismatch_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384) // mismatch
        .can_verify(true)
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects keygen when usage flags mismatch (sign without verify).
#[session_test]
fn test_ecc_key_pair_usage_mismatch_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        // missing can_verify
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Generates a derive-only pair and verifies the returned capabilities and sizes.
#[session_test]
fn test_ecc_key_pair_valid_derive_succeeds(session: HsmSession) {
    for curve in [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521] {
        let (priv_builder, pub_builder) = ecc_key_pair_props_builders(curve, true, true);
        let (priv_key, pub_key) = gen_ecc_key_pair(
            &session,
            priv_builder.build().expect("Failed to build private props"),
            pub_builder.build().expect("Failed to build public props"),
        )
        .expect("Derive-only key generation should succeed");

        assert!(priv_key.can_derive());
        assert!(!priv_key.can_sign());
        assert!(!priv_key.can_verify());
        assert!(pub_key.can_derive());
        assert!(!pub_key.can_sign());
        assert!(!pub_key.can_verify());
        assert_eq!(priv_key.bits(), curve.key_size_bits() as u32);
        assert_eq!(pub_key.bits(), curve.key_size_bits() as u32);
        assert_eq!(priv_key.ecc_curve(), Some(curve));
        assert_eq!(pub_key.ecc_curve(), Some(curve));

        HsmKeyManager::delete_key(priv_key).expect("Failed to delete private key");
        HsmKeyManager::delete_key(pub_key).expect("Failed to delete public key");
    }
}

// Rejects ECC private key props when bits conflict with curve.
#[session_test]
fn test_ecc_priv_props_bits_curve_mismatch_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .bits(384) // mismatch
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap fails when public key props are invalid.
#[session_test]
fn test_ecc_unwrap_invalid_pub_props_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private) // invalid
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures keygen works across multiple ECC curves.
#[session_test]
fn test_ecc_key_pair_multiple_curves_succeed(session: HsmSession) {
    for curve in [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521] {
        let priv_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Private)
            .key_kind(HsmKeyKind::Ecc)
            .ecc_curve(curve)
            .can_sign(true)
            .build()
            .unwrap();

        let pub_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Public)
            .key_kind(HsmKeyKind::Ecc)
            .ecc_curve(curve)
            .can_verify(true)
            .build()
            .unwrap();

        gen_ecc_key_pair(&session, priv_props, pub_props)
            .expect("Keygen should succeed for all curves");
    }
}

// Rejects derive private with verify public (invalid usage pairing).
#[session_test]
fn test_ecc_key_pair_derive_private_verify_public_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true) //
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects sign private with derive public.
#[session_test]
fn test_ecc_key_pair_sign_private_derive_public_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true) //
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Accepts ECC private key props when bits match curve.
#[session_test]
fn test_ecc_priv_props_bits_matches_curve_succeeds(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .bits(256) // Bits must match curve size
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    gen_ecc_key_pair(&session, priv_props, pub_props)
        .expect("Matching bits + curve should succeed");
}

// Rejects public key with multiple usage flags.
#[session_test]
fn test_ecc_pub_props_multiple_usage_flags_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .can_derive(true) //
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures private cannot have multiple usage flags even if both are individually valid.
#[session_test]
fn test_ecc_priv_props_multiple_usage_flags_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .can_derive(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects mismatched curve between private and public keys.
#[session_test]
fn test_ecc_unwrap_curve_mismatch_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384) // mismatch
        .can_verify(true)
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects missing public usage flags.
#[session_test]
fn test_ecc_unwrap_usage_mismatch_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build() // missing verify
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Verifies EX rejects inconsistent ECC properties before sending a command,
/// while legacy unwrap retains its invalid-blob error behavior.
#[session_test]
fn test_ecc_unwrap_bits_curve_mismatch_fails(session: HsmSession) {
    let priv_prop = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .bits(384) // mismatch
        .can_sign(true)
        .build()
        .unwrap();

    let pub_prop = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = unwrap_ecc_with_props(&session, priv_prop, pub_prop);

    let expected_error = if crate::utils::session::api_rev_at_least(1, 1) {
        matches!(result, Err(HsmError::InvalidKeyProps))
    } else {
        matches!(result, Err(HsmError::DdiCmdFailure))
    };

    assert!(
        expected_error,
        "Unexpected ECC unwrap error for mismatched bits/curve: {:?}",
        result.as_ref().err()
    );
}

// Ensures unwrap rejects derive private + verify public combination.
#[session_test]
fn test_ecc_unwrap_derive_private_verify_public_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true) //
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects invalid public key kind (non-ECC).
#[session_test]
fn test_ecc_unwrap_invalid_pub_kind_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects invalid private key kind (non-ECC).
#[session_test]
fn test_ecc_unwrap_invalid_priv_kind_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects private key with no usage flags.
#[session_test]
fn test_ecc_unwrap_priv_no_usage_flags_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build() //
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects public key with multiple usage flags.
#[session_test]
fn test_ecc_unwrap_pub_multiple_flags_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .can_derive(true)
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects public key with no usage flags.
#[session_test]
fn test_ecc_unwrap_pub_no_usage_flags_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build() //
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects private key with multiple usage flags.
#[session_test]
fn test_ecc_unwrap_priv_multiple_usage_flags_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .can_derive(true) // both set
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Public bit length is ignored; the returned size must follow the requested curve.
#[session_test]
fn test_ecc_pub_props_bits_normalized_to_curve(session: HsmSession) {
    for (curve, other_curve) in [
        (HsmEccCurve::P256, HsmEccCurve::P384),
        (HsmEccCurve::P384, HsmEccCurve::P521),
        (HsmEccCurve::P521, HsmEccCurve::P256),
    ] {
        for can_derive in [false, true] {
            let (priv_builder, pub_builder) = ecc_key_pair_props_builders(curve, can_derive, true);
            let (priv_key, pub_key) = gen_ecc_key_pair(
                &session,
                priv_builder.build().expect("Failed to build private props"),
                pub_builder
                    .bits(other_curve.key_size_bits() as u32)
                    .build()
                    .expect("Failed to build public props"),
            )
            .expect("Public bit length should be normalized to the curve");

            assert_eq!(priv_key.bits(), curve.key_size_bits() as u32);
            assert_eq!(pub_key.bits(), curve.key_size_bits() as u32);
            assert_eq!(priv_key.ecc_curve(), Some(curve));
            assert_eq!(pub_key.ecc_curve(), Some(curve));

            HsmKeyManager::delete_key(priv_key).expect("Failed to delete private key");
            HsmKeyManager::delete_key(pub_key).expect("Failed to delete public key");
        }
    }
}

#[session_test]
fn test_ecc_key_pair_session_mismatch_fails(session: HsmSession) {
    for is_session in [false, true] {
        let (priv_builder, pub_builder) = ecc_key_pair_props_builders(HsmEccCurve::P256, false, true);
        let priv_props = priv_builder
            .is_session(is_session)
            .build()
            .expect("Failed to build private props");
        let pub_props = pub_builder
            .is_session(!is_session)
            .build()
            .expect("Failed to build public props");
        let result = gen_ecc_key_pair(&session, priv_props, pub_props);

        assert_eq!(
            result.err(),
            Some(HsmError::InvalidKeyProps),
            "Mismatched session flags must be rejected with private session={is_session}"
        );
    }
}

#[session_test]
fn test_ecc_key_pair_explicit_scope_mismatch_fails(session: HsmSession) {
    let scopes = [
        HsmKeyScope::Session,
        HsmKeyScope::Ephemeral,
        HsmKeyScope::Local,
        HsmKeyScope::SecurityDomain,
    ];
    for private_scope in scopes {
        for public_scope in scopes {
            if private_scope == public_scope {
                continue;
            }
            let (priv_builder, pub_builder) = ecc_key_pair_props_builders(HsmEccCurve::P256, false, true);
            let priv_props = priv_builder
                .scope(private_scope)
                .build()
                .expect("Failed to build private props");
            let pub_props = pub_builder
                .scope(public_scope)
                .build()
                .expect("Failed to build public props");
            let result = gen_ecc_key_pair(&session, priv_props, pub_props);

            assert_eq!(
                result.err(),
                Some(HsmError::InvalidKeyProps),
                "Mismatched scopes must be rejected: {private_scope:?}/{public_scope:?}"
            );
        }
    }
}

/// Equivalent explicit and implicit scopes must agree after session-flag normalization.
/// Legacy sessions reject explicit scopes on either half, even when the pair matches.
#[session_test]
fn test_ecc_key_pair_equivalent_scopes(session: HsmSession) {
    for scope in [HsmKeyScope::Session, HsmKeyScope::Local] {
        for (explicit_private, explicit_public) in [(true, false), (false, true), (true, true)] {
            let is_session = scope == HsmKeyScope::Session;
            let (priv_builder, pub_builder) = ecc_key_pair_props_builders(HsmEccCurve::P256, false, true);
            let mut priv_builder = priv_builder.is_session(is_session);
            let mut pub_builder = pub_builder.is_session(is_session);
            if explicit_private {
                priv_builder = priv_builder.is_session(!is_session).scope(scope);
            }
            if explicit_public {
                pub_builder = pub_builder.is_session(!is_session).scope(scope);
            }
            let priv_props = priv_builder.build().expect("Failed to build private props");
            let pub_props = pub_builder.build().expect("Failed to build public props");
            assert_eq!(priv_props.is_session(), is_session);
            assert_eq!(pub_props.is_session(), is_session);

            let result = gen_ecc_key_pair(&session, priv_props, pub_props);
            if crate::utils::session::api_rev_at_least(1, 1) {
                let (priv_key, pub_key) = result.expect("Equivalent scopes should generate a pair");
                assert_eq!(priv_key.is_session(), is_session);
                assert_eq!(pub_key.is_session(), is_session);
                HsmKeyManager::delete_key(priv_key).expect("Failed to delete private key");
                HsmKeyManager::delete_key(pub_key).expect("Failed to delete public key");
            } else {
                assert_eq!(
                    result.err(),
                    Some(HsmError::UnsupportedApiRevision),
                    "Legacy sessions must reject explicit scope on either half"
                );
            }
        }
    }
}

#[session_test]
fn test_ecc_key_labels_preserved(session: HsmSession) {
    for curve in [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521] {
        for can_derive in [false, true] {
            for label in [
                Vec::new(),
                b"ecc-key".to_vec(),
                vec![b'e'; TBOR_KEY_LABEL_MAX_LEN - 1],
                vec![b'e'; TBOR_KEY_LABEL_MAX_LEN],
            ] {
                let (priv_builder, pub_builder) = ecc_key_pair_props_builders(curve, can_derive, true);
                let priv_props = priv_builder
                    .label(&label)
                    .build()
                    .expect("Failed to build private props");
                let pub_props = pub_builder.build().expect("Failed to build public props");
                let (priv_key, pub_key) = gen_ecc_key_pair(&session, priv_props, pub_props)
                    .expect("Key generation should accept labels within the limit");

                assert_eq!(priv_key.label(), label.as_slice());
                assert_eq!(priv_key.bits(), curve.key_size_bits() as u32);
                assert_eq!(pub_key.bits(), curve.key_size_bits() as u32);
                HsmKeyManager::delete_key(priv_key).expect("Failed to delete private key");
                HsmKeyManager::delete_key(pub_key).expect("Failed to delete public key");
            }
        }
    }
}

/// Overflow is rejected by TBOR property validation or the legacy MBOR field conversion.
#[session_test]
fn test_ecc_key_label_too_long_fails(session: HsmSession) {
    let expected_error = if crate::utils::session::api_rev_at_least(1, 1) {
        HsmError::InvalidKeyProps
    } else {
        HsmError::InternalError
    };
    let label = vec![b'e'; TBOR_KEY_LABEL_MAX_LEN + 1];

    for can_derive in [false, true] {
        let (priv_builder, pub_builder) =
            ecc_key_pair_props_builders(HsmEccCurve::P256, can_derive, true);
        let priv_props = priv_builder
            .label(&label)
            .build()
            .expect("Failed to build private props");
        let pub_props = pub_builder.build().expect("Failed to build public props");
        let result = gen_ecc_key_pair(&session, priv_props, pub_props);

        assert_eq!(
            result.err(),
            Some(expected_error),
            "Oversized labels must be rejected with derive={can_derive}"
        );
    }
}

// Ensures unwrap rejects private key props with missing curve.
#[session_test]
fn test_ecc_unwrap_priv_missing_curve_fails(_session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .can_sign(true)
        .build();
    assert!(priv_props.is_err());
}

// Ensures unwrap rejects public key props with missing curve.
#[session_test]
fn test_ecc_unwrap_pub_missing_curve_fails(_session: HsmSession) {
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .can_verify(true)
        .build();

    assert!(pub_props.is_err());
}

// Ensures unwrap rejects sign private + derive public combination.
#[session_test]
fn test_ecc_unwrap_sign_private_derive_public_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false); // sign = true

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true) //  invalid with sign private
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
