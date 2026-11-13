// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_api::*;
use tsra_api_tests_macro::*;
use tsra_crypto as crypto;
use tsra_crypto::ExportableKey;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::testvectors::rsa::RSA_PSS_TEST_VECTORS;

use super::*;

// ================================
// Helper functions
// ================================

/// Helper to generate an RSA unwrapping key pair with given key properties.
fn gen_rsa_unwrapping_key_pair(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(HsmRsaPrivateKey, HsmRsaPublicKey), HsmError> {
    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
}

/// Helper to invoke RSA unwrap using provided key properties and return the result.
fn unwrap_rsa_with_props(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(HsmRsaPrivateKey, HsmRsaPublicKey), HsmError> {
    let fixture = RsaImportFixture::new(session, &rsa_fixture_der(2048));
    let (private_props, public_props) = rsa_import_builders(2048, HsmKeyKind::Rsa, false, false);
    let control = fixture
        .import(
            private_props.build().unwrap(),
            public_props.build().unwrap(),
        )
        .expect("valid RSA import control must succeed");
    assert_rsa_import_properties(&control, 2048, HsmKeyKind::Rsa, false, false);
    drop(control);

    fixture.import(priv_key_props, pub_key_props)
}

fn rsa_import_builders(
    bits: u32,
    kind: HsmKeyKind,
    signing: bool,
    session_key: bool,
) -> (HsmKeyPropsBuilder, HsmKeyPropsBuilder) {
    (
        HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Private)
            .key_kind(kind)
            .bits(bits)
            .can_sign(signing)
            .can_decrypt(!signing)
            .is_session(session_key),
        HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Public)
            .key_kind(HsmKeyKind::Rsa)
            .bits(bits)
            .can_verify(signing)
            .can_encrypt(!signing)
            .is_session(session_key),
    )
}

struct RsaImportFixture {
    unwrapping_key: HsmRsaPrivateKey,
    wrapped_key: Vec<u8>,
}

fn rsa_fixture_der(bits: u32) -> Vec<u8> {
    if let Some(vector) = RSA_PSS_TEST_VECTORS
        .iter()
        .find(|vector| vector.s.len() * 8 == bits as usize)
    {
        return vector.private_der.to_vec();
    }
    crypto::RsaPrivateKey::generate(bits as usize / 8)
        .expect("generate supported RSA fixture")
        .to_vec()
        .expect("export RSA fixture")
}

impl RsaImportFixture {
    fn new(session: &HsmSession, der: &[u8]) -> Self {
        let (unwrapping_key, wrapping_key) = get_rsa_unwrapping_key_pair(session);
        let mut wrap = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
        let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap, &wrapping_key, der)
            .expect("wrap valid RSA fixture");
        Self {
            unwrapping_key,
            wrapped_key,
        }
    }

    fn import(
        &self,
        private_props: HsmKeyProps,
        public_props: HsmKeyProps,
    ) -> HsmResult<(HsmRsaPrivateKey, HsmRsaPublicKey)> {
        let mut unwrap = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
        HsmKeyManager::unwrap_key_pair(
            &mut unwrap,
            &self.unwrapping_key,
            &self.wrapped_key,
            private_props,
            public_props,
        )
    }
}

fn assert_rsa_import_properties(
    pair: &(HsmRsaPrivateKey, HsmRsaPublicKey),
    bits: u32,
    kind: HsmKeyKind,
    signing: bool,
    session_key: bool,
) {
    let (private_key, public_key) = pair;
    assert_eq!(private_key.class(), HsmKeyClass::Private);
    assert_eq!(private_key.kind(), kind);
    assert_eq!(private_key.bits(), bits);
    assert_eq!(private_key.ecc_curve(), None);
    assert_eq!(private_key.is_session(), session_key);
    assert!(!private_key.is_local());
    assert!(private_key.is_sensitive());
    assert!(private_key.is_extractable());
    assert_eq!(private_key.can_sign(), signing);
    assert_eq!(private_key.can_decrypt(), !signing);
    assert!(!private_key.can_encrypt());
    assert!(!private_key.can_verify());
    assert!(!private_key.can_derive());
    assert!(!private_key.can_wrap());
    assert!(!private_key.can_unwrap());
    assert_eq!(public_key.class(), HsmKeyClass::Public);
    assert_eq!(public_key.kind(), HsmKeyKind::Rsa);
    assert_eq!(public_key.bits(), bits);
    assert_eq!(public_key.ecc_curve(), None);
    assert_eq!(public_key.is_session(), session_key);
    assert!(!public_key.is_local());
    assert!(!public_key.is_sensitive());
    assert!(public_key.is_extractable());
    assert_eq!(public_key.can_verify(), signing);
    assert_eq!(public_key.can_encrypt(), !signing);
    assert!(!public_key.can_sign());
    assert!(!public_key.can_decrypt());
    assert!(!public_key.can_derive());
    assert!(!public_key.can_wrap());
    assert!(!public_key.can_unwrap());
}

macro_rules! rsa_size_tests {
    ($name:ident, $run:ident $(, $argument:expr)*) => {
        mod $name {
            use super::*;

            #[session_test]
            fn rsa2048(session: HsmSession) {
                $run(&session, 2048 $(, $argument)*);
            }

            #[session_test]
            fn rsa3072(session: HsmSession) {
                $run(&session, 3072 $(, $argument)*);
            }

            #[session_test]
            fn rsa4096(session: HsmSession) {
                $run(&session, 4096 $(, $argument)*);
            }
        }
    };
}

fn run_rsa_import_properties(session: &HsmSession, bits: u32) {
    const DOCUMENTED_LABEL_CAPACITY: usize = 128;
    let der = rsa_fixture_der(bits);
    for kind in [HsmKeyKind::Rsa, HsmKeyKind::RsaCrt] {
        for signing in [true, false] {
            for session_key in [true, false] {
                let fixture = RsaImportFixture::new(session, &der);
                for label in [
                    Vec::new(),
                    b"rsa-attributes".to_vec(),
                    vec![b'x'; DOCUMENTED_LABEL_CAPACITY - 1],
                ] {
                    let (private_props, public_props) =
                        rsa_import_builders(bits, kind, signing, session_key);
                    let pair = fixture
                        .import(
                            private_props.label(&label).build().unwrap(),
                            public_props.label(&label).build().unwrap(),
                        )
                        .expect("valid RSA import properties must succeed");
                    assert_rsa_import_properties(&pair, bits, kind, signing, session_key);
                    assert_eq!(pair.0.label().as_slice(), label);
                    assert_eq!(pair.1.label().as_slice(), label);
                }
            }
        }
    }
}

rsa_size_tests!(test_rsa_import_properties, run_rsa_import_properties);

fn run_rsa_import_flag(
    session: &HsmSession,
    bits: u32,
    private_half: bool,
    set_flag: impl Fn(HsmKeyPropsBuilder, bool) -> HsmKeyPropsBuilder,
) {
    let der = rsa_fixture_der(bits);
    for kind in [HsmKeyKind::Rsa, HsmKeyKind::RsaCrt] {
        for signing in [true, false] {
            for session_key in [true, false] {
                let fixture = RsaImportFixture::new(session, &der);
                let properties = |enabled| {
                    let (private_props, public_props) =
                        rsa_import_builders(bits, kind, signing, session_key);
                    if private_half {
                        (
                            set_flag(private_props, enabled).build().unwrap(),
                            public_props.build().unwrap(),
                        )
                    } else {
                        (
                            private_props.build().unwrap(),
                            set_flag(public_props, enabled).build().unwrap(),
                        )
                    }
                };
                let (private_props, public_props) = properties(false);
                let control = fixture
                    .import(private_props, public_props)
                    .expect("RSA control with the selected flag disabled must succeed");
                assert_rsa_import_properties(&control, bits, kind, signing, session_key);
                drop(control);
                let (private_props, public_props) = properties(true);
                let result = fixture.import(private_props, public_props);
                assert_eq!(
                    result.err(),
                    Some(HsmError::InvalidKeyProps),
                    "{kind:?}/{bits}, signing={signing}, session={session_key}, private={private_half}"
                );
            }
        }
    }
}

rsa_size_tests!(
    test_rsa_private_encrypt_rejected,
    run_rsa_import_flag,
    true,
    |props, enabled| props.can_encrypt(enabled)
);
rsa_size_tests!(
    test_rsa_private_verify_rejected,
    run_rsa_import_flag,
    true,
    |props, enabled| props.can_verify(enabled)
);
rsa_size_tests!(
    test_rsa_private_derive_rejected,
    run_rsa_import_flag,
    true,
    |props, enabled| props.can_derive(enabled)
);
rsa_size_tests!(
    test_rsa_private_wrap_rejected,
    run_rsa_import_flag,
    true,
    |props, enabled| props.can_wrap(enabled)
);
rsa_size_tests!(
    test_rsa_private_unwrap_extra_rejected,
    run_rsa_import_flag,
    true,
    |props, enabled| props.can_unwrap(enabled)
);
rsa_size_tests!(
    test_rsa_public_sign_rejected,
    run_rsa_import_flag,
    false,
    |props, enabled| props.can_sign(enabled)
);
rsa_size_tests!(
    test_rsa_public_decrypt_rejected,
    run_rsa_import_flag,
    false,
    |props, enabled| props.can_decrypt(enabled)
);
rsa_size_tests!(
    test_rsa_public_derive_rejected,
    run_rsa_import_flag,
    false,
    |props, enabled| props.can_derive(enabled)
);
rsa_size_tests!(
    test_rsa_public_unwrap_rejected,
    run_rsa_import_flag,
    false,
    |props, enabled| props.can_unwrap(enabled)
);
rsa_size_tests!(
    test_rsa_public_wrap_extra_rejected,
    run_rsa_import_flag,
    false,
    |props, enabled| props.can_wrap(enabled)
);

#[derive(Clone, Copy, Debug)]
enum RsaPairProblem {
    PrivateUsageMissing,
    PublicUsageMissing,
    PrivateUsageConflict,
    PublicUsageConflict,
    UsageMismatch,
    SessionMismatch,
    PrivateClass,
    PublicClass,
    PrivateKind,
    PublicKind,
    PrivateCurve,
    PublicCurve,
    BitsMismatch,
}

fn run_rsa_import_problem(session: &HsmSession, bits: u32, problem: RsaPairProblem) {
    let der = rsa_fixture_der(bits);
    for kind in [HsmKeyKind::Rsa, HsmKeyKind::RsaCrt] {
        for signing in [true, false] {
            for session_key in [true, false] {
                let fixture = RsaImportFixture::new(session, &der);
                let (private_props, public_props) =
                    rsa_import_builders(bits, kind, signing, session_key);
                let control = fixture
                    .import(
                        private_props.build().unwrap(),
                        public_props.build().unwrap(),
                    )
                    .expect("RSA pair control must import successfully");
                assert_rsa_import_properties(&control, bits, kind, signing, session_key);
                drop(control);
                let (mut private_props, mut public_props) =
                    rsa_import_builders(bits, kind, signing, session_key);
                match problem {
                    RsaPairProblem::PrivateUsageMissing => {
                        private_props = private_props.can_sign(false).can_decrypt(false)
                    }
                    RsaPairProblem::PublicUsageMissing => {
                        public_props = public_props.can_verify(false).can_encrypt(false)
                    }
                    RsaPairProblem::PrivateUsageConflict => {
                        private_props = private_props.can_sign(true).can_decrypt(true)
                    }
                    RsaPairProblem::PublicUsageConflict => {
                        public_props = public_props.can_verify(true).can_encrypt(true)
                    }
                    RsaPairProblem::UsageMismatch => {
                        public_props = public_props.can_verify(!signing).can_encrypt(signing)
                    }
                    RsaPairProblem::SessionMismatch => {
                        public_props = public_props.is_session(!session_key)
                    }
                    RsaPairProblem::PrivateClass => {
                        private_props = private_props.class(HsmKeyClass::Public)
                    }
                    RsaPairProblem::PublicClass => {
                        public_props = public_props.class(HsmKeyClass::Private)
                    }
                    RsaPairProblem::PrivateKind => {
                        private_props = private_props.key_kind(HsmKeyKind::Ecc)
                    }
                    RsaPairProblem::PublicKind => {
                        public_props = public_props.key_kind(HsmKeyKind::RsaCrt)
                    }
                    RsaPairProblem::PrivateCurve => {
                        private_props = private_props.ecc_curve(HsmEccCurve::P256)
                    }
                    RsaPairProblem::PublicCurve => {
                        public_props = public_props.ecc_curve(HsmEccCurve::P256)
                    }
                    RsaPairProblem::BitsMismatch => {
                        public_props = public_props.bits(if bits == 2048 { 3072 } else { 2048 })
                    }
                }
                let result = fixture.import(
                    private_props.build().unwrap(),
                    public_props.build().unwrap(),
                );
                assert_eq!(
                    result.err(),
                    Some(HsmError::InvalidKeyProps),
                    "{problem:?}: {kind:?}/{bits}, signing={signing}, session={session_key}"
                );
            }
        }
    }
}

rsa_size_tests!(
    test_rsa_private_usage_missing,
    run_rsa_import_problem,
    RsaPairProblem::PrivateUsageMissing
);
rsa_size_tests!(
    test_rsa_public_usage_missing,
    run_rsa_import_problem,
    RsaPairProblem::PublicUsageMissing
);
rsa_size_tests!(
    test_rsa_private_usage_conflict,
    run_rsa_import_problem,
    RsaPairProblem::PrivateUsageConflict
);
rsa_size_tests!(
    test_rsa_public_usage_conflict,
    run_rsa_import_problem,
    RsaPairProblem::PublicUsageConflict
);
rsa_size_tests!(
    test_rsa_import_usage_mismatch,
    run_rsa_import_problem,
    RsaPairProblem::UsageMismatch
);
rsa_size_tests!(
    test_rsa_import_session_mismatch,
    run_rsa_import_problem,
    RsaPairProblem::SessionMismatch
);
rsa_size_tests!(
    test_rsa_import_private_class,
    run_rsa_import_problem,
    RsaPairProblem::PrivateClass
);
rsa_size_tests!(
    test_rsa_import_public_class,
    run_rsa_import_problem,
    RsaPairProblem::PublicClass
);
rsa_size_tests!(
    test_rsa_import_private_kind,
    run_rsa_import_problem,
    RsaPairProblem::PrivateKind
);
rsa_size_tests!(
    test_rsa_import_public_kind,
    run_rsa_import_problem,
    RsaPairProblem::PublicKind
);
rsa_size_tests!(
    test_rsa_import_private_curve,
    run_rsa_import_problem,
    RsaPairProblem::PrivateCurve
);
rsa_size_tests!(
    test_rsa_import_public_curve,
    run_rsa_import_problem,
    RsaPairProblem::PublicCurve
);
rsa_size_tests!(
    test_rsa_import_bits_mismatch,
    run_rsa_import_problem,
    RsaPairProblem::BitsMismatch
);

/// Helper to assert RSA keygen fails for unsupported bits.
fn rsa_keygen_should_fail(session: &HsmSession, bits: u32) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Helper to run RSA keygen and assert expected outcome.
fn rsa_keygen_expect(session: &HsmSession, bits: u32, should_succeed: bool) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(session, priv_key_props, pub_key_props);

    if should_succeed {
        if let Err(e) = result {
            panic!("RSA {}-bit expected success but got {:?}", bits, e);
        }
    } else {
        match result {
            Ok(_) => panic!("RSA {}-bit expected failure but got success", bits),
            Err(e) => assert!(
                matches!(e, HsmError::InvalidKeyProps),
                "RSA {}-bit expected InvalidKeyProps but got {:?}",
                bits,
                e
            ),
        }
    }
}

// ============================================================
// test case section
// ============================================================

// Generates a valid RSA unwrapping key pair and expects keygen to succeed.
#[session_test]
fn test_rsa_unwrapping_key_pair_valid_props_succeeds(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let (_priv_key, _pub_key) =
        gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props)
            .expect("RSA unwrapping keygen should succeed");
}

// Rejects RSA unwrapping keygen when private key class is not Private.
#[session_test]
fn test_rsa_unwrapping_keygen_invalid_priv_class_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrapping keygen when public key class is not Public.
#[session_test]
fn test_rsa_unwrapping_keygen_invalid_pub_class_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrapping keygen when key kind is not RSA.
#[session_test]
fn test_rsa_unwrapping_keygen_invalid_kind_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrapping keygen when props include an ECC curve.
#[session_test]
fn test_rsa_unwrapping_keygen_ecc_curve_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .ecc_curve(HsmEccCurve::P256)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA private key props when multiple usage flags are set.
#[session_test]
fn test_rsa_priv_props_multiple_usage_flags_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when public key props include an unsupported usage flag.
#[session_test]
fn test_rsa_pub_props_unsupported_usage_flag_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .expect("Failed to build public key props");

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures valid RSA properties import real wrapped key material successfully.
#[session_test]
fn test_rsa_unwrap_valid_props_succeeds(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    let (private_key, public_key) = result.expect("valid RSA properties must import successfully");
    assert!(private_key.can_decrypt());
    assert!(public_key.can_encrypt());
}

// Rejects RSA keygen when private and public key sizes mismatch.
#[session_test]
fn test_rsa_keygen_mismatched_bits_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(3072)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when private/public key kinds mismatch.
#[session_test]
fn test_rsa_keygen_mismatched_key_kind_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects RSA unwrap when private key has no usage flag.
#[session_test]
fn test_rsa_unwrap_priv_missing_usage_flag_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects RSA unwrap when public key has no usage flag.
#[session_test]
fn test_rsa_unwrap_pub_missing_usage_flag_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when private key has wrong usage flag.
#[session_test]
fn test_rsa_priv_wrong_usage_flag_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_sign(true) // wrong usage
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when public key has wrong usage flag.
#[session_test]
fn test_rsa_pub_wrong_usage_flag_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_verify(true) // wrong usage
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when key size is zero.
#[session_test]
fn test_rsa_keygen_zero_bits_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(0)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(0)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when private key props are missing key kind.
#[session_test]
fn test_rsa_keygen_missing_key_kind_fails(_session: HsmSession) {
    let result = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .bits(2048)
        .can_unwrap(true)
        .build();

    assert!(result.is_err());
}

// Rejects RSA key props when bits are missing.
#[session_test]
fn test_rsa_keygen_missing_bits_fails(_session: HsmSession) {
    let result = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .can_unwrap(true)
        .build();

    assert!(result.is_err());
}

// Rejects RSA key props when class is missing.
#[session_test]
fn test_rsa_keygen_missing_class_fails(_session: HsmSession) {
    let result = HsmKeyPropsBuilder::default()
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build();

    assert!(result.is_err());
}

// RSA keygen rejects unsupported 1024-bit keys.
#[session_test]
fn test_rsa_keygen_1024_fails(session: HsmSession) {
    rsa_keygen_should_fail(&session, 1024);
}

// RSA keygen rejects unsupported 3072-bit keys.
#[session_test]
fn test_rsa_keygen_3072_fails(session: HsmSession) {
    rsa_keygen_should_fail(&session, 3072);
}

// RSA keygen rejects unsupported 4096-bit keys.
#[session_test]
fn test_rsa_keygen_4096_fails(session: HsmSession) {
    rsa_keygen_should_fail(&session, 4096);
}

// Generates a valid 2048-bit RSA key pair and expects success.
#[session_test]
fn test_rsa_keygen_2048_succeeds(session: HsmSession) {
    rsa_keygen_expect(&session, 2048, true);
}

// Rejects RSA keygen when bits are just below supported boundary.
#[session_test]
fn test_rsa_keygen_2047_fails(session: HsmSession) {
    rsa_keygen_should_fail(&session, 2047);
}

// Rejects RSA keygen when bits are just above supported boundary.
#[session_test]
fn test_rsa_keygen_2049_fails(session: HsmSession) {
    rsa_keygen_should_fail(&session, 2049);
}

// RSA keygen rejects sign/verify usage for unwrapping algo.
#[session_test]
fn test_rsa_keygen_sign_verify_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_verify(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// RSA rejects ECC curve in props.
#[session_test]
fn test_rsa_with_ecc_curve_in_pub_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .ecc_curve(HsmEccCurve::P256) // invalid
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when private key has both wrap and unwrap usage.
#[session_test]
fn test_rsa_priv_wrap_and_unwrap_conflict_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when both private and public keys lack usage flags.
#[session_test]
fn test_rsa_both_missing_usage_flags_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA key props when ECC curve is provided on both keys.
#[session_test]
fn test_rsa_both_with_ecc_curve_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .ecc_curve(HsmEccCurve::P256)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .ecc_curve(HsmEccCurve::P256)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when private/public classes are swapped.
#[session_test]
fn test_rsa_keygen_swapped_classes_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public) // swapped
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private) // swapped
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when key kind is AES.
#[session_test]
fn test_rsa_keygen_with_aes_key_kind_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Aes) // invalid
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Aes) // invalid
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when private/public key kinds are AES/RSA mixed.
#[session_test]
fn test_rsa_keygen_mixed_aes_rsa_kind_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Aes)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when public key has multiple usage flags.
#[session_test]
fn test_rsa_pub_multiple_usage_flags_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .can_wrap(true) // multiple usage
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when public key class is not Public.
#[session_test]
fn test_rsa_unwrap_invalid_pub_class_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private) // invalid
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects RSA unwrap when usage pair is logically incompatible.
#[session_test]
fn test_rsa_usage_pair_mismatch_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true) // wrong pairing
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects unwrap when private/public bits mismatch.
#[session_test]
fn test_rsa_unwrap_mismatched_bits_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(4096)
        .can_encrypt(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
/// Ensures exactly one usage flag is required.
#[session_test]
fn test_rsa_exactly_one_usage_required(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .can_decrypt(true) // extra
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects RSA unwrap when private key has can_wrap only.
#[session_test]
fn test_rsa_priv_can_wrap_only_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true) // invalid
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects RSA unwrap when public key has can_unwrap usage.
#[session_test]
fn test_rsa_pub_can_unwrap_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true) // invalid
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
