// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub(crate) fn ecc_key_pair_props_builders(
    curve: HsmEccCurve,
    can_derive: bool,
    is_session: bool,
) -> (HsmKeyPropsBuilder, HsmKeyPropsBuilder) {
    let priv_builder = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(!can_derive)
        .can_derive(can_derive)
        .is_session(is_session);
    let pub_builder = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(!can_derive)
        .can_derive(can_derive)
        .is_session(is_session);
    (priv_builder, pub_builder)
}

pub(crate) fn gen_ecc_key_pair(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> HsmResult<(HsmEccPrivateKey, HsmEccPublicKey)> {
    let mut algo = HsmEccKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
}

/// Generates an ECC key pair with signing (private) and verification (public) capabilities
pub(crate) fn generate_ecc_key_pair(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let (priv_builder, pub_builder) = ecc_key_pair_props_builders(curve, false, true);
    gen_ecc_key_pair(
        session,
        priv_builder
            .build()
            .expect("Failed to build private key props"),
        pub_builder
            .build()
            .expect("Failed to build public key props"),
    )
    .expect("Failed to generate ECC key pair")
}

/// Computes hash of input data using the specified hash algorithm
pub(crate) fn hash_data(session: &HsmSession, mut hash_algo: HsmHashAlgo, data: &[u8]) -> Vec<u8> {
    HsmHasher::hash_vec(session, &mut hash_algo, data).expect("Failed to hash data")
}

/// Signs a precomputed hash using the given ECC private key
pub(crate) fn sign_hash(priv_key: &HsmEccPrivateKey, hash: &[u8]) -> Vec<u8> {
    let mut sign_algo = HsmEccSignAlgo::default();
    HsmSigner::sign_vec(&mut sign_algo, priv_key, hash).expect("Signature generation failed")
}
