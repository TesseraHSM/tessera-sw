// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end DARC key-transfer flow over the public api surface.
//!
//! Drives the source→target hand-off on a single partition (acting as both
//! endpoints) through [`HsmSession`]'s DARC methods: mint a Transfer
//! Masking Key (TMK), mint source and target key-exchange keys, seal the
//! TMK to the target (`export`), and re-open it (`import`) — proving the
//! TMK survives the export→import round-trip. The key wrap/unwrap surface
//! is exercised as a full happy path — mint an ECC signing key, wrap it
//! under the TMK ([`HsmEccKeyDarcKeyWrapAlgo`]), unwrap it back
//! ([`HsmEccKeyDarcKeyUnwrapAlgo`]), then sign with the recovered key and
//! verify against the original public key.

use tsra_api::*;
use tsra_ddi_tbor_types::KEY_SCOPE_LOCAL;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::DarcReady;
use crate::utils::sd_provision::RAW_PUB_LEN;
use crate::utils::sd_provision::darc_sd_initialized_session;
use crate::utils::sd_provision::make_chain;

/// P-384 coordinate width; the DARC key-exchange keys are always P-384.
const COORD_LEN: usize = 48;

/// A minted DARC key-exchange key: its masked blob (the HPKE identity the
/// device unmasks on export/import) and its public key as raw big-endian
/// `X ‖ Y` — the certificate-leaf format the cert chains carry.
struct KexKey {
    masked: [u8; MASKED_KEX_KEY_LEN],
    pub_raw: [u8; RAW_PUB_LEN],
}

/// Mint a `DarcKexKeyGen` key and convert its device little-endian
/// `x ‖ y` public key into the raw big-endian `X ‖ Y` a certificate leaf
/// carries (reversing each P-384 coordinate).
fn mint_kex(ready: &DarcReady) -> KexKey {
    let (masked, pub_le) = ready
        .session
        .darc_kex_key_gen(KEY_SCOPE_LOCAL)
        .expect("darc_kex_key_gen");
    let mut pub_raw = [0u8; RAW_PUB_LEN];
    pub_raw.copy_from_slice(&pub_le);
    pub_raw[..COORD_LEN].reverse();
    pub_raw[COORD_LEN..].reverse();
    KexKey { masked, pub_raw }
}

/// Full DARC TMK transfer: create a TMK on the source, mint the source and
/// target key-exchange identities, seal the TMK to the target
/// (DATA-anchored target chain), then re-open it on the target
/// (POTA-anchored sender chain) — the export→import hand-off that ships a
/// TMK from one endpoint to another.
#[test]
fn darc_transfer_tmk_export_import_roundtrip() {
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    // (1) Originate a TMK (masked under the SDMK).
    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    assert_eq!(masked_tmk.len(), MASKED_TMK_LEN);

    // (2) Mint the source and target key-exchange identities.
    let source_kex = mint_kex(&ready);
    let target_kex = mint_kex(&ready);

    // (3) Seal the TMK to the target, anchoring the target chain to the
    // policy DATA CA.
    let target_chain = make_chain(&ready.data, &target_kex.pub_raw);
    let sealed_tmk = session
        .darc_tmk_export(
            &source_kex.masked,
            &masked_tmk,
            &ready.policy,
            &target_chain.certs(),
        )
        .expect("darc_tmk_export");
    assert_eq!(sealed_tmk.len(), SEALED_TMK_LEN);
    assert!(
        sealed_tmk.iter().any(|&b| b != 0),
        "sealed TMK must not be all-zero",
    );

    // (4) Re-open the sealed TMK on the target: the target key is the
    // receiver, the source key the sender (attested by a POTA-anchored
    // chain). A non-zero masked TMK proves the hand-off succeeded.
    let source_chain = make_chain(&ready.pota, &source_kex.pub_raw);
    let imported_tmk = session
        .darc_tmk_import(
            &target_kex.masked,
            &ready.policy,
            &sealed_tmk,
            &source_chain.certs(),
        )
        .expect("darc_tmk_import");
    assert_eq!(imported_tmk.len(), MASKED_TMK_LEN);
    assert!(
        imported_tmk.iter().any(|&b| b != 0),
        "re-imported masked TMK must not be all-zero",
    );
}

/// The key-exchange and TMK generation primitives return well-formed,
/// non-zero envelopes of the pinned wire lengths, and each mint is fresh.
#[test]
fn darc_kex_and_tmk_gen_smoke() {
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    let (masked_kex, pub_kex) = session
        .darc_kex_key_gen(KEY_SCOPE_LOCAL)
        .expect("darc_kex_key_gen");
    assert_eq!(masked_kex.len(), MASKED_KEX_KEY_LEN);
    assert_eq!(pub_kex.len(), KEX_PUB_KEY_LEN);
    assert!(
        masked_kex.iter().any(|&b| b != 0),
        "masked KEX key must not be all-zero",
    );
    assert!(
        pub_kex.iter().any(|&b| b != 0),
        "KEX public key must not be all-zero",
    );

    // Each mint draws a fresh key, so two masked envelopes differ.
    let (masked_kex2, _) = session
        .darc_kex_key_gen(KEY_SCOPE_LOCAL)
        .expect("second darc_kex_key_gen");
    assert_ne!(
        masked_kex, masked_kex2,
        "each DarcKexKeyGen must mint a fresh key",
    );

    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    assert_eq!(masked_tmk.len(), MASKED_TMK_LEN);
    assert!(
        masked_tmk.iter().any(|&b| b != 0),
        "masked TMK must not be all-zero",
    );
}

/// The public wrap/unwrap surface performs a full DARC key transfer: an
/// ECC signing key wrapped under a TMK unwraps to a usable key on the same
/// partition (acting as both endpoints), and a signature from the recovered
/// key verifies against the original public key.
#[test]
fn darc_key_wrap_unwrap_sign_round_trip() {
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    let tmk = HsmDarcTmk::new(session.clone(), masked_tmk);

    // Mint a P-256 signing key on the source to transfer under the TMK.
    let (source_key, source_pub) = HsmKeyManager::generate_key_pair(
        session,
        &mut HsmEccKeyGenAlgo {},
        p256_sign_priv_props(),
        p256_verify_pub_props(),
    )
    .expect("generate ECC signing key");

    // Wrap it under the TMK, then unwrap it back under the same TMK.
    let wrapped = HsmKeyManager::wrap_key(&mut HsmEccKeyDarcKeyWrapAlgo::new(), &tmk, &source_key)
        .expect("darc wrap_key");
    assert!(!wrapped.is_empty(), "wrapped key must not be empty");

    let (recovered_key, _recovered_pub) = HsmKeyManager::unwrap_key_pair(
        &mut HsmEccKeyDarcKeyUnwrapAlgo::new(),
        &tmk,
        &wrapped,
        p256_sign_priv_props(),
        p256_verify_pub_props(),
    )
    .expect("darc unwrap_key_pair");

    // Sign with the recovered key and verify against the original public key.
    let digest = [0x11u8; 32];
    let signature = HsmSigner::sign_vec(&mut HsmEccSignAlgo::default(), &recovered_key, &digest)
        .expect("sign with recovered key");
    let verified = HsmVerifier::verify(
        &mut HsmEccSignAlgo::default(),
        &source_pub,
        &digest,
        &signature,
    )
    .expect("verify signature");
    assert!(
        verified,
        "signature from the recovered key must verify against the original public key",
    );
}

/// A bogus wrapped envelope fails the AES-KWP integrity check under a
/// (valid) TMK, proving the api marshals the payload through to the
/// on-device crypto rather than accepting it blindly.
#[test]
fn darc_key_unwrap_rejects_bogus_envelope() {
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    let tmk = HsmDarcTmk::new(session.clone(), masked_tmk);

    let bogus_wrapped = vec![0u8; 40];
    let unwrap = HsmKeyManager::unwrap_key_pair(
        &mut HsmEccKeyDarcKeyUnwrapAlgo::new(),
        &tmk,
        &bogus_wrapped,
        p256_sign_priv_props(),
        p256_verify_pub_props(),
    );
    assert!(
        unwrap.is_err(),
        "unwrapping a bogus envelope must be rejected",
    );
}

/// P-256 signing private-key properties.
fn p256_sign_priv_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("build P-256 signing private props")
}

/// P-256 verifying public-key properties.
fn p256_verify_pub_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("build P-256 verifying public props")
}

/// A target certificate chain that does not chain up to the policy DATA
/// anchor is rejected: the on-device anchor check fails after the policy
/// hash verifies, surfacing as `InvalidArgument`.
#[test]
fn darc_tmk_export_rejects_unanchored_target_chain() {
    let _guard = PARTITION_LOCK.lock();
    let ready = darc_sd_initialized_session();
    let session = &ready.session;

    let masked_tmk = session.darc_tmk_gen().expect("darc_tmk_gen");
    let source_kex = mint_kex(&ready);
    let target_kex = mint_kex(&ready);

    // Anchor the target chain to an unrelated CA while the bound policy's
    // DATA anchor is unchanged, so the anchor check fails.
    let rogue_ca = CaKey::generate();
    let rogue_chain = make_chain(&rogue_ca, &target_kex.pub_raw);

    let result = session.darc_tmk_export(
        &source_kex.masked,
        &masked_tmk,
        &ready.policy,
        &rogue_chain.certs(),
    );
    assert!(
        matches!(result, Err(HsmError::InvalidArgument)),
        "an unanchored target chain must be rejected with InvalidArgument, got {result:?}",
    );
}
