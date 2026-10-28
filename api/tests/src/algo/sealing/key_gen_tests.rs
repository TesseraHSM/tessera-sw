// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the security-domain sealing-key generation API
//! ([`HsmSealingKeyGenAlgo`] via [`HsmKeyManager::generate_key`]) against
//! the emulator or hardware backend.
//!
//! Property-validation guards run before the device round-trip, so they are
//! deterministic. Round-trip tests finalize the partition, then generate a
//! sealing key and validate the masked blob and public key. SecurityDomain
//! coverage additionally provisions the SD before generation and attestation.

use tsra_api::*;
use tsra_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use tsra_ddi_tbor_types::MASKED_SEALING_KEY_LEN;

use crate::utils::partition_ex_helpers::*;
use crate::utils::sd_provision;

/// Well-formed sealing key props: a `Sealing`-kind P-384 secret key
/// permitted for derivation only, matching the wire contract.
fn sealing_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .build()
        .expect("build sealing props")
}

/// A `Sealing` key that is not P-384 sized is rejected up front, before
/// any device round-trip: `SdSealingKeyGen` always produces a 384-bit
/// scalar.
#[test]
fn sealing_key_gen_rejects_wrong_bits() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(256)
        .can_derive(true)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// A `Sealing` key without derive usage is rejected: derivation is the
/// only permitted usage for a sealing key.
#[test]
fn sealing_key_gen_rejects_missing_derive() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// A non-`Sealing` key kind is rejected, even with an otherwise valid
/// secret derive key.
#[test]
fn sealing_key_gen_rejects_wrong_kind() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_derive(true)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// A `Sealing` derive key that is not a `Secret` is rejected.
#[test]
fn sealing_key_gen_rejects_wrong_class() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// Derivation is the only permitted usage; an additional capability (here
/// `sign`) fails the supported-flags check.
#[test]
fn sealing_key_gen_rejects_extra_capability() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .can_sign(true)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// Valid props pass the host-side guards and reach the device, so the call
/// is never rejected with [`HsmError::InvalidKeyProps`] /
/// [`HsmError::InvalidArgument`] (it may still fail on-device on an
/// unprovisioned partition).
#[test]
fn sealing_key_gen_valid_props_pass_host_guards() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, sealing_props());

    // `HsmSealingKey` is not `Debug`, so inspect only the error variant.
    assert!(
        !matches!(
            res.as_ref().err(),
            Some(HsmError::InvalidKeyProps) | Some(HsmError::InvalidArgument)
        ),
        "valid sealing props must pass the host guards, got error: {:?}",
        res.err(),
    );
}

/// Full round trip: on a fully provisioned partition, generating a sealing
/// key succeeds and yields a usable key — the pinned 276-byte masked blob
/// plus a P-384 public key — with the expected typed properties.
#[test]
fn sealing_key_gen_roundtrip_generates_usable_sealing_key() {
    let _guard = PARTITION_LOCK.lock();
    let session = crate::utils::sd_provision::finalized_co_session();

    let mut algo = HsmSealingKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut algo, sealing_props())
        .expect("generate sealing key on a provisioned partition");

    // Typed properties describe a P-384 `Sealing` secret derive key.
    assert_eq!(key.kind(), HsmKeyKind::Sealing);
    assert_eq!(key.class(), HsmKeyClass::Secret);
    assert_eq!(key.bits(), 384);
    assert!(key.can_derive());

    // The masked private-key blob is the pinned wire length and non-zero.
    let masked = key.masked_key_vec().expect("masked key");
    assert_eq!(masked.len(), MASKED_SEALING_KEY_LEN);
    assert!(
        masked.iter().any(|&b| b != 0),
        "masked key must not be all-zero"
    );

    // The public key is retrievable as DER SubjectPublicKeyInfo.
    let pub_der = key.pub_key_der_vec().expect("public key der");
    assert!(!pub_der.is_empty());
}

/// Explicit deletion exercises the `Unpinned` no-op instead of relying on
/// `Drop`, which intentionally ignores deletion errors.
#[test]
fn sealing_key_explicit_delete_succeeds() {
    let _guard = PARTITION_LOCK.lock();
    let session = crate::utils::sd_provision::finalized_co_session();

    let mut algo = HsmSealingKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut algo, sealing_props())
        .expect("generate sealing key on a provisioned partition");

    HsmKeyManager::delete_key(key).expect("delete unpinned sealing key");
}

/// Each `SdSealingKeyGen` call produces fresh key material: two keys
/// generated on the same provisioned session have distinct masked blobs
/// and distinct public keys.
#[test]
fn sealing_key_gen_roundtrip_yields_distinct_keys() {
    let _guard = PARTITION_LOCK.lock();
    let session = crate::utils::sd_provision::finalized_co_session();

    let generate = || {
        let mut algo = HsmSealingKeyGenAlgo::default();
        let key = HsmKeyManager::generate_key(&session, &mut algo, sealing_props())
            .expect("generate sealing key");
        let masked = key.masked_key_vec().expect("masked key");
        let pub_der = key.pub_key_der_vec().expect("public key der");
        (masked, pub_der)
    };

    let (masked1, pub1) = generate();
    let (masked2, pub2) = generate();

    assert_eq!(masked1.len(), MASKED_SEALING_KEY_LEN);
    assert_eq!(masked2.len(), MASKED_SEALING_KEY_LEN);
    assert!(!pub1.is_empty());
    assert!(!pub2.is_empty());
    // Fresh randomness → distinct masked blobs and public keys.
    assert_ne!(masked1, masked2);
    assert_ne!(pub1, pub2);
}

/// Session scope is rejected by the host before any device round-trip.
#[test]
fn sealing_key_gen_rejects_session_scope() {
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .scope(HsmKeyScope::Session)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props);
    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// An explicit `Local` scope round-trips: the device masks under the
/// partition-local masking key and stamps the requested scope into the
/// blob, so generation succeeds on a provisioned partition.
#[test]
fn sealing_key_gen_roundtrip_honors_explicit_local_scope() {
    let _guard = PARTITION_LOCK.lock();
    let session = crate::utils::sd_provision::finalized_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .scope(HsmKeyScope::Local)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut algo, props)
        .expect("generate Local-scoped sealing key on a provisioned partition");

    let masked = key.masked_key_vec().expect("masked key");
    assert_eq!(masked.len(), MASKED_SEALING_KEY_LEN);
}

/// An explicit `Ephemeral` scope round-trips: the ephemeral masking key is
/// provisioned at partition finalization, so generation succeeds and the
/// device stamps the requested scope into the masked blob.
#[test]
fn sealing_key_gen_roundtrip_honors_ephemeral_scope() {
    let _guard = PARTITION_LOCK.lock();
    let session = crate::utils::sd_provision::finalized_co_session();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .scope(HsmKeyScope::Ephemeral)
        .build()
        .expect("build props");

    let mut algo = HsmSealingKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut algo, props)
        .expect("generate Ephemeral-scoped sealing key on a provisioned partition");

    let masked = key.masked_key_vec().expect("masked key");
    assert_eq!(masked.len(), MASKED_SEALING_KEY_LEN);
}

/// SecurityDomain scope requires a provisioned SD masking key, after which
/// generation and attestation both succeed on the same session.
#[test]
fn sealing_key_gen_sd_scope() {
    let _guard = PARTITION_LOCK.lock();
    let sata = sd_provision::CaKey::generate();
    let (session, policy, pid_pub) = sd_provision::finalized_backing_session(&sata);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .scope(HsmKeyScope::SecurityDomain)
        .build()
        .expect("build props");
    let mut algo = HsmSealingKeyGenAlgo::default();
    let res = HsmKeyManager::generate_key(&session, &mut algo, props.clone());
    assert!(
        matches!(res.as_ref().err(), Some(HsmError::DdiCmdFailure)),
        "an absent SD masking key must be rejected by firmware, got {:?}",
        res.err(),
    );

    let (masked, receiver_pub, report) = sd_provision::masked_key_and_report(&session);
    let evidence = sd_provision::build_receiver_evidence(&pid_pub, &receiver_pub, &sata, &report);
    evidence
        .with_create_backup(|receiver_chain, receiver| {
            session.sd_create_remote_backup(&policy, &masked, receiver_chain, receiver)
        })
        .expect("provision security domain with a Local-scoped sealing key");

    let key = HsmKeyManager::generate_key(&session, &mut algo, props)
        .expect("generate SecurityDomain-scoped sealing key");
    assert_eq!(key.kind(), HsmKeyKind::Sealing);
    assert_eq!(key.class(), HsmKeyClass::Secret);
    assert_eq!(key.bits(), 384);
    assert!(key.can_derive());
    assert!(!key.is_session());
    assert_eq!(
        key.masked_key_vec().expect("masked key").len(),
        MASKED_SEALING_KEY_LEN,
    );
    assert!(!key.pub_key_der_vec().expect("public key der").is_empty());

    let report_data = [0u8; KEY_REPORT_DATA_LEN];
    let report_len = key
        .generate_key_report(&report_data, None)
        .expect("key report size");
    let mut report = vec![0u8; report_len];
    let written = key
        .generate_key_report(&report_data, Some(&mut report))
        .expect("attest SecurityDomain-scoped sealing key");
    assert!(written > 0);
    assert!(written <= report.len());
}
