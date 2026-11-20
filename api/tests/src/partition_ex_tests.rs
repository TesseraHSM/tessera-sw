// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR partition-provisioning session API
//! (`HsmSession::part_init_ex` and `HsmSession::part_final_ex`).
//!
//! These exercise partition provisioning and input-validation guards through the *public*
//! `tsra_api` surface against the emulator or hardware backend. The
//! negative-path guard tests return before the device round-trip, so they
//! are deterministic
//! and need no FW-accepted policy / cert chain; the
//! `*_valid_inputs_pass_host_guards` tests deliberately clear the guards
//! and reach the device to exercise the request-construction path.

use tsra_api::*;
use tsra_crypto::pem_to_der;
use tsra_ddi_tbor_test_harness::policy::TestPolicy;
use tsra_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_ddi_tbor_types::MAX_CERTS;
use x509::X509Certificate;
use x509::X509CertificateOp;

use crate::utils::partition_ex_helpers::*;

/// Well-formed machine seed for `PartInit`.
fn valid_mach_seed() -> Vec<u8> {
    vec![0u8; MACH_SEED_LEN]
}

/// A structurally valid CBOR partition policy (all-zero thumbprints).
fn valid_policy() -> Vec<u8> {
    TestPolicy::new([0u8; POLICY_THUMBPRINT_LEN], [0u8; POLICY_THUMBPRINT_LEN]).encode()
}

/// A one-entry PTA cert placeholder (4 opaque bytes). The host-side
/// guards never parse DER, so its contents are irrelevant.
fn one_cert() -> Vec<u8> {
    vec![0u8; 4]
}

// ── PartInit ────────────────────────────────────────────────────────────────

/// An empty or over-long (`> PART_POLICY_MAX_LEN`) policy is rejected by
/// the host before the device round-trip.
#[test]
fn part_init_rejects_bad_policy_len() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();
    let mach_seed = valid_mach_seed();

    for len in [0, PART_POLICY_MAX_LEN + 1] {
        let policy = vec![0xA0u8; len];
        let res = session.part_init_ex(&policy, &mach_seed);
        assert!(
            matches!(res, Err(HsmError::InvalidArgument)),
            "policy len {len}"
        );
    }
}

/// A policy within the host length bounds but not valid CBOR passes the
/// host guard and is rejected by the firmware.
#[test]
fn part_init_rejects_malformed_policy() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();
    let mach_seed = valid_mach_seed();

    for policy in [vec![0xFFu8; 16], vec![0u8; PART_POLICY_MAX_LEN]] {
        let res = session.part_init_ex(&policy, &mach_seed);
        assert!(res.is_err(), "malformed policy accepted");
    }
}

/// `PartFinal` rejects an empty or over-long policy on the host.
#[test]
fn part_final_rejects_bad_policy_len() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();
    let cert = one_cert();
    let chain = [HsmCert { cert: &cert }];

    for len in [0, PART_POLICY_MAX_LEN + 1] {
        let policy = vec![0xA0u8; len];
        let res = session.part_final_ex(&policy, &chain, None);
        assert!(
            matches!(res, Err(HsmError::InvalidArgument)),
            "policy len {len}"
        );
    }
}

/// `PartFinal` rejects an empty cert chain.
#[test]
fn part_final_rejects_empty_cert_descriptors() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();
    let policy = valid_policy();

    let res = session.part_final_ex(&policy, &[], None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects a cert chain containing an empty (zero-length)
/// certificate, which is not valid DER and would yield a zero-length
/// out-of-band descriptor.
#[test]
fn part_final_rejects_empty_cert() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();
    let policy = valid_policy();
    let empty_cert: Vec<u8> = Vec::new();
    let chain = [HsmCert {
        cert: empty_cert.as_slice(),
    }];

    let res = session.part_final_ex(&policy, &chain, None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects more than [`MAX_CERTS`] certificates.
#[test]
fn part_final_rejects_too_many_cert_descriptors() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();
    let policy = valid_policy();
    let cert = one_cert();
    let too_many = vec![
        HsmCert {
            cert: cert.as_slice()
        };
        MAX_CERTS + 1
    ];

    let res = session.part_final_ex(&policy, &too_many, None);
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// `PartFinal` rejects a `prev_local_mk_backup` whose length is not
/// exactly [`LOCAL_MK_BACKUP_LEN`] (near-miss under-length), exercising
/// the fixed-size guard rather than a coarse max-length check.
#[test]
fn part_final_rejects_wrong_len_prev_local_mk_backup() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();
    let policy = valid_policy();
    let wrong_len = vec![0u8; LOCAL_MK_BACKUP_LEN - 1];

    let cert = one_cert();
    let chain = [HsmCert { cert: &cert }];
    let res = session.part_final_ex(&policy, &chain, Some(&wrong_len));
    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

// ── Host-guard pass-through (request-construction / round-trip) ──────────────

/// Valid-length `PartInit` inputs pass every host-side guard, so the
/// request is sealed, constructed, and shipped to the device. The call
/// is therefore never rejected with [`HsmError::InvalidArgument`] (the
/// host-guard error); it may still fail on-device with a different
/// error. This exercises the request-construction / TBOR wiring path
/// that the negative guard tests skip.
#[test]
fn part_init_valid_inputs_pass_host_guards() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();
    let mach_seed = valid_mach_seed();
    let policy = valid_policy();

    let res = session.part_init_ex(&policy, &mach_seed);
    assert!(!matches!(res, Err(HsmError::InvalidArgument)));
}

/// Valid-length `PartFinal` inputs pass every host-side guard, so the
/// request is built — each cert ships as its own out-of-band SGL Data
/// Block and its `(index, length)` descriptor is derived — and shipped
/// to the device. The call is therefore never rejected with
/// [`HsmError::InvalidArgument`]; it may still fail on-device. This
/// exercises the request-construction / TBOR-OOB wiring path.
#[test]
fn part_final_valid_inputs_pass_host_guards() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let session = new_co_session();
    let policy = valid_policy();
    let cert = one_cert();
    let chain = [HsmCert { cert: &cert }];

    let res = session.part_final_ex(&policy, &chain, None);
    assert!(!matches!(res, Err(HsmError::InvalidArgument)));
}

/// Slot 2 serves the on-demand, PTA-signed PID certificate that only
/// exists once the partition has been TBOR-finalized. Drive a full
/// finalization through the public API, then read `cert_chain(2)`
/// repeatedly: every read must regenerate and return a valid,
/// parseable PID certificate (the slot-2 path bypasses the cached
/// slot-0 chain, so stability across repeated reads is exercised here).
#[test]
fn test_cert_chain_slot2_pid_after_finalization() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = crate::utils::partition_ex_helpers::PARTITION_LOCK.lock();

    // Keep the partition (and its session) alive for the duration of the
    // reads; the finalized slot-2 cert is served off this partition.
    let (part, _rev, _session) = crate::utils::sd_provision::finalized_co_partition();

    // Repeated reads each regenerate the on-demand PID certificate; every
    // one must succeed and yield a single, valid PID certificate.
    for attempt in 0..3 {
        let cert_chain = part
            .cert_chain(2)
            .unwrap_or_else(|e| panic!("slot-2 cert_chain failed on attempt {attempt}: {e:?}"));
        assert!(
            !cert_chain.is_empty(),
            "slot-2 cert chain is empty on attempt {attempt}"
        );
        assert!(
            cert_chain.contains("-----BEGIN CERTIFICATE-----"),
            "slot-2 cert chain missing PEM header on attempt {attempt}"
        );

        let certs = X509Certificate::from_pem_stack(cert_chain.as_bytes())
            .expect("Failed to parse slot-2 cert chain PEM stack");
        assert_eq!(
            certs.len(),
            1,
            "slot-2 chain should contain exactly the PID leaf certificate on attempt {attempt}"
        );

        // The single certificate must be a well-formed X.509 PID cert: its
        // DER round-trips through the parser and carries a non-empty body.
        let der = pem_to_der(cert_chain.as_bytes()).expect("Failed to parse slot-2 PID cert PEM");
        assert!(
            !der.is_empty(),
            "slot-2 PID certificate DER is empty on attempt {attempt}"
        );
    }
}
