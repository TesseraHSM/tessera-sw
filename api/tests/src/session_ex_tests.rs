// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR security-domain session API
//! (`HsmPartition::open_session_ex`).
//!
//! These go through the *public* `tsra_api` surface — the two-phase
//! HPKE handshake plus the resulting `HsmSession` (V2) handle — against
//! the emulator or hardware backend, exactly as an external caller (and
//! the native FFI) would.

use tsra_api::*;
use tsra_crypto::x509_builder::der_helpers::MLDSA87_SPKI_HEADER;
use x509::X509Certificate;
use x509::X509CertificateOp;

use crate::utils::partition_ex_helpers::*;

#[test]
fn session_ex_migration_reopen_uses_default_psk_and_restores_psk_change() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    let root = test_root_spki_sha384(&part);
    let psk = [0xB4; PSK_LEN];
    let session = part
        .open_session_ex(
            rev,
            &root,
            HsmSessionPsk::new(HsmPskId::CU),
            HsmSessionSuite::EcdhP384,
        )
        .expect("open CU");
    session.change_psk(&psk).expect("rotate");
    part.reset().expect("migration");
    assert_eq!(
        session.change_psk(&[0xC5; PSK_LEN]),
        Err(HsmError::SessionNeedsRenegotiation)
    );
    assert!(
        session.reopen_ex(&root, Some(&[0xD6; PSK_LEN])).is_err(),
        "wrong PSK"
    );
    // The migration returned the PSKs to their defaults.
    assert!(
        session.reopen_ex(&root, Some(&psk)).is_err(),
        "rotated PSK after migration"
    );
    session
        .reopen_ex(&root, None)
        .expect("retry with the default PSK");
    // It also restored the change allowance, so the role rotates again.
    session.change_psk(&psk).expect("rotate after migration");
    assert_eq!(
        session.change_psk(&[0xC5; PSK_LEN]),
        Err(HsmError::PskChangeAlreadyUsed)
    );
}

#[test]
fn session_ex_migration_close_does_not_require_reopen() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    let root = test_root_spki_sha384(&part);
    let session = part
        .open_session_ex(
            rev,
            &root,
            HsmSessionPsk::new(HsmPskId::CO),
            HsmSessionSuite::EcdhP384,
        )
        .expect("open CO");
    part.reset().expect("migration");
    drop(session);
    part.open_session_ex(
        rev,
        &root,
        HsmSessionPsk::new(HsmPskId::CO),
        HsmSessionSuite::EcdhP384,
    )
    .expect("stale close freed the CO slot");
}

#[test]
fn open_session_ex_rejects_wrong_root_pin() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    let pin = test_root_spki_sha384(&part);
    let mut wrong_pin = pin;
    wrong_pin[0] ^= 1;
    assert!(matches!(
        part.open_session_ex(
            rev,
            &wrong_pin,
            HsmSessionPsk::new(HsmPskId::CO),
            HsmSessionSuite::EcdhP384,
        ),
        Err(HsmError::InvalidSignature)
    ));
    part.open_session_ex(
        rev,
        &pin,
        HsmSessionPsk::new(HsmPskId::CO),
        HsmSessionSuite::EcdhP384,
    )
    .expect("correct root pin must still open");
}

/// Happy path: a CO session under the ECDH P-384 suite returns a
/// live `HsmSession` over the public API.
#[test]
fn open_session_ex_co_ecdh_p384() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    if crate::utils::session::api_rev_at_least(2, 0) {
        // Exercise the encrypted session transport, not a 1.x fallback.
        assert_eq!((rev.major, rev.minor), (2, 0));
    }

    let session = part
        .open_session_ex(
            rev,
            &test_root_spki_sha384(&part),
            HsmSessionPsk::new(HsmPskId::CO),
            HsmSessionSuite::EcdhP384,
        )
        .expect("CO/ECDH-P384 open_session_ex should succeed against emu");

    // The V2 session must carry the negotiated api revision through.
    let sess_rev = session.api_rev();
    assert_eq!(
        (sess_rev.major, sess_rev.minor),
        (rev.major, rev.minor),
        "session must echo the negotiated api revision"
    );
}

/// Happy path: a CU session under the ECDH P-384 suite.
#[test]
fn open_session_ex_cu_ecdh_p384() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();

    let session = part
        .open_session_ex(
            rev,
            &test_root_spki_sha384(&part),
            HsmSessionPsk::new(HsmPskId::CU),
            HsmSessionSuite::EcdhP384,
        )
        .expect("CU/ECDH-P384 open_session_ex should succeed against emu");

    let sess_rev = session.api_rev();
    assert_eq!(
        (sess_rev.major, sess_rev.minor),
        (rev.major, rev.minor),
        "session must echo the negotiated api revision"
    );
}

#[test]
fn open_session_ex_unknown_suite_rejected() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    let result = part.open_session_ex(
        rev,
        &test_root_spki_sha384(&part),
        HsmSessionPsk::new(HsmPskId::CU),
        HsmSessionSuite(0x03),
    );
    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

#[test]
fn open_session_ex_mlkem1024_authenticates_rotates_and_recovers_both_roles() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let suite = HsmSessionSuite::MlKem1024MlDsa87;
    let host_available = crate::utils::partition_ex_helpers::host_pqc_available(
        tsra_crypto::MlDsaPrivateKey::from_seed(tsra_crypto::MlDsaVariant::MlDsa87, &[7; 32]),
    ) && crate::utils::partition_ex_helpers::host_pqc_available(
        tsra_crypto::MlKemPrivateKey::from_seed(tsra_crypto::MlKemVariant::MlKem1024, &[7; 64]),
    );
    for role in [HsmPskId::CO, HsmPskId::CU] {
        let (part, rev) = new_partition();
        if !crate::utils::partition_ex_helpers::backend_mldsa_available(&part) {
            assert!(matches!(
                part.open_session_ex(
                    rev,
                    &test_root_spki_sha384(&part),
                    HsmSessionPsk::new(role),
                    suite,
                ),
                Err(HsmError::UnsupportedAlgorithm)
            ));
            continue;
        }
        if !host_available {
            continue;
        }
        let root =
            crate::utils::partition_ex_helpers::test_root_spki_sha384_for_suite(&part, suite);
        let pem = part.cert_chain_mldsa(0).expect("ML-DSA certificate bank");
        let certificates =
            X509Certificate::from_pem_stack(pem.as_bytes()).expect("ML-DSA bank certificates");
        let leaf = certificates.first().expect("PID leaf");
        let path = leaf
            .verified_chain(&certificates[1..])
            .expect("verify certificate path")
            .expect("valid certificate path");
        assert!(path.len() > 1, "PID path must include its issuer");
        let all_mldsa = path.iter().all(|certificate| {
            certificate
                .subject_public_key_info_der()
                .expect("certificate SPKI")
                .starts_with(&MLDSA87_SPKI_HEADER)
        });
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(matches!(
            part.open_session_ex(rev, &wrong_root, HsmSessionPsk::new(role), suite,),
            Err(HsmError::InvalidSignature)
        ));
        // Uno may serve an ML-DSA leaf under its P-384 alias chain.
        if !all_mldsa {
            assert!(matches!(
                part.open_session_ex(rev, &root, HsmSessionPsk::new(role), suite),
                Err(HsmError::InvalidSignature)
            ));
            continue;
        }
        let psk = [0xB5; PSK_LEN];
        let session = part
            .open_session_ex(rev, &root, HsmSessionPsk::new(role), suite)
            .expect("ML-KEM session");
        assert_eq!(session.api_rev(), rev);
        session.change_psk(&psk).expect("rotate role PSK");
        drop(session);
        let session = part
            .open_session_ex(rev, &root, HsmSessionPsk::with_psk(role, &psk), suite)
            .expect("ML-KEM session with rotated PSK");
        part.reset().expect("migration");
        session
            .reopen_ex(&root, None)
            .expect("ML-KEM recovery with default PSK");
        session.change_psk(&psk).expect("rotate after migration");
        drop(session);
        assert!(
            part.open_session_ex(rev, &root, HsmSessionPsk::new(role), suite,)
                .is_err()
        );
    }
}

/// PSK-rotation round trip: after rotating the CO PSK from the default,
/// the partition accepts the new secret and rejects the default — the
/// full `change_psk` + optional-PSK-`open_session_ex` flow end to end.
#[test]
fn change_psk_rotates_co_psk() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }

    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();

    // A non-default replacement CO PSK.
    let new_psk = [0x5Au8; PSK_LEN];

    // Open with the default CO PSK, rotate it, then close the session.
    {
        let session = part
            .open_session_ex(
                rev,
                &test_root_spki_sha384(&part),
                HsmSessionPsk::new(HsmPskId::CO),
                HsmSessionSuite::EcdhP384,
            )
            .expect("open with the default CO PSK");
        session
            .change_psk(&new_psk)
            .expect("rotate the CO PSK to the new secret");
    }

    // Reopening with the rotated secret must now succeed.
    part.open_session_ex(
        rev,
        &test_root_spki_sha384(&part),
        HsmSessionPsk::with_psk(HsmPskId::CO, &new_psk),
        HsmSessionSuite::EcdhP384,
    )
    .expect("open with the rotated CO PSK should succeed");

    // Reopening with the (now stale) default CO PSK must be rejected.
    let stale = part.open_session_ex(
        rev,
        &test_root_spki_sha384(&part),
        HsmSessionPsk::new(HsmPskId::CO),
        HsmSessionSuite::EcdhP384,
    );
    assert!(
        stale.is_err(),
        "the default CO PSK must be rejected after rotation",
    );
}

#[test]
fn session_ex_cu_rotation_keeps_session_and_consumes_allowance() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    let pin = test_root_spki_sha384(&part);
    let psk = [0xA5; PSK_LEN];
    let bootstrap = part
        .open_session_ex(
            rev,
            &pin,
            HsmSessionPsk::new(HsmPskId::CU),
            HsmSessionSuite::EcdhP384,
        )
        .expect("bootstrap CU session");
    bootstrap.change_psk(&psk).expect("initial rotation");
    assert_eq!(
        bootstrap.change_psk(&[0xB6; PSK_LEN]),
        Err(HsmError::PskChangeAlreadyUsed)
    );
    drop(bootstrap);
    let session = part
        .open_session_ex(
            rev,
            &pin,
            HsmSessionPsk::with_psk(HsmPskId::CU, &psk),
            HsmSessionSuite::EcdhP384,
        )
        .expect("reopen with rotated PSK");
    assert_eq!(session.change_psk(&psk), Err(HsmError::InvalidArgument));
}
