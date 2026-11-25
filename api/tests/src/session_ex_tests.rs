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
fn open_session_ex_removed_suite_rejected() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();
    let result = part.open_session_ex(
        rev,
        &test_root_spki_sha384(&part),
        HsmSessionPsk::new(HsmPskId::CU),
        HsmSessionSuite(0x02),
    );
    assert!(matches!(result, Err(HsmError::InvalidArgument)));
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
