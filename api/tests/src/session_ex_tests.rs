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

/// Happy path: a CU session under the ML-KEM-1024 suite.
#[test]
fn open_session_ex_cu_mlkem1024() {
    if !crate::utils::session::api_rev_at_least(1, 1) {
        return;
    }
    let _guard = PARTITION_LOCK.lock();
    let (part, rev) = new_partition();

    let session = part
        .open_session_ex(
            rev,
            HsmSessionPsk::new(HsmPskId::CU),
            HsmSessionSuite::MlKem1024,
        )
        .expect("CU/ML-KEM-1024 open_session_ex should succeed against emu");

    let sess_rev = session.api_rev();
    assert_eq!(
        (sess_rev.major, sess_rev.minor),
        (rev.major, rev.minor),
        "session must echo the negotiated api revision"
    );
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
        HsmSessionPsk::with_psk(HsmPskId::CO, &new_psk),
        HsmSessionSuite::EcdhP384,
    )
    .expect("open with the rotated CO PSK should succeed");

    // Reopening with the (now stale) default CO PSK must be rejected.
    let stale = part.open_session_ex(
        rev,
        HsmSessionPsk::new(HsmPskId::CO),
        HsmSessionSuite::EcdhP384,
    );
    assert!(
        stale.is_err(),
        "the default CO PSK must be rejected after rotation",
    );
}
