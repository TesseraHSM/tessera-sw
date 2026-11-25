// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdSealingKeyGen` command.
//!
//! Cross-test isolation comes from `open_dev`'s NSSR; no
//! per-test cleanup is required (see [`tsra_ddi_tbor_test_harness::fixture`]).
//!
//! The command generates a P-384, ML-KEM-1024 or MLKEM1024-P384 sealing
//! keypair (request `kem`) and returns the
//! **masked** private key (masked under the requested scope's masking
//! key) plus the public key — nothing is stored on the device.  The
//! Ephemeral/Local masking keys are provisioned by `PartFinal`, so the
//! happy-path tests first drive `PartInit → PartFinal`.
//!
//! Coverage:
//! * Happy path (Ephemeral + Local) × each KEM — returns a non-zero masked
//!   key + public key of the KEM's length; a second call yields a distinct
//!   keypair.
//! * Unknown KEM discriminant → `InvalidArg`.
//! * Session scope and SecurityDomain before SD provisioning return
//!   `UnsupportedKeyScope`.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).
//!
//! `SdSealingKeyGen` itself carries no out-of-band data — the request is a
//! session id plus 1-byte scope and KEM, and the response is the masked
//! key plus the public key — so the command runs on any transport.
//! The *setup* is what needs OOB: [`finalized_co_session`] drives
//! `PartFinal`, whose PTA chain travels out of band, so the tests that
//! need a finalized partition also need the driver's data-transfer path.

use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::SessionSuite;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::TborSdSealingKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use tsra_ddi_tbor_types::MASKED_SEALING_KEY_MAX_LEN;
use tsra_ddi_tbor_types::SD_SEALING_MLKEM1024_P384_PUB_KEY_LEN;
use tsra_ddi_tbor_types::SD_SEALING_MLKEM1024_PUB_KEY_LEN;
use tsra_ddi_tbor_types::SD_SEALING_PUB_KEY_LEN;
use tsra_ddi_tbor_types::TRANSFER_KEM_MLKEM1024;
use tsra_ddi_tbor_types::TRANSFER_KEM_MLKEM1024_P384;
use tsra_ddi_tbor_types::TRANSFER_KEM_P384;

use crate::commands::part_init::mach_seed;
use crate::commands::part_init::part_policy_with_pota;

/// `KeyScope` discriminants (wire mirror of the firmware `HsmKeyScope`).
const SCOPE_SESSION: u8 = 0b001;
const SCOPE_EPHEMERAL: u8 = 0b010;
const SCOPE_LOCAL: u8 = 0b011;
const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// Bring a partition to `Initialized` on a rotated CO session:
/// bootstrap → `PartInit` → `PartFinal`.  Post-condition: the
/// Ephemeral/Local masking keys exist, so `SdSealingKeyGen` can mask
/// under them.  Returns the live CO session.
///
/// `PartFinal` validates the supplied PTA certificate chain against the
/// POTA trust anchor bound into the policy, so this mints a POTA CA, binds
/// its public key into the policy, and issues a POTA-anchored PTA chain
/// from the `PartInit` CSR (mirrors the `part_final` happy-path setup).
pub(crate) fn finalized_co_session(ctx: &TestCtx) -> SessionHandshake {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let init = ctx
        .part_init(&session, &mach_seed(), &policy)
        .expect("PartInit");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");
    session
}

/// `(kem, masked key length, public key length)` for each sealing KEM.
const KEMS: [(u8, usize, usize); 3] = [
    (
        TRANSFER_KEM_P384,
        MASKED_SEALING_KEY_LEN,
        SD_SEALING_PUB_KEY_LEN,
    ),
    (
        TRANSFER_KEM_MLKEM1024,
        MASKED_SEALING_KEY_MAX_LEN,
        SD_SEALING_MLKEM1024_PUB_KEY_LEN,
    ),
    (
        TRANSFER_KEM_MLKEM1024_P384,
        264,
        SD_SEALING_MLKEM1024_P384_PUB_KEY_LEN,
    ),
];

/// Happy path for a supported `scope` and every KEM: the masked key and
/// public key are full/non-zero, and a second call yields a distinct
/// keypair.
fn roundtrip_for_scope(scope: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for (kem, masked_len, pub_len) in KEMS {
        roundtrip_for_kem(&ctx, &session, scope, kem, masked_len, pub_len);
    }
}

fn roundtrip_for_kem(
    ctx: &TestCtx,
    session: &SessionHandshake,
    scope: u8,
    kem: u8,
    masked_len: usize,
    pub_len: usize,
) {
    let req = TborSdSealingKeyGenReq {
        session_id: session.session_id,
        scope,
        kem,
    };
    let resp = ctx.tbor(&req).expect("SdSealingKeyGen roundtrip");

    // Masked private key: exactly the KEM's length, non-zero.
    assert_eq!(resp.masked_key.len(), masked_len);
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked_key must not be all-zero",
    );
    // Public key: the KEM's full, non-zero public key.
    assert_eq!(resp.pub_key.len(), pub_len);
    assert!(
        resp.pub_key.iter().any(|&b| b != 0),
        "pub_key must not be all-zero",
    );

    // Each call generates fresh randomness → a distinct keypair.
    let resp2 = ctx.tbor(&req).expect("second SdSealingKeyGen");
    assert_ne!(
        resp.masked_key, resp2.masked_key,
        "each generation must yield a distinct masked key",
    );
    assert_ne!(
        resp.pub_key, resp2.pub_key,
        "each generation must yield a distinct public key",
    );
}

#[test]
fn sd_sealing_key_gen_ephemeral_roundtrip() {
    roundtrip_for_scope(SCOPE_EPHEMERAL);
}

#[test]
fn sd_sealing_key_gen_local_roundtrip() {
    roundtrip_for_scope(SCOPE_LOCAL);
}

#[test]
fn sd_sealing_key_gen_rejects_unknown_kem() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborSdSealingKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
        kem: 3,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[test]
fn sd_sealing_key_gen_rejects_unsupported_scope() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Session scope is unsupported for sealing keys. SecurityDomain is
    // unavailable until SD creation or restoration provisions its masking
    // key; this fixture only finalizes the partition.
    for scope in [SCOPE_SESSION, SCOPE_SECURITY_DOMAIN] {
        let req = TborSdSealingKeyGenReq {
            session_id: session.session_id,
            scope,
            kem: TRANSFER_KEM_P384,
        };
        ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
    }
}

#[test]
fn sd_sealing_key_gen_rejects_before_finalize() {
    let ctx = TestCtx::new();
    // Rotated CO session but no PartInit/PartFinal → the partition is not
    // Initialized, so the scope's masking key does not exist yet.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let req = TborSdSealingKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
        kem: TRANSFER_KEM_P384,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[test]
fn sd_sealing_key_gen_rejected_on_cu_session() {
    let ctx = TestCtx::new();

    // Rotate the CU PSK out of the default so the dispatcher's default-PSK
    // gate does not fire first; then reopen a CU session under the rotated
    // PSK.  CU sessions are pinned to `SessionSuite::EcdhP384` (CO-only is
    // `Authenticated`).
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    // SdSealingKeyGen is Crypto-Officer-only: the handler's role gate
    // (checked before the scope/state gates) rejects a CU session.
    let req = TborSdSealingKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
        kem: TRANSFER_KEM_P384,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
}

#[test]
fn sd_sealing_key_gen_rejected_on_default_psk() {
    let ctx = TestCtx::new();
    // Open a CO session WITHOUT rotating the PSK (still the public
    // default) — the dispatcher's default-PSK gate must reject the command
    // before the handler runs.
    let session = ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("open_session must succeed");

    let req = TborSdSealingKeyGenReq {
        session_id: session.session_id(),
        scope: SCOPE_EPHEMERAL,
        kem: TRANSFER_KEM_P384,
    };
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}
