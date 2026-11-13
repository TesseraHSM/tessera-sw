// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain policy tests for `PartInit`.
//!
//! The SATA / SAPOTA trust anchors are carried as thumbprints inside the
//! CBOR partition policy (keys 3 and 4).  The security-domain *local
//! masking keys* are deliberately NOT derived by `PartInit` — that is
//! deferred to `PartFinal` (which binds them to the POTA-endorsed PTA
//! cert chain).  These tests therefore assert that `PartInit` accepts
//! the SD anchors and that they are bound into the derived PTA key
//! (the partition root is derived over the full policy bytes).

use tsra_ddi_tbor_test_harness::assertions;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::POLICY_THUMBPRINT_LEN;
use x509::X509Csr;
use x509::X509CsrOp;

use super::known_good_part_policy;
use super::known_good_test_policy;
use super::mach_seed;

const SAPOTA_TP: [u8; POLICY_THUMBPRINT_LEN] = [0x33; POLICY_THUMBPRINT_LEN];

/// Run `PartInit` on a fresh partition with `policy` and return the PTA
/// SubjectPublicKeyInfo from the CSR.
fn pta_pub_for(policy: &[u8]) -> Vec<u8> {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let resp = ctx
        .part_init(&session, &mach_seed(), policy)
        .expect("PartInit with SD policy must succeed");
    assert!(!resp.pta_csr.is_empty(), "PTACSR must be present");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be present");
    X509Csr::from_der(&resp.pta_csr)
        .expect("PTACSR parses")
        .get_public_key_der()
        .expect("CSR SPKI extracts")
}

/// A policy carrying a SAPOTA thumbprint alongside SATA is accepted.
#[test]
fn part_init_with_sapota() {
    let policy = known_good_test_policy().with_sapota(SAPOTA_TP).encode();
    pta_pub_for(&policy);
}

/// The SATA thumbprint is bound into PTA-key derivation: changing only
/// its last byte changes the PTA public key.
#[test]
fn part_init_sata_thumbprint_changes_pta_key() {
    let base = known_good_test_policy();
    let mut other = base.clone();
    other.sata_spki_thumbprint[POLICY_THUMBPRINT_LEN - 1] ^= 0x01;

    assert_ne!(
        pta_pub_for(&base.encode()),
        pta_pub_for(&other.encode()),
        "changing the SATA thumbprint must change the PTA public key",
    );
}

/// The optional SAPOTA thumbprint is bound into PTA-key derivation:
/// adding it changes the PTA public key.
#[test]
fn part_init_sapota_presence_changes_pta_key() {
    let base = known_good_test_policy();
    let with_sapota = base.clone().with_sapota(SAPOTA_TP);

    assert_ne!(
        pta_pub_for(&base.encode()),
        pta_pub_for(&with_sapota.encode()),
        "adding a SAPOTA thumbprint must change the PTA public key",
    );
}

/// A session created before erase cannot be reused for PartInit.
#[test]
fn part_init_with_stale_session_after_erase_is_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.erase().expect("erase must succeed");

    let err = ctx
        .part_init(&session, &mach_seed(), &known_good_part_policy())
        .expect_err("PartInit with a session created before erase must be rejected");

    assertions::assert_fw_rejects(
        &err,
        ctx.unknown_session_status(TborStatus::DefaultPskMustRotate),
    );
}
