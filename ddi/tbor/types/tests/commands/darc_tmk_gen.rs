// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `DarcTmkGen` command.
//!
//! `DarcTmkGen` originates a fresh DARC Transfer Masking Key (TMK) and
//! returns it masked under the partition security-domain masking key
//! (SDMK).  It is the source-side counterpart of `DarcTmkImport`; both
//! emit the identical 164-byte masked envelope, so a created and an
//! imported TMK are interchangeable downstream.
//!
//! Coverage:
//! * Round-trip — the minted TMK comes back as a non-zero 164-byte masked
//!   envelope, and two calls yield distinct envelopes (fresh IV).
//! * Envelope parity with `DarcTmkImport` — the masked-key metadata (AAD)
//!   of a created TMK matches that of an imported one (same kind / attrs /
//!   label), proving the two are interchangeable.
//! * Before SD init (partition `Initialized` but no security domain) →
//!   `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).

use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborDarcTmkGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_ddi_tbor_types::TMK_LEN;

use crate::commands::darc_tmk_import::build_valid_import;
use crate::commands::darc_tmk_import::sd_initialized_session;
use crate::commands::darc_tmk_import::SdReady;
use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// Masked-key envelope layout: `header(8) ‖ iv(12) ‖ aad(96) ‖ ct ‖ tag`.
/// The 96-byte `MaskedKeyMetadata` AAD begins at offset 20.
const AAD_START: usize = 8 + 12;
const AAD_END: usize = AAD_START + 96;

/// A raw TMK to feed the harness `DarcTmkImport` for the envelope-parity
/// comparison (value is irrelevant — only the metadata is compared).
const TMK: [u8; TMK_LEN] = [0x5Au8; TMK_LEN];

/// Mint a TMK via `DarcTmkGen` and return the masked envelope.
fn key_gen(ready: &SdReady) -> Vec<u8> {
    let req = TborDarcTmkGenReq {
        session_id: ready.session.session_id,
    };
    let resp = ready.ctx.tbor(&req).expect("DarcTmkGen");
    resp.masked_tmk
}

/// Import a known TMK via `DarcTmkImport` and return the masked envelope
/// (the reference the created envelope's metadata must match).
fn import_tmk(ready: &SdReady) -> Vec<u8> {
    let (req, chain) = build_valid_import(ready, &ready.pota, &TMK);
    let resp = ready
        .ctx
        .tbor_oob(&req, &chain.der_items())
        .expect("DarcTmkImport");
    resp.masked_tmk
}

#[test]
fn darc_tmk_gen_roundtrip() {
    let ready = sd_initialized_session();

    let masked = key_gen(&ready);
    assert_eq!(
        masked.len(),
        MASKED_TMK_LEN,
        "masked TMK must be the fixed 164-byte envelope",
    );
    assert!(
        masked.iter().any(|&b| b != 0),
        "masked TMK must not be all-zero",
    );

    // Each call draws a fresh TMK under a fresh IV, so the envelopes differ.
    let masked2 = key_gen(&ready);
    assert_ne!(
        masked, masked2,
        "each DarcTmkGen must yield a fresh masked envelope",
    );
}

#[test]
fn darc_tmk_gen_envelope_matches_import() {
    let ready = sd_initialized_session();

    // A created TMK and an imported TMK must carry identical masked-key
    // metadata (kind / attrs / label / svn / owner), so they are
    // interchangeable in later commands.  The IV and ciphertext differ;
    // the 96-byte AAD does not.
    let created = key_gen(&ready);
    let imported = import_tmk(&ready);
    assert_eq!(
        created[AAD_START..AAD_END],
        imported[AAD_START..AAD_END],
        "created and imported TMK envelopes must share masked-key metadata",
    );
}

#[test]
fn darc_tmk_gen_rejects_before_sd_init() {
    // The partition is finalized (`Initialized`) but its security domain
    // is not set up, so the SDMK the output would be masked under does
    // not exist yet → rejected before any RNG/masking work.
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborDarcTmkGenReq {
        session_id: session.session_id,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_gen_rejected_on_cu_session() {
    // DarcTmkGen is Crypto-Officer-only: a CU session is rejected at
    // the role gate before any crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let req = TborDarcTmkGenReq {
        session_id: session.session_id,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
}

#[test]
fn darc_tmk_gen_rejects_before_finalize() {
    // A rotated CO session but no PartInit/PartFinal → the partition is
    // not `Initialized`, so the command is rejected at the lifecycle gate.
    let ctx = TestCtx::new();
    let session = tsra_ddi_tbor_test_harness::bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let req = TborDarcTmkGenReq {
        session_id: session.session_id,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[test]
fn darc_tmk_gen_rejected_on_default_psk() {
    // A CO session on the still-default PSK is rejected by the
    // dispatcher's default-PSK gate before the handler runs.
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");
    let req = TborDarcTmkGenReq {
        session_id: session.session_id(),
    };
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}
