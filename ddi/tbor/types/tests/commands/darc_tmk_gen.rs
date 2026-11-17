// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `DarcTmkGen` command.
//!
//! `DarcTmkGen` originates a fresh DARC Transfer Masking Key (TMK) and
//! returns it masked under the partition security-domain masking key
//! (SDMK).  It is the source-side counterpart of `DarcTmkImport`; both
//! emit the identical 264-byte masked envelope, so a created and an
//! imported TMK are interchangeable downstream.
//!
//! Coverage:
//! * Round-trip — the minted TMK comes back as a non-zero 264-byte masked
//!   envelope, and two calls yield distinct envelopes (fresh IV).
//! * Envelope parity with `DarcTmkImport` — the masked-key metadata (AAD)
//!   of a created TMK matches that of an imported one (same kind / attrs /
//!   label), proving the two are interchangeable.
//! * Before SD init (partition `Initialized` but no security domain) →
//!   `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).
//! * Repeated generations retain the envelope header and AAD while rotating IVs.
//! * Invalid session requests do not disrupt the live CO session.
//! * Alternating import and generation preserves metadata and generation freshness.

use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::SessionSuite;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::TborDarcTmkGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_ddi_tbor_types::TMK_LEN;

use crate::commands::darc_tmk_import::build_valid_import;
use crate::commands::darc_tmk_import::sd_initialized_session;
use crate::commands::darc_tmk_import::SdReady;
use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// Masked-key envelope layout: `header(8) ‖ iv(16) ‖ aad(192) ‖ ct ‖ tag`.
/// The 192-byte `MaskedKeyMetadata` AAD begins at offset 24.
const AAD_START: usize = 8 + 16;
const AAD_END: usize = AAD_START + 192;

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

/// Generates a correctly sized, nonzero masked TMK envelope that changes on the next call.
#[test]
fn darc_tmk_gen_roundtrip() {
    let ready = sd_initialized_session();

    let masked = key_gen(&ready);
    assert_eq!(
        masked.len(),
        MASKED_TMK_LEN,
        "masked TMK must be the fixed 264-byte envelope",
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

/// Checks that generated and imported TMKs share the same 192-byte metadata.
#[test]
fn darc_tmk_gen_envelope_matches_import() {
    let ready = sd_initialized_session();

    // A created TMK and an imported TMK must carry identical masked-key
    // metadata (kind / attrs / label / svn / owner), so they are
    // interchangeable in later commands.  The IV and ciphertext differ;
    // the 192-byte AAD does not.
    let created = key_gen(&ready);
    let imported = import_tmk(&ready);
    assert_eq!(
        created[AAD_START..AAD_END],
        imported[AAD_START..AAD_END],
        "created and imported TMK envelopes must share masked-key metadata",
    );
}

/// Rejects TMK generation when the partition security domain is not initialized.
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

/// Rejects TMK generation from a Crypto-User session.
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

/// Rejects TMK generation before partition finalization.
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

/// Rejects TMK generation when the Crypto-Officer PSK is not rotated.
#[test]
fn darc_tmk_gen_rejected_on_default_psk() {
    // A CO session on the still-default PSK is rejected by the
    // dispatcher's default-PSK gate before the handler runs.
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("open_session must succeed");
    let req = TborDarcTmkGenReq {
        session_id: session.session_id(),
    };
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}

/// Ensures ten successive TMK generations produce distinct valid envelopes.
#[test]
fn darc_tmk_gen_repeated_generation_produces_unique_envelopes() {
    let ready = sd_initialized_session();
    let mut previous = Vec::new();

    for iteration in 0..10 {
        let masked = key_gen(&ready);

        assert_eq!(
            masked.len(),
            MASKED_TMK_LEN,
            "iteration {iteration}: unexpected envelope length",
        );

        assert!(
            masked.iter().any(|&b| b != 0),
            "iteration {iteration}: masked TMK must not be all-zero",
        );

        assert!(
            !previous.iter().any(|key: &Vec<u8>| key == &masked),
            "iteration {iteration}: duplicate masked TMK envelope",
        );

        previous.push(masked);
    }
}

/// Ensures every generated TMK envelope uses a fresh initialization vector.
#[test]
fn darc_tmk_gen_uses_fresh_iv_for_each_generation() {
    let ready = sd_initialized_session();

    // Envelope layout:
    // header(8) | iv(16) | aad(192) | ciphertext | tag
    const IV_START: usize = 8;
    const IV_END: usize = IV_START + 16;

    let mut ivs = Vec::new();

    for iteration in 0..10 {
        let masked = key_gen(&ready);

        assert_eq!(masked.len(), MASKED_TMK_LEN);

        let iv = masked[IV_START..IV_END].to_vec();

        assert!(!ivs.contains(&iv), "iteration {iteration}: IV was reused",);

        ivs.push(iv);
    }
}

/// Ensures generated TMK metadata stays stable across repeated calls.
#[test]
fn darc_tmk_gen_metadata_stable_across_generations() {
    let ready = sd_initialized_session();

    let first = key_gen(&ready);
    assert_eq!(first.len(), MASKED_TMK_LEN);

    let expected_aad = &first[AAD_START..AAD_END];

    for iteration in 0..5 {
        let masked = key_gen(&ready);

        assert_eq!(masked.len(), MASKED_TMK_LEN);

        assert_eq!(
            &masked[AAD_START..AAD_END],
            expected_aad,
            "iteration {iteration}: generated TMK metadata changed",
        );
    }
}

/// Verifies generated TMK metadata repeatedly matches imported TMK metadata.
#[test]
fn darc_tmk_gen_metadata_matches_import_across_repeated_calls() {
    let ready = sd_initialized_session();

    let imported = import_tmk(&ready);
    assert_eq!(imported.len(), MASKED_TMK_LEN);

    let expected_aad = &imported[AAD_START..AAD_END];

    for iteration in 0..5 {
        let generated = key_gen(&ready);

        assert_eq!(generated.len(), MASKED_TMK_LEN);

        assert_eq!(
            &generated[AAD_START..AAD_END],
            expected_aad,
            "iteration {iteration}: generated/imported metadata mismatch",
        );
    }
}

/// Verifies TMK generation still works with unchanged metadata after an import.
#[test]
fn darc_tmk_gen_still_works_after_import() {
    let ready = sd_initialized_session();

    let before_import = key_gen(&ready);
    assert_eq!(before_import.len(), MASKED_TMK_LEN);

    let imported = import_tmk(&ready);
    assert_eq!(imported.len(), MASKED_TMK_LEN);

    let after_import = key_gen(&ready);
    assert_eq!(after_import.len(), MASKED_TMK_LEN);

    assert_ne!(
        before_import, after_import,
        "TMK generation must remain fresh after import",
    );

    assert_eq!(
        &before_import[AAD_START..AAD_END],
        &after_import[AAD_START..AAD_END],
        "TMK metadata must remain consistent after import",
    );

    assert_eq!(
        &after_import[AAD_START..AAD_END],
        &imported[AAD_START..AAD_END],
        "generated and imported TMKs must share metadata",
    );
}

/// Rejects the maximum session ID when it does not identify the current session.
#[test]
fn darc_tmk_gen_rejects_max_session_id() {
    let ready = sd_initialized_session();

    let req = TborDarcTmkGenReq {
        session_id: u16::MAX,
    };

    ready
        .ctx
        .expect_session_reject(&req, TborStatus::FileHandleSessionIdDoesNotMatch);
}

/// Rejects a session ID different from the active Crypto-Officer session.
#[test]
fn darc_tmk_gen_rejects_unknown_session_id() {
    let ready = sd_initialized_session();

    let valid_id = ready.session.session_id;

    // Select a different session ID.
    // This does not guarantee it is unused, but the fresh
    // fixture is expected to have only the known CO session.
    let invalid_id = if valid_id == u16::MAX {
        u16::MAX - 1
    } else {
        u16::MAX
    };

    assert_ne!(valid_id, invalid_id);

    let req = TborDarcTmkGenReq {
        session_id: invalid_id,
    };

    ready
        .ctx
        .expect_session_reject(&req, TborStatus::FileHandleSessionIdDoesNotMatch);
}

/// Preserves the masked-key header across fresh TMKs generated in one security domain.
#[test]
fn darc_tmk_gen_header_stable_across_generations() {
    let ready = sd_initialized_session();
    const HEADER_END: usize = 8;

    let first = key_gen(&ready);
    assert_eq!(first.len(), MASKED_TMK_LEN);

    for iteration in 0..5 {
        let next = key_gen(&ready);
        assert_eq!(next.len(), MASKED_TMK_LEN);
        assert_eq!(
            &first[..HEADER_END],
            &next[..HEADER_END],
            "iteration {iteration}: masked-key header changed",
        );
    }
}

/// Keeps the valid CO session usable after requests with unknown session IDs are rejected.
#[test]
fn darc_tmk_gen_invalid_session_does_not_disrupt_valid_session() {
    let ready = sd_initialized_session();
    let valid_id = ready.session.session_id;
    let before = key_gen(&ready);
    assert_eq!(before.len(), MASKED_TMK_LEN);

    for invalid_id in [u16::MAX, u16::MAX - 1, u16::MAX - 2] {
        if invalid_id == valid_id {
            continue;
        }
        let req = TborDarcTmkGenReq {
            session_id: invalid_id,
        };
        ready
            .ctx
            .expect_session_reject(&req, TborStatus::FileHandleSessionIdDoesNotMatch);
    }

    let after = key_gen(&ready);
    assert_eq!(after.len(), MASKED_TMK_LEN);
    assert_ne!(
        before, after,
        "valid session must still generate a fresh TMK"
    );
    assert_eq!(
        &before[AAD_START..AAD_END],
        &after[AAD_START..AAD_END],
        "invalid session requests must not change generated TMK metadata",
    );
}

/// Maintains fresh generated envelopes and stable metadata when import and generation alternate.
#[test]
fn darc_tmk_gen_interleaved_with_imports() {
    let ready = sd_initialized_session();
    let first = key_gen(&ready);
    assert_eq!(first.len(), MASKED_TMK_LEN);
    let expected_aad = first[AAD_START..AAD_END].to_vec();
    let mut previous_generated = first;

    for iteration in 0..3 {
        let imported = import_tmk(&ready);
        assert_eq!(imported.len(), MASKED_TMK_LEN);
        assert_eq!(
            &imported[AAD_START..AAD_END],
            expected_aad.as_slice(),
            "iteration {iteration}: imported metadata changed",
        );

        let generated = key_gen(&ready);
        assert_eq!(generated.len(), MASKED_TMK_LEN);
        assert_eq!(
            &generated[AAD_START..AAD_END],
            expected_aad.as_slice(),
            "iteration {iteration}: generated metadata changed",
        );
        assert_ne!(
            generated, previous_generated,
            "iteration {iteration}: generation repeated a previous envelope",
        );
        previous_generated = generated;
    }
}
