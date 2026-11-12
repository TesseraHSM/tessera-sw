// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Masking must accept payloads that are not a whole number of AES
//! blocks.
//!
//! The HSM AES engine rejects any CTR length that is not a multiple of 16
//! with `0x08f09005` (`AesError::CMD_ERROR`), so the PAL's GCM never
//! hands it a partial block, and every masked key length must succeed.
//! Before that, masking failed for every non-aligned payload: odd HMAC
//! key lengths, P-521 scalars and every RSA private key.
//!
//! `HmacGenerateKey` is the probe because its `key_length` is free-form,
//! so it can mask an arbitrary size on demand. Nothing here is specific
//! to HMAC.
//!
//! Gated **out** of the emulator rather than into it. The constraint is
//! a property of the HSM AES engine; the emulator's software AES has no
//! such limit, so running this there would prove nothing.

use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborHmacGenerateKeyReq;
use tsra_ddi_tbor_types::HMAC_HASH_SHA256;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

use crate::commands::common::SCOPE_LOCAL;

/// AES block size; the granularity the engine demands.
const AES_BLOCK_SIZE: u8 = 16;

/// Valid `key_length` range for HMAC-SHA-256.
const SHA256_KEY_LEN_RANGE: core::ops::RangeInclusive<u8> = 32..=64;

#[test]
fn masking_accepts_partial_blocks() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let rejected: Vec<_> = SHA256_KEY_LEN_RANGE
        .filter_map(|key_length| {
            ctx.tbor(&TborHmacGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                hash_algo: HMAC_HASH_SHA256,
                key_length,
                key_label: Vec::new(),
            })
            .err()
            .map(|e| (key_length, e))
        })
        .collect();

    assert!(
        rejected.is_empty(),
        "every HMAC-SHA-256 key length must mask, including those that are \
         not a multiple of the {AES_BLOCK_SIZE}-byte AES block: {rejected:?}"
    );
}

/// Generate an HMAC-SHA-256 key and assert that masking succeeds.
fn assert_masking_succeeds(ctx: &TestCtx, session_id: u16, key_length: u8, key_label: &[u8]) {
    let result = ctx.tbor(&TborHmacGenerateKeyReq {
        session_id,
        scope: SCOPE_LOCAL,
        hash_algo: HMAC_HASH_SHA256,
        key_length,
        key_label: key_label.to_vec(),
    });

    assert!(
        result.is_ok(),
        "masking failed for key_length={key_length}, \
         remainder={}, label_length={}: {result:?}",
        key_length % AES_BLOCK_SIZE,
        key_label.len(),
    );
}

/// Verify all 16 possible AES block remainders.
///
/// The existing exhaustive test covers these indirectly.
/// This test makes the alignment requirement explicit.
#[test]
fn masking_accepts_every_aes_block_remainder() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for remainder in 0..AES_BLOCK_SIZE {
        let key_length = 32 + remainder;

        assert_masking_succeeds(&ctx, session.session_id, key_length, &[]);
    }
}

/// Verify lengths immediately before, at, and after
/// AES block boundaries.
#[test]
fn masking_accepts_aes_block_boundaries() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for key_length in [32u8, 33, 47, 48, 49, 63, 64] {
        assert_masking_succeeds(&ctx, session.session_id, key_length, &[]);
    }
}

/// Verify that repeated non-aligned masking operations
/// do not corrupt the session or AES engine state.
#[test]
fn masking_accepts_repeated_partial_blocks() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for _ in 0..5 {
        for key_length in [33u8, 47, 49, 63] {
            assert_masking_succeeds(&ctx, session.session_id, key_length, &[]);
        }
    }
}

/// Verify alternating aligned and non-aligned key lengths.
///
/// This checks that processing a partial block does not
/// interfere with a subsequent aligned operation.
#[test]
fn masking_accepts_alternating_aligned_lengths() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for key_length in [32u8, 33, 32, 47, 48, 49, 48, 63, 64, 63, 64] {
        assert_masking_succeeds(&ctx, session.session_id, key_length, &[]);
    }
}

/// Verify that different key label lengths do not
/// interfere with masking non-aligned keys.
#[test]
fn masking_accepts_partial_blocks_with_labels() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for key_length in [33u8, 47, 49, 63] {
        for label_length in [0usize, 1, 15, 16, 17, 31] {
            let label = vec![0xAB; label_length];

            assert_masking_succeeds(&ctx, session.session_id, key_length, &label);
        }
    }
}

/// Verify that partial-block masking works across
/// independently initialized finalized sessions.
#[test]
fn masking_accepts_partial_blocks_across_sessions() {
    for key_length in [33u8, 47, 49, 63] {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        assert_masking_succeeds(&ctx, session.session_id, key_length, &[]);
    }
}

/// Verify that masking still succeeds after processing
/// several different non-aligned payload lengths.
#[test]
fn masking_accepts_mixed_partial_block_lengths() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for key_length in [
        33u8, 63, 35, 61, 37, 59, 39, 57, 41, 55, 43, 53, 45, 51, 47, 49, 32, 48, 64,
    ] {
        assert_masking_succeeds(&ctx, session.session_id, key_length, &[]);
    }
}

#[test]
fn masking_sock_diagnostic() {
    let ctx = TestCtx::new();

    println!("STEP 1: Creating finalized session");
    let session = finalized_co_session(&ctx);

    println!("STEP 2: Session created: {}", session.session_id);

    for key_length in [32u8, 33, 47, 48, 49, 63, 64] {
        println!(
            "STEP 3: Testing key_length={}, remainder={}",
            key_length,
            key_length % AES_BLOCK_SIZE
        );

        let result = ctx.tbor(&TborHmacGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HMAC_HASH_SHA256,
            key_length,
            key_label: Vec::new(),
        });

        println!(
            "RESULT: key_length={}, success={}, error={:?}",
            key_length,
            result.is_ok(),
            result.as_ref().err()
        );
    }
}
