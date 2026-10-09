// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pins the CP1 AES engine's block-alignment constraint on CTR.
//!
//! The engine rejects any CTR length that is not a multiple of 16 with
//! `0x08f09005` (`AesError::CMD_ERROR`), even though the driver
//! deliberately exempts CTR from its own block-multiple check --
//! correctly, in the abstract, since CTR is a stream cipher. See
//! known-issues 2.4 for the full decode.
//!
//! This asserts the **current, defective** behaviour, so it fails the
//! moment the engine (or the CTR path feeding it) starts accepting
//! partial blocks. That is the intent: whoever fixes it should be told
//! by a red test, not discover later that a constraint quietly lifted.
//! On fix, invert the assertion -- every length in the range should
//! succeed -- and drop this note.
//!
//! `HmacGenerateKey` is the probe because its `key_length` is free-form,
//! so it can mask an arbitrary size on demand. Nothing here is specific
//! to HMAC; the same constraint is why `EccGenerateKey` on P-521 (a
//! 66-byte scalar) cannot work on silicon.
//!
//! Gated **out** of the emulator rather than into it. The constraint is
//! a property of the CP1 AES engine; the emulator's software AES has no
//! such limit and accepts every length, so running this there would fail
//! on behaviour that is actually correct. It is the hardware backends
//! that must keep asserting it -- an emu-only version would pass while
//! proving nothing, which is how the defect survived in the first place.
#![cfg(not(feature = "emu"))]

use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborHmacGenerateKeyReq;
use tsra_ddi_tbor_types::HMAC_HASH_SHA256;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local`.
const SCOPE_LOCAL: u8 = 0b011;

/// AES block size; the granularity the engine demands.
const AES_BLOCK_SIZE: u8 = 16;

/// Valid `key_length` range for HMAC-SHA-256.
const SHA256_KEY_LEN_RANGE: core::ops::RangeInclusive<u8> = 32..=64;

#[test]
fn aes_ctr_accepts_only_whole_blocks() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let mut accepted = Vec::new();
    let mut rejected = Vec::new();

    for key_length in SHA256_KEY_LEN_RANGE {
        let outcome = ctx.tbor(&TborHmacGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HMAC_HASH_SHA256,
            key_length,
            key_label: Vec::new(),
        });

        match outcome {
            Ok(_) => accepted.push(key_length),
            Err(_) => rejected.push(key_length),
        }
    }

    let expected_accepted: Vec<u8> = SHA256_KEY_LEN_RANGE
        .filter(|n| n % AES_BLOCK_SIZE == 0)
        .collect();

    assert_eq!(
        accepted, expected_accepted,
        "only block-aligned key lengths should be accepted while \
         known-issue 2.4 is open; if the non-aligned lengths now \
         succeed the engine constraint has been lifted and this test \
         should be inverted (accepted={accepted:?} rejected={rejected:?})"
    );
    assert!(
        !rejected.is_empty(),
        "expected the non-aligned lengths to be rejected"
    );
}
