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
