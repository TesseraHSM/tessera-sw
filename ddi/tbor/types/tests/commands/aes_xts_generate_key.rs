// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `AesXtsGenerateKey` command.
//!
//! `AesXtsGenerateKey` generates a double-wide AES-256-XTS key
//! (`K1 ‖ K2`, 64 bytes) and returns it as a single masked blob
//! ([`MASKED_AES_XTS_KEY_LEN`] bytes); nothing is persisted on-device.
//!
//! Coverage:
//! * Generation succeeds for Session / Ephemeral / Local scopes after
//!   `PartFinal`, with the expected masked length and fresh randomness.
//! * Session scope works before `PartFinal`; Ephemeral / Local are
//!   rejected before `PartFinal`.
//! * Usage other than encrypt + decrypt is rejected.
//! * An invalid session id is rejected.

use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborAesXtsGenerateKeyReq;
use tsra_ddi_tbor_types::KEY_USAGE_DECRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use tsra_ddi_tbor_types::MASKED_AES_XTS_KEY_LEN;

/// Builds an `AesXtsGenerateKey` request with encrypt + decrypt usage.
pub(crate) fn generate_xts_key_req(session_id: u16, scope: u8) -> TborAesXtsGenerateKeyReq {
    TborAesXtsGenerateKeyReq {
        session_id,
        scope,
        key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        key_label: b"AES XTS Key".to_vec(),
    }
}

/// Generates a masked AES-XTS key of `scope` on `session_id`.
pub(crate) fn generate_xts_key(ctx: &TestCtx, session_id: u16, scope: u8) -> Vec<u8> {
    ctx.tbor(&generate_xts_key_req(session_id, scope))
        .expect("AesXtsGenerateKey")
        .masked_key
}

/// Happy path: expected length, non-zero, and a fresh blob per call.
fn roundtrip(ctx: &TestCtx, session_id: u16, scope: u8) {
    let masked = generate_xts_key(ctx, session_id, scope);
    assert_eq!(masked.len(), MASKED_AES_XTS_KEY_LEN);
    assert!(
        masked.iter().any(|&b| b != 0),
        "masked_key must not be all-zero"
    );
    let masked2 = generate_xts_key(ctx, session_id, scope);
    assert_ne!(
        masked, masked2,
        "each generation must yield a distinct masked key"
    );
}

mod tests {
    use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
    use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
    use tsra_ddi_tbor_types::TborStatus;

    use super::*;
    use crate::commands::aes_generate_key::SCOPE_EPHEMERAL;
    use crate::commands::aes_generate_key::SCOPE_LOCAL;
    use crate::commands::aes_generate_key::SCOPE_SESSION;
    use crate::commands::sd_sealing_key_gen::finalized_co_session;

    /// Generates an XTS key under each masking scope after `PartFinal`.
    #[test]
    fn aes_xts_generate_key_roundtrip_all_scopes_after_part_final() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);
        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            roundtrip(&ctx, session.session_id, scope);
        }
    }

    /// Session scope works before `PartFinal`.
    #[test]
    fn aes_xts_generate_key_session_scope_before_finalize() {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        roundtrip(&ctx, session.session_id, SCOPE_SESSION);
    }

    /// Ephemeral and Local scopes are rejected before `PartFinal`.
    #[test]
    fn aes_xts_generate_key_rejects_non_session_scope_before_finalize() {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        for scope in [SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            let req = generate_xts_key_req(session.session_id, scope);
            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Any usage other than exactly encrypt + decrypt is rejected.
    #[test]
    fn aes_xts_generate_key_rejects_invalid_usage() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);
        for usage in [0, KEY_USAGE_ENCRYPT, KEY_USAGE_DECRYPT, 1 << 2] {
            let req = TborAesXtsGenerateKeyReq {
                key_usage: usage,
                ..generate_xts_key_req(session.session_id, SCOPE_LOCAL)
            };
            ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
        }
    }

    /// A request bound to an unknown session id is rejected.
    #[test]
    fn aes_xts_generate_key_rejects_invalid_session() {
        let ctx = TestCtx::new();
        let _session = finalized_co_session(&ctx);
        let req = generate_xts_key_req(u16::MAX, SCOPE_LOCAL);
        ctx.expect_fw_reject(&req, TborStatus::FileHandleSessionIdDoesNotMatch);
    }
}
