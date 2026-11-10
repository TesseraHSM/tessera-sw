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
        ctx.expect_session_reject(&req, TborStatus::FileHandleSessionIdDoesNotMatch);
    }

    /// A zero session id is accepted after PartFinal and
    /// generates a valid masked AES-XTS key.
    #[test]
    fn aes_xts_generate_key_accepts_zero_session_id() {
        let ctx = TestCtx::new();
        let _session = finalized_co_session(&ctx);

        let req = generate_xts_key_req(0, SCOPE_LOCAL);

        let resp = ctx
            .tbor(&req)
            .expect("AesXtsGenerateKey with zero session id");

        assert_eq!(resp.masked_key.len(), MASKED_AES_XTS_KEY_LEN,);

        assert!(
            resp.masked_key.iter().any(|&b| b != 0),
            "masked key must not be all-zero"
        );
    }

    /// Additional usage bits must be rejected even when both
    /// required encrypt and decrypt permissions are present.
    #[test]
    fn aes_xts_generate_key_rejects_extra_usage_bits() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let valid_usage = KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT;

        for extra_bit in [1 << 2, 1 << 3, 1 << 4] {
            let req = TborAesXtsGenerateKeyReq {
                key_usage: valid_usage | extra_bit,
                ..generate_xts_key_req(session.session_id, SCOPE_LOCAL)
            };

            ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
        }
    }

    /// Repeated generation must produce distinct masked blobs.
    #[test]
    fn aes_xts_generate_key_multiple_generations_are_unique() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let mut generated = Vec::new();

        for _ in 0..16 {
            let masked = generate_xts_key(&ctx, session.session_id, SCOPE_LOCAL);

            assert_eq!(masked.len(), MASKED_AES_XTS_KEY_LEN);

            assert!(
                masked.iter().any(|&b| b != 0),
                "generated masked key must not be all-zero"
            );

            assert!(
                !generated.contains(&masked),
                "duplicate masked key generated"
            );

            generated.push(masked);
        }
    }

    /// Generating keys across different scopes must succeed
    /// without interfering with subsequent generation.
    #[test]
    fn aes_xts_generate_key_interleaved_scopes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let scopes = [
            SCOPE_SESSION,
            SCOPE_LOCAL,
            SCOPE_EPHEMERAL,
            SCOPE_LOCAL,
            SCOPE_SESSION,
            SCOPE_EPHEMERAL,
        ];

        let mut generated = Vec::new();

        for scope in scopes {
            let masked = generate_xts_key(&ctx, session.session_id, scope);

            assert_eq!(
                masked.len(),
                MASKED_AES_XTS_KEY_LEN,
                "unexpected masked key length for scope={scope}"
            );

            assert!(
                !generated.contains(&masked),
                "duplicate masked blob for scope={scope}"
            );

            generated.push(masked);
        }
    }

    /// Key generation must accept different non-empty labels.
    #[test]
    fn aes_xts_generate_key_accepts_different_labels() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let labels: [&[u8]; 4] = [
            b"A",
            b"AES XTS Key",
            b"XTS test key 123",
            b"XTS_key_with_symbols_-_",
        ];

        for label in labels {
            let req = TborAesXtsGenerateKeyReq {
                key_label: label.to_vec(),
                ..generate_xts_key_req(session.session_id, SCOPE_LOCAL)
            };

            let resp = ctx.tbor(&req).expect("AesXtsGenerateKey with custom label");

            assert_eq!(
                resp.masked_key.len(),
                MASKED_AES_XTS_KEY_LEN,
                "unexpected masked key length for label={label:?}"
            );
        }
    }

    /// An invalid usage request must not prevent subsequent
    /// valid AES-XTS key generation.
    #[test]
    fn aes_xts_generate_key_recovers_after_invalid_usage() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let valid_before = generate_xts_key(&ctx, session.session_id, SCOPE_LOCAL);

        let invalid_req = TborAesXtsGenerateKeyReq {
            key_usage: 0,
            ..generate_xts_key_req(session.session_id, SCOPE_LOCAL)
        };

        ctx.expect_fw_reject(&invalid_req, TborStatus::InvalidPermissions);

        let valid_after = generate_xts_key(&ctx, session.session_id, SCOPE_LOCAL);

        assert_eq!(valid_before.len(), MASKED_AES_XTS_KEY_LEN);
        assert_eq!(valid_after.len(), MASKED_AES_XTS_KEY_LEN);

        assert_ne!(
            valid_before, valid_after,
            "generation after invalid request returned identical masked blob"
        );
    }

    /// Generation should accept an empty key label if supported.
    #[test]
    fn aes_xts_generate_key_empty_label() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let req = TborAesXtsGenerateKeyReq {
            key_label: Vec::new(),
            ..generate_xts_key_req(session.session_id, SCOPE_LOCAL)
        };

        let resp = ctx.tbor(&req).expect("AesXtsGenerateKey with empty label");

        assert_eq!(resp.masked_key.len(), MASKED_AES_XTS_KEY_LEN);
    }

    /// Generation should support labels containing arbitrary bytes.
    #[test]
    fn aes_xts_generate_key_binary_label() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let req = TborAesXtsGenerateKeyReq {
            key_label: vec![0x00, 0x01, 0x7F, 0x80, 0xFF],
            ..generate_xts_key_req(session.session_id, SCOPE_LOCAL)
        };

        let resp = ctx.tbor(&req).expect("AesXtsGenerateKey with binary label");

        assert_eq!(resp.masked_key.len(), MASKED_AES_XTS_KEY_LEN);
    }

    /// Repeated generation with the same label should produce
    /// distinct masked key blobs.
    #[test]
    fn aes_xts_generate_key_same_label_produces_distinct_blobs() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let req = generate_xts_key_req(session.session_id, SCOPE_LOCAL);

        let first = ctx.tbor(&req).expect("first AesXtsGenerateKey").masked_key;

        let second = ctx.tbor(&req).expect("second AesXtsGenerateKey").masked_key;

        assert_eq!(first.len(), MASKED_AES_XTS_KEY_LEN);
        assert_eq!(second.len(), MASKED_AES_XTS_KEY_LEN);

        assert_ne!(
            first, second,
            "repeated generation returned identical masked blobs"
        );
    }

    /// An invalid scope should not prevent a subsequent
    /// valid key generation.
    #[test]
    fn aes_xts_generate_key_recovers_after_invalid_scope() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let invalid_req = generate_xts_key_req(session.session_id, u8::MAX);

        let result = ctx.tbor(&invalid_req);

        assert!(result.is_err(), "invalid scope unexpectedly succeeded");

        let valid = generate_xts_key(&ctx, session.session_id, SCOPE_LOCAL);

        assert_eq!(valid.len(), MASKED_AES_XTS_KEY_LEN);
    }

    /// Generating keys with different labels should succeed
    /// independently within the same session.
    #[test]
    fn aes_xts_generate_key_multiple_labels_same_session() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let mut generated = Vec::new();

        for index in 0..8 {
            let req = TborAesXtsGenerateKeyReq {
                key_label: format!("XTS Key {index}").into_bytes(),
                ..generate_xts_key_req(session.session_id, SCOPE_LOCAL)
            };

            let masked = ctx
                .tbor(&req)
                .expect("AesXtsGenerateKey with indexed label")
                .masked_key;

            assert_eq!(masked.len(), MASKED_AES_XTS_KEY_LEN);

            assert!(
                !generated.contains(&masked),
                "duplicate masked blob for index={index}"
            );

            generated.push(masked);
        }
    }
}
