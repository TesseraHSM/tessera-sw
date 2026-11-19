// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `AesGenerateKey` command.
//!
//! The command generates a random AES key of the requested size and
//! returns it **masked** under the requested scope's masking key — nothing
//! is stored on-device.  Like the other general crypto commands,
//! `AesGenerateKey` is available to both Crypto-Officer and Crypto-User
//! sessions.
//!
//! Coverage:
//! * Happy path per key size (128/192/256) — the masked key has the
//!   expected length (248/264/264 B) and is non-zero; a second call yields
//!   a distinct key.
//! * Every AES masking scope exercised after `PartFinal`: `Session`, `Ephemeral`,
//!   and `Local`; `Session` is also available before finalization.
//! * `SecurityDomain` scope before `CreateSD` → `UnsupportedKeyScope`.
//! * `Ephemeral` scope before `PartFinal` → `InvalidArg`.
//! * Unknown key size → `InvalidArg`.
//! * Exact masked metadata: AES kind, scope, local origin, encrypt/decrypt-only usage,
//!   and the caller's label, including boundary lengths and arbitrary bytes.
//! * Missing, forbidden, mixed, and unknown usage bits → `InvalidPermissions`.

use tsra_crypto::aead_envelope;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_types::TborAesGenerateKeyReq;
use tsra_ddi_tbor_types::AES_KEY_SIZE_128;
use tsra_ddi_tbor_types::AES_KEY_SIZE_192;
use tsra_ddi_tbor_types::AES_KEY_SIZE_256;
use tsra_ddi_tbor_types::KEY_KIND_AES128;
use tsra_ddi_tbor_types::KEY_KIND_AES192;
use tsra_ddi_tbor_types::KEY_KIND_AES256;
use tsra_ddi_tbor_types::KEY_USAGE_DECRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use tsra_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;
use zerocopy::little_endian::U16 as Le16;
use zerocopy::little_endian::U64 as Le64;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::KnownLayout;
use zerocopy::Unaligned;

use crate::commands::common::ENVELOPE_AAD_LEN;
pub(crate) use crate::commands::common::SCOPE_EPHEMERAL;
pub(crate) use crate::commands::common::SCOPE_LOCAL;
pub(crate) use crate::commands::common::SCOPE_SECURITY_DOMAIN;
pub(crate) use crate::commands::common::SCOPE_SESSION;

/// Masked metadata uses vault-attribute bits, not the request's `KEY_USAGE_*` bits.
const KEY_ATTR_LOCAL: u64 = 1 << 5;
const KEY_ATTR_ENCRYPT: u64 = 1 << 10;
const KEY_ATTR_DECRYPT: u64 = 1 << 11;
const KEY_ATTR_SCOPE_SHIFT: u32 = 17;

/// Fixed-layout authenticated metadata through the key-label slot.
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct MaskedKeyMetadataPrefix {
    magic: [u8; 4],
    version: Le16,
    key_kind: u8,
    key_label_len: u8,
    usage_flags: Le64,
    _svn: Le64,
    _owner_seed_id: Le16,
    key_label: [u8; TBOR_KEY_LABEL_MAX_LEN],
}

/// Checks the exact generated AES attributes and caller-supplied label.
pub(crate) fn assert_generated_aes_key(
    masked_key: &[u8],
    scope: u8,
    key_kind: u8,
    key_label: &[u8],
) {
    assert_aes_key_attrs(masked_key, scope, key_kind, key_label, true);
}

/// Checks exact AES metadata for either locally generated or imported keys.
pub(crate) fn assert_aes_key_attrs(
    masked_key: &[u8],
    scope: u8,
    key_kind: u8,
    key_label: &[u8],
    is_local: bool,
) {
    let envelope = aead_envelope::inspect(masked_key).expect("valid masked-key envelope");
    assert!(matches!(envelope.alg, aead_envelope::AeadAlg::AesGcm256));
    assert_eq!(envelope.aad.len(), ENVELOPE_AAD_LEN);
    let (metadata, _) = MaskedKeyMetadataPrefix::ref_from_prefix(envelope.aad)
        .expect("complete masked-key metadata prefix");
    assert_eq!(metadata.magic, *b"MKEY");
    assert_eq!(metadata.version.get(), 1);
    assert_eq!(metadata.key_kind, key_kind, "AES key kind must match");
    let local_attr = if is_local { KEY_ATTR_LOCAL } else { 0 };
    assert_eq!(
        metadata.usage_flags.get(),
        local_attr
            | KEY_ATTR_ENCRYPT
            | KEY_ATTR_DECRYPT
            | (u64::from(scope) << KEY_ATTR_SCOPE_SHIFT),
        "AES key scope, encrypt/decrypt-only usage, and local origin must match",
    );
    assert_eq!(usize::from(metadata.key_label_len), key_label.len());
    assert_eq!(metadata.key_label.get(..key_label.len()), Some(key_label));
    assert!(
        metadata
            .key_label
            .get(key_label.len()..)
            .expect("label fits its metadata slot")
            .iter()
            .all(|&byte| byte == 0),
        "unused label bytes must be zero",
    );
}

/// Masked-key envelope length for a given AES key length: `header(8) ‖
/// iv(16) ‖ aad(192) ‖ pt(key padded to 16 B) ‖ tag(16)`.
fn masked_len(key_len: usize) -> usize {
    8 + 16 + 192 + key_len.next_multiple_of(16) + 16
}

/// Expected AES key length (bytes) for a wire key-size discriminant.
pub(crate) fn key_len_for_size(size: u8) -> usize {
    match size {
        AES_KEY_SIZE_128 => 16,
        AES_KEY_SIZE_192 => 24,
        AES_KEY_SIZE_256 => 32,
        other => panic!("unexpected key-size discriminant {other}"),
    }
}

/// Generate a masked AES key of `(scope, size)` on `session_id`.
pub(crate) fn generate_key(ctx: &TestCtx, session_id: u16, scope: u8, size: u8) -> Vec<u8> {
    let req = generate_key_req(session_id, scope, size);
    let masked_key = ctx.tbor(&req).expect("AesGenerateKey").masked_key;
    let key_kind = match size {
        AES_KEY_SIZE_128 => KEY_KIND_AES128,
        AES_KEY_SIZE_192 => KEY_KIND_AES192,
        AES_KEY_SIZE_256 => KEY_KIND_AES256,
        other => panic!("unexpected key-size discriminant {other}"),
    };
    assert_generated_aes_key(&masked_key, scope, key_kind, &req.key_label);
    masked_key
}

/// Happy path for a `(scope, size)` pair: the masked key has the expected
/// length, is non-zero, and a second call yields a distinct blob.
fn roundtrip(ctx: &TestCtx, session_id: u16, scope: u8, size: u8) {
    let masked = generate_key(ctx, session_id, scope, size);
    assert_eq!(
        masked.len(),
        masked_len(key_len_for_size(size)),
        "masked key length must match the requested AES key size",
    );
    assert!(
        masked.iter().any(|&b| b != 0),
        "masked_key must not be all-zero",
    );

    // Each call samples fresh randomness → a distinct masked blob.
    let masked2 = generate_key(ctx, session_id, scope, size);
    assert_ne!(
        masked, masked2,
        "each generation must yield a distinct masked key",
    );
}

/// Builds a standard AES key-generation request for tests.
fn generate_key_req(session_id: u16, scope: u8, key_size: u8) -> TborAesGenerateKeyReq {
    TborAesGenerateKeyReq {
        session_id,
        scope,
        key_size,
        key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        key_label: b"AES Key".to_vec(),
    }
}

mod tests {
    use tsra_ddi_tbor_types::TborAesEncryptDecryptReq;
    use tsra_ddi_tbor_types::TborStatus;
    use tsra_ddi_tbor_types::AES_MODE_CBC;
    use tsra_ddi_tbor_types::AES_OP_DECRYPT;
    use tsra_ddi_tbor_types::AES_OP_ENCRYPT;
    use tsra_ddi_tbor_types::KEY_USAGE_DERIVE;
    use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
    use tsra_ddi_tbor_types::KEY_USAGE_UNWRAP;
    use tsra_ddi_tbor_types::KEY_USAGE_VERIFY;
    use tsra_ddi_tbor_types::KEY_USAGE_WRAP;

    use super::*;
    use crate::commands::sd_sealing_key_gen::finalized_co_session;

    /// Generates every supported AES size under each masking scope exercised after `PartFinal`.
    #[test]
    fn aes_generate_key_roundtrip_all_sizes_after_part_final() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            for size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
                roundtrip(&ctx, session.session_id, scope, size);
            }
        }
    }

    /// Verifies Session-scoped generation works for every AES size before `PartFinal`.
    #[test]
    fn aes_generate_key_session_scope_all_sizes_before_finalize() {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        for size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
            roundtrip(&ctx, session.session_id, SCOPE_SESSION, size);
        }
    }

    /// Requires exactly ENCRYPT+DECRYPT for every supported size and masking scope.
    /// Each negative keeps the other request attributes valid and has a successful control.
    #[test]
    fn aes_generate_key_rejects_invalid_usage() {
        let valid_usage = KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT;
        let invalid_usages = [
            0,
            KEY_USAGE_ENCRYPT,
            KEY_USAGE_DECRYPT,
            KEY_USAGE_SIGN,
            KEY_USAGE_VERIFY,
            KEY_USAGE_DERIVE,
            KEY_USAGE_WRAP,
            KEY_USAGE_UNWRAP,
            valid_usage | KEY_USAGE_SIGN,
            valid_usage | KEY_USAGE_VERIFY,
            valid_usage | KEY_USAGE_DERIVE,
            valid_usage | KEY_USAGE_WRAP,
            valid_usage | KEY_USAGE_UNWRAP,
            valid_usage | KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
            valid_usage | KEY_USAGE_WRAP | KEY_USAGE_UNWRAP,
            valid_usage | KEY_USAGE_DERIVE | KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
            1 << 7,
            valid_usage | (1 << 7),
            1 << 63,
            valid_usage | (1 << 63),
            u64::MAX,
        ];

        for key_usage in invalid_usages {
            for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
                for key_size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
                    let ctx = TestCtx::new();
                    let session = finalized_co_session(&ctx);
                    let mut req = generate_key_req(session.session_id, scope, key_size);
                    ctx.tbor(&req).expect("valid AES usage must succeed");

                    req.key_usage = key_usage;
                    ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
                }
            }
        }
    }

    /// Preserves empty, short, boundary-length, and binary labels in every AES kind and scope.
    #[test]
    fn aes_generate_key_labels_roundtrip() {
        for key_label in [
            Vec::new(),
            vec![b'L'],
            vec![b'L'; TBOR_KEY_LABEL_MAX_LEN - 1],
            vec![b'L'; TBOR_KEY_LABEL_MAX_LEN],
            vec![0x00, 0x80, 0xff, b'A', 0x00],
        ] {
            for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
                for (key_size, key_kind) in [
                    (AES_KEY_SIZE_128, KEY_KIND_AES128),
                    (AES_KEY_SIZE_192, KEY_KIND_AES192),
                    (AES_KEY_SIZE_256, KEY_KIND_AES256),
                ] {
                    let ctx = TestCtx::new();
                    let session = finalized_co_session(&ctx);
                    let mut req = generate_key_req(session.session_id, scope, key_size);
                    req.key_label.clone_from(&key_label);
                    let resp = ctx.tbor(&req).expect("AES key with a supported label");

                    assert_eq!(
                        resp.masked_key.len(),
                        masked_len(key_len_for_size(key_size))
                    );
                    assert_generated_aes_key(&resp.masked_key, scope, key_kind, &key_label);
                }
            }
        }
    }

    /// Rejects 129-byte labels in firmware, with a successful 128-byte control per case.
    #[test]
    fn aes_generate_key_rejects_oversized_label() {
        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            for key_size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
                let ctx = TestCtx::new();
                let session = finalized_co_session(&ctx);
                let mut req = generate_key_req(session.session_id, scope, key_size);
                req.key_label = vec![b'L'; TBOR_KEY_LABEL_MAX_LEN];
                ctx.tbor(&req)
                    .expect("maximum-length AES label must succeed");

                req.key_label.push(b'L');
                ctx.expect_fw_reject(&req, TborStatus::TborInvalidFixedLength);
            }
        }
    }

    /// Rejects Ephemeral scope before `PartFinal` for every supported AES size.
    #[test]
    fn aes_generate_key_rejects_ephemeral_before_finalize_all_sizes() {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        for key_size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
            let req = generate_key_req(session.session_id, SCOPE_EPHEMERAL, key_size);

            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Rejects Local scope before `PartFinal` for every supported AES size.
    #[test]
    fn aes_generate_key_rejects_local_before_finalize_all_sizes() {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        for key_size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
            let req = generate_key_req(session.session_id, SCOPE_LOCAL, key_size);

            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Rejects SecurityDomain scope for every supported AES key size.
    #[test]
    fn aes_generate_key_rejects_security_domain_scope_all_sizes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for key_size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
            let req = generate_key_req(session.session_id, SCOPE_SECURITY_DOMAIN, key_size);

            ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
        }
    }

    /// Rejects minimum and maximum invalid AES key-size discriminants.
    #[test]
    fn aes_generate_key_rejects_unknown_sizes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for key_size in [0, u8::MAX] {
            let req = generate_key_req(session.session_id, SCOPE_EPHEMERAL, key_size);

            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Rejects key-size discriminants adjacent to the supported AES sizes.
    #[test]
    fn aes_generate_key_rejects_adjacent_invalid_sizes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let valid = [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256];

        let candidates = [
            AES_KEY_SIZE_128.wrapping_sub(1),
            AES_KEY_SIZE_128.wrapping_add(1),
            AES_KEY_SIZE_192.wrapping_sub(1),
            AES_KEY_SIZE_192.wrapping_add(1),
            AES_KEY_SIZE_256.wrapping_sub(1),
            AES_KEY_SIZE_256.wrapping_add(1),
        ];

        for key_size in candidates {
            if valid.contains(&key_size) {
                continue;
            }

            let req = generate_key_req(session.session_id, SCOPE_EPHEMERAL, key_size);

            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Rejects an invalid AES key size across every masking scope exercised after `PartFinal`.
    #[test]
    fn aes_generate_key_rejects_invalid_size_after_part_final_scopes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            let req = generate_key_req(session.session_id, scope, 0);

            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Rejects an invalid AES key size before `PartFinal` for Session scope.
    #[test]
    fn aes_generate_key_rejects_invalid_size_before_finalize() {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        let req = generate_key_req(session.session_id, SCOPE_SESSION, 0);

        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }

    /// Rejects invalid key-scope discriminants across every supported AES size.
    #[test]
    fn aes_generate_key_rejects_invalid_scopes_for_all_sizes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for scope in [0, u8::MAX] {
            for key_size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
                let req = generate_key_req(session.session_id, scope, key_size);

                ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
            }
        }
    }

    /// Rejects a request whose session ID does not match the active file-handle session.
    #[test]
    fn aes_generate_key_rejects_session_id_mismatch() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let mismatched_session_id = session.session_id.wrapping_add(1);

        assert_ne!(
            mismatched_session_id, session.session_id,
            "mismatched session ID must differ from the active session",
        );

        let req = generate_key_req(mismatched_session_id, SCOPE_SESSION, AES_KEY_SIZE_256);

        ctx.expect_session_reject(&req, TborStatus::FileHandleSessionIdDoesNotMatch);
    }

    /// Verifies repeated generations do not reuse an earlier masked-key blob.
    #[test]
    fn aes_generate_key_repeated_generations_are_distinct() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let mut generated = Vec::new();

        for _ in 0..4 {
            let masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, AES_KEY_SIZE_256);

            assert!(
                generated.iter().all(|previous| previous != &masked),
                "each AesGenerateKey call must return a distinct masked key",
            );

            generated.push(masked);
        }
    }

    /// Verifies repeated generation across every AES size on one active session.
    #[test]
    fn aes_generate_key_multiple_sizes_same_session() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for _ in 0..3 {
            for size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
                roundtrip(&ctx, session.session_id, SCOPE_EPHEMERAL, size);
            }
        }
    }

    /// Verifies AES keys generated under each masking scope exercised after `PartFinal` can be
    /// consumed successfully by `AesEncryptDecrypt`.
    #[test]
    fn aes_generate_key_after_part_final_scopes_usable_by_aes_encrypt_decrypt() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let plaintext = vec![0xA5u8; 32];
        let iv = vec![0x11u8; 16];

        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            let masked_key = generate_key(&ctx, session.session_id, scope, AES_KEY_SIZE_256);

            let encrypt_req = TborAesEncryptDecryptReq {
                session_id: session.session_id,
                masked_key: masked_key.clone(),
                op: AES_OP_ENCRYPT,
                mode: AES_MODE_CBC,
                iv: iv.clone(),
                msg: plaintext.clone(),
            };

            let encrypted = ctx.tbor(&encrypt_req).expect("AesEncryptDecrypt encrypt");

            assert_eq!(
                encrypted.msg.len(),
                plaintext.len(),
                "ciphertext length must match plaintext length for scope {scope}",
            );

            assert_ne!(
                encrypted.msg, plaintext,
                "encryption must transform plaintext for scope {scope}",
            );

            let decrypt_req = TborAesEncryptDecryptReq {
                session_id: session.session_id,
                masked_key,
                op: AES_OP_DECRYPT,
                mode: AES_MODE_CBC,
                iv: iv.clone(),
                msg: encrypted.msg,
            };

            let decrypted = ctx.tbor(&decrypt_req).expect("AesEncryptDecrypt decrypt");

            assert_eq!(
                decrypted.msg, plaintext,
                "AES key generated under scope {scope} must decrypt correctly",
            );
        }
    }

    /// Verifies invalid key size takes precedence when both size and scope are invalid.
    #[test]
    fn aes_generate_key_invalid_size_takes_precedence_over_invalid_scope() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let req = generate_key_req(session.session_id, 0, 0);

        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }

    /// Rejects the firmware-reserved `Internal` key-scope discriminant (0b101).
    #[test]
    fn aes_generate_key_rejects_internal_scope() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let req = generate_key_req(
            session.session_id,
            SCOPE_SECURITY_DOMAIN + 1,
            AES_KEY_SIZE_256,
        );

        ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
    }
}
