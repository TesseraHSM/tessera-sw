// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `EccSign` command.
//!
//! `EccSign` produces a raw ECDSA `r ‖ s` signature over a host-supplied
//! pre-computed digest using a caller-held **masked** ECC private key
//! (from [`EccGenerateKey`](super::ecc_generate_key)). These tests
//! generate a key on-device, sign a digest, and verify the signature on
//! the host with `tsra_crypto` (OpenSSL) against the returned public key
//! — exercising the full unmask → sign → return path for every curve.
//!
//! The device speaks its native crypto byte order on the wire: the
//! public key is `x ‖ y` and the signature is `r ‖ s` (each component at
//! the head of a zero-padded lane of the curve's wire coordinate length;
//! P-521 uses 68-byte lanes on little-endian devices and 72-byte lanes on
//! big-endian ones). `tsra_crypto` is big-endian native, so the test
//! converts each component before verifying. The host verifies the full big-endian
//! digest; ECDSA truncation retains its most significant curve-width bits
//! when the digest is longer than the curve's order.

use tsra_crypto::EccCurve;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::ExportableKey;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::device_is_little_endian;
use tsra_ddi_tbor_test_harness::wire_coord_len;
use tsra_ddi_tbor_test_harness::SessionOpenInitOptions;
use tsra_ddi_tbor_test_harness::SessionSuite;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::ecc_sign_input;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborEccSignReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::ECC_CURVE_P384;
use tsra_ddi_tbor_types::ECC_CURVE_P521;
use tsra_ddi_tbor_types::ECC_SIGN_INPUT_MAX_LEN;
use tsra_ddi_tbor_types::HASH_ALGO_SHA1;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::HASH_ALGO_SHAKE256;
use tsra_ddi_tbor_types::KEY_CLASS_AES;
use tsra_ddi_tbor_types::KEY_CLASS_ECC;
use tsra_ddi_tbor_types::KEY_USAGE_DERIVE;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;

use crate::commands::common::assert_ecc_signs;
use crate::commands::common::assert_masked_key_layout_rejected;
use crate::commands::common::curve_coord_len;
use crate::commands::common::sign;
use crate::commands::common::sign_req;
use crate::commands::common::verify_wire_ecdsa;
use crate::commands::common::with_generated_ecc_key;
use crate::commands::common::CO;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::common::SCOPE_SESSION;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;

/// All supported ECC curves used by command tests.
pub(crate) const ECC_CURVES: [u8; 3] = [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521];

/// `KeyScope::Unspecified` discriminant.
const SCOPE_UNSPECIFIED: u8 = 0b000;

/// `KeyScope::Internal` discriminant.
const SCOPE_INTERNAL: u8 = 0b101;

/// Generate an ECC key on-device for `curve` under `scope`.
fn generate_in_scope(ctx: &TestCtx, session_id: u16, scope: u8, curve: u8) -> (Vec<u8>, Vec<u8>) {
    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope,
            curve,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");
    (resp.masked_key, resp.pub_key)
}

/// Signs and verifies a curve-appropriate digest on every supported ECC curve.
#[test]
fn ecc_sign_roundtrip_all_curves() {
    for (curve, digest_len) in [
        (ECC_CURVE_P256, 32usize),
        (ECC_CURVE_P384, 48usize),
        (ECC_CURVE_P521, 64usize),
    ] {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            assert_ecc_signs(ctx, session_id, masked_key, &pub_key, digest_len);
        });
    }
}

/// Verifies every supported ECC curve and SHA-2 digest-length pairing.
#[test]
fn ecc_sign_all_supported_curve_digest_pairs() {
    for (curve, digest_lens) in [
        (ECC_CURVE_P256, &[32usize, 48, 64][..]),
        (ECC_CURVE_P384, &[32usize, 48, 64][..]),
        (ECC_CURVE_P521, &[32usize, 48, 64][..]),
    ] {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            for &digest_len in digest_lens {
                let digest: Vec<u8> = (0..digest_len)
                    .map(|i| (i as u8).wrapping_mul(13).wrapping_add(0x29))
                    .collect();
                let signature = sign(ctx, session_id, curve, masked_key.clone(), &digest);
                assert!(
                    verify_wire_ecdsa(&pub_key, &signature, &digest),
                    "signature must verify for curve {curve} with a {digest_len}-byte digest",
                );
            }
        });
    }
}

/// Confirms a signature authenticates only the digest that was actually signed.
#[test]
fn ecc_sign_signature_rejects_different_digest() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest = vec![0x31; 32];
            let signature = sign(ctx, session_id, curve, masked_key, &digest);

            let different_digest = vec![0x32; 32];
            assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
            assert!(
                !verify_wire_ecdsa(&pub_key, &signature, &different_digest),
                "signature must not verify against a different digest",
            );
        });
    }
}

/// Confirms distinct digest request values produce signatures bound to each digest.
#[test]
fn ecc_sign_distinct_digests_are_independently_verified() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest_a = vec![0x11; 32];
            let digest_b = vec![0x22; 32];

            let signature_a = sign(ctx, session_id, curve, masked_key.clone(), &digest_a);

            let signature_b = sign(ctx, session_id, curve, masked_key, &digest_b);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature_a, &digest_a),
                "first signature must verify against its original digest",
            );

            assert!(
                verify_wire_ecdsa(&pub_key, &signature_b, &digest_b),
                "second signature must verify against its original digest",
            );

            assert!(
                !verify_wire_ecdsa(&pub_key, &signature_a, &digest_b),
                "first signature must not verify against the second digest",
            );

            assert!(
                !verify_wire_ecdsa(&pub_key, &signature_b, &digest_a),
                "second signature must not verify against the first digest",
            );
        });
    }
}

/// Signs and verifies a digest containing zero-valued bytes.
#[test]
fn ecc_sign_digest_with_zero_bytes_roundtrip() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let mut digest = vec![0u8; 32];
            digest[1] = 0xA5;
            digest[15] = 0x5A;
            digest[30] = 0xC3;
            let signature = sign(ctx, session_id, curve, masked_key, &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "digest containing zero bytes must survive the TBOR request unchanged",
            );
        });
    }
}

/// Verifies P-521 signatures zero-fill the lane padding after each
/// component (2 bytes on a little-endian device, 6 on a big-endian one).
#[test]
fn ecc_sign_p521_signature_padding_is_zero() {
    with_generated_ecc_key(ECC_CURVE_P521, |ctx, session_id, masked_key, pub_key| {
        let digest = vec![0x43; 64];
        let signature = sign(ctx, session_id, ECC_CURVE_P521, masked_key, &digest);
        let wire = wire_coord_len(66);
        assert_eq!(signature.len(), 2 * wire);
        assert!(
            signature[66..wire].iter().all(|&b| b == 0),
            "r padding must be zero",
        );
        assert!(
            signature[wire + 66..].iter().all(|&b| b == 0),
            "s padding must be zero",
        );
        assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
    });
}

/// Signs and verifies with a key masked under the partition-local scope.

#[test]
fn ecc_sign_local_scoped_key() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);
        let (masked_key, pub_key) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, curve);
        let digest = vec![0x5A; 32];
        let signature = sign(&ctx, session.session_id, curve, masked_key, &digest);
        assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
    }
}

/// Confirms a Crypto-User (`PlainText`) session is authorized to sign.
#[test]
fn ecc_sign_allowed_on_crypto_user_session() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
        let (masked_key, pub_key) =
            generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, curve);
        let digest = vec![0x6B; 32];
        let signature = sign(&ctx, session.session_id, curve, masked_key, &digest);
        assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
    }
}

/// Signs and verifies with an ECC private key imported through `UnwrapKey`.

#[test]
fn ecc_sign_with_unwrapped_key() {
    for (curve, host_curve) in [
        (ECC_CURVE_P256, EccCurve::P256),
        (ECC_CURVE_P384, EccCurve::P384),
        (ECC_CURVE_P521, EccCurve::P521),
    ] {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);
        let host_key = EccPrivateKey::from_curve(host_curve).expect("generate host ECC key");
        let der = host_key.to_vec().expect("PKCS#8 DER export");
        let imported = unwrap(&ctx, session.session_id, KEY_CLASS_ECC, &der);
        assert!(
            !imported.pub_key.is_empty(),
            "an imported ECC key returns a re-derived public key",
        );
        let digest: Vec<u8> = (0..32)
            .map(|i| (i as u8).wrapping_mul(5).wrapping_add(3))
            .collect();
        let signature = sign(
            &ctx,
            session.session_id,
            curve,
            imported.masked_key,
            &digest,
        );
        assert!(
            verify_wire_ecdsa(&imported.pub_key, &signature, &digest),
            "signature from the unwrapped ECC key must verify for curve {curve}",
        );
    }
}

/// Rejects hash algorithms other than SHA-256 / SHA-384 / SHA-512.
#[test]
fn ecc_sign_unsupported_hash_algo_rejected() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, _pub_key| {
            let coord = curve_coord_len(curve);
            for (hash_algo, digest_len) in [
                (HASH_ALGO_SHA1, 20usize),
                (HASH_ALGO_SHAKE256, 32),
                (0xFF, 32),
            ] {
                ctx.expect_fw_reject(
                    &TborEccSignReq {
                        session_id,
                        hash_algo,
                        masked_key: masked_key.clone(),
                        input: ecc_sign_input(coord, wire_coord_len(1), &vec![0xAB; digest_len])
                            .expect("valid ECC layout"),
                    },
                    TborStatus::InvalidArg,
                );
            }
        });
    }
}

/// Rejects a packed input whose length does not match the curve and hash.
#[test]
fn ecc_sign_input_length_mismatch_rejected() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, _pub_key| {
            let coord = curve_coord_len(curve);
            let good = sign_req(session_id, masked_key.clone(), coord, &[0xAB; 32]).input;
            let pad = wire_coord_len(1);
            let long = [good.as_slice(), &vec![0u8; pad]].concat();
            let inputs = [
                Vec::new(),
                good[..good.len() - pad].to_vec(),
                long,
                // A SHA-512 sized input labelled SHA-256.
                ecc_sign_input(coord, pad, &[0xAB; 64]).expect("valid ECC layout"),
            ];
            // Inputs over the field's max_len fail TBOR decode, not the handler.
            for input in inputs
                .into_iter()
                .filter(|input| input.len() <= ECC_SIGN_INPUT_MAX_LEN)
            {
                ctx.expect_fw_reject(
                    &TborEccSignReq {
                        session_id,
                        hash_algo: HASH_ALGO_SHA256,
                        masked_key: masked_key.clone(),
                        input,
                    },
                    TborStatus::InvalidArg,
                );
            }
        });
    }
}

/// Rejects a non-zero byte in the digest lane's padding.
#[test]
fn ecc_sign_nonzero_digest_lane_tail_rejected() {
    with_generated_ecc_key(ECC_CURVE_P521, |ctx, session_id, masked_key, _pub_key| {
        let mut req = sign_req(
            session_id,
            masked_key,
            curve_coord_len(ECC_CURVE_P521),
            &[0xAB; 32],
        );
        *req.input.last_mut().expect("non-empty input") = 1;
        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    });
}

/// Verifies long digests retain their most significant curve-width bits.
#[test]
fn ecc_sign_long_digests_use_most_significant_curve_bits() {
    for (curve, digest_len) in [
        (ECC_CURVE_P256, 48usize),
        (ECC_CURVE_P256, 64usize),
        (ECC_CURVE_P384, 64usize),
    ] {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest: Vec<u8> = (0..digest_len)
                .map(|index| u8::try_from(index).expect("digest byte offset must fit u8"))
                .collect();
            let signature = sign(ctx, session_id, curve, masked_key, &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "long digest signature must verify (curve {curve}, digest {digest_len} B)",
            );

            // The digest is in device byte order: locate its least and most
            // significant bytes accordingly.
            let (low, high) = if device_is_little_endian() {
                (0, digest_len - 1)
            } else {
                (digest_len - 1, 0)
            };
            let mut discarded_bit_changed = digest.clone();
            discarded_bit_changed[low] ^= 0x01;
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &discarded_bit_changed),
                "discarded low digest bits must not affect verification (curve {curve}, digest {digest_len} B)",
            );

            let mut retained_bit_changed = digest;
            retained_bit_changed[high] ^= 0x01;
            assert!(
                !verify_wire_ecdsa(&pub_key, &signature, &retained_bit_changed),
                "changed high digest bits must invalidate the signature (curve {curve}, digest {digest_len} B)",
            );
        });
    }
}

/// Rejects a masked private key whose authenticated ciphertext was modified.
#[test]
fn ecc_sign_tampered_masked_key_rejected() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, mut masked_key, _pub_key| {
            let last = masked_key
                .len()
                .checked_sub(1)
                .expect("masked ECC key must not be empty");
            masked_key[last] ^= 0x01;
            ctx.expect_fw_reject(
                &sign_req(session_id, masked_key, curve_coord_len(curve), &[0x7C; 32]),
                TborStatus::AesGcmDecryptTagDoesNotMatch,
            );
        });
    }
}

/// Rejects a valid masked key whose key class is AES rather than ECC private.

#[test]
fn ecc_sign_wrong_key_class_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let aes = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &[0x54; 32]);

    ctx.expect_fw_reject(
        &sign_req(
            session.session_id,
            aes.masked_key,
            curve_coord_len(ECC_CURVE_P256),
            &[0x65; 32],
        ),
        TborStatus::InvalidKeyType,
    );
}

#[test]
fn ecc_sign_mismatched_session_id_rejected() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, _pub_key| {
            let mismatched_session_id = u16::MAX;

            assert_ne!(
                session_id, mismatched_session_id,
                "test requires a mismatched session id",
            );

            ctx.expect_session_reject(
                &sign_req(
                    mismatched_session_id,
                    masked_key,
                    curve_coord_len(curve),
                    &[0x8D; 32],
                ),
                TborStatus::FileHandleSessionIdDoesNotMatch,
            );
        });
    }
}

/// Rejects `KeyScope::Unspecified` for a caller-generated ECC key.

#[test]
fn ecc_generate_key_unspecified_scope_rejected() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        ctx.expect_fw_reject(
            &TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_UNSPECIFIED,
                curve,
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            },
            TborStatus::UnsupportedKeyScope,
        );
    }
}

/// Rejects the firmware-internal scope for a caller-generated ECC key.

#[test]
fn ecc_generate_key_internal_scope_rejected() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        ctx.expect_fw_reject(
            &TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_INTERNAL,
                curve,
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            },
            TborStatus::UnsupportedKeyScope,
        );
    }
}

/// Confirms a signature does not verify against a different public key.
#[test]
fn ecc_sign_signature_rejects_different_public_key() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let other = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id,
                    scope: SCOPE_SESSION,
                    curve,
                    key_usage: KEY_USAGE_SIGN,
                    key_label: Vec::new(),
                })
                .expect("EccGenerateKey");
            let digest = vec![0x42; 32];
            let signature = sign(ctx, session_id, curve, masked_key, &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "signature must verify against the originating public key",
            );
            assert!(
                !verify_wire_ecdsa(&other.pub_key, &signature, &digest),
                "signature must not verify against a different public key",
            );
        });
    }
}

/// Rejects a session-scoped ECC private key from a replacement session.
#[test]
fn ecc_sign_session_scoped_key_rejected_in_different_session() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session_a = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        let (masked_key, _) = generate_in_scope(&ctx, session_a.session_id, SCOPE_SESSION, curve);
        ctx.session_close(session_a.session_id)
            .expect("close originating CO session");
        let opts =
            SessionOpenInitOptions::new(CO, SessionSuite::EcdhP384).with_psk(&ROTATED_CO_PSK);
        let pending = ctx
            .session_open_init_with_options(opts)
            .expect("open replacement CO session");
        let session_b = ctx
            .session_open_finish(pending)
            .expect("finish replacement CO session");
        ctx.expect_fw_reject(
            &sign_req(
                session_b.session_id,
                masked_key,
                curve_coord_len(curve),
                &[0x91; 32],
            ),
            TborStatus::AesGcmDecryptTagDoesNotMatch,
        );
    }
}

/// Confirms changing one bit of the digest invalidates the signature.
#[test]
fn ecc_sign_signature_rejects_single_bit_digest_change() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest = vec![0xA5; 32];
            let signature = sign(ctx, session_id, curve, masked_key, &digest);
            let mut modified_digest = digest.clone();
            modified_digest[17] ^= 0x01;
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "signature must verify against the original digest",
            );

            assert!(
                !verify_wire_ecdsa(&pub_key, &signature, &modified_digest),
                "changing one digest bit must invalidate the signature",
            );
        });
    }
}

/// Signs and verifies an all-zero SHA-256 digest.
#[test]
fn ecc_sign_all_zero_digest_roundtrip() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest = vec![0u8; 32];
            let signature = sign(ctx, session_id, curve, masked_key, &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "an all-zero 32-byte digest must be signed and verified correctly",
            );
        });
    }
}

/// Signs and verifies a SHA-256 digest containing all 0xFF bytes.
#[test]
fn ecc_sign_all_ones_digest_roundtrip() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest = vec![0xFF; 32];
            let signature = sign(ctx, session_id, curve, masked_key, &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "an all-0xFF digest must be signed and verified correctly",
            );
        });
    }
}

/// Confirms the same masked ECC key can sign multiple digests.
#[test]
fn ecc_sign_masked_key_can_be_reused() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            for value in [0x11u8, 0x22, 0x33] {
                let digest = vec![value; 32];
                let signature = sign(ctx, session_id, curve, masked_key.clone(), &digest);
                assert!(
                    verify_wire_ecdsa(&pub_key, &signature, &digest),
                    "reused masked key must sign digest value {value:#04x}",
                );
            }
        });
    }
}

/// Rejects signing with a derive-only ECC key on every curve.
#[test]
fn ecc_sign_key_without_sign_usage_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for curve in ECC_CURVES {
        let key = ctx
            .tbor(&TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                curve,
                key_usage: KEY_USAGE_DERIVE,
                key_label: Vec::new(),
            })
            .expect("EccGenerateKey (derive)");

        ctx.expect_fw_reject(
            &sign_req(
                session.session_id,
                key.masked_key,
                curve_coord_len(curve),
                &[0x42; 32],
            ),
            TborStatus::InvalidPermissions,
        );
    }
}

/// Rejects a misaligned masked key and one without its padding entry.
#[test]
fn ecc_sign_rejects_bad_masked_key_layout() {
    with_generated_ecc_key(ECC_CURVE_P256, |ctx, session_id, masked_key, _| {
        assert_masked_key_layout_rejected(
            ctx,
            &sign_req(
                session_id,
                masked_key,
                curve_coord_len(ECC_CURVE_P256),
                &[0x42; 32],
            ),
        );
    });
}
