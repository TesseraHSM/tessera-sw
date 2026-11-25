// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for message-level TBOR `EcdsaVerify`.

use tsra_crypto::EccAlgo;
use tsra_crypto::EccCurve;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::Hasher;
use tsra_crypto::Signer;
use tsra_ddi_tbor_test_harness::dev_rev;
use tsra_ddi_tbor_test_harness::device_is_little_endian;
use tsra_ddi_tbor_test_harness::wire_coord_len;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborEcdsaSignReq;
use tsra_ddi_tbor_types::TborEcdsaVerifyReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::ECC_CURVE_P384;
use tsra_ddi_tbor_types::ECC_CURVE_P521;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::KEY_CLASS_ECC;
use tsra_ddi_tbor_types::KEY_USAGE_DERIVE;

use crate::commands::common::with_generated_ecc_key;
use crate::commands::ecc_sign::ECC_CURVES;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;

fn host_signature_to_wire(signature: &[u8], raw_len: usize, lane_len: usize) -> Vec<u8> {
    assert_eq!(signature.len(), raw_len * 2);
    let r = dev_rev(&signature[..raw_len]);
    let s = dev_rev(&signature[raw_len..]);
    let mut wire = vec![0; lane_len * 2];
    wire[..raw_len].copy_from_slice(&r);
    wire[lane_len..lane_len + raw_len].copy_from_slice(&s);
    wire
}

#[test]
fn ecdsa_verify_accepts_device_signature_over_raw_oob_message() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, _| {
            let message = b"verify exactly the raw OOB bytes";
            let sign = ctx
                .tbor_oob(
                    &TborEcdsaSignReq {
                        session_id,
                        masked_key: masked_key.clone(),
                        hash_algo: HASH_ALGO_SHA256,
                        message_index: 0,
                        message_len: message.len() as u16,
                    },
                    &[message],
                )
                .expect("EcdsaSign");
            let verify = TborEcdsaVerifyReq {
                session_id,
                masked_key: masked_key.clone(),
                hash_algo: HASH_ALGO_SHA256,
                message_index: 0,
                message_len: message.len() as u16,
                signature: sign.signature.clone(),
            };
            ctx.tbor_oob(&verify, &[message]).unwrap_or_else(|error| {
                panic!("EcdsaVerify accepts valid signature for curve {curve}: {error}")
            });

            let mut changed_signature = verify.signature.clone();
            changed_signature[0] ^= 1;
            ctx.expect_fw_reject_oob(
                &TborEcdsaVerifyReq {
                    signature: changed_signature,
                    ..verify.clone()
                },
                &[message],
                TborStatus::EccVerifyFailed,
            );
            ctx.expect_fw_reject_oob(
                &TborEcdsaVerifyReq {
                    signature: verify.signature[..verify.signature.len() - 1].to_vec(),
                    ..verify.clone()
                },
                &[message],
                TborStatus::InvalidArg,
            );

            let changed = b"verify exactly the raw OOB byteS";
            ctx.expect_fw_reject_oob(
                &TborEcdsaVerifyReq {
                    message_len: changed.len() as u16,
                    ..verify
                },
                &[changed],
                TborStatus::EccVerifyFailed,
            );
        });
    }
}

#[test]
fn ecdsa_verify_rejects_nonzero_p521_component_padding() {
    with_generated_ecc_key(ECC_CURVES[2], |ctx, session_id, masked_key, _| {
        let message = b"check P-521 padded signature lanes";
        let signed = ctx
            .tbor_oob(
                &TborEcdsaSignReq {
                    session_id,
                    masked_key: masked_key.clone(),
                    hash_algo: HASH_ALGO_SHA256,
                    message_index: 0,
                    message_len: message.len() as u16,
                },
                &[message],
            )
            .expect("EcdsaSign");
        let lane_len = signed.signature.len() / 2;
        assert!(lane_len > 66);
        let mut malformed = signed.signature;
        malformed[66] = 1;
        ctx.expect_fw_reject_oob(
            &TborEcdsaVerifyReq {
                session_id,
                masked_key,
                hash_algo: HASH_ALGO_SHA256,
                message_index: 0,
                message_len: message.len() as u16,
                signature: malformed,
            },
            &[message],
            TborStatus::InvalidArg,
        );
    });
}

#[test]
fn ecdsa_verify_accepts_independent_host_signatures_for_all_curves_and_hashes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let curves = [
        (ECC_CURVE_P256, EccCurve::P256, 32),
        (ECC_CURVE_P384, EccCurve::P384, 48),
        (ECC_CURVE_P521, EccCurve::P521, 66),
    ];
    let hashes = [
        (tsra_ddi_tbor_types::HASH_ALGO_SHA256, HashAlgo::sha256()),
        (tsra_ddi_tbor_types::HASH_ALGO_SHA384, HashAlgo::sha384()),
        (tsra_ddi_tbor_types::HASH_ALGO_SHA512, HashAlgo::sha512()),
    ];
    let message = b"host-generated ECDSA signature over asymmetric bytes \0 and tail";

    for (curve_id, curve, raw_len) in curves {
        let private = EccPrivateKey::from_curve(curve).expect("host ECC key");
        let der = private.to_vec().expect("export host ECC key");
        let imported = unwrap(&ctx, session.session_id, KEY_CLASS_ECC, &der);
        let lane_len = if raw_len == 66 && !device_is_little_endian() {
            72
        } else {
            wire_coord_len(raw_len)
        };
        for (hash_id, mut hash_algo) in hashes.iter().cloned() {
            let digest = Hasher::hash_vec(&mut hash_algo, message).expect("host message hash");
            let signature = Signer::sign_vec(&mut EccAlgo::default(), &private, &digest)
                .expect("independent host ECDSA signature");
            let wire_signature = host_signature_to_wire(&signature, raw_len, lane_len);
            ctx.tbor_oob(
                &TborEcdsaVerifyReq {
                    session_id: session.session_id,
                    masked_key: imported.masked_key.clone(),
                    hash_algo: hash_id,
                    message_index: 0,
                    message_len: message.len() as u16,
                    signature: wire_signature,
                },
                &[message],
            )
            .unwrap_or_else(|error| {
                panic!(
                    "EcdsaVerify rejected host signature for curve {curve_id}, hash {hash_id}: {error}"
                )
            });
        }
    }

    ctx.session_close(session.session_id)
        .expect("session close should succeed");
}

#[test]
fn ecdsa_verify_rejects_derive_only_keys() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let derive_only = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: crate::commands::common::SCOPE_SESSION,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_DERIVE,
            key_label: Vec::new(),
        })
        .expect("derive-only ECC key generation");
    ctx.expect_fw_reject_oob(
        &TborEcdsaVerifyReq {
            session_id: session.session_id,
            masked_key: derive_only.masked_key,
            hash_algo: tsra_ddi_tbor_types::HASH_ALGO_SHA256,
            message_index: 0,
            message_len: 0,
            signature: vec![0; 64],
        },
        &[],
        TborStatus::InvalidPermissions,
    );
    ctx.session_close(session.session_id)
        .expect("session close should succeed");
}

#[test]
fn ecdsa_verify_accepts_empty_message_without_oob_item() {
    with_generated_ecc_key(ECC_CURVES[0], |ctx, session_id, masked_key, _| {
        let sign = ctx
            .tbor_oob(
                &TborEcdsaSignReq {
                    session_id,
                    masked_key: masked_key.clone(),
                    hash_algo: HASH_ALGO_SHA256,
                    message_index: 0,
                    message_len: 0,
                },
                &[],
            )
            .expect("empty-message EcdsaSign");
        ctx.tbor_oob(
            &TborEcdsaVerifyReq {
                session_id,
                masked_key,
                hash_algo: HASH_ALGO_SHA256,
                message_index: 0,
                message_len: 0,
                signature: sign.signature,
            },
            &[],
        )
        .expect("empty-message EcdsaVerify");
    });
}

#[test]
fn ecdsa_verify_rejects_invalid_oob_references_and_lengths() {
    with_generated_ecc_key(ECC_CURVES[0], |ctx, session_id, masked_key, _| {
        let message = b"descriptor check";
        let sign = ctx
            .tbor_oob(
                &TborEcdsaSignReq {
                    session_id,
                    masked_key: masked_key.clone(),
                    hash_algo: HASH_ALGO_SHA256,
                    message_index: 0,
                    message_len: message.len() as u16,
                },
                &[message],
            )
            .expect("EcdsaSign");
        let request = |message_index, message_len| TborEcdsaVerifyReq {
            session_id,
            masked_key: masked_key.clone(),
            hash_algo: HASH_ALGO_SHA256,
            message_index,
            message_len,
            signature: sign.signature.clone(),
        };
        ctx.expect_fw_reject_oob(&request(0, 1), &[], TborStatus::InvalidArg);
        ctx.expect_fw_reject_oob(
            &request(1, message.len() as u16),
            &[message],
            TborStatus::InvalidArg,
        );
        ctx.expect_fw_reject_oob(
            &request(0, message.len() as u16 + 1),
            &[message],
            TborStatus::InvalidArg,
        );
        ctx.expect_fw_reject_oob(
            &request(0, message.len() as u16 - 1),
            &[message],
            TborStatus::InvalidArg,
        );
        ctx.expect_fw_reject_oob(&request(1, 0), &[], TborStatus::InvalidArg);
    });
}

#[test]
fn ecdsa_verify_rejects_oversized_message_before_oob_read() {
    with_generated_ecc_key(ECC_CURVES[0], |ctx, session_id, masked_key, _| {
        ctx.expect_fw_reject_oob(
            &TborEcdsaVerifyReq {
                session_id,
                masked_key,
                hash_algo: HASH_ALGO_SHA256,
                message_index: 0,
                message_len: 8193,
                signature: vec![0; 64],
            },
            &[],
            TborStatus::InvalidArg,
        );
    });
}
