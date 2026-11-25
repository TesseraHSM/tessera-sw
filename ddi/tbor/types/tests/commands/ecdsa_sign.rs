// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for message-level TBOR `EcdsaSign`.

use tsra_crypto::HashAlgo;
use tsra_crypto::Hasher;
use tsra_ddi_tbor_test_harness::dev_rev;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborEcdsaSignReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::HASH_ALGO_SHA1;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::HASH_ALGO_SHA384;
use tsra_ddi_tbor_types::HASH_ALGO_SHA512;
use tsra_ddi_tbor_types::KEY_USAGE_DERIVE;

use crate::commands::common::verify_wire_ecdsa;
use crate::commands::common::with_generated_ecc_key;
use crate::commands::ecc_sign::ECC_CURVES;
use crate::commands::sd_sealing_key_gen::finalized_co_session;

#[test]
fn ecdsa_sign_hashes_oob_message_for_all_curves_and_hashes() {
    let hashes = [
        (HASH_ALGO_SHA256, HashAlgo::sha256()),
        (HASH_ALGO_SHA384, HashAlgo::sha384()),
        (HASH_ALGO_SHA512, HashAlgo::sha512()),
    ];
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            for (hash_id, mut hash_algo) in hashes.iter().cloned() {
                let message = b"asymmetric ECDSA message bytes \0 with a final tail";
                let req = TborEcdsaSignReq {
                    session_id,
                    masked_key: masked_key.clone(),
                    hash_algo: hash_id,
                    message_index: 0,
                    message_len: message.len() as u16,
                };
                let response = ctx
                    .tbor_oob(&req, &[message])
                    .expect("EcdsaSign over OOB message");
                assert!(
                    response.signature.len() == pub_key.len()
                        || (pub_key.len() == 132 && response.signature.len() == 144),
                    "signature length must match the curve's padded component lanes"
                );

                let digest = Hasher::hash_vec(&mut hash_algo, message).expect("host hash");
                assert!(
                    verify_wire_ecdsa(&pub_key, &response.signature, &dev_rev(&digest)),
                    "signature must verify over the original raw message"
                );
            }
        });
    }
}

#[test]
fn ecdsa_sign_accepts_empty_message_without_oob_item() {
    with_generated_ecc_key(ECC_CURVES[0], |ctx, session_id, masked_key, _| {
        let response = ctx
            .tbor_oob(
                &TborEcdsaSignReq {
                    session_id,
                    masked_key,
                    hash_algo: HASH_ALGO_SHA256,
                    message_index: 0,
                    message_len: 0,
                },
                &[],
            )
            .expect("empty-message EcdsaSign");
        assert_eq!(response.signature.len(), 64);
    });
}

#[test]
fn ecdsa_sign_rejects_oversized_message_before_oob_read() {
    with_generated_ecc_key(ECC_CURVES[0], |ctx, session_id, masked_key, _| {
        let req = TborEcdsaSignReq {
            session_id,
            masked_key,
            hash_algo: HASH_ALGO_SHA256,
            message_index: 0,
            message_len: 8193,
        };
        ctx.expect_fw_reject_oob(&req, &[], TborStatus::InvalidArg);
    });
}

#[test]
fn ecdsa_sign_hashes_message_boundaries() {
    with_generated_ecc_key(ECC_CURVES[0], |ctx, session_id, masked_key, pub_key| {
        for len in [
            0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1023, 1024, 1025, 4095, 4096, 4097,
            8191, 8192,
        ] {
            let message: Vec<u8> = (0..len)
                .map(|index| (index as u8).wrapping_mul(37).wrapping_add(0x5B))
                .collect();
            let oob = if message.is_empty() {
                Vec::new()
            } else {
                vec![message.as_slice()]
            };
            let response = ctx
                .tbor_oob(
                    &TborEcdsaSignReq {
                        session_id,
                        masked_key: masked_key.clone(),
                        hash_algo: HASH_ALGO_SHA256,
                        message_index: 0,
                        message_len: len as u16,
                    },
                    &oob,
                )
                .unwrap_or_else(|error| {
                    panic!("EcdsaSign failed at message length {len}: {error}")
                });
            let digest = Hasher::hash_vec(&mut HashAlgo::sha256(), &message).expect("host hash");
            assert!(
                verify_wire_ecdsa(&pub_key, &response.signature, &dev_rev(&digest)),
                "signature must verify over the original {len}-byte message"
            );
        }
    });
}

#[test]
fn ecdsa_sign_rejects_invalid_oob_references_and_lengths() {
    with_generated_ecc_key(ECC_CURVES[0], |ctx, session_id, masked_key, _| {
        let request = |message_index, message_len| TborEcdsaSignReq {
            session_id,
            masked_key: masked_key.clone(),
            hash_algo: HASH_ALGO_SHA256,
            message_index,
            message_len,
        };
        ctx.expect_fw_reject_oob(&request(0, 1), &[], TborStatus::InvalidArg);
        ctx.expect_fw_reject_oob(&request(1, 1), &[b"x"], TborStatus::InvalidArg);
        ctx.expect_fw_reject_oob(&request(0, 2), &[b"x"], TborStatus::InvalidArg);
        ctx.expect_fw_reject_oob(&request(0, 1), &[b"xy"], TborStatus::InvalidArg);
        ctx.expect_fw_reject_oob(&request(1, 0), &[], TborStatus::InvalidArg);
        ctx.expect_fw_reject_oob(
            &TborEcdsaSignReq {
                hash_algo: HASH_ALGO_SHA1,
                ..request(0, 1)
            },
            &[b"x"],
            TborStatus::InvalidArg,
        );
        ctx.expect_fw_reject_oob(
            &TborEcdsaSignReq {
                hash_algo: 0xFF,
                ..request(0, 1)
            },
            &[b"x"],
            TborStatus::InvalidArg,
        );
    });
}

#[test]
fn ecdsa_sign_requires_sign_permission() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let response = ctx
        .tbor(&tsra_ddi_tbor_types::TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: crate::commands::common::SCOPE_SESSION,
            curve: ECC_CURVES[0],
            key_usage: KEY_USAGE_DERIVE,
            key_label: Vec::new(),
        })
        .expect("derive-only ECC key generation");
    ctx.expect_fw_reject_oob(
        &TborEcdsaSignReq {
            session_id: session.session_id,
            masked_key: response.masked_key,
            hash_algo: HASH_ALGO_SHA256,
            message_index: 0,
            message_len: 0,
        },
        &[],
        TborStatus::InvalidPermissions,
    );
    ctx.session_close(session.session_id)
        .expect("session close should succeed");
}
