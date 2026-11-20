// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `EccVerify` command.

use tsra_crypto::testvectors::ecc::ECC_P256_TEST_VECTORS;
use tsra_crypto::testvectors::ecc::ECC_P384_TEST_VECTORS;
use tsra_crypto::testvectors::ecc::ECC_P521_TEST_VECTORS;
use tsra_crypto::DerEccSignature;
use tsra_crypto::EccAlgo;
use tsra_crypto::EccCurve;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::ExportableKey;
use tsra_crypto::Signer;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::dev_rev;
use tsra_ddi_tbor_test_harness::device_is_little_endian;
use tsra_ddi_tbor_test_harness::wire_coord_len;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::ecc_sign_input;
use tsra_ddi_tbor_types::TborAesGenerateKeyReq;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborEccSignReq;
use tsra_ddi_tbor_types::TborEccVerifyReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::ECC_CURVE_P384;
use tsra_ddi_tbor_types::ECC_CURVE_P521;
use tsra_ddi_tbor_types::HASH_ALGO_SHA1;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::HASH_ALGO_SHA384;
use tsra_ddi_tbor_types::HASH_ALGO_SHA512;
use tsra_ddi_tbor_types::KEY_CLASS_ECC;
use tsra_ddi_tbor_types::KEY_USAGE_DECRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_DERIVE;
use tsra_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;

use crate::commands::common::assert_masked_key_layout_rejected;
use crate::commands::common::SCOPE_SESSION;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;

fn verify_req(
    session_id: u16,
    hash_algo: u8,
    masked_key: Vec<u8>,
    input: Vec<u8>,
) -> TborEccVerifyReq {
    TborEccVerifyReq {
        session_id,
        hash_algo,
        masked_key,
        input,
    }
}

fn raw_coord_len(curve: u8) -> usize {
    match curve {
        ECC_CURVE_P256 => 32,
        ECC_CURVE_P384 => 48,
        ECC_CURVE_P521 => 66,
        _ => unreachable!("test uses supported curves"),
    }
}

fn packed_input(curve: u8, digest: &[u8], signature: &[u8]) -> Vec<u8> {
    let sign_coord_len = wire_coord_len(raw_coord_len(curve));
    let verify_coord_len = if curve == ECC_CURVE_P521 && !device_is_little_endian() {
        72
    } else {
        sign_coord_len
    };
    assert_eq!(signature.len(), sign_coord_len * 2);

    let mut input = vec![0; verify_coord_len * 2];
    for (index, component) in signature.chunks_exact(sign_coord_len).enumerate() {
        let start = index * verify_coord_len;
        input[start..start + sign_coord_len].copy_from_slice(component);
    }

    let digest_lane_len = digest
        .len()
        .next_multiple_of(if device_is_little_endian() { 4 } else { 8 })
        .max(verify_coord_len);
    let mut digest_lane = digest.to_vec();
    digest_lane.resize(digest_lane_len, 0);
    input.extend_from_slice(&digest_lane);
    input
}

fn sign_digest(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: Vec<u8>,
    digest: &[u8],
    curve: u8,
) -> Vec<u8> {
    ctx.tbor(&TborEccSignReq {
        session_id,
        masked_key,
        hash_algo: match digest.len() {
            32 => HASH_ALGO_SHA256,
            48 => HASH_ALGO_SHA384,
            64 => HASH_ALGO_SHA512,
            _ => unreachable!("test uses SHA-2 digests"),
        },
        input: ecc_sign_input(
            wire_coord_len(raw_coord_len(curve)),
            if device_is_little_endian() { 4 } else { 8 },
            digest,
        )
        .expect("valid ECC sign input"),
    })
    .expect("EccSign")
    .signature
}

/// Verify fixed NIST signatures, independently of device signing.
#[test]
fn ecc_verify_known_answer_vectors() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for (curve, wire_curve, vectors) in [
        (EccCurve::P256, ECC_CURVE_P256, ECC_P256_TEST_VECTORS),
        (EccCurve::P384, ECC_CURVE_P384, ECC_P384_TEST_VECTORS),
        (EccCurve::P521, ECC_CURVE_P521, ECC_P521_TEST_VECTORS),
    ] {
        let vector = vectors.first().expect("NIST vector for each curve");
        let imported = unwrap(
            &ctx,
            session.session_id,
            KEY_CLASS_ECC,
            vector.private_key_der,
        );
        let signature =
            DerEccSignature::from_der(curve, vector.sig_der).expect("parse NIST signature");
        let mut signature_wire = Vec::new();
        for component in [signature.r(), signature.s()] {
            let mut lane = dev_rev(component);
            lane.resize(wire_coord_len(component.len()), 0);
            signature_wire.extend(lane);
        }
        let hash_algo = match vector.digest.len() {
            32 => HASH_ALGO_SHA256,
            48 => HASH_ALGO_SHA384,
            64 => HASH_ALGO_SHA512,
            _ => panic!("selected NIST vector must use SHA-2"),
        };
        let mut digest_wire = dev_rev(vector.digest);
        ctx.tbor(&verify_req(
            session.session_id,
            hash_algo,
            imported.masked_key.clone(),
            packed_input(wire_curve, &digest_wire, &signature_wire),
        ))
        .expect("verify NIST known-answer signature");

        let retained_byte = if device_is_little_endian() {
            digest_wire.len() - 1
        } else {
            0
        };
        digest_wire[retained_byte] ^= 1;
        ctx.expect_fw_reject(
            &verify_req(
                session.session_id,
                hash_algo,
                imported.masked_key,
                packed_input(wire_curve, &digest_wire, &signature_wire),
            ),
            TborStatus::EccVerifyFailed,
        );
    }
}

/// Exercises all curve and SHA-2 combinations with generated sign-only keys.
#[test]
fn ecc_verify_all_curve_hash_pairs() {
    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        for (hash_algo, digest_len) in [
            (HASH_ALGO_SHA256, 32),
            (HASH_ALGO_SHA384, 48),
            (HASH_ALGO_SHA512, 64),
        ] {
            let ctx = TestCtx::new();
            let session = finalized_co_session(&ctx);
            let generated = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id: session.session_id,
                    scope: SCOPE_SESSION,
                    curve,
                    key_usage: KEY_USAGE_SIGN,
                    key_label: Vec::new(),
                })
                .expect("EccGenerateKey");
            let digest: Vec<u8> = (0..digest_len)
                .map(|index| (index as u8).wrapping_mul(17).wrapping_add(0x35))
                .collect();
            let digest_wire = dev_rev(&digest);
            let signature = sign_digest(
                &ctx,
                session.session_id,
                generated.masked_key.clone(),
                &digest_wire,
                curve,
            );
            let input = packed_input(curve, &digest_wire, &signature);

            ctx.tbor(&verify_req(
                session.session_id,
                hash_algo,
                generated.masked_key.clone(),
                input,
            ))
            .unwrap_or_else(|error| {
                panic!("EccVerify failed for curve {curve}, hash {hash_algo}: {error:?}")
            });

            // The request only unmasks its DMA-backed copy; the caller's
            // original masked envelope remains reusable.
            sign_digest(
                &ctx,
                session.session_id,
                generated.masked_key,
                &digest_wire,
                curve,
            );
        }
    }
}

/// Aligned masked-key fields reject misalignment and noncanonical layouts.
#[test]
fn ecc_verify_rejects_bad_masked_key_layout() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let generated = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");
    let digest = [0x23; 32];
    let signature = sign_digest(
        &ctx,
        session.session_id,
        generated.masked_key.clone(),
        &digest,
        ECC_CURVE_P256,
    );
    let req = verify_req(
        session.session_id,
        HASH_ALGO_SHA256,
        generated.masked_key,
        packed_input(ECC_CURVE_P256, &digest, &signature),
    );
    assert_masked_key_layout_rejected(&ctx, &req);
}

/// Invalid signatures produce `EccVerifyFailed`, and a later valid request
/// succeeds in the same session.
#[test]
fn ecc_verify_invalid_signature_then_recovers() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let generated = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");
    let digest = [0x51; 32];
    let signature = sign_digest(
        &ctx,
        session.session_id,
        generated.masked_key.clone(),
        &digest,
        ECC_CURVE_P256,
    );
    let mut input = packed_input(ECC_CURVE_P256, &digest, &signature);
    input[0] ^= 0x80;
    ctx.expect_fw_reject(
        &verify_req(
            session.session_id,
            HASH_ALGO_SHA256,
            generated.masked_key.clone(),
            input,
        ),
        TborStatus::EccVerifyFailed,
    );

    let input = packed_input(ECC_CURVE_P256, &digest, &signature);
    ctx.tbor(&verify_req(
        session.session_id,
        HASH_ALGO_SHA256,
        generated.masked_key,
        input,
    ))
    .expect("valid verification after invalid signature");
}

/// Verifies an independently generated host signature using an imported
/// private key, then rejects nonzero P-521 component padding.
#[test]
fn ecc_verify_host_signature_and_p521_padding() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = EccPrivateKey::from_curve(EccCurve::P256).expect("generate host ECC key");
    let der = key.to_vec().expect("export private key");
    let imported = unwrap(&ctx, session.session_id, KEY_CLASS_ECC, &der);
    let digest_be: Vec<u8> = (0..48)
        .map(|index| (index as u8).wrapping_mul(11).wrapping_add(0x27))
        .collect();
    let signature_be =
        Signer::sign_vec(&mut EccAlgo::default(), &key, &digest_be).expect("host ECDSA signature");
    let coord_len = 32;
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(&dev_rev(&signature_be[..coord_len]));
    signature.extend_from_slice(&dev_rev(&signature_be[coord_len..]));
    let digest_wire = dev_rev(&digest_be);
    ctx.tbor(&verify_req(
        session.session_id,
        HASH_ALGO_SHA384,
        imported.masked_key.clone(),
        packed_input(ECC_CURVE_P256, &digest_wire, &signature),
    ))
    .expect("verify host-generated signature with imported key");
    let mut discarded_bit_change = digest_be.clone();
    discarded_bit_change[47] ^= 1;
    let discarded_wire = dev_rev(&discarded_bit_change);
    ctx.tbor(&verify_req(
        session.session_id,
        HASH_ALGO_SHA384,
        imported.masked_key.clone(),
        packed_input(ECC_CURVE_P256, &discarded_wire, &signature),
    ))
    .expect("discarded SHA-384 bits do not affect P-256 ECDSA");
    let mut retained_bit_change = digest_be;
    retained_bit_change[0] ^= 1;
    let retained_wire = dev_rev(&retained_bit_change);
    ctx.expect_fw_reject(
        &verify_req(
            session.session_id,
            HASH_ALGO_SHA384,
            imported.masked_key,
            packed_input(ECC_CURVE_P256, &retained_wire, &signature),
        ),
        TborStatus::EccVerifyFailed,
    );

    let generated = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            curve: ECC_CURVE_P521,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("generate P-521 key");
    let digest = [0x6B; 64];
    let signature = sign_digest(
        &ctx,
        session.session_id,
        generated.masked_key.clone(),
        &digest,
        ECC_CURVE_P521,
    );
    let mut input = packed_input(ECC_CURVE_P521, &digest, &signature);
    input[66] = 1;
    ctx.expect_fw_reject(
        &verify_req(
            session.session_id,
            HASH_ALGO_SHA512,
            generated.masked_key.clone(),
            input,
        ),
        TborStatus::InvalidArg,
    );
    let mut input = packed_input(ECC_CURVE_P521, &digest, &signature);
    let verify_coord = if device_is_little_endian() { 68 } else { 72 };
    input[verify_coord * 2 + digest.len()] = 1;
    ctx.expect_fw_reject(
        &verify_req(
            session.session_id,
            HASH_ALGO_SHA512,
            generated.masked_key,
            input,
        ),
        TborStatus::InvalidArg,
    );
}

/// Unsupported hashes and malformed packed lengths are rejected before
/// entering the backend.
#[test]
fn ecc_verify_rejects_unsupported_hash_and_input_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let generated = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");
    let digest = [0x19; 32];
    let signature = sign_digest(
        &ctx,
        session.session_id,
        generated.masked_key.clone(),
        &digest,
        ECC_CURVE_P256,
    );
    let mut input = packed_input(ECC_CURVE_P256, &digest, &signature);

    ctx.expect_fw_reject(
        &verify_req(
            session.session_id,
            HASH_ALGO_SHA1,
            generated.masked_key.clone(),
            input.clone(),
        ),
        TborStatus::InvalidArg,
    );

    input.push(0);
    ctx.expect_fw_reject(
        &verify_req(
            session.session_id,
            HASH_ALGO_SHA256,
            generated.masked_key,
            input,
        ),
        TborStatus::InvalidArg,
    );
}

/// Derive-only private keys cannot be used for verification.
#[test]
fn ecc_verify_rejects_derive_only_key() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let generated = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_DERIVE,
            key_label: Vec::new(),
        })
        .expect("generate derive-only key");

    ctx.expect_fw_reject(
        &verify_req(
            session.session_id,
            HASH_ALGO_SHA256,
            generated.masked_key,
            vec![0; 96],
        ),
        TborStatus::InvalidPermissions,
    );
}

/// Non-ECC key kinds are rejected before usage permission checks.
#[test]
fn ecc_verify_rejects_non_ecc_key_kind() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let generated = ctx
        .tbor(&TborAesGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            key_size: tsra_ddi_tbor_types::AES_KEY_SIZE_256,
            key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
            key_label: Vec::new(),
        })
        .expect("generate AES key");

    ctx.expect_fw_reject(
        &verify_req(
            session.session_id,
            HASH_ALGO_SHA256,
            generated.masked_key,
            vec![0; 96],
        ),
        TborStatus::InvalidKeyType,
    );
}

/// The request is available to CO and CU sessions.
#[test]
fn ecc_verify_crypto_user_session() {
    let ctx = TestCtx::new();
    let cu = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let generated_cu = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: cu.session_id,
            scope: SCOPE_SESSION,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey in CU session");
    let cu_digest = [0xA7; 32];
    let cu_signature = sign_digest(
        &ctx,
        cu.session_id,
        generated_cu.masked_key.clone(),
        &cu_digest,
        ECC_CURVE_P256,
    );
    ctx.tbor(&verify_req(
        cu.session_id,
        HASH_ALGO_SHA256,
        generated_cu.masked_key,
        packed_input(ECC_CURVE_P256, &cu_digest, &cu_signature),
    ))
    .expect("EccVerify in CU session");
}
