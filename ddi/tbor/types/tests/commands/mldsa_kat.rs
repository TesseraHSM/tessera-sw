// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Known-answer tests for the PQC commands, run through the TBOR wire.
//!
//! These were a standalone `pqc_kat` binary. They belong here: they need a
//! session like every other keyed command, and the harness is the only
//! place that has one. Keeping them as a tool meant duplicating the
//! handshake.
//!
//! Two kinds of check, neither of which needs a key import — the device
//! has no import command and none is required:
//!
//! * **NIST ACVP vectors.** `MlDsaVerify` takes the public key on the
//!   wire, so NIST's known keys, messages and signatures replay directly.
//!   Each positive vector is replayed a second time with a flipped
//!   signature bit, which must be rejected.
//! * **Device/host interop.** Both directions, and only public keys
//!   cross: the device generates and signs while the host verifies with
//!   `tsra_crypto`, an independent implementation, then that host side
//!   generates and signs while the device verifies.

use tsra_crypto::testvectors::mldsa::MLDSA_SIGVER_SHORT_MSG_TEST_VECTORS;
use tsra_crypto::ExportableKey;
use tsra_crypto::ImportableKey;
use tsra_crypto::MlDsaAlgo;
use tsra_crypto::MlDsaPrivateKey;
use tsra_crypto::MlDsaPublicKey;
use tsra_crypto::MlDsaVariant;
use tsra_crypto::PrivateKey;
use tsra_crypto::SignOp;
use tsra_crypto::VerifyOp;
use tsra_ddi_tbor_test_harness::pqc::MlDsaParams;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_44;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_65;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_87;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborMlDsaGenerateKeyReq;
use tsra_ddi_tbor_types::TborMlDsaSignReq;
use tsra_ddi_tbor_types::TborMlDsaVerifyReq;
use tsra_ddi_tbor_types::TborStatus;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// `MlDsaVerify` on the device: `Ok(())` means accepted, the dedicated
/// `MlDsaVerifyFailed` status means a well-formed rejection. Anything
/// else is a transport or argument fault and is not a verdict.
fn device_verify(
    ctx: &TestCtx,
    session_id: u16,
    pub_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> bool {
    match ctx.tbor(&TborMlDsaVerifyReq {
        session_id,
        pub_key: pub_key.to_vec(),
        message: message.to_vec(),
        ctx: context.to_vec(),
        signature: signature.to_vec(),
    }) {
        Ok(_) => true,
        Err(tsra_ddi_interface::DdiError::TborStatus(TborStatus::MlDsaVerifyFailed)) => false,
        Err(e) => panic!("MlDsaVerify transport/argument fault: {e:?}"),
    }
}

/// (1) Replay NIST's vectors, then (2) flip a signature bit on the ones
/// that should pass and replay again — a device that accepted everything
/// would otherwise sail through (1).
#[test]
fn mldsa_nist_acvp_vectors() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // `tsra_crypto` owns the NIST ACVP vectors; this short-message subset
    // is the one whose messages and contexts fit the TBOR inline wire
    // limits, so every entry replays directly through `MlDsaVerify`.
    let vectors = MLDSA_SIGVER_SHORT_MSG_TEST_VECTORS;
    assert!(!vectors.is_empty(), "no NIST vectors were embedded");

    for v in vectors {
        let got = device_verify(&ctx, session.session_id, v.pub_key, v.msg, v.ctx, v.sig);
        assert_eq!(
            got, v.expected_pass,
            "ML-DSA-{}: device said {got}, NIST says {} ({})",
            v.param_set, v.expected_pass, v.reason
        );

        if v.expected_pass {
            let mut bad = v.sig.to_vec();
            let last = bad.len() - 1;
            bad[last] ^= 0x01;
            assert!(
                !device_verify(&ctx, session.session_id, v.pub_key, v.msg, v.ctx, &bad),
                "ML-DSA-{}: device accepted a tampered signature ({})",
                v.param_set,
                v.reason,
            );
        }
    }
}

fn dsa_variant(p: &MlDsaParams) -> MlDsaVariant {
    match p.name {
        "ML-DSA-44" => MlDsaVariant::MlDsa44,
        "ML-DSA-65" => MlDsaVariant::MlDsa65,
        "ML-DSA-87" => MlDsaVariant::MlDsa87,
        other => panic!("unknown parameter set {other}"),
    }
}

/// Device signs, host verifies with the independent `tsra_crypto`
/// implementation. Only the public key crosses, so this needs no
/// unmasking and no key import.
fn dsa_device_to_host(p: &MlDsaParams, rounds: usize) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for round in 0..rounds {
        let key = ctx
            .tbor(&TborMlDsaGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                key_kind: p.key_kind,
            })
            .unwrap_or_else(|e| panic!("MlDsaGenerateKey({}): {e:?}", p.name));

        let message: Vec<u8> = (0..64u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(round as u8))
            .collect();
        let signed = ctx
            .tbor(&TborMlDsaSignReq {
                session_id: session.session_id,
                masked_key: key.masked_key.clone(),
                message: message.clone(),
                ctx: Vec::new(),
            })
            .unwrap_or_else(|e| panic!("MlDsaSign({}): {e:?}", p.name));

        let crypto_pk = MlDsaPublicKey::from_bytes(&key.pub_key).expect("import device pk");
        assert!(
            MlDsaAlgo::new(&[])
                .expect("mldsa engine")
                .verify(&crypto_pk, &message, &signed.signature)
                .expect("crypto verify"),
            "{} round {round}: host rejected a device signature",
            p.name
        );
    }
}

/// Host (independent `tsra_crypto` implementation) signs, device
/// verifies — including a tampered signature the device must reject.
fn dsa_host_to_device(p: &MlDsaParams, rounds: usize) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let variant = dsa_variant(p);

    for round in 0..rounds {
        let xi = [round as u8 ^ 0x5A; 32];
        let crypto_sk = MlDsaPrivateKey::from_seed(variant, &xi).expect("crypto keygen");
        let mut pk = vec![0u8; p.pub_key_len];
        crypto_sk
            .public_key()
            .expect("crypto public key")
            .to_bytes(Some(&mut pk))
            .expect("encode crypto pk");

        let message: Vec<u8> = (0..48u8).map(|i| i.wrapping_add(round as u8)).collect();
        let mut sig = vec![0u8; p.sig_len];
        MlDsaAlgo::new(&[])
            .expect("mldsa engine")
            .sign(&crypto_sk, &message, Some(&mut sig))
            .expect("crypto sign");

        assert!(
            device_verify(&ctx, session.session_id, &pk, &message, &[], &sig),
            "{} round {round}: device rejected a host signature",
            p.name,
        );

        let mut bad = sig.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(
            !device_verify(&ctx, session.session_id, &pk, &message, &[], &bad),
            "{} round {round}: device accepted a tampered host signature",
            p.name,
        );
    }
}

#[test]
fn mldsa_interop_device_to_host_44() {
    dsa_device_to_host(&ML_DSA_44, 3);
}

#[test]
fn mldsa_interop_device_to_host_65() {
    dsa_device_to_host(&ML_DSA_65, 3);
}

#[test]
fn mldsa_interop_device_to_host_87() {
    dsa_device_to_host(&ML_DSA_87, 3);
}

#[test]
fn mldsa_interop_host_to_device_44() {
    dsa_host_to_device(&ML_DSA_44, 3);
}

#[test]
fn mldsa_interop_host_to_device_65() {
    dsa_host_to_device(&ML_DSA_65, 3);
}

#[test]
fn mldsa_interop_host_to_device_87() {
    dsa_host_to_device(&ML_DSA_87, 3);
}
