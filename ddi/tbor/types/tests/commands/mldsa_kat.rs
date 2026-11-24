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
//!   wire, so NIST's known keys and signatures replay directly, over the
//!   `μ` of each message, computed on the host.
//!   Each positive vector is replayed a second time with a flipped
//!   signature bit, which must be rejected.
//! * **Device/host interop.** Both directions, and only public keys
//!   cross: the device generates and signs while the host verifies with
//!   `tsra_crypto`, an independent implementation, then that host side
//!   generates and signs while the device verifies.

use tsra_crypto::testvectors::mldsa::MLDSA_SIGVER_SHORT_MSG_TEST_VECTORS;
use tsra_crypto::testvectors::mldsa::MLDSA_SIGVER_TEST_VECTORS;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::Hasher;
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
use tsra_ddi_tbor_types::MLDSA_HEDGE_PREFERRED;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// The `μ` of `message` under `context` and `pub_key`, computed on the
/// host: the input `MlDsaSign` and `MlDsaVerify` take.
fn host_mu(pub_key: &[u8], context: &[u8], message: &[u8]) -> Vec<u8> {
    MlDsaPublicKey::from_bytes(pub_key)
        .and_then(|pk| HashAlgo::mldsa_mu(&pk, context))
        .and_then(|mut algo| Hasher::hash_vec(&mut algo, message))
        .expect("host mu")
}

/// `MlDsaVerify` on the device, over the `μ` of `message` under `context`:
/// `Ok(())` means accepted, the dedicated `MlDsaVerifyFailed` status means
/// a well-formed rejection. Anything else is a transport or argument fault
/// and is not a verdict.
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
        mu: host_mu(pub_key, context, message),
        signature: signature.to_vec(),
    }) {
        Ok(_) => true,
        Err(tsra_ddi_interface::DdiError::TborStatus(TborStatus::MlDsaVerifyFailed)) => false,
        Err(e) => panic!("MlDsaVerify transport/argument fault: {e:?}"),
    }
}

/// Generate a host key and sign a message under the requested context.
fn host_sign_case(
    p: &MlDsaParams,
    seed: [u8; 32],
    message: &[u8],
    context: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let sk = MlDsaPrivateKey::from_seed(dsa_variant(p), &seed).expect("host keygen");

    let mut pk = vec![0u8; p.pub_key_len];
    sk.public_key()
        .expect("host public key")
        .to_bytes(Some(&mut pk))
        .expect("encode public key");

    let mut sig = vec![0u8; p.sig_len];
    MlDsaAlgo::new(context)
        .expect("host ML-DSA engine")
        .sign(&sk, message, Some(&mut sig))
        .expect("host sign");

    (pk, sig)
}

/// (1) Replay NIST's vectors, then (2) flip a signature bit on the ones
/// that should pass and replay again — a device that accepted everything
/// would otherwise sail through (1).
#[test]
fn mldsa_nist_acvp_vectors() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // `tsra_crypto` owns the NIST ACVP vectors.  The wire carries `μ`
    // rather than the message, so messages of any length replay.
    assert!(
        !MLDSA_SIGVER_TEST_VECTORS.is_empty() && !MLDSA_SIGVER_SHORT_MSG_TEST_VECTORS.is_empty(),
        "no NIST vectors were embedded"
    );

    for v in MLDSA_SIGVER_TEST_VECTORS
        .iter()
        .chain(MLDSA_SIGVER_SHORT_MSG_TEST_VECTORS)
    {
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
                mu: host_mu(&key.pub_key, &[], &message),
                hedge: MLDSA_HEDGE_PREFERRED,
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

/// Verify signatures bind to the exact message and context.
fn dsa_message_context_binding(p: &MlDsaParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let message = b"ML-DSA message binding";
    let context = b"tbor-pqc-context";

    let (pk, sig) = host_sign_case(p, [0x42; 32], message, context);

    // Original message and context must verify.
    assert!(
        device_verify(&ctx, session.session_id, &pk, message, context, &sig,),
        "{}: valid signature rejected",
        p.name,
    );

    // Changing one message bit must invalidate the signature.
    let mut changed = message.to_vec();
    changed[0] ^= 0x01;

    assert!(
        !device_verify(&ctx, session.session_id, &pk, &changed, context, &sig,),
        "{}: modified message accepted",
        p.name,
    );

    // The correct message with a different context must fail.
    assert!(
        !device_verify(
            &ctx,
            session.session_id,
            &pk,
            message,
            b"other-context",
            &sig,
        ),
        "{}: wrong context accepted",
        p.name,
    );

    // Removing the original context must also fail.
    assert!(
        !device_verify(&ctx, session.session_id, &pk, message, b"", &sig,),
        "{}: missing context accepted",
        p.name,
    );

    // A failed verification must not corrupt session state.
    assert!(
        device_verify(&ctx, session.session_id, &pk, message, context, &sig,),
        "{}: valid verification failed after rejections",
        p.name,
    );
}

/// Check message and context binding for ML-DSA-44.
#[test]
fn mldsa_message_context_binding_44() {
    dsa_message_context_binding(&ML_DSA_44);
}

/// Check message and context binding for ML-DSA-65.
#[test]
fn mldsa_message_context_binding_65() {
    dsa_message_context_binding(&ML_DSA_65);
}

/// Check message and context binding for ML-DSA-87.
#[test]
fn mldsa_message_context_binding_87() {
    dsa_message_context_binding(&ML_DSA_87);
}

/// Reject valid signatures when verified under another public key.
fn dsa_wrong_public_key(p: &MlDsaParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let message = b"ML-DSA public key binding";

    let (pk_a, sig_a) = host_sign_case(p, [0x11; 32], message, b"");

    let (pk_b, sig_b) = host_sign_case(p, [0x22; 32], message, b"");

    assert_ne!(
        pk_a, pk_b,
        "{}: distinct seeds produced identical public keys",
        p.name,
    );

    // Each signature must verify under its matching key.
    assert!(
        device_verify(&ctx, session.session_id, &pk_a, message, b"", &sig_a,),
        "{}: signature A rejected",
        p.name,
    );

    assert!(
        device_verify(&ctx, session.session_id, &pk_b, message, b"", &sig_b,),
        "{}: signature B rejected",
        p.name,
    );

    // Swapping the keys must cause verification failure.
    assert!(
        !device_verify(&ctx, session.session_id, &pk_b, message, b"", &sig_a,),
        "{}: signature A accepted under key B",
        p.name,
    );

    assert!(
        !device_verify(&ctx, session.session_id, &pk_a, message, b"", &sig_b,),
        "{}: signature B accepted under key A",
        p.name,
    );

    // Both correct pairs must remain valid after rejection.
    for (pk, sig) in [(&pk_a, &sig_a), (&pk_b, &sig_b)] {
        assert!(
            device_verify(&ctx, session.session_id, pk, message, b"", sig,),
            "{}: valid pair failed after key mismatch",
            p.name,
        );
    }
}

/// Reject public-key substitution for ML-DSA-44.
#[test]
fn mldsa_wrong_public_key_44() {
    dsa_wrong_public_key(&ML_DSA_44);
}

/// Reject public-key substitution for ML-DSA-65.
#[test]
fn mldsa_wrong_public_key_65() {
    dsa_wrong_public_key(&ML_DSA_65);
}

/// Reject public-key substitution for ML-DSA-87.
#[test]
fn mldsa_wrong_public_key_87() {
    dsa_wrong_public_key(&ML_DSA_87);
}

/// Verify empty and boundary-length messages through host/device interop.
fn dsa_message_lengths(p: &MlDsaParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let lengths = [0usize, 1, 2, 31, 32, 63, 64, 65, 127, 128, 255, 256, 1024];

    for (case, len) in lengths.into_iter().enumerate() {
        let message: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(17)).collect();

        let seed = [case as u8 ^ 0xA5; 32];

        let (pk, sig) = host_sign_case(p, seed, &message, b"");

        assert!(
            device_verify(&ctx, session.session_id, &pk, &message, b"", &sig,),
            "{}: verification failed for message length {len}",
            p.name,
        );

        // Changing the message length must invalidate the signature.
        let mut extended = message.clone();
        extended.push(0xA5);

        assert!(
            !device_verify(&ctx, session.session_id, &pk, &extended, b"", &sig,),
            "{}: accepted signature for extended message length {len}",
            p.name,
        );
    }
}

/// Exercise empty and boundary-length messages for ML-DSA-44.
#[test]
fn mldsa_message_lengths_44() {
    dsa_message_lengths(&ML_DSA_44);
}

/// Exercise empty and boundary-length messages for ML-DSA-65.
#[test]
fn mldsa_message_lengths_65() {
    dsa_message_lengths(&ML_DSA_65);
}

/// Exercise empty and boundary-length messages for ML-DSA-87.
#[test]
fn mldsa_message_lengths_87() {
    dsa_message_lengths(&ML_DSA_87);
}

/// Verify repeated requests and recovery after signature rejection.
fn dsa_repeated_verification(p: &MlDsaParams) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let message = b"ML-DSA repeated verification";
    let (pk, sig) = host_sign_case(p, [0x77; 32], message, b"");

    let mut bad_sig = sig.clone();
    let middle = bad_sig.len() / 2;
    bad_sig[middle] ^= 0x01;

    for round in 0..10 {
        assert!(
            device_verify(&ctx, session.session_id, &pk, message, b"", &sig,),
            "{} round {round}: valid signature rejected",
            p.name,
        );

        assert!(
            !device_verify(&ctx, session.session_id, &pk, message, b"", &bad_sig,),
            "{} round {round}: corrupted signature accepted",
            p.name,
        );

        assert!(
            device_verify(&ctx, session.session_id, &pk, message, b"", &sig,),
            "{} round {round}: recovery failed",
            p.name,
        );
    }
}

/// Verify repeated requests and rejection recovery for ML-DSA-44.
#[test]
fn mldsa_repeated_verification_44() {
    dsa_repeated_verification(&ML_DSA_44);
}

/// Verify repeated requests and rejection recovery for ML-DSA-65.
#[test]
fn mldsa_repeated_verification_65() {
    dsa_repeated_verification(&ML_DSA_65);
}

/// Verify repeated requests and rejection recovery for ML-DSA-87.
#[test]
fn mldsa_repeated_verification_87() {
    dsa_repeated_verification(&ML_DSA_87);
}
