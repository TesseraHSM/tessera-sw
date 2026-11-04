// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `MlDsaSign` / `MlDsaVerify` over the message representative `μ`.
//!
//! `μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)`, with
//! `tr = SHAKE256(pk, 64)`, is what pure ML-DSA signs for a message `M` under
//! a context string `ctx`, and the commands take it in place of the message,
//! as `EccSign` takes a digest. These tests check that a signature over `μ`
//! is a pure signature over `M` and `ctx` in both directions, against an
//! independent host implementation (`tsra_crypto`); replay NIST's
//! external-`μ` vectors; compute `μ` on the device itself with `Hash`
//! (SHAKE256); and pin the length of `μ`.

use tsra_crypto::testvectors::mldsa::MLDSA_EXTERNAL_MU_SIGVER_TEST_VECTORS;
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
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::pqc::MlDsaParams;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_44;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_65;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_87;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborHashReq;
use tsra_ddi_tbor_types::TborMlDsaGenerateKeyReq;
use tsra_ddi_tbor_types::TborMlDsaSignReq;
use tsra_ddi_tbor_types::TborMlDsaVerifyReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::HASH_ALGO_SHAKE256;
use tsra_ddi_tbor_types::MLDSA_HEDGE_PREFERRED;
use tsra_ddi_tbor_types::MLDSA_MU_LEN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Every parameter set.
const PARAMS: [&MlDsaParams; 3] = [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87];

/// The message signed, and the context string bound with it. The context is
/// non-empty so that `μ` is seen to carry it.
const MSG: &[u8] = b"external mu message";
const CTX: &[u8] = b"external mu context";

fn variant(p: &MlDsaParams) -> MlDsaVariant {
    match p.name {
        "ML-DSA-44" => MlDsaVariant::MlDsa44,
        "ML-DSA-65" => MlDsaVariant::MlDsa65,
        "ML-DSA-87" => MlDsaVariant::MlDsa87,
        other => panic!("unknown parameter set {other}"),
    }
}

/// Generate a key on the device: `(masked_key, pub_key)`.
fn generate(ctx: &TestCtx, session_id: u16, p: &MlDsaParams) -> (Vec<u8>, Vec<u8>) {
    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            key_kind: p.key_kind,
        })
        .unwrap_or_else(|e| panic!("MlDsaGenerateKey({}): {e:?}", p.name));
    (key.masked_key, key.pub_key)
}

/// `MlDsaSign` on the device.
fn sign_req(session_id: u16, masked_key: &[u8], mu: &[u8]) -> TborMlDsaSignReq {
    TborMlDsaSignReq {
        session_id,
        masked_key: masked_key.to_vec(),
        mu: mu.to_vec(),
        hedge: MLDSA_HEDGE_PREFERRED,
    }
}

/// `MlDsaVerify` on the device.
fn verify_req(session_id: u16, pub_key: &[u8], mu: &[u8], signature: &[u8]) -> TborMlDsaVerifyReq {
    TborMlDsaVerifyReq {
        session_id,
        pub_key: pub_key.to_vec(),
        mu: mu.to_vec(),
        signature: signature.to_vec(),
    }
}

/// Sign `mu` on the device, returning the signature.
fn device_sign(ctx: &TestCtx, session_id: u16, masked_key: &[u8], mu: &[u8]) -> Vec<u8> {
    ctx.tbor(&sign_req(session_id, masked_key, mu))
        .unwrap_or_else(|e| panic!("MlDsaSign: {e:?}"))
        .signature
}

/// Verify on the device: `true` when accepted, `false` on the dedicated
/// `MlDsaVerifyFailed` status. Anything else is a fault, not a verdict.
fn device_verify(
    ctx: &TestCtx,
    session_id: u16,
    pub_key: &[u8],
    mu: &[u8],
    signature: &[u8],
) -> bool {
    match ctx.tbor(&verify_req(session_id, pub_key, mu, signature)) {
        Ok(_) => true,
        Err(DdiError::TborStatus(TborStatus::MlDsaVerifyFailed)) => false,
        Err(e) => panic!("MlDsaVerify fault: {e:?}"),
    }
}

/// `μ` for `MSG` under `CTX` and `pub_key`, computed on the host.
fn host_mu(pub_key: &[u8]) -> Vec<u8> {
    MlDsaPublicKey::from_bytes(pub_key)
        .and_then(|pk| HashAlgo::mldsa_mu(&pk, CTX))
        .and_then(|mut algo| Hasher::hash_vec(&mut algo, MSG))
        .expect("host mu")
}

/// Pure verification of `MSG` under `CTX` on the host.
fn host_verify(pub_key: &[u8], signature: &[u8]) -> bool {
    let pk = MlDsaPublicKey::from_bytes(pub_key).expect("import device pk");
    MlDsaAlgo::new(CTX)
        .expect("mldsa engine")
        .verify(&pk, MSG, signature)
        .expect("host verify")
}

/// SHAKE256 with a 64-byte output, computed on the device with `Hash`.
fn device_shake256_64(ctx: &TestCtx, session_id: u16, data: &[u8]) -> Vec<u8> {
    ctx.tbor(&TborHashReq {
        session_id,
        algo: HASH_ALGO_SHAKE256,
        out_len: Some(MLDSA_MU_LEN as u16),
        msg: data.to_vec(),
    })
    .expect("Hash SHAKE256")
    .digest
}

/// `μ` for `MSG` under `CTX` and `pub_key`, computed on the device: two
/// `Hash` calls, one for `tr` and one for `μ`.
fn device_mu(ctx: &TestCtx, session_id: u16, pub_key: &[u8]) -> Vec<u8> {
    let tr = device_shake256_64(ctx, session_id, pub_key);
    let mut m_prime = tr;
    m_prime.push(0);
    m_prime.push(CTX.len() as u8);
    m_prime.extend_from_slice(CTX);
    m_prime.extend_from_slice(MSG);
    device_shake256_64(ctx, session_id, &m_prime)
}

/// A signature over `μ` is a pure signature over the message it was computed
/// from: the host accepts it as one, and the device accepts it over `μ`.
#[test]
fn mldsa_sign_external_mu_verifies_as_pure() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);

        let sig = device_sign(&ctx, sid, &masked_key, &mu);
        assert_eq!(sig.len(), p.sig_len, "{} signature length", p.name);
        assert!(
            host_verify(&pub_key, &sig),
            "{}: host rejected a signature over mu as a pure signature",
            p.name
        );
        assert!(
            device_verify(&ctx, sid, &pub_key, &mu, &sig),
            "{}: device rejected its own signature over mu",
            p.name
        );
    }
}

/// A pure signature made by the host verifies on the device over the `μ` of
/// its message; any change to `μ` breaks it, for the device's signatures
/// too.
#[test]
fn mldsa_verify_external_mu_accepts_pure_signatures() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = host_mu(&pub_key);
        let sig = device_sign(&ctx, sid, &masked_key, &mu);
        let mut bad_mu = mu.clone();
        bad_mu[0] ^= 0x01;
        assert!(
            !device_verify(&ctx, sid, &pub_key, &bad_mu, &sig),
            "{}: device accepted a signature over a modified mu",
            p.name
        );

        // Host-made key and pure signature: only the public key crosses.
        let sk = MlDsaPrivateKey::from_seed(variant(p), &[0x3C; 32]).expect("host keygen");
        let mut host_pk = vec![0u8; p.pub_key_len];
        sk.public_key()
            .expect("host public key")
            .to_bytes(Some(&mut host_pk))
            .expect("encode host pk");
        let mut host_sig = vec![0u8; p.sig_len];
        MlDsaAlgo::new(CTX)
            .expect("mldsa engine")
            .sign(&sk, MSG, Some(&mut host_sig))
            .expect("host sign");
        let host_pk_mu = host_mu(&host_pk);
        assert!(
            device_verify(&ctx, sid, &host_pk, &host_pk_mu, &host_sig),
            "{}: device rejected a host pure signature over mu",
            p.name
        );
        let mut bad_mu = host_pk_mu;
        bad_mu[MLDSA_MU_LEN - 1] ^= 0x80;
        assert!(
            !device_verify(&ctx, sid, &host_pk, &bad_mu, &host_sig),
            "{}: device accepted a host signature over a modified mu",
            p.name
        );
    }
}

/// NIST's external-`μ` verification vectors replay directly, since the
/// public key travels on the wire; each passing one is replayed again with
/// a flipped signature bit, which must be rejected.
#[test]
fn mldsa_external_mu_nist_acvp_vectors() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    assert!(!MLDSA_EXTERNAL_MU_SIGVER_TEST_VECTORS.is_empty());
    for v in MLDSA_EXTERNAL_MU_SIGVER_TEST_VECTORS {
        let got = device_verify(&ctx, sid, v.pub_key, v.mu, v.sig);
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
                !device_verify(&ctx, sid, v.pub_key, v.mu, &bad),
                "ML-DSA-{}: device accepted a tampered signature ({})",
                v.param_set,
                v.reason
            );
        }
    }
}

/// The device can compute `μ` itself, with two SHAKE256 `Hash` calls: it
/// matches the host's, and a signature over it is a pure signature over the
/// message.
#[test]
fn mldsa_external_mu_computed_on_device() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;

    for p in PARAMS {
        let (masked_key, pub_key) = generate(&ctx, sid, p);
        let mu = device_mu(&ctx, sid, &pub_key);
        assert_eq!(
            mu,
            host_mu(&pub_key),
            "{}: device mu differs from the host's",
            p.name
        );

        let sig = device_sign(&ctx, sid, &masked_key, &mu);
        assert!(
            host_verify(&pub_key, &sig),
            "{}: host rejected a signature over the device's mu",
            p.name
        );
        assert!(
            device_verify(&ctx, sid, &pub_key, &mu, &sig),
            "{}: device rejected a signature over its own mu",
            p.name
        );
    }
}

/// `μ` is exactly 64 bytes; any other length fails to decode, on both
/// commands.
#[test]
fn mldsa_rejects_mu_of_the_wrong_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let sid = session.session_id;
    let p = &ML_DSA_44;
    let (masked_key, pub_key) = generate(&ctx, sid, p);
    let sig = vec![0u8; p.sig_len];

    let mu = [0x5Au8; MLDSA_MU_LEN + 1];
    for len in [0, MLDSA_MU_LEN - 1, MLDSA_MU_LEN + 1] {
        ctx.expect_fw_reject(
            &sign_req(sid, &masked_key, &mu[..len]),
            TborStatus::TborInvalidFixedLength,
        );
        ctx.expect_fw_reject(
            &verify_req(sid, &pub_key, &mu[..len], &sig),
            TborStatus::TborInvalidFixedLength,
        );
    }
}
