// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Known-answer and device-interop tests for ML-KEM.
//!
//! The shape is the one the ML-DSA KATs use: the **device** holds the
//! private key and performs the private-key operation, the **host**
//! performs the public-key operation with a reference implementation.
//! Nothing is unmasked — the device's private key and the shared secret
//! stay sealed under a vault-scope masking key the host cannot derive,
//! which is the property worth preserving.
//!
//! ## What can and cannot be asserted
//!
//! ML-DSA verification is *publicly* verifiable, so `mldsa_kat` can
//! check a device signature end to end against the public key.
//!
//! ML-KEM's output is a **secret**, not a publicly verifiable artifact.
//! The device returns it masked, and there is deliberately no way for
//! the host to recover it, so a shared-secret equality check is not
//! available and should not be faked. The old `pqc_kat` tool compared
//! secrets only because masking was bypassed and it held a hardcoded
//! key; that comparison stopped being meaningful the moment masking
//! became real.
//!
//! What is left is still worth having: the device must accept a
//! ciphertext produced by an independent implementation against the
//! public key it published, and answer with a well-formed secret. That
//! catches a wrong or mis-encoded encapsulation key, a length or
//! framing error, and a decapsulation path that rejects foreign input.

use tsra_crypto::EncapsulateOp;
use tsra_crypto::ImportableKey;
use tsra_crypto::MlKemAlgo;
use tsra_crypto::MlKemPublicKey;
use tsra_ddi_tbor_test_harness::pqc::MlKemParams;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_1024;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_512;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_768;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborMlKemDecapsulateReq;
use tsra_ddi_tbor_types::TborMlKemGenerateKeyReq;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Masked shared secret: 32-byte secret plus the 228-byte AEAD envelope.
const MASKED_SHARED_SECRET_LEN: usize = 228 + 32;

/// Device generates the key and decapsulates; the host encapsulates
/// against the published encapsulation key using an independent
/// implementation (`tsra_crypto`).
fn kem_host_encaps_device_decaps(p: &MlKemParams, rounds: usize) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for round in 0..rounds {
        let key = ctx
            .tbor(&TborMlKemGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                key_kind: p.key_kind,
            })
            .unwrap_or_else(|e| panic!("MlKemGenerateKey({}): {e:?}", p.name));

        assert_eq!(
            key.pub_key.len(),
            p.pub_key_len,
            "{}: encapsulation key length",
            p.name,
        );

        // Public-key operation, on the host, with an independent
        // implementation — against the key the device just published. The
        // shared secret is discarded: it is a secret the device returns
        // masked, so there is deliberately nothing to compare it against.
        let crypto_ek = MlKemPublicKey::from_bytes(&key.pub_key).expect("import device ek");
        let mut ct = vec![0u8; p.ciphertext_len];
        let mut ss_host = [0u8; 32];
        MlKemAlgo::new()
            .encapsulate(&crypto_ek, Some(&mut ct), Some(&mut ss_host))
            .unwrap_or_else(|e| panic!("encaps against device key ({}): {e:?}", p.name));

        // Private-key operation, on the device, over that ciphertext.
        let decap = ctx
            .tbor(&TborMlKemDecapsulateReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                masked_key: key.masked_key.clone(),
                ciphertext: ct.clone(),
            })
            .unwrap_or_else(|e| panic!("MlKemDecapsulate({}) on a host ciphertext: {e:?}", p.name));

        assert_eq!(
            decap.masked_shared_secret.len(),
            MASKED_SHARED_SECRET_LEN,
            "{} round {round}: masked shared-secret length",
            p.name,
        );
        assert!(
            decap.masked_shared_secret.iter().any(|&b| b != 0),
            "{} round {round}: masked shared secret is all zeroes",
            p.name,
        );

        // FIPS 203 implicit rejection: a tampered ciphertext must still
        // return a secret rather than an error, so a caller cannot use
        // the error channel as a validity oracle.
        let mut bad = ct;
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        let rejected = ctx
            .tbor(&TborMlKemDecapsulateReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                masked_key: key.masked_key.clone(),
                ciphertext: bad,
            })
            .unwrap_or_else(|e| {
                panic!(
                    "MlKemDecapsulate({}) must implicitly reject, not error: {e:?}",
                    p.name
                )
            });
        assert_eq!(
            rejected.masked_shared_secret.len(),
            MASKED_SHARED_SECRET_LEN,
            "{} round {round}: implicit-rejection secret length",
            p.name,
        );
    }
}

#[test]
fn mlkem_host_encaps_device_decaps_512() {
    kem_host_encaps_device_decaps(&ML_KEM_512, 2);
}

#[test]
fn mlkem_host_encaps_device_decaps_768() {
    kem_host_encaps_device_decaps(&ML_KEM_768, 2);
}

#[test]
fn mlkem_host_encaps_device_decaps_1024() {
    kem_host_encaps_device_decaps(&ML_KEM_1024, 2);
}

/// `Session` scope works for TBOR commands, and ML-KEM agrees with ECC.
///
/// TBOR sessions use the v2 `SessionEx` schedule, whose masking key is
/// the 32-byte AES-256-GCM key — not the legacy 80-byte MBOR CBC key.
/// The uno PAL used to read the legacy length for every schedule, which
/// returned `masking_key ‖ mac_tx` on a CO session and failed the length
/// check in `resolve_masking_key` as `UnsupportedKeyScope`.
///
/// ECC is asserted alongside so the two cannot drift apart again.
#[test]
fn mlkem_session_scope_matches_ecc() {
    const SCOPE_SESSION: u8 = 0b001;
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let kem = ctx
        .tbor(&TborMlKemGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            key_kind: ML_KEM_512.key_kind,
        })
        .expect("MlKemGenerateKey at Session scope");
    let ecc = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey at Session scope");

    // Both must come back as AEAD envelopes, not raw key material.
    for (what, blob) in [("ML-KEM", &kem.masked_key), ("ECC", &ecc.masked_key)] {
        assert_eq!(
            &blob[..4],
            b"AEAD",
            "{what}: masked key is not an AEAD envelope"
        );
    }
}
