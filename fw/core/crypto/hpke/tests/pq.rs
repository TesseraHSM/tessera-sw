// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Post-quantum HPKE suites (HPKE-10: MLKEM1024-P384, HPKE-13:
//! ML-KEM-1024; both SHAKE256 / AES-256-GCM) on the std PAL,
//! cross-checked against the `hpke` crate and the draft-ietf-hpke-pq
//! KEM test vectors.

#[path = "common/harness.rs"]
mod harness;
#[path = "common/vectors.rs"]
mod vectors;

use harness::*;
use hpke::aead::AesGcm256;
use hpke::kdf::KdfShake256;
use hpke::kem::MlKem1024;
use hpke::kem::MlKem1024P384;
use hpke::Deserializable;
use hpke::Kem;
use hpke::OpModeR;
use hpke::OpModeS;
use hpke::PskBundle;
use hpke::Serializable;
use tsra_fw_core_crypto_hpke::*;
use tsra_fw_hsm_pal_std_uno::StdHsmIo;
use tsra_fw_hsm_pal_std_uno::StdHsmPal;
use tsra_fw_hsm_pal_traits::*;

const INFO: &[u8] = b"tsra hpke pq info";
const AAD: &[u8] = b"tsra hpke pq aad";
const PT: &[u8] = b"post-quantum hpke plaintext";
const PSK: &[u8] = &[0x5a; 32];
const PSK_ID: &[u8] = b"psk id";
const EXP_CTX: &[u8] = b"exporter context";
const EXP_LEN: usize = 45;

fn unhex(parts: &[&str]) -> Vec<u8> {
    hex::decode(parts.concat()).expect("hex")
}

/// Recipient key pair `(sk, pk)` from the official vectors.
fn recipient(suite: HpkeSuite) -> (Vec<u8>, Vec<u8>) {
    match suite {
        HpkeSuite::MlKem1024Shake256AesGcm256 => (
            unhex(vectors::MLKEM1024_SK_R),
            unhex(vectors::MLKEM1024_PK_R),
        ),
        HpkeSuite::MlKem1024P384Shake256AesGcm256 => (
            unhex(vectors::MLKEM1024_P384_SK_R),
            unhex(vectors::MLKEM1024_P384_PK_R),
        ),
        _ => unreachable!("not a PQ suite"),
    }
}

const SUITES: [HpkeSuite; 2] = [
    HpkeSuite::MlKem1024P384Shake256AesGcm256,
    HpkeSuite::MlKem1024Shake256AesGcm256,
];

fn psk_params() -> PskParams<'static> {
    PskParams {
        psk: PSK,
        psk_id: PSK_ID,
    }
}

fn ref_psk() -> PskBundle<'static> {
    PskBundle::new(PSK, PSK_ID).expect("psk bundle")
}

// ── reference (hpke crate) wrappers ────────────────────────────────

fn ref_seal<K: Kem>(pk: &[u8], psk: bool) -> (Vec<u8>, Vec<u8>) {
    let pk = K::PublicKey::from_bytes(pk).expect("ref pk");
    let mode = if psk {
        OpModeS::Psk(ref_psk())
    } else {
        OpModeS::Base
    };
    let (enc, ct) = hpke::single_shot_seal::<AesGcm256, KdfShake256, K>(&mode, &pk, INFO, PT, AAD)
        .expect("ref seal");
    (enc.to_bytes().to_vec(), ct)
}

fn ref_open<K: Kem>(sk: &[u8], psk: bool, enc: &[u8], ct: &[u8]) -> Vec<u8> {
    let sk = K::PrivateKey::from_bytes(sk).expect("ref sk");
    let enc = K::EncappedKey::from_bytes(enc).expect("ref enc");
    let mode = if psk {
        OpModeR::Psk(ref_psk())
    } else {
        OpModeR::Base
    };
    hpke::single_shot_open::<AesGcm256, KdfShake256, K>(&mode, &sk, &enc, INFO, ct, AAD)
        .expect("ref open")
}

fn ref_send_export<K: Kem>(pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pk = K::PublicKey::from_bytes(pk).expect("ref pk");
    let (enc, ctx) = hpke::setup_sender::<AesGcm256, KdfShake256, K>(&OpModeS::Base, &pk, INFO)
        .expect("ref setup sender");
    let mut out = vec![0u8; EXP_LEN];
    ctx.export(EXP_CTX, &mut out).expect("ref export");
    (enc.to_bytes().to_vec(), out)
}

fn ref_receive_export<K: Kem>(sk: &[u8], enc: &[u8]) -> Vec<u8> {
    let sk = K::PrivateKey::from_bytes(sk).expect("ref sk");
    let enc = K::EncappedKey::from_bytes(enc).expect("ref enc");
    let ctx = hpke::setup_receiver::<AesGcm256, KdfShake256, K>(&OpModeR::Base, &sk, &enc, INFO)
        .expect("ref setup receiver");
    let mut out = vec![0u8; EXP_LEN];
    ctx.export(EXP_CTX, &mut out).expect("ref export");
    out
}

/// Dispatches a generic reference helper on the suite's KEM.
macro_rules! with_ref_kem {
    ($suite:expr, $f:ident($($arg:expr),*)) => {
        match $suite {
            HpkeSuite::MlKem1024Shake256AesGcm256 => $f::<MlKem1024>($($arg),*),
            HpkeSuite::MlKem1024P384Shake256AesGcm256 => $f::<MlKem1024P384>($($arg),*),
            _ => unreachable!("not a PQ suite"),
        }
    };
}

// ── tests ──────────────────────────────────────────────────────────

/// Anchors the reference implementation to the official KEM vectors so
/// the interop tests below are tied to the spec.
fn check_ref_kem_vectors<K: Kem>(
    ikm: &[&str],
    sk: &[&str],
    pk: &[&str],
    enc: &[&str],
    ss: &[&str],
) {
    let (dsk, dpk) = K::derive_keypair(&unhex(ikm));
    assert_eq!(dsk.to_bytes().to_vec(), unhex(sk), "DeriveKeyPair sk");
    assert_eq!(dpk.to_bytes().to_vec(), unhex(pk), "DeriveKeyPair pk");
    let enc = K::EncappedKey::from_bytes(&unhex(enc)).expect("enc");
    let got = K::decap(&dsk, None, &enc).expect("decap");
    assert_eq!(got.0.to_vec(), unhex(ss), "Decap shared secret");
}

#[test]
fn reference_matches_kem_vectors() {
    use vectors::*;
    check_ref_kem_vectors::<MlKem1024>(
        MLKEM1024_IKM_R,
        MLKEM1024_SK_R,
        MLKEM1024_PK_R,
        MLKEM1024_ENC,
        MLKEM1024_SS,
    );
    check_ref_kem_vectors::<MlKem1024P384>(
        MLKEM1024_P384_IKM_R,
        MLKEM1024_P384_SK_R,
        MLKEM1024_P384_PK_R,
        MLKEM1024_P384_ENC,
        MLKEM1024_P384_SS,
    );
}

#[tokio::test]
async fn reference_seal_fw_open() {
    let (pal, io) = pal_and_io();
    for suite in SUITES {
        let (sk, pk) = recipient(suite);
        for psk in [false, true] {
            let (enc, ct) = with_ref_kem!(suite, ref_seal(&pk, psk));
            assert_eq!(enc.len(), suite.nenc());
            let cfg = if psk {
                HpkeOpenConfig::psk(suite, &sk, &pk, INFO, AAD, psk_params())
            } else {
                HpkeOpenConfig::base(suite, &sk, &pk, INFO, AAD)
            };
            let pt = fw_open(&pal, &io, &cfg, &enc, &ct).await.expect("fw open");
            assert_eq!(pt, PT, "{suite:?} psk={psk}");
        }
    }
}

#[tokio::test]
async fn fw_seal_reference_open() {
    let (pal, io) = pal_and_io();
    for suite in SUITES {
        let (sk, pk) = recipient(suite);
        for psk in [false, true] {
            let cfg = if psk {
                HpkeSealConfig::psk(suite, &pk, INFO, AAD, psk_params())
            } else {
                HpkeSealConfig::base(suite, &pk, INFO, AAD)
            };
            let (enc, ct) = fw_seal(&pal, &io, &cfg, PT).await.expect("fw seal");
            assert_eq!(enc.len(), suite.nenc());
            let pt = with_ref_kem!(suite, ref_open(&sk, psk, &enc, &ct));
            assert_eq!(pt, PT, "{suite:?} psk={psk}");
        }
    }
}

#[tokio::test]
async fn export_interop() {
    let (pal, io) = pal_and_io();
    for suite in SUITES {
        let (sk, pk) = recipient(suite);

        let (enc, want) = with_ref_kem!(suite, ref_send_export(&pk));
        let cfg = HpkeReceiveExportConfig::base(suite, &sk, &pk, INFO, EXP_CTX);
        let got = fw_receive_export(&pal, &io, &cfg, &enc, EXP_LEN)
            .await
            .expect("fw receive export");
        assert_eq!(got, want, "{suite:?} ref -> fw");

        let cfg = HpkeSendExportConfig::base(suite, &pk, INFO, EXP_CTX);
        let (enc, got) = fw_send_export(&pal, &io, &cfg, EXP_LEN)
            .await
            .expect("fw send export");
        let want = with_ref_kem!(suite, ref_receive_export(&sk, &enc));
        assert_eq!(got, want, "{suite:?} fw -> ref");
    }
}

#[tokio::test]
async fn auth_modes_rejected() {
    let (pal, io) = pal_and_io();
    let sk_s = [1u8; 48];
    for suite in SUITES {
        let (sk, pk) = recipient(suite);
        let auth = AuthParams {
            sk_s: dma(&sk_s),
            pk_s: &pk,
        };
        let cfg = HpkeSealConfig::auth(suite, &pk, INFO, AAD, auth);
        assert_eq!(
            fw_seal(&pal, &io, &cfg, PT).await.err(),
            Some(HsmError::InvalidArg)
        );
        let cfg = HpkeSealConfig::auth_psk(suite, &pk, INFO, AAD, auth, psk_params());
        assert_eq!(
            fw_seal(&pal, &io, &cfg, PT).await.err(),
            Some(HsmError::InvalidArg)
        );

        let (enc, ct) = with_ref_kem!(suite, ref_seal(&pk, false));
        let cfg = HpkeOpenConfig::auth(suite, &sk, &pk, INFO, AAD, &pk);
        assert_eq!(
            fw_open(&pal, &io, &cfg, &enc, &ct).await.err(),
            Some(HsmError::InvalidArg)
        );
    }
}

#[tokio::test]
async fn tampered_inputs_fail_open() {
    let (pal, io) = pal_and_io();
    for suite in SUITES {
        let (sk, pk) = recipient(suite);
        let (enc, ct) = with_ref_kem!(suite, ref_seal(&pk, false));
        let cfg = HpkeOpenConfig::base(suite, &sk, &pk, INFO, AAD);

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert!(fw_open(&pal, &io, &cfg, &enc, &bad_ct).await.is_err());

        // ML-KEM implicit rejection: a modified ciphertext still decaps,
        // but to a different secret, so the AEAD tag check fails.
        let mut bad_enc = enc.clone();
        bad_enc[0] ^= 1;
        assert!(fw_open(&pal, &io, &cfg, &bad_enc, &ct).await.is_err());

        assert!(fw_open(&pal, &io, &cfg, &enc[1..], &ct).await.is_err());
        assert!(
            fw_open(&pal, &io, &cfg, &[enc.as_slice(), &[0]].concat(), &ct)
                .await
                .is_err()
        );

        let short_sk = HpkeOpenConfig::base(suite, &sk[1..], &pk, INFO, AAD);
        assert!(fw_open(&pal, &io, &short_sk, &enc, &ct).await.is_err());
    }
}

#[tokio::test]
async fn hybrid_invalid_ct_t_point_rejected() {
    let (pal, io) = pal_and_io();
    let suite = HpkeSuite::MlKem1024P384Shake256AesGcm256;
    let (sk, pk) = recipient(suite);
    let (mut enc, ct) = ref_seal::<MlKem1024P384>(&pk, false);
    // Flip the last y-coordinate byte: the point is no longer on P-384.
    *enc.last_mut().expect("enc") ^= 1;
    let cfg = HpkeOpenConfig::base(suite, &sk, &pk, INFO, AAD);
    assert!(fw_open(&pal, &io, &cfg, &enc, &ct).await.is_err());

    // Not an uncompressed SEC1 point.
    let (mut enc, ct) = ref_seal::<MlKem1024P384>(&pk, false);
    enc[1568] = 0x02;
    assert!(fw_open(&pal, &io, &cfg, &enc, &ct).await.is_err());
}

#[tokio::test]
async fn invalid_encapsulation_key_rejected() {
    let (pal, io) = pal_and_io();
    for suite in SUITES {
        let (_, mut pk) = recipient(suite);
        // First 12-bit coefficient = 0xFFF >= q = 3329 (FIPS 203 §7.2).
        pk[0] = 0xff;
        pk[1] |= 0x0f;
        let cfg = HpkeSealConfig::base(suite, &pk, INFO, AAD);
        assert!(fw_seal(&pal, &io, &cfg, PT).await.is_err(), "{suite:?}");

        let (_, mut pk) = recipient(suite);
        pk.pop();
        let cfg = HpkeSealConfig::base(suite, &pk, INFO, AAD);
        assert!(fw_seal(&pal, &io, &cfg, PT).await.is_err(), "{suite:?}");
    }

    // The hybrid T component must be a valid P-384 point.
    let suite = HpkeSuite::MlKem1024P384Shake256AesGcm256;
    let (_, mut pk) = recipient(suite);
    *pk.last_mut().expect("pk") ^= 1;
    let cfg = HpkeSealConfig::base(suite, &pk, INFO, AAD);
    assert!(fw_seal(&pal, &io, &cfg, PT).await.is_err());
}

async fn fw_public_key(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    suite: HpkeSuite,
    sk: &[u8],
) -> HsmResult<Vec<u8>> {
    pal.alloc_scoped_async(io, async |alloc| {
        let mut pk = vec![0u8; suite.npk()];
        public_key(pal, io, suite, sk, &mut pk, alloc).await?;
        Ok(pk)
    })
    .await
}

async fn fw_generate(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    suite: HpkeSuite,
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    pal.alloc_scoped_async(io, async |alloc| {
        let mut sk = vec![0u8; suite.nsk()];
        let mut pk = vec![0u8; suite.npk()];
        generate_key_pair(pal, io, suite, dma_mut(&mut sk), &mut pk, alloc).await?;
        Ok((sk, pk))
    })
    .await
}

#[tokio::test]
async fn public_key_matches_vectors() {
    let (pal, io) = pal_and_io();
    for suite in SUITES {
        let (sk, pk) = recipient(suite);
        let got = fw_public_key(&pal, &io, suite, &sk)
            .await
            .expect("public key");
        assert_eq!(got, pk, "{suite:?}");
        assert!(fw_public_key(&pal, &io, suite, &sk[1..]).await.is_err());
    }
}

#[tokio::test]
async fn generated_key_pairs_interoperate() {
    let (pal, io) = pal_and_io();
    for suite in SUITES {
        let (sk, pk) = fw_generate(&pal, &io, suite).await.expect("generate");
        let (sk2, _) = fw_generate(&pal, &io, suite).await.expect("generate");
        assert_ne!(sk, sk2, "{suite:?} seeds must be fresh");
        assert_eq!(
            fw_public_key(&pal, &io, suite, &sk)
                .await
                .expect("public key"),
            pk
        );
        let (enc, ct) = with_ref_kem!(suite, ref_seal(&pk, false));
        let cfg = HpkeOpenConfig::base(suite, &sk, &pk, INFO, AAD);
        let pt = fw_open(&pal, &io, &cfg, &enc, &ct).await.expect("fw open");
        assert_eq!(pt, PT);
        let cfg = HpkeSealConfig::base(suite, &pk, INFO, AAD);
        let (enc, ct) = fw_seal(&pal, &io, &cfg, PT).await.expect("fw seal");
        assert_eq!(with_ref_kem!(suite, ref_open(&sk, false, &enc, &ct)), PT);
    }
}

#[tokio::test]
async fn key_generation_rejects_dhkem_suites() {
    let (pal, io) = pal_and_io();
    let suite = HpkeSuite::DHKemP384Sha384AesGcm256;
    assert!(fw_generate(&pal, &io, suite).await.is_err());
    assert!(fw_public_key(&pal, &io, suite, &[1; 48]).await.is_err());
}
