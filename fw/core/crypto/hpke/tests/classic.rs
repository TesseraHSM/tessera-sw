// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Classic DHKEM suites (P-256 / HKDF-SHA256 and P-384 / HKDF-SHA384,
//! AES-256-GCM) on the std PAL, cross-checked against the `hpke`
//! crate in all four modes.
//!
//! P-521 is rejected by the firmware DHKEM and the CBC AEADs are not
//! RFC 9180 suites, so neither has a reference counterpart here.

#[path = "common/harness.rs"]
mod harness;

use harness::*;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kdf::HkdfSha384;
use hpke::kdf::Kdf;
use hpke::kem::DhP256HkdfSha256;
use hpke::kem::DhP384HkdfSha384;
use hpke::Deserializable;
use hpke::Kem;
use hpke::OpModeR;
use hpke::OpModeS;
use hpke::PskBundle;
use hpke::Serializable;
use tsra_fw_core_crypto_hpke::*;

const INFO: &[u8] = b"tsra hpke classic info";
const AAD: &[u8] = b"tsra hpke classic aad";
const PT: &[u8] = b"classic hpke plaintext";
const PSK: &[u8] = &[0xa5; 32];
const PSK_ID: &[u8] = b"psk id";
const EXP_CTX: &[u8] = b"exporter context";
const EXP_LEN: usize = 41;

const SUITES: [HpkeSuite; 2] = [
    HpkeSuite::DHKemP256Sha256AesGcm256,
    HpkeSuite::DHKemP384Sha384AesGcm256,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Base,
    Psk,
    Auth,
    AuthPsk,
}

const MODES: [Mode; 4] = [Mode::Base, Mode::Psk, Mode::Auth, Mode::AuthPsk];

impl Mode {
    fn psk(self) -> bool {
        matches!(self, Mode::Psk | Mode::AuthPsk)
    }

    fn auth(self) -> bool {
        matches!(self, Mode::Auth | Mode::AuthPsk)
    }
}

/// One key pair in both encodings: `sk_be`/`pk` as serialized by
/// RFC 9180 (big-endian scalar, SEC1 uncompressed point) and `sk` in
/// the std PAL's big-endian private-key encoding.
struct KeyPair {
    sk_be: Vec<u8>,
    sk: Vec<u8>,
    pk: Vec<u8>,
}

struct Keys {
    r: KeyPair,
    s: KeyPair,
}

fn derive<K: Kem>(ikm: &[u8]) -> KeyPair {
    let (sk, pk) = K::derive_keypair(ikm);
    let sk_be = sk.to_bytes().to_vec();
    KeyPair {
        sk: sk_be.clone(),
        sk_be,
        pk: pk.to_bytes().to_vec(),
    }
}

fn keys<K: Kem>() -> Keys {
    Keys {
        r: derive::<K>(b"tsra hpke classic recipient ikm"),
        s: derive::<K>(b"tsra hpke classic sender ikm"),
    }
}

fn psk_params() -> PskParams<'static> {
    PskParams {
        psk: PSK,
        psk_id: PSK_ID,
    }
}

// ── firmware configs ───────────────────────────────────────────────

fn seal_cfg<'a>(suite: HpkeSuite, mode: Mode, k: &'a Keys) -> HpkeSealConfig<'a> {
    let auth = AuthParams {
        sk_s: dma(&k.s.sk),
        pk_s: &k.s.pk,
    };
    match mode {
        Mode::Base => HpkeSealConfig::base(suite, &k.r.pk, INFO, AAD),
        Mode::Psk => HpkeSealConfig::psk(suite, &k.r.pk, INFO, AAD, psk_params()),
        Mode::Auth => HpkeSealConfig::auth(suite, &k.r.pk, INFO, AAD, auth),
        Mode::AuthPsk => HpkeSealConfig::auth_psk(suite, &k.r.pk, INFO, AAD, auth, psk_params()),
    }
}

fn open_cfg<'a>(suite: HpkeSuite, mode: Mode, k: &'a Keys, pk_s: &'a [u8]) -> HpkeOpenConfig<'a> {
    let (sk, pk) = (&k.r.sk[..], &k.r.pk[..]);
    match mode {
        Mode::Base => HpkeOpenConfig::base(suite, sk, pk, INFO, AAD),
        Mode::Psk => HpkeOpenConfig::psk(suite, sk, pk, INFO, AAD, psk_params()),
        Mode::Auth => HpkeOpenConfig::auth(suite, sk, pk, INFO, AAD, pk_s),
        Mode::AuthPsk => HpkeOpenConfig::auth_psk(suite, sk, pk, INFO, AAD, pk_s, psk_params()),
    }
}

fn send_export_cfg<'a>(suite: HpkeSuite, mode: Mode, k: &'a Keys) -> HpkeSendExportConfig<'a> {
    let auth = AuthParams {
        sk_s: dma(&k.s.sk),
        pk_s: &k.s.pk,
    };
    let pk = &k.r.pk[..];
    match mode {
        Mode::Base => HpkeSendExportConfig::base(suite, pk, INFO, EXP_CTX),
        Mode::Psk => HpkeSendExportConfig::psk(suite, pk, INFO, EXP_CTX, psk_params()),
        Mode::Auth => HpkeSendExportConfig::auth(suite, pk, INFO, EXP_CTX, auth),
        Mode::AuthPsk => {
            HpkeSendExportConfig::auth_psk(suite, pk, INFO, EXP_CTX, auth, psk_params())
        }
    }
}

fn receive_export_cfg<'a>(
    suite: HpkeSuite,
    mode: Mode,
    k: &'a Keys,
) -> HpkeReceiveExportConfig<'a> {
    let (sk, pk, pk_s) = (&k.r.sk[..], &k.r.pk[..], &k.s.pk[..]);
    match mode {
        Mode::Base => HpkeReceiveExportConfig::base(suite, sk, pk, INFO, EXP_CTX),
        Mode::Psk => HpkeReceiveExportConfig::psk(suite, sk, pk, INFO, EXP_CTX, psk_params()),
        Mode::Auth => HpkeReceiveExportConfig::auth(suite, sk, pk, INFO, EXP_CTX, pk_s),
        Mode::AuthPsk => {
            HpkeReceiveExportConfig::auth_psk(suite, sk, pk, INFO, EXP_CTX, pk_s, psk_params())
        }
    }
}

// ── reference (hpke crate) ─────────────────────────────────────────

fn ref_psk() -> PskBundle<'static> {
    PskBundle::new(PSK, PSK_ID).expect("psk bundle")
}

fn ref_mode_s<K: Kem>(mode: Mode, k: &Keys) -> OpModeS<'static, K> {
    let sender = || {
        (
            K::PrivateKey::from_bytes(&k.s.sk_be).expect("ref sk_s"),
            K::PublicKey::from_bytes(&k.s.pk).expect("ref pk_s"),
        )
    };
    match mode {
        Mode::Base => OpModeS::Base,
        Mode::Psk => OpModeS::Psk(ref_psk()),
        Mode::Auth => OpModeS::Auth(sender()),
        Mode::AuthPsk => OpModeS::AuthPsk(sender(), ref_psk()),
    }
}

fn ref_mode_r<K: Kem>(mode: Mode, k: &Keys) -> OpModeR<'static, K> {
    let pk_s = || K::PublicKey::from_bytes(&k.s.pk).expect("ref pk_s");
    match mode {
        Mode::Base => OpModeR::Base,
        Mode::Psk => OpModeR::Psk(ref_psk()),
        Mode::Auth => OpModeR::Auth(pk_s()),
        Mode::AuthPsk => OpModeR::AuthPsk(pk_s(), ref_psk()),
    }
}

fn ref_seal<K: Kem, F: Kdf>(mode: Mode, k: &Keys) -> (Vec<u8>, Vec<u8>) {
    let pk = K::PublicKey::from_bytes(&k.r.pk).expect("ref pk");
    let (enc, ct) =
        hpke::single_shot_seal::<AesGcm256, F, K>(&ref_mode_s(mode, k), &pk, INFO, PT, AAD)
            .expect("ref seal");
    (enc.to_bytes().to_vec(), ct)
}

fn ref_open<K: Kem, F: Kdf>(mode: Mode, k: &Keys, enc: &[u8], ct: &[u8]) -> Vec<u8> {
    let sk = K::PrivateKey::from_bytes(&k.r.sk_be).expect("ref sk");
    let enc = K::EncappedKey::from_bytes(enc).expect("ref enc");
    hpke::single_shot_open::<AesGcm256, F, K>(&ref_mode_r(mode, k), &sk, &enc, INFO, ct, AAD)
        .expect("ref open")
}

fn ref_send_export<K: Kem, F: Kdf>(mode: Mode, k: &Keys) -> (Vec<u8>, Vec<u8>) {
    let pk = K::PublicKey::from_bytes(&k.r.pk).expect("ref pk");
    let (enc, ctx) = hpke::setup_sender::<AesGcm256, F, K>(&ref_mode_s(mode, k), &pk, INFO)
        .expect("ref setup sender");
    let mut out = vec![0u8; EXP_LEN];
    ctx.export(EXP_CTX, &mut out).expect("ref export");
    (enc.to_bytes().to_vec(), out)
}

fn ref_receive_export<K: Kem, F: Kdf>(mode: Mode, k: &Keys, enc: &[u8]) -> Vec<u8> {
    let sk = K::PrivateKey::from_bytes(&k.r.sk_be).expect("ref sk");
    let enc = K::EncappedKey::from_bytes(enc).expect("ref enc");
    let ctx = hpke::setup_receiver::<AesGcm256, F, K>(&ref_mode_r(mode, k), &sk, &enc, INFO)
        .expect("ref setup receiver");
    let mut out = vec![0u8; EXP_LEN];
    ctx.export(EXP_CTX, &mut out).expect("ref export");
    out
}

/// Dispatches a generic reference helper on the suite's KEM and KDF.
macro_rules! with_ref {
    ($suite:expr, $f:ident($($arg:expr),*)) => {
        match $suite {
            HpkeSuite::DHKemP256Sha256AesGcm256 => $f::<DhP256HkdfSha256, HkdfSha256>($($arg),*),
            HpkeSuite::DHKemP384Sha384AesGcm256 => $f::<DhP384HkdfSha384, HkdfSha384>($($arg),*),
            _ => unreachable!("no reference suite"),
        }
    };
}

fn suite_keys(suite: HpkeSuite) -> Keys {
    match suite {
        HpkeSuite::DHKemP256Sha256AesGcm256 => keys::<DhP256HkdfSha256>(),
        HpkeSuite::DHKemP384Sha384AesGcm256 => keys::<DhP384HkdfSha384>(),
        _ => unreachable!("no reference suite"),
    }
}

// ── tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn reference_seal_fw_open() {
    let (pal, io) = pal_and_io().await;
    for suite in SUITES {
        let k = suite_keys(suite);
        for mode in MODES {
            let (enc, ct) = with_ref!(suite, ref_seal(mode, &k));
            assert_eq!(enc.len(), suite.nenc());
            let cfg = open_cfg(suite, mode, &k, &k.s.pk);
            let pt = fw_open(&pal, &io, &cfg, &enc, &ct).await.expect("fw open");
            assert_eq!(pt, PT, "{suite:?} {mode:?}");
        }
    }
}

#[tokio::test]
async fn fw_seal_reference_open() {
    let (pal, io) = pal_and_io().await;
    for suite in SUITES {
        let k = suite_keys(suite);
        for mode in MODES {
            let cfg = seal_cfg(suite, mode, &k);
            let (enc, ct) = fw_seal(&pal, &io, &cfg, PT).await.expect("fw seal");
            assert_eq!(enc.len(), suite.nenc());
            let pt = with_ref!(suite, ref_open(mode, &k, &enc, &ct));
            assert_eq!(pt, PT, "{suite:?} {mode:?}");
        }
    }
}

#[tokio::test]
async fn export_interop() {
    let (pal, io) = pal_and_io().await;
    for suite in SUITES {
        let k = suite_keys(suite);
        for mode in MODES {
            let (enc, want) = with_ref!(suite, ref_send_export(mode, &k));
            let cfg = receive_export_cfg(suite, mode, &k);
            let got = fw_receive_export(&pal, &io, &cfg, &enc, EXP_LEN)
                .await
                .expect("fw receive export");
            assert_eq!(got, want, "{suite:?} {mode:?} ref -> fw");

            let cfg = send_export_cfg(suite, mode, &k);
            let (enc, got) = fw_send_export(&pal, &io, &cfg, EXP_LEN)
                .await
                .expect("fw send export");
            let want = with_ref!(suite, ref_receive_export(mode, &k, &enc));
            assert_eq!(got, want, "{suite:?} {mode:?} fw -> ref");
        }
    }
}

#[tokio::test]
async fn wrong_sender_key_fails_auth_open() {
    let (pal, io) = pal_and_io().await;
    for suite in SUITES {
        let k = suite_keys(suite);
        for mode in MODES.into_iter().filter(|m| m.auth()) {
            let (enc, ct) = with_ref!(suite, ref_seal(mode, &k));
            // The recipient's own key stands in for an impostor sender.
            let cfg = open_cfg(suite, mode, &k, &k.r.pk);
            assert!(
                fw_open(&pal, &io, &cfg, &enc, &ct).await.is_err(),
                "{suite:?} {mode:?}"
            );
        }
    }
}

#[tokio::test]
async fn psk_mismatch_fails_open() {
    let (pal, io) = pal_and_io().await;
    for suite in SUITES {
        let k = suite_keys(suite);
        for mode in MODES.into_iter().filter(|m| m.psk()) {
            let (enc, ct) = with_ref!(suite, ref_seal(mode, &k));
            let other = [0x3c; 32];
            let psk = PskParams {
                psk: &other,
                psk_id: PSK_ID,
            };
            let cfg = match mode {
                Mode::Psk => HpkeOpenConfig::psk(suite, &k.r.sk, &k.r.pk, INFO, AAD, psk),
                _ => HpkeOpenConfig::auth_psk(suite, &k.r.sk, &k.r.pk, INFO, AAD, &k.s.pk, psk),
            };
            assert!(
                fw_open(&pal, &io, &cfg, &enc, &ct).await.is_err(),
                "{suite:?} {mode:?}"
            );
        }
    }
}
