// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Interop with the `hpke` crate: every GCM suite in every supported
//! mode, both directions, plus the draft-ietf-hpke-pq KEM test vectors
//! and negative cases for the post-quantum suites.

#[path = "../../../../../fw/core/crypto/hpke/tests/common/vectors.rs"]
mod vectors;

use ::hpke::Deserializable;
use ::hpke::Kem;
use ::hpke::OpModeR;
use ::hpke::OpModeS;
use ::hpke::PskBundle;
use ::hpke::Serializable;
use ::hpke::aead::AesGcm256;
use ::hpke::kdf::HkdfSha256;
use ::hpke::kdf::HkdfSha384;
use ::hpke::kdf::HkdfSha512;
use ::hpke::kdf::Kdf;
use ::hpke::kdf::KdfShake256;
use ::hpke::kem::DhP256HkdfSha256;
use ::hpke::kem::DhP384HkdfSha384;
use ::hpke::kem::DhP521HkdfSha512;
use ::hpke::kem::MlKem1024;
use ::hpke::kem::MlKem1024P384;

use crate::hpke::kem;
use crate::*;

const INFO: &[u8] = b"tsra hpke interop info";
const AAD: &[u8] = b"tsra hpke interop aad";
const PT: &[u8] = b"tsra hpke interop plaintext";
const PSK: &[u8] = &[0x5a; 32];
const PSK_ID: &[u8] = b"psk id";
const EXP_CTX: &[u8] = b"exporter context";
const EXP_LEN: usize = 45;
const IKM_R: &[u8] = b"tsra hpke interop recipient ikm";
const IKM_S: &[u8] = b"tsra hpke interop sender ikm";

#[derive(Debug, Clone, Copy)]
enum Mode {
    Base,
    Psk,
    Auth,
    AuthPsk,
}

const ALL_MODES: [Mode; 4] = [Mode::Base, Mode::Psk, Mode::Auth, Mode::AuthPsk];
const PQ_MODES: [Mode; 2] = [Mode::Base, Mode::Psk];

const PQ_SUITES: [HpkeSuite; 2] = [
    HpkeSuite::MlKem1024P384Shake256AesGcm256,
    HpkeSuite::MlKem1024Shake256AesGcm256,
];

fn unhex(parts: &[&str]) -> Vec<u8> {
    hex::decode(parts.concat()).expect("hex")
}

fn psk_params() -> PskParams<'static> {
    PskParams {
        psk: PSK,
        psk_id: PSK_ID,
    }
}

fn ref_psk() -> PskBundle<'static> {
    PskBundle::new(PSK, PSK_ID).expect("psk bundle")
}

fn ecc_sk(kp: &HpkeKeyPair) -> &EccPrivateKey {
    match kp.private_key() {
        HpkePrivateKey::Ecc(sk) => sk,
        _ => panic!("not an ECC key pair"),
    }
}

fn ecc_pk(kp: &HpkeKeyPair) -> &EccPublicKey {
    match kp.public_key() {
        HpkePublicKey::Ecc(pk) => pk,
        _ => panic!("not an ECC key pair"),
    }
}

/// Both sides' key pairs, derived from the same IKM by the host and by
/// the reference implementation.
struct Keys<K: Kem> {
    r: HpkeKeyPair,
    s: HpkeKeyPair,
    ref_r: (K::PrivateKey, K::PublicKey),
    ref_s: (K::PrivateKey, K::PublicKey),
}

fn keys<K: Kem>(suite: HpkeSuite) -> Keys<K> {
    let derive = |ikm: &[u8]| {
        let host = suite.derive_keypair(ikm).expect("host derive_keypair");
        let reference = K::derive_keypair(ikm);
        assert_eq!(
            host.public_key().to_vec().expect("pk bytes"),
            reference.1.to_bytes().to_vec(),
            "{suite:?} DeriveKeyPair public key"
        );
        (host, reference)
    };
    let (r, ref_r) = derive(IKM_R);
    let (s, ref_s) = derive(IKM_S);
    Keys { r, s, ref_r, ref_s }
}

fn ref_mode_s<K: Kem>(mode: Mode, k: &Keys<K>) -> OpModeS<'static, K> {
    match mode {
        Mode::Base => OpModeS::Base,
        Mode::Psk => OpModeS::Psk(ref_psk()),
        Mode::Auth => OpModeS::Auth(k.ref_s.clone()),
        Mode::AuthPsk => OpModeS::AuthPsk(k.ref_s.clone(), ref_psk()),
    }
}

fn ref_mode_r<K: Kem>(mode: Mode, k: &Keys<K>) -> OpModeR<'static, K> {
    match mode {
        Mode::Base => OpModeR::Base,
        Mode::Psk => OpModeR::Psk(ref_psk()),
        Mode::Auth => OpModeR::Auth(k.ref_s.1.clone()),
        Mode::AuthPsk => OpModeR::AuthPsk(k.ref_s.1.clone(), ref_psk()),
    }
}

fn seal_cfg<K: Kem>(suite: HpkeSuite, mode: Mode, k: &Keys<K>) -> HpkeSealConfig<'_> {
    let pk = k.r.public_key();
    match mode {
        Mode::Base => HpkeSealConfig::base(suite, pk, INFO, AAD),
        Mode::Psk => HpkeSealConfig::psk(suite, pk, INFO, AAD, psk_params()),
        Mode::Auth => HpkeSealConfig::auth(suite, pk, INFO, AAD, ecc_sk(&k.s)),
        Mode::AuthPsk => HpkeSealConfig::auth_psk(suite, pk, INFO, AAD, ecc_sk(&k.s), psk_params()),
    }
}

fn open_cfg<K: Kem>(suite: HpkeSuite, mode: Mode, k: &Keys<K>) -> HpkeOpenConfig<'_> {
    let (sk, pk) = (k.r.private_key(), k.r.public_key());
    match mode {
        Mode::Base => HpkeOpenConfig::base(suite, sk, pk, INFO, AAD),
        Mode::Psk => HpkeOpenConfig::psk(suite, sk, pk, INFO, AAD, psk_params()),
        Mode::Auth => HpkeOpenConfig::auth(suite, sk, pk, INFO, AAD, ecc_pk(&k.s)),
        Mode::AuthPsk => {
            HpkeOpenConfig::auth_psk(suite, sk, pk, INFO, AAD, ecc_pk(&k.s), psk_params())
        }
    }
}

fn send_export_cfg<K: Kem>(suite: HpkeSuite, mode: Mode, k: &Keys<K>) -> HpkeSendExportConfig<'_> {
    let pk = k.r.public_key();
    match mode {
        Mode::Base => HpkeSendExportConfig::base(suite, pk, INFO, EXP_CTX),
        Mode::Psk => HpkeSendExportConfig::psk(suite, pk, INFO, EXP_CTX, psk_params()),
        Mode::Auth => HpkeSendExportConfig::auth(suite, pk, INFO, EXP_CTX, ecc_sk(&k.s)),
        Mode::AuthPsk => {
            HpkeSendExportConfig::auth_psk(suite, pk, INFO, EXP_CTX, ecc_sk(&k.s), psk_params())
        }
    }
}

fn receive_export_cfg<K: Kem>(
    suite: HpkeSuite,
    mode: Mode,
    k: &Keys<K>,
) -> HpkeReceiveExportConfig<'_> {
    let (sk, pk) = (k.r.private_key(), k.r.public_key());
    match mode {
        Mode::Base => HpkeReceiveExportConfig::base(suite, sk, pk, INFO, EXP_CTX),
        Mode::Psk => HpkeReceiveExportConfig::psk(suite, sk, pk, INFO, EXP_CTX, psk_params()),
        Mode::Auth => HpkeReceiveExportConfig::auth(suite, sk, pk, INFO, EXP_CTX, ecc_pk(&k.s)),
        Mode::AuthPsk => HpkeReceiveExportConfig::auth_psk(
            suite,
            sk,
            pk,
            INFO,
            EXP_CTX,
            ecc_pk(&k.s),
            psk_params(),
        ),
    }
}

/// Seal/open and export in both directions for every mode.
fn interop<Kd: Kdf, K: Kem>(suite: HpkeSuite, modes: &[Mode]) {
    let k = keys::<K>(suite);
    for &mode in modes {
        // reference -> host
        let (enc, ct) = ::hpke::single_shot_seal::<AesGcm256, Kd, K>(
            &ref_mode_s(mode, &k),
            &k.ref_r.1,
            INFO,
            PT,
            AAD,
        )
        .expect("ref seal");
        let enc = enc.to_bytes().to_vec();
        assert_eq!(enc.len(), suite.nenc(), "{suite:?} {mode:?} enc len");
        let pt = open_vec(&open_cfg(suite, mode, &k), &enc, &ct).expect("host open");
        assert_eq!(pt, PT, "{suite:?} {mode:?} ref -> host");

        // host -> reference
        let sealed = seal_vec(&seal_cfg(suite, mode, &k), PT).expect("host seal");
        assert_eq!(sealed.enc.len(), suite.nenc(), "{suite:?} {mode:?} enc len");
        let enc = K::EncappedKey::from_bytes(&sealed.enc).expect("ref enc");
        let pt = ::hpke::single_shot_open::<AesGcm256, Kd, K>(
            &ref_mode_r(mode, &k),
            &k.ref_r.0,
            &enc,
            INFO,
            &sealed.ct,
            AAD,
        )
        .expect("ref open");
        assert_eq!(pt, PT, "{suite:?} {mode:?} host -> ref");

        // export, reference -> host
        let (enc, ctx) =
            ::hpke::setup_sender::<AesGcm256, Kd, K>(&ref_mode_s(mode, &k), &k.ref_r.1, INFO)
                .expect("ref setup sender");
        let mut want = vec![0u8; EXP_LEN];
        ctx.export(EXP_CTX, &mut want).expect("ref export");
        let got = receive_export_vec(
            &receive_export_cfg(suite, mode, &k),
            &enc.to_bytes(),
            EXP_LEN,
        )
        .expect("host receive export");
        assert_eq!(got, want, "{suite:?} {mode:?} export ref -> host");

        // export, host -> reference
        let sent =
            send_export_vec(&send_export_cfg(suite, mode, &k), EXP_LEN).expect("host send export");
        let enc = K::EncappedKey::from_bytes(&sent.enc).expect("ref enc");
        let ctx = ::hpke::setup_receiver::<AesGcm256, Kd, K>(
            &ref_mode_r(mode, &k),
            &k.ref_r.0,
            &enc,
            INFO,
        )
        .expect("ref setup receiver");
        let mut want = vec![0u8; EXP_LEN];
        ctx.export(EXP_CTX, &mut want).expect("ref export");
        assert_eq!(sent.exported, want, "{suite:?} {mode:?} export host -> ref");
    }
}

#[test]
fn dhkem_p256_interop() {
    interop::<HkdfSha256, DhP256HkdfSha256>(HpkeSuite::DHKemP256Sha256AesGcm256, &ALL_MODES);
}

#[test]
fn dhkem_p384_interop() {
    interop::<HkdfSha384, DhP384HkdfSha384>(HpkeSuite::DHKemP384Sha384AesGcm256, &ALL_MODES);
}

#[test]
fn dhkem_p521_interop() {
    interop::<HkdfSha512, DhP521HkdfSha512>(HpkeSuite::DHKemP521Sha512AesGcm256, &ALL_MODES);
}

#[test]
fn mlkem1024_interop() {
    interop::<KdfShake256, MlKem1024>(HpkeSuite::MlKem1024Shake256AesGcm256, &PQ_MODES);
}

#[test]
fn mlkem1024_p384_interop() {
    interop::<KdfShake256, MlKem1024P384>(HpkeSuite::MlKem1024P384Shake256AesGcm256, &PQ_MODES);
}

/// DeriveKeyPair and Decap against the draft-ietf-hpke-pq vectors.
#[test]
fn pq_kem_vectors() {
    use vectors::*;
    let cases = [
        (
            HpkeSuite::MlKem1024Shake256AesGcm256,
            MLKEM1024_IKM_R,
            MLKEM1024_SK_R,
            MLKEM1024_PK_R,
            MLKEM1024_ENC,
            MLKEM1024_SS,
        ),
        (
            HpkeSuite::MlKem1024P384Shake256AesGcm256,
            MLKEM1024_P384_IKM_R,
            MLKEM1024_P384_SK_R,
            MLKEM1024_P384_PK_R,
            MLKEM1024_P384_ENC,
            MLKEM1024_P384_SS,
        ),
    ];
    for (suite, ikm, sk, pk, enc, ss) in cases {
        let kp = suite.derive_keypair(&unhex(ikm)).expect("derive_keypair");
        let seed = match kp.private_key() {
            HpkePrivateKey::MlKem1024(s) | HpkePrivateKey::MlKem1024P384(s) => s.to_vec(),
            HpkePrivateKey::Ecc(_) => panic!("not a PQ key"),
        };
        assert_eq!(seed, unhex(sk), "{suite:?} sk");
        assert_eq!(
            kp.public_key().to_vec().expect("pk"),
            unhex(pk),
            "{suite:?} pk"
        );
        let got = kem::decap(suite, &unhex(enc), kp.private_key(), kp.public_key()).expect("decap");
        assert_eq!(got.to_vec(), unhex(ss), "{suite:?} ss");
    }
}

#[test]
fn pq_generate_keypair_roundtrip() {
    for suite in PQ_SUITES {
        let kp = suite.generate_keypair().expect("generate_keypair");
        assert_eq!(kp.suite(), suite);
        assert_eq!(kp.public_key().to_vec().expect("pk").len(), suite.npk());
        kp.public_key().validate(suite).expect("validate");
        let sealed =
            seal_vec(&HpkeSealConfig::base(suite, kp.public_key(), INFO, AAD), PT).expect("seal");
        let cfg = HpkeOpenConfig::base(suite, kp.private_key(), kp.public_key(), INFO, AAD);
        assert_eq!(open_vec(&cfg, &sealed.enc, &sealed.ct).expect("open"), PT);
    }
}

#[test]
fn pq_auth_modes_rejected() {
    let ecc = HpkeSuite::DHKemP384Sha384AesGcm256
        .derive_keypair(IKM_S)
        .expect("ecc key");
    for suite in PQ_SUITES {
        let kp = suite.derive_keypair(IKM_R).expect("derive_keypair");
        let (sk, pk) = (kp.private_key(), kp.public_key());
        let errs = [
            seal_vec(
                &HpkeSealConfig::auth(suite, pk, INFO, AAD, ecc_sk(&ecc)),
                PT,
            )
            .err(),
            seal_vec(
                &HpkeSealConfig::auth_psk(suite, pk, INFO, AAD, ecc_sk(&ecc), psk_params()),
                PT,
            )
            .err(),
            send_export_vec(
                &HpkeSendExportConfig::auth(suite, pk, INFO, EXP_CTX, ecc_sk(&ecc)),
                EXP_LEN,
            )
            .err(),
        ];
        for err in errs {
            assert_eq!(err, Some(CryptoError::HpkeInvalidModeConfig), "{suite:?}");
        }

        let sealed = seal_vec(&HpkeSealConfig::base(suite, pk, INFO, AAD), PT).expect("seal");
        let cfg = HpkeOpenConfig::auth(suite, sk, pk, INFO, AAD, ecc_pk(&ecc));
        assert_eq!(
            open_vec(&cfg, &sealed.enc, &sealed.ct).err(),
            Some(CryptoError::HpkeInvalidModeConfig)
        );
    }
}

#[test]
fn wrong_key_kind_rejected() {
    let ecc = HpkeSuite::DHKemP384Sha384AesGcm256
        .derive_keypair(IKM_R)
        .expect("ecc key");
    let mlkem = HpkeSuite::MlKem1024Shake256AesGcm256
        .derive_keypair(IKM_R)
        .expect("mlkem key");

    let suite = HpkeSuite::MlKem1024P384Shake256AesGcm256;
    for pk in [ecc.public_key(), mlkem.public_key()] {
        let cfg = HpkeSealConfig::base(suite, pk, INFO, AAD);
        assert_eq!(
            seal_vec(&cfg, PT).err(),
            Some(CryptoError::HpkeInvalidPublicKey)
        );
    }

    let suite = HpkeSuite::DHKemP384Sha384AesGcm256;
    let cfg = HpkeSealConfig::base(suite, mlkem.public_key(), INFO, AAD);
    assert_eq!(
        seal_vec(&cfg, PT).err(),
        Some(CryptoError::HpkeInvalidPublicKey)
    );

    // ECC key on the wrong curve.
    let p256 = HpkeSuite::DHKemP256Sha256AesGcm256
        .derive_keypair(IKM_R)
        .expect("p256 key");
    assert!(p256.public_key().validate(suite).is_err());
    assert!(
        seal_vec(
            &HpkeSealConfig::base(suite, p256.public_key(), INFO, AAD),
            PT
        )
        .is_err()
    );
}

#[test]
fn invalid_pq_public_keys_rejected() {
    for suite in PQ_SUITES {
        let kp = suite.derive_keypair(IKM_R).expect("derive_keypair");
        let good = kp.public_key().to_vec().expect("pk");

        // First 12-bit coefficient = 0xFFF >= q = 3329 (FIPS 203 §7.2).
        let mut bad = good.clone();
        bad[0] = 0xff;
        bad[1] |= 0x0f;
        let mut short = good.clone();
        short.pop();
        let mut long = good.clone();
        long.push(0);

        for pk in [bad, short, long] {
            let pk = match suite {
                HpkeSuite::MlKem1024Shake256AesGcm256 => HpkePublicKey::MlKem1024(&pk),
                _ => HpkePublicKey::MlKem1024P384(&pk),
            };
            assert!(pk.validate(suite).is_err(), "{suite:?}");
            let cfg = HpkeSealConfig::base(suite, pk, INFO, AAD);
            assert_eq!(
                seal_vec(&cfg, PT).err(),
                Some(CryptoError::HpkeInvalidPublicKey),
                "{suite:?}"
            );
        }
    }

    // The hybrid T component must be a valid uncompressed P-384 point.
    let suite = HpkeSuite::MlKem1024P384Shake256AesGcm256;
    let kp = suite.derive_keypair(IKM_R).expect("derive_keypair");
    let good = kp.public_key().to_vec().expect("pk");
    let mut off_curve = good.clone();
    *off_curve.last_mut().expect("pk") ^= 1;
    let mut compressed = good;
    compressed[1568] = 0x02;
    for pk in [off_curve, compressed] {
        let cfg = HpkeSealConfig::base(suite, HpkePublicKey::MlKem1024P384(&pk), INFO, AAD);
        assert!(seal_vec(&cfg, PT).is_err());
    }
}

#[test]
fn pq_tampered_inputs_fail_open() {
    for suite in PQ_SUITES {
        let kp = suite.derive_keypair(IKM_R).expect("derive_keypair");
        let sealed =
            seal_vec(&HpkeSealConfig::base(suite, kp.public_key(), INFO, AAD), PT).expect("seal");
        let cfg = HpkeOpenConfig::base(suite, kp.private_key(), kp.public_key(), INFO, AAD);

        let mut bad_ct = sealed.ct.clone();
        bad_ct[0] ^= 1;
        assert!(open_vec(&cfg, &sealed.enc, &bad_ct).is_err());

        // ML-KEM implicit rejection: a modified ciphertext still decaps,
        // but to a different secret, so the AEAD tag check fails.
        let mut bad_enc = sealed.enc.clone();
        bad_enc[0] ^= 1;
        assert!(open_vec(&cfg, &bad_enc, &sealed.ct).is_err());

        assert!(open_vec(&cfg, &sealed.enc[1..], &sealed.ct).is_err());
        let long = [sealed.enc.as_slice(), &[0]].concat();
        assert!(open_vec(&cfg, &long, &sealed.ct).is_err());

        let seed = match kp.private_key() {
            HpkePrivateKey::MlKem1024(s) | HpkePrivateKey::MlKem1024P384(s) => s,
            HpkePrivateKey::Ecc(_) => panic!("not a PQ key"),
        };
        let short_sk = match suite {
            HpkeSuite::MlKem1024Shake256AesGcm256 => HpkePrivateKey::MlKem1024(&seed[1..]),
            _ => HpkePrivateKey::MlKem1024P384(&seed[1..]),
        };
        let cfg = HpkeOpenConfig::base(suite, short_sk, kp.public_key(), INFO, AAD);
        assert!(open_vec(&cfg, &sealed.enc, &sealed.ct).is_err());
    }

    // Hybrid ct_T that is not on P-384.
    let suite = HpkeSuite::MlKem1024P384Shake256AesGcm256;
    let kp = suite.derive_keypair(IKM_R).expect("derive_keypair");
    let sealed =
        seal_vec(&HpkeSealConfig::base(suite, kp.public_key(), INFO, AAD), PT).expect("seal");
    let cfg = HpkeOpenConfig::base(suite, kp.private_key(), kp.public_key(), INFO, AAD);
    let mut enc = sealed.enc.clone();
    *enc.last_mut().expect("enc") ^= 1;
    assert!(open_vec(&cfg, &enc, &sealed.ct).is_err());
}

#[test]
fn pq_export_length_limit() {
    // One-stage export uses LabeledDerive with a 2-byte length.
    let suite = HpkeSuite::MlKem1024Shake256AesGcm256;
    let kp = suite.derive_keypair(IKM_R).expect("derive_keypair");
    let cfg = HpkeSendExportConfig::base(suite, kp.public_key(), INFO, EXP_CTX);
    send_export_vec(&cfg, 0xffff).expect("max export");
    assert_eq!(
        send_export_vec(&cfg, 0x1_0000).err(),
        Some(CryptoError::HpkeExportTooLarge)
    );
}
