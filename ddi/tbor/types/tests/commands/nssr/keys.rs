// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR rows for in-session key and crypto opcodes.
//!
//! Keys are created before the reset under the `Local` scope, so the
//! recovered checkpoint shows that replaying `local_mk_backup` restores
//! them. Deterministic outputs (digests, MACs, derived keys, raw RSA,
//! ciphertexts) must match their pre-reset values; masked keys and
//! secrets are compared through the ciphertext of a fixed block.

use std::thread;
use std::time::Duration;
use std::time::Instant;

use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo as CryptoHashAlgo;
use tsra_crypto::Hasher;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::RsaSignAlgo;
use tsra_crypto::Verifier;
use tsra_ddi_interface::DdiError;
use tsra_ddi_interface::DdiResult;
use tsra_ddi_interface::TborOobItem;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_44;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_512;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborAesEncryptDecryptReq;
use tsra_ddi_tbor_types::TborAesGcmEncryptDecryptReq;
use tsra_ddi_tbor_types::TborAesGenerateKeyReq;
use tsra_ddi_tbor_types::TborAesXtsEncryptDecryptReq;
use tsra_ddi_tbor_types::TborConcatKdfDeriveReq;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborEccGenerateKeyResp;
use tsra_ddi_tbor_types::TborEccSignReq;
use tsra_ddi_tbor_types::TborEcdhDeriveReq;
use tsra_ddi_tbor_types::TborGetPublicKeyReq;
use tsra_ddi_tbor_types::TborGetUnwrappingKeyReq;
use tsra_ddi_tbor_types::TborHashReq;
use tsra_ddi_tbor_types::TborHkdfDeriveReq;
use tsra_ddi_tbor_types::TborHmacGenerateKeyReq;
use tsra_ddi_tbor_types::TborHmacReq;
use tsra_ddi_tbor_types::TborKeyReportReq;
use tsra_ddi_tbor_types::TborMlDsaGenerateKeyReq;
use tsra_ddi_tbor_types::TborMlDsaGenerateKeyResp;
use tsra_ddi_tbor_types::TborMlDsaSignReq;
use tsra_ddi_tbor_types::TborMlDsaVerifyReq;
use tsra_ddi_tbor_types::TborMlKemDecapsulateReq;
use tsra_ddi_tbor_types::TborMlKemEncapsulateReq;
use tsra_ddi_tbor_types::TborMlKemGenerateKeyReq;
use tsra_ddi_tbor_types::TborMlKemGenerateKeyResp;
use tsra_ddi_tbor_types::TborRsaModExpReq;
use tsra_ddi_tbor_types::TborSdSealingKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::TborUnwrapKeyReq;
use tsra_ddi_tbor_types::TborVerifyKeyReq;
use tsra_ddi_tbor_types::AES_KEY_SIZE_256;
use tsra_ddi_tbor_types::AES_MODE_CBC;
use tsra_ddi_tbor_types::AES_OP_DECRYPT;
use tsra_ddi_tbor_types::AES_OP_ENCRYPT;
use tsra_ddi_tbor_types::CONCAT_KDF_ALG_X963;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::GCM_IV_LEN;
use tsra_ddi_tbor_types::GCM_IV_SOURCE_HOST;
use tsra_ddi_tbor_types::GCM_TAG_LEN;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::KDF_KEY_TYPE_AES256;
use tsra_ddi_tbor_types::KEY_CLASS_AES;
use tsra_ddi_tbor_types::KEY_CLASS_RSA;
use tsra_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use tsra_ddi_tbor_types::KEY_USAGE_DECRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_DERIVE;
use tsra_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::KEY_USAGE_VERIFY;
use tsra_ddi_tbor_types::MLDSA_HEDGE_PREFERRED;
use tsra_ddi_tbor_types::MLDSA_MU_LEN;
use tsra_ddi_tbor_types::RSA_OP_SIGN;

use super::assert_in_session_contract;
use super::expect_status;
use super::World;
use crate::commands::aes_generate_key::generate_key;
use crate::commands::aes_xts_generate_key::generate_xts_key;
use crate::commands::aes_xts_generate_key::generate_xts_key_req;
use crate::commands::common::rev;
use crate::commands::common::rsa_aes_wrap;
use crate::commands::common::test_integer;
use crate::commands::common::verify_wire_ecdsa;
use crate::commands::common::SCOPE_EPHEMERAL;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::common::SCOPE_SESSION;
use crate::commands::key_report::verify_key_report;
use crate::commands::unwrap_key::get_unwrapping_key;
use crate::commands::unwrap_key::unwrap_with_usage;

const BLOCK: [u8; 32] = [0x3C; 32];
const IV: [u8; 16] = [0x11; 16];

/// Records the first value and asserts every later one matches it.
#[track_caller]
fn same_as_before(first: &mut Option<Vec<u8>>, value: Vec<u8>, what: &str) {
    match first {
        None => *first = Some(value),
        Some(expected) => assert_eq!(&value, expected, "{what} must match its pre-NSSR value"),
    }
}

fn aes_cbc(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: &[u8],
    op: u8,
    msg: &[u8],
) -> DdiResult<Vec<u8>> {
    Ok(ctx
        .tbor(&TborAesEncryptDecryptReq {
            session_id,
            op,
            mode: AES_MODE_CBC,
            iv: IV.to_vec(),
            msg: msg.to_vec(),
            masked_key: masked_key.to_vec(),
        })?
        .msg)
}

/// Identifies the key behind a masked AES key: AES-CBC of a fixed block.
pub(super) fn aes_fingerprint(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: &[u8],
) -> DdiResult<Vec<u8>> {
    aes_cbc(ctx, session_id, masked_key, AES_OP_ENCRYPT, &BLOCK)
}

fn hkdf_aes(ctx: &TestCtx, session_id: u16, masked_secret: Vec<u8>) -> DdiResult<Vec<u8>> {
    Ok(ctx
        .tbor(&TborHkdfDeriveReq {
            session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_ALGO_SHA256,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret,
            salt: Vec::new(),
            info: b"nssr".to_vec(),
            key_label: Vec::new(),
        })?
        .masked_key)
}

/// Identifies the secret behind a masked shared secret through an
/// HKDF-derived AES key.
fn secret_fingerprint(
    ctx: &TestCtx,
    session_id: u16,
    masked_secret: Vec<u8>,
) -> DdiResult<Vec<u8>> {
    let key = hkdf_aes(ctx, session_id, masked_secret)?;
    aes_fingerprint(ctx, session_id, &key)
}

fn ecc_key(w: &World, usage: u64) -> TborEccGenerateKeyResp {
    w.ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: w.sid(),
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: usage,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey")
}

fn ecdh_secret(
    ctx: &TestCtx,
    session_id: u16,
    local: &TborEccGenerateKeyResp,
    peer_pub: &[u8],
) -> DdiResult<Vec<u8>> {
    Ok(ctx
        .tbor(&TborEcdhDeriveReq {
            session_id,
            scope: SCOPE_LOCAL,
            masked_key: local.masked_key.clone(),
            peer_pub_key: peer_pub.to_vec(),
            key_label: Vec::new(),
        })?
        .masked_secret)
}

/// An ECDH shared secret between two `Local` keys.
fn shared_secret(w: &World) -> Vec<u8> {
    let a = ecc_key(w, KEY_USAGE_DERIVE);
    let b = ecc_key(w, KEY_USAGE_DERIVE);
    ecdh_secret(&w.ctx, w.sid(), &a, &b.pub_key).expect("EcdhDerive")
}

fn mldsa_key(w: &World) -> TborMlDsaGenerateKeyResp {
    w.ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: w.sid(),
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .expect("MlDsaGenerateKey")
}

fn mlkem_key(w: &World) -> TborMlKemGenerateKeyResp {
    w.ctx
        .tbor(&TborMlKemGenerateKeyReq {
            session_id: w.sid(),
            scope: SCOPE_LOCAL,
            key_kind: ML_KEM_512.key_kind,
        })
        .expect("MlKemGenerateKey")
}

/// Retries while the device is still generating its unwrapping key.
fn retry_pending<T>(mut op: impl FnMut() -> DdiResult<T>) -> DdiResult<T> {
    let start = Instant::now();
    loop {
        match op() {
            Err(DdiError::TborStatus(TborStatus::PendingKeyGeneration))
                if start.elapsed() < Duration::from_secs(30) =>
            {
                thread::sleep(Duration::from_millis(100));
            }
            other => return other,
        }
    }
}

fn gcm(
    ctx: &TestCtx,
    session_id: u16,
    op: u8,
    masked_key: &[u8],
    tag: &[u8],
    input: &[u8],
) -> DdiResult<(Vec<u8>, Vec<u8>)> {
    let req = TborAesGcmEncryptDecryptReq {
        session_id,
        op,
        iv_source: GCM_IV_SOURCE_HOST,
        aad_len: 0,
        data_len: input.len() as u16,
        in_index: 0,
        out_index: 1,
        iv: vec![0x22; GCM_IV_LEN],
        tag: tag.to_vec(),
        masked_key: masked_key.to_vec(),
    };
    let mut out = vec![0u8; input.len()];
    let resp = ctx.tbor_oob_io(
        &req,
        &mut [TborOobItem::In(input), TborOobItem::Out(&mut out)],
    )?;
    Ok((out, resp.tag))
}

fn xts(
    ctx: &TestCtx,
    session_id: u16,
    op: u8,
    masked_key: &[u8],
    data: &[u8],
) -> DdiResult<Vec<u8>> {
    let req = TborAesXtsEncryptDecryptReq {
        session_id,
        op,
        data_len: data.len() as u16,
        dul: data.len() as u16,
        in_index: 0,
        out_index: 1,
        tweak: 7u64.to_le_bytes().to_vec(),
        masked_key: masked_key.to_vec(),
    };
    let mut out = vec![0u8; data.len()];
    ctx.tbor_oob_io(
        &req,
        &mut [TborOobItem::In(data), TborOobItem::Out(&mut out)],
    )?;
    Ok(out)
}

#[test]
pub(super) fn nssr_aes_generate_key() {
    let mut w = World::new();
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let key = ctx
            .tbor(&TborAesGenerateKeyReq {
                session_id,
                scope: SCOPE_LOCAL,
                key_size: AES_KEY_SIZE_256,
                key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                key_label: Vec::new(),
            })?
            .masked_key;
        aes_fingerprint(ctx, session_id, &key)
    });
}

#[test]
pub(super) fn nssr_aes_encrypt_decrypt() {
    let mut w = World::new();
    let key = generate_key(&w.ctx, w.sid(), SCOPE_LOCAL, AES_KEY_SIZE_256);
    let ciphertext = aes_cbc(&w.ctx, w.sid(), &key, AES_OP_ENCRYPT, &BLOCK).expect("encrypt");
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let plain = aes_cbc(ctx, session_id, &key, AES_OP_DECRYPT, &ciphertext)?;
        assert_eq!(plain, BLOCK);
        Ok(())
    });
}

#[test]
pub(super) fn nssr_aes_gcm_encrypt_decrypt() {
    let mut w = World::new();
    let key = generate_key(&w.ctx, w.sid(), SCOPE_LOCAL, AES_KEY_SIZE_256);
    let (ciphertext, tag) = gcm(
        &w.ctx,
        w.sid(),
        AES_OP_ENCRYPT,
        &key,
        &[0; GCM_TAG_LEN],
        &BLOCK,
    )
    .expect("encrypt");
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let (plain, _) = gcm(ctx, session_id, AES_OP_DECRYPT, &key, &tag, &ciphertext)?;
        assert_eq!(plain, BLOCK);
        Ok(())
    });
}

#[test]
pub(super) fn nssr_aes_xts_generate_key() {
    let mut w = World::new();
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let key = ctx
            .tbor(&generate_xts_key_req(session_id, SCOPE_LOCAL))?
            .masked_key;
        xts(ctx, session_id, AES_OP_ENCRYPT, &key, &BLOCK)
    });
}

#[test]
pub(super) fn nssr_aes_xts_encrypt_decrypt() {
    let mut w = World::new();
    let key = generate_xts_key(&w.ctx, w.sid(), SCOPE_LOCAL);
    let ciphertext = xts(&w.ctx, w.sid(), AES_OP_ENCRYPT, &key, &BLOCK).expect("encrypt");
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let plain = xts(ctx, session_id, AES_OP_DECRYPT, &key, &ciphertext)?;
        assert_eq!(plain, BLOCK);
        Ok(())
    });
}

#[test]
pub(super) fn nssr_ecc_generate_key() {
    let mut w = World::new();
    assert_in_session_contract(&mut w, |ctx, session_id| {
        ctx.tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .map(|resp| resp.pub_key)
    });
}

#[test]
pub(super) fn nssr_ecc_sign() {
    let mut w = World::new();
    let key = ecc_key(&w, KEY_USAGE_SIGN);
    let digest = [0x5A; 32];
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let signature = ctx
            .tbor(&TborEccSignReq {
                session_id,
                masked_key: key.masked_key.clone(),
                digest: digest.to_vec(),
            })?
            .signature;
        assert!(verify_wire_ecdsa(&key.pub_key, &signature, &digest));
        Ok(())
    });
}

#[test]
pub(super) fn nssr_ecdh_derive() {
    let mut w = World::new();
    let local = ecc_key(&w, KEY_USAGE_DERIVE);
    let peer = ecc_key(&w, KEY_USAGE_DERIVE);
    let mut first = None;
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let secret = ecdh_secret(ctx, session_id, &local, &peer.pub_key)?;
        let fingerprint = secret_fingerprint(ctx, session_id, secret).expect("fingerprint");
        same_as_before(&mut first, fingerprint, "ECDH shared secret");
        Ok(())
    });
}

#[test]
pub(super) fn nssr_hkdf_derive() {
    let mut w = World::new();
    let secret = shared_secret(&w);
    let mut first = None;
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let key = hkdf_aes(ctx, session_id, secret.clone())?;
        let fingerprint = aes_fingerprint(ctx, session_id, &key).expect("fingerprint");
        same_as_before(&mut first, fingerprint, "HKDF-derived key");
        Ok(())
    });
}

#[test]
pub(super) fn nssr_concat_kdf_derive() {
    let mut w = World::new();
    let secret = shared_secret(&w);
    let mut first = None;
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let key = ctx
            .tbor(&TborConcatKdfDeriveReq {
                session_id,
                scope: SCOPE_LOCAL,
                hash_algo: HASH_ALGO_SHA256,
                kdf_alg: CONCAT_KDF_ALG_X963,
                key_type: KDF_KEY_TYPE_AES256,
                key_length: 0,
                masked_secret: secret.clone(),
                info: b"nssr".to_vec(),
            })?
            .masked_key;
        let fingerprint = aes_fingerprint(ctx, session_id, &key).expect("fingerprint");
        same_as_before(&mut first, fingerprint, "Concat-KDF-derived key");
        Ok(())
    });
}

#[test]
pub(super) fn nssr_hash() {
    let mut w = World::new();
    let msg = b"nssr hash".to_vec();
    let expected = Hasher::hash_vec(&mut CryptoHashAlgo::sha256(), &msg).expect("host hash");
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let digest = ctx
            .tbor(&TborHashReq {
                session_id,
                algo: HASH_ALGO_SHA256,
                out_len: None,
                msg: msg.clone(),
            })?
            .digest;
        assert_eq!(digest, expected);
        Ok(())
    });
}

#[test]
pub(super) fn nssr_hmac_generate_key() {
    let mut w = World::new();
    assert_in_session_contract(&mut w, |ctx, session_id| {
        ctx.tbor(&TborHmacGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_ALGO_SHA256,
            key_length: 32,
            key_label: Vec::new(),
        })
        .map(|resp| resp.masked_key)
    });
}

#[test]
pub(super) fn nssr_hmac() {
    let mut w = World::new();
    let key = w
        .ctx
        .tbor(&TborHmacGenerateKeyReq {
            session_id: w.sid(),
            scope: SCOPE_LOCAL,
            hash_algo: HASH_ALGO_SHA256,
            key_length: 32,
            key_label: Vec::new(),
        })
        .expect("HmacGenerateKey")
        .masked_key;
    let mut first = None;
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let tag = ctx
            .tbor(&TborHmacReq {
                session_id,
                masked_key: key.clone(),
                msg: b"nssr hmac".to_vec(),
            })?
            .tag;
        same_as_before(&mut first, tag, "HMAC tag");
        Ok(())
    });
}

#[test]
pub(super) fn nssr_get_public_key() {
    let mut w = World::new();
    let key = ecc_key(&w, KEY_USAGE_SIGN);
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let pub_key = ctx
            .tbor(&TborGetPublicKeyReq {
                session_id,
                masked_key: key.masked_key.clone(),
            })?
            .pub_key;
        assert_eq!(pub_key, key.pub_key);
        Ok(())
    });
}

#[test]
pub(super) fn nssr_get_unwrapping_key() {
    let mut w = World::new();
    let mut first = None;
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let pub_key = retry_pending(|| ctx.tbor(&TborGetUnwrappingKeyReq { session_id }))?.pub_key;
        same_as_before(&mut first, pub_key.to_vec(), "unwrapping public key");
        Ok(())
    });
}

#[test]
pub(super) fn nssr_unwrap_key() {
    let mut w = World::new();
    let hsm_pub = get_unwrapping_key(&w.ctx, w.sid());
    let wrapped = rsa_aes_wrap(&hsm_pub, &[0x42; 32], CryptoHashAlgo::sha256());
    let mut first = None;
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let key = retry_pending(|| {
            ctx.tbor(&TborUnwrapKeyReq {
                session_id,
                scope: SCOPE_LOCAL,
                key_class: KEY_CLASS_AES,
                key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                oaep_hash_algo: HASH_ALGO_SHA256,
                wrapped_blob: wrapped.clone(),
                key_label: b"nssr".to_vec(),
            })
        })?
        .masked_key;
        let fingerprint = aes_fingerprint(ctx, session_id, &key).expect("fingerprint");
        same_as_before(&mut first, fingerprint, "unwrapped key");
        Ok(())
    });
}

#[test]
pub(super) fn nssr_rsa_mod_exp() {
    let mut w = World::new();
    let rsa = RsaPrivateKey::generate(256).expect("host RSA key");
    let der = rsa.to_vec().expect("RSA DER");
    let pubkey = rsa.public_key().expect("RSA public key");
    let masked = unwrap_with_usage(
        &w.ctx,
        w.sid(),
        KEY_CLASS_RSA,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &der,
    )
    .masked_key;
    let m = test_integer(256);
    let mut first = None;
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let x = ctx
            .tbor(&TborRsaModExpReq {
                session_id,
                y: rev(&m),
                masked_key: masked.clone(),
                op_type: RSA_OP_SIGN,
            })?
            .x;
        let verified = Verifier::verify(&mut RsaSignAlgo::with_no_padding(), &pubkey, &m, &rev(&x))
            .expect("raw RSA verify");
        assert!(verified, "RsaModExp signature must verify");
        same_as_before(&mut first, x, "raw RSA signature");
        Ok(())
    });
}

#[test]
pub(super) fn nssr_verify_key() {
    let mut w = World::new();
    let key = ecc_key(&w, KEY_USAGE_SIGN);
    assert_in_session_contract(&mut w, |ctx, session_id| {
        ctx.tbor(&TborVerifyKeyReq {
            session_id,
            masked_key: key.masked_key.clone(),
        })
        .map(|_| ())
    });
}

/// Currently fails with `SessionAuthFailure`. `KeyReport` checks the
/// session's auth binding (a digest of the PSK the session authenticated
/// with) against the role's current PSK (`fw/core/lib/src/session.rs`).
/// After an NSSR the single CO slot can only be reopened under the reverted
/// default PSK, so re-rotating the PSK on it leaves the binding stale. This
/// is the same failure the SDK key-report tests hit after a restore.
#[test]
pub(super) fn nssr_key_report() {
    let mut w = World::new();
    let seal = w
        .ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id: w.sid(),
            scope: SCOPE_LOCAL,
        })
        .expect("SdSealingKeyGen");
    let report_data = [0xA5; KEY_REPORT_DATA_LEN];
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let report = ctx
            .tbor(&TborKeyReportReq {
                session_id,
                masked_key: seal.masked_key.to_vec(),
                report_data,
                auth_envelope: Vec::new(),
            })?
            .report;
        verify_key_report(ctx, &report, &seal.pub_key, &report_data);
        Ok(())
    });
}

#[test]
pub(super) fn nssr_mldsa_generate_key() {
    let mut w = World::new();
    assert_in_session_contract(&mut w, |ctx, session_id| {
        ctx.tbor(&TborMlDsaGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_DSA_44.key_kind,
        })
        .map(|resp| resp.pub_key.len())
    });
}

#[test]
pub(super) fn nssr_mldsa_sign() {
    let mut w = World::new();
    let key = mldsa_key(&w);
    let mu = vec![0x5A; MLDSA_MU_LEN];
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let signature = ctx
            .tbor(&TborMlDsaSignReq {
                session_id,
                masked_key: key.masked_key.clone(),
                mu: mu.clone(),
                hedge: MLDSA_HEDGE_PREFERRED,
            })?
            .signature;
        ctx.tbor(&TborMlDsaVerifyReq {
            session_id,
            pub_key: key.pub_key.clone(),
            mu: mu.clone(),
            signature,
        })
        .expect("signature must verify");
        Ok(())
    });
}

#[test]
pub(super) fn nssr_mldsa_verify() {
    let mut w = World::new();
    let key = mldsa_key(&w);
    let mu = vec![0x5A; MLDSA_MU_LEN];
    let signature = w
        .ctx
        .tbor(&TborMlDsaSignReq {
            session_id: w.sid(),
            masked_key: key.masked_key.clone(),
            mu: mu.clone(),
            hedge: MLDSA_HEDGE_PREFERRED,
        })
        .expect("MlDsaSign")
        .signature;
    assert_in_session_contract(&mut w, |ctx, session_id| {
        ctx.tbor(&TborMlDsaVerifyReq {
            session_id,
            pub_key: key.pub_key.clone(),
            mu: mu.clone(),
            signature: signature.clone(),
        })
        .map(|_| ())
    });
}

#[test]
pub(super) fn nssr_mlkem_generate_key() {
    let mut w = World::new();
    assert_in_session_contract(&mut w, |ctx, session_id| {
        ctx.tbor(&TborMlKemGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            key_kind: ML_KEM_512.key_kind,
        })
        .map(|resp| resp.pub_key.len())
    });
}

#[test]
pub(super) fn nssr_mlkem_encapsulate() {
    let mut w = World::new();
    let key = mlkem_key(&w);
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let resp = ctx.tbor(&TborMlKemEncapsulateReq {
            session_id,
            scope: SCOPE_LOCAL,
            pub_key: key.pub_key.clone(),
        })?;
        assert_eq!(resp.ciphertext.len(), ML_KEM_512.ciphertext_len);
        Ok(())
    });
}

#[test]
pub(super) fn nssr_mlkem_decapsulate() {
    let mut w = World::new();
    let key = mlkem_key(&w);
    let encap = w
        .ctx
        .tbor(&TborMlKemEncapsulateReq {
            session_id: w.sid(),
            scope: SCOPE_LOCAL,
            pub_key: key.pub_key.clone(),
        })
        .expect("MlKemEncapsulate");
    assert_in_session_contract(&mut w, |ctx, session_id| {
        let secret = ctx
            .tbor(&TborMlKemDecapsulateReq {
                session_id,
                scope: SCOPE_LOCAL,
                masked_key: key.masked_key.clone(),
                ciphertext: encap.ciphertext.clone(),
            })?
            .masked_shared_secret;
        assert_eq!(secret.len(), encap.masked_shared_secret.len());
        Ok(())
    });
}

/// Which key scopes stay usable after an NSSR and full recovery:
/// `Session` keys come back with the session's `bmk_session` and `Local`
/// keys with the replayed `local_mk_backup`. `Ephemeral` keys are lost,
/// because `PartFinal` provisions a fresh ephemeral masking key.
#[test]
fn nssr_key_scopes_after_recovery() {
    let mut w = World::new();
    let scopes = [
        ("Session", SCOPE_SESSION),
        ("Ephemeral", SCOPE_EPHEMERAL),
        ("Local", SCOPE_LOCAL),
    ];
    let keys: Vec<_> = scopes
        .iter()
        .map(|&(_, scope)| generate_key(&w.ctx, w.sid(), scope, AES_KEY_SIZE_256))
        .collect();
    let before: Vec<_> = keys
        .iter()
        .map(|key| aes_fingerprint(&w.ctx, w.sid(), key).expect("fingerprint"))
        .collect();

    w.nssr();
    w.recover();

    for ((name, scope), (key, before)) in scopes.iter().zip(keys.iter().zip(before)) {
        let after = aes_fingerprint(&w.ctx, w.sid(), key);
        if *scope == SCOPE_EPHEMERAL {
            expect_status(
                after,
                TborStatus::AesGcmDecryptTagDoesNotMatch,
                "Ephemeral-scope key after recovery",
            );
        } else {
            assert_eq!(
                after.as_ref().ok(),
                Some(&before),
                "{name}-scope key after recovery: {after:?}"
            );
        }
    }
}
