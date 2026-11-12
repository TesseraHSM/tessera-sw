// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR rows for in-session opcodes that operate on a key.
//!
//! Each row runs [`Lm::cycle_keyed`]: the old session id is rejected with
//! `SessionNeedsRenegotiation`, then (after `ReopenSession`) the old key id
//! with `KeyNotFound` because NSSR wiped the vault, and the key restored by
//! `UnmaskKey` reproduces the pre-NSSR output.

#![cfg(test)]

use test_with_tracing::test;
use tsra_crypto::*;

use super::*;
use crate::integration::attest_key::helper_get_cert_chain;
use crate::integration::attest_key::verify_report;

/// ECDH of `priv_key_id` with `peer` into a `Secret256` derive key.
fn ecdh(
    dev: &Dev,
    sid: u16,
    priv_key_id: u16,
    peer: &DdiDerPublicKey,
) -> Result<DdiEcdhKeyExchangeCmdResp, DdiError> {
    helper_ecdh_key_exchange(
        dev,
        Some(sid),
        REV,
        priv_key_id,
        MborByteArray::from_slice(peer.der.as_slice()).expect("peer public key"),
        DdiKeyType::Secret256,
        key_props(DdiKeyUsage::Derive, DdiKeyAvailability::Session),
    )
}

/// A `Secret256` derived by ECDH of two fresh P-256 keys.
fn ecdh_secret(dev: &Dev, sid: u16) -> DdiEcdhKeyExchangeResp {
    let a = ecc_key(dev, sid, DdiKeyUsage::Derive);
    let b = ecc_key(dev, sid, DdiKeyUsage::Derive);
    ecdh(dev, sid, a.private_key_id, &b.pub_key)
        .expect("EcdhKeyExchange")
        .data
}

fn hkdf_aes(dev: &Dev, sid: u16, secret_id: u16) -> Result<DdiHkdfDeriveCmdResp, DdiError> {
    helper_hkdf_derive(
        dev,
        Some(sid),
        REV,
        secret_id,
        DdiHashAlgorithm::Sha256,
        Some(MborByteArray::from_slice(b"salt").expect("salt")),
        Some(MborByteArray::from_slice(b"info").expect("info")),
        DdiKeyType::Aes256,
        key_props(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session),
        None,
    )
}

fn kbkdf_aes(
    dev: &Dev,
    sid: u16,
    secret_id: u16,
) -> Result<DdiKbkdfCounterHmacDeriveCmdResp, DdiError> {
    helper_kbkdf_derive(
        dev,
        Some(sid),
        REV,
        secret_id,
        DdiHashAlgorithm::Sha256,
        Some(MborByteArray::from_slice(b"label").expect("label")),
        Some(MborByteArray::from_slice(b"context").expect("context")),
        DdiKeyType::Aes256,
        key_props(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session),
        None,
    )
}

#[test]
fn nssr_delete_key() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let key = aes_key(dev, sid, DdiKeyAvailability::App);
            let delete = |dev: &Dev, key_id: u16| helper_delete_key(dev, Some(sid), REV, key_id);
            let restored = lm.cycle_keyed(dev, key.key_id, key.masked_key, delete);
            delete(dev, restored.key_id).expect("checkpoint 3");
            assert_status(
                delete(dev, restored.key_id),
                DdiStatus::KeyNotFound,
                "second delete",
            );
            assert_status(
                aes_cbc(dev, sid, restored.key_id, DdiAesOp::Encrypt, &MSG),
                DdiStatus::KeyNotFound,
                "use after delete",
            );
        },
    );
}

#[test]
fn nssr_attest_key() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let (key_id, _, masked_key) =
                ecc_gen_key_tsra(dev, DdiEccCurve::P256, Some(sid), DdiKeyUsage::SignVerify);
            let attest = |dev: &Dev, key_id: u16| {
                helper_attest_key_cmd(dev, Some(sid), REV, [0x7E; REPORT_DATA_SIZE], key_id)
            };
            // Verifies the report against the partition's current chain.
            let verified = |dev: &mut Dev, resp: DdiAttestKeyCmdResp| {
                let report =
                    verify_report(&resp.data.report.data_take(), &helper_get_cert_chain(dev));
                report.public_key[..usize::from(report.public_key_size)].to_vec()
            };
            let before = verified(dev, attest(dev, key_id).expect("AttestKey"));
            let restored = lm.cycle_keyed(dev, key_id, masked_key, attest);
            let after = verified(dev, attest(dev, restored.key_id).expect("checkpoint 3"));
            assert_eq!(
                after, before,
                "the new identity attests the same public key"
            );
        },
    );
}

#[test]
fn nssr_rsa_mod_exp() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let (_, key_id, masked_key) =
                store_rsa_keys_no_crt(dev, sid, DdiKeyUsage::EncryptDecrypt, 2);
            let mut msg = vec![0x02u8; 256];
            msg[0] = 0x01;
            let pub_key =
                RsaPublicKey::from_bytes(&TEST_RSA_2K_PUBLIC_KEY).expect("RSA public key");
            let ciphertext =
                Encrypter::encrypt_vec(&mut RsaEncryptAlgo::with_no_padding(), &pub_key, &msg)
                    .expect("raw RSA encrypt");
            let decrypt = |dev: &Dev, key_id: u16| {
                helper_rsa_mod_exp(
                    dev,
                    Some(sid),
                    REV,
                    key_id,
                    MborByteArray::from_slice(&ciphertext).expect("ciphertext"),
                    DdiRsaOpType::Decrypt,
                )
            };
            let x = |resp: DdiRsaModExpCmdResp| resp.data.x.as_slice().to_vec();
            assert_eq!(x(decrypt(dev, key_id).expect("RsaModExp")), msg);
            let restored = lm.cycle_keyed(dev, key_id, masked_key, decrypt);
            assert_eq!(x(decrypt(dev, restored.key_id).expect("checkpoint 3")), msg);
        },
    );
}

/// Recovery B for the unwrapping key is `GetUnwrappingKey`, not `UnmaskKey`
/// (which refuses it): the partition re-imports its per-allocation unwrapping
/// key into the wiped vault (fw/plat/std/pal/src/part.rs:650-653).
#[test]
fn nssr_rsa_unwrap() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let (unwrap_id, unwrap_pub, unwrap_masked) = get_unwrapping_key(dev, sid);
            let blob = wrap_data(unwrap_pub.clone(), &TEST_AES_256);
            let unwrap = |dev: &Dev, unwrap_id: u16| {
                helper_rsa_unwrap(
                    dev,
                    Some(sid),
                    REV,
                    unwrap_id,
                    MborByteArray::from_slice(&blob).expect("wrapped blob"),
                    DdiKeyClass::Aes,
                    DdiRsaCryptoPadding::Oaep,
                    DdiHashAlgorithm::Sha256,
                    key_props(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
                )
            };
            let aes = unwrap(dev, unwrap_id).expect("RsaUnwrap").data.key_id;
            let ciphertext = aes_cbc(dev, sid, aes, DdiAesOp::Encrypt, &MSG).expect("encrypt");

            nssr(dev);
            assert_stale_session(unwrap(dev, unwrap_id));
            lm.recover_session(dev);
            assert_status(
                unwrap(dev, unwrap_id),
                DdiStatus::KeyNotFound,
                "checkpoint 2 (stale key)",
            );
            let masked = MborByteArray::from_slice(unwrap_masked.as_slice()).expect("masked key");
            assert_status(
                helper_unmask_key(dev, Some(sid), REV, masked),
                DdiStatus::InvalidKeyType,
                "UnmaskKey of the unwrapping key",
            );
            let (unwrap_id, restored_pub, _) = get_unwrapping_key(dev, sid);
            assert_eq!(restored_pub, unwrap_pub, "the pre-NSSR unwrapping key");
            let aes = unwrap(dev, unwrap_id).expect("checkpoint 3").data.key_id;
            let plaintext =
                aes_cbc(dev, sid, aes, DdiAesOp::Decrypt, &ciphertext).expect("decrypt");
            assert_eq!(plaintext, MSG);
        },
    );
}

#[test]
fn nssr_ecc_sign() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let key = ecc_key(dev, sid, DdiKeyUsage::SignVerify);
            let digest = crypto_sha256(&MSG);
            let sign = |dev: &Dev, key_id: u16| {
                helper_ecc_sign(
                    dev,
                    Some(sid),
                    REV,
                    key_id,
                    MborByteArray::from_slice(&digest).expect("digest"),
                    DdiHashAlgorithm::Sha256,
                )
            };
            // Checks a signature against the pre-NSSR public key.
            let verifies = |resp: DdiEccSignCmdResp| {
                let mut padded = [0u8; 96];
                padded[..digest.len()].copy_from_slice(&digest);
                let signature = resp.data.signature;
                ecc_verify_local_openssl(signature.as_slice(), &key.pub_key, padded, digest.len())
            };
            assert!(verifies(sign(dev, key.private_key_id).expect("EccSign")));
            let restored = lm.cycle_keyed(dev, key.private_key_id, key.masked_key, sign);
            assert_eq!(restored.pub_key.as_ref(), Some(&key.pub_key));
            assert!(verifies(sign(dev, restored.key_id).expect("checkpoint 3")));
        },
    );
}

#[test]
fn nssr_aes_encrypt_decrypt() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let key = aes_key(dev, sid, DdiKeyAvailability::App);
            let encrypt =
                |dev: &Dev, key_id: u16| aes_cbc(dev, sid, key_id, DdiAesOp::Encrypt, &MSG);
            let ciphertext = encrypt(dev, key.key_id).expect("encrypt");
            let restored = lm.cycle_keyed(dev, key.key_id, key.masked_key, encrypt);
            assert_eq!(
                encrypt(dev, restored.key_id).expect("checkpoint 3"),
                ciphertext
            );
            let plaintext = aes_cbc(dev, sid, restored.key_id, DdiAesOp::Decrypt, &ciphertext)
                .expect("decrypt");
            assert_eq!(plaintext, MSG);
        },
    );
}

#[test]
fn nssr_ecdh_key_exchange() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let mine = ecc_key(dev, sid, DdiKeyUsage::Derive);
            let peer = ecc_key(dev, sid, DdiKeyUsage::Derive);
            let exchange = |dev: &Dev, key_id: u16| ecdh(dev, sid, key_id, &peer.pub_key);
            // Shared secrets are compared through an AES key derived from them.
            let aes = |dev: &Dev, resp: DdiEcdhKeyExchangeCmdResp| {
                hkdf_aes(dev, sid, resp.data.key_id)
                    .expect("HkdfDerive")
                    .data
                    .key_id
            };
            let key = aes(
                dev,
                exchange(dev, mine.private_key_id).expect("EcdhKeyExchange"),
            );
            let ciphertext = aes_cbc(dev, sid, key, DdiAesOp::Encrypt, &MSG).expect("encrypt");
            let restored = lm.cycle_keyed(dev, mine.private_key_id, mine.masked_key, exchange);
            let key = aes(dev, exchange(dev, restored.key_id).expect("checkpoint 3"));
            let plaintext =
                aes_cbc(dev, sid, key, DdiAesOp::Decrypt, &ciphertext).expect("decrypt");
            assert_eq!(plaintext, MSG);
        },
    );
}

#[test]
fn nssr_hkdf_derive() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let secret = ecdh_secret(dev, sid);
            let derive = |dev: &Dev, secret_id: u16| hkdf_aes(dev, sid, secret_id);
            let key = derive(dev, secret.key_id).expect("HkdfDerive").data.key_id;
            let ciphertext = aes_cbc(dev, sid, key, DdiAesOp::Encrypt, &MSG).expect("encrypt");
            let restored = lm.cycle_keyed(dev, secret.key_id, secret.masked_key, derive);
            let key = derive(dev, restored.key_id)
                .expect("checkpoint 3")
                .data
                .key_id;
            let plaintext =
                aes_cbc(dev, sid, key, DdiAesOp::Decrypt, &ciphertext).expect("decrypt");
            assert_eq!(plaintext, MSG);
        },
    );
}

#[test]
fn nssr_kbkdf_counter_hmac_derive() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let secret = ecdh_secret(dev, sid);
            let derive = |dev: &Dev, secret_id: u16| kbkdf_aes(dev, sid, secret_id);
            let key = derive(dev, secret.key_id)
                .expect("KbkdfCounterHmacDerive")
                .data
                .key_id;
            let ciphertext = aes_cbc(dev, sid, key, DdiAesOp::Encrypt, &MSG).expect("encrypt");
            let restored = lm.cycle_keyed(dev, secret.key_id, secret.masked_key, derive);
            let key = derive(dev, restored.key_id)
                .expect("checkpoint 3")
                .data
                .key_id;
            let plaintext =
                aes_cbc(dev, sid, key, DdiAesOp::Decrypt, &ciphertext).expect("decrypt");
            assert_eq!(plaintext, MSG);
        },
    );
}

#[test]
fn nssr_hmac() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let key = create_hmac_key_ex(sid, DdiKeyType::HmacSha256, dev, None)
                .expect("HMAC key")
                .data;
            let mac = |dev: &Dev, key_id: u16| {
                helper_hmac(
                    dev,
                    Some(sid),
                    REV,
                    key_id,
                    MborByteArray::from_slice(&MSG).expect("message"),
                )
            };
            let tag = mac(dev, key.key_id).expect("Hmac").data.tag;
            let restored = lm.cycle_keyed(dev, key.key_id, key.masked_key, mac);
            assert_eq!(
                mac(dev, restored.key_id).expect("checkpoint 3").data.tag,
                tag
            );
        },
    );
}

/// The UnmaskKey row stops at recovery A: the masked keys are what survive.
#[test]
fn nssr_unmask_key() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let unmask = |dev: &Dev, masked_key| helper_unmask_key(dev, Some(sid), REV, masked_key);
            let keys = [DdiKeyAvailability::App, DdiKeyAvailability::Session].map(|availability| {
                let key = aes_key(dev, sid, availability);
                let ciphertext =
                    aes_cbc(dev, sid, key.key_id, DdiAesOp::Encrypt, &MSG).expect("encrypt");
                (key.masked_key, ciphertext)
            });
            lm.cycle(dev, |dev| unmask(dev, keys[0].0));
            for (masked_key, ciphertext) in keys {
                let key_id = unmask(dev, masked_key)
                    .expect("UnmaskKey of a pre-NSSR key")
                    .data
                    .key_id;
                let plaintext =
                    aes_cbc(dev, sid, key_id, DdiAesOp::Decrypt, &ciphertext).expect("decrypt");
                assert_eq!(plaintext, MSG);
            }
        },
    );
}
