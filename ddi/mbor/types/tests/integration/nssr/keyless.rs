// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR rows for in-session opcodes that take no pre-existing key.
//!
//! Each row runs [`Lm::cycle`]: the old session id is rejected with
//! `SessionNeedsRenegotiation`, and after recovery A the op succeeds again.

#![cfg(test)]

use test_with_tracing::test;

use super::*;

#[test]
fn nssr_sha_digest() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let digest = |dev: &Dev| {
                helper_sha_digest(
                    dev,
                    Some(sid),
                    REV,
                    MborByteArray::from_slice(&MSG).expect("message"),
                    DdiHashAlgorithm::Sha256,
                )
            };
            let before = digest(dev).expect("ShaDigest").data.digest;
            lm.cycle(dev, digest);
            let after = digest(dev).expect("ShaDigest after recovery").data.digest;
            assert_eq!(after, before);
            assert_eq!(after.as_slice(), crypto_sha256(&MSG));
        },
    );
}

#[test]
fn nssr_aes_generate_key() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let generate = |dev: &Dev| {
                helper_aes_generate(
                    dev,
                    Some(sid),
                    REV,
                    DdiAesKeySize::Aes256,
                    key_props(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
                )
            };
            generate(dev).expect("AesGenerateKey");
            lm.cycle(dev, generate);
            let key_id = generate(dev)
                .expect("AesGenerateKey after recovery")
                .data
                .key_id;
            let ciphertext = aes_cbc(dev, sid, key_id, DdiAesOp::Encrypt, &MSG).expect("encrypt");
            let plaintext =
                aes_cbc(dev, sid, key_id, DdiAesOp::Decrypt, &ciphertext).expect("decrypt");
            assert_eq!(plaintext, MSG);
        },
    );
}

#[test]
fn nssr_ecc_generate_key_pair() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let generate = |dev: &Dev| {
                helper_ecc_generate_key_pair(
                    dev,
                    Some(sid),
                    REV,
                    DdiEccCurve::P256,
                    key_props(DdiKeyUsage::SignVerify, DdiKeyAvailability::Session),
                )
            };
            generate(dev).expect("EccGenerateKeyPair");
            lm.cycle(dev, generate);
            let key = generate(dev)
                .expect("EccGenerateKeyPair after recovery")
                .data;
            let mut digest = [0u8; 96];
            digest[..32].copy_from_slice(&crypto_sha256(&MSG));
            let signature = helper_ecc_sign(
                dev,
                Some(sid),
                REV,
                key.private_key_id,
                MborByteArray::new(digest, 32).expect("digest"),
                DdiHashAlgorithm::Sha256,
            )
            .expect("EccSign with the new key")
            .data
            .signature;
            assert!(ecc_verify_local_openssl(
                signature.as_slice(),
                &key.pub_key,
                digest,
                32
            ));
        },
    );
}

/// The vault wipe drops the unwrapping key, but the partition re-imports
/// its per-allocation copy on the next read (fw/plat/std/pal/src/part.rs:650-653),
/// so the masked unwrapping key `EstablishCredential` accepts is not needed.
#[test]
fn nssr_get_unwrapping_key() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let (_, before, _) = get_unwrapping_key(dev, sid);
            lm.cycle(dev, |dev| helper_get_unwrapping_key(dev, Some(sid), REV));
            let (_, after, _) = get_unwrapping_key(dev, sid);
            assert_eq!(after, before, "the same unwrapping key");
        },
    );
}

#[test]
fn nssr_change_pin() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let change = |dev: &Dev, (pin, pub_key): (DdiEncryptedPin, DdiDerPublicKey)| {
                helper_change_pin(dev, Some(sid), REV, pin, pub_key)
            };
            let stale = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);
            nssr(dev);
            assert_stale_session(change(dev, stale.clone()));
            lm.recover_session(dev);
            assert_status(
                change(dev, stale),
                DdiStatus::NonceMismatch,
                "pre-NSSR payload",
            );
            change(dev, encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT))
                .expect("ChangePin after recovery");

            // New sessions authenticate with the new PIN only.
            let dev2 = ddi.open_dev(path).expect("second handle");
            let open = |pin| {
                let (credential, pub_key) = encrypt_userid_pin_for_open_session(
                    &dev2,
                    TEST_CRED_ID,
                    pin,
                    TEST_SESSION_SEED,
                );
                helper_open_session(&dev2, None, REV, credential, pub_key)
            };
            assert_status(
                open(TEST_CRED_PIN),
                DdiStatus::InvalidAppCredentials,
                "old PIN",
            );
            let sid2 = open(TEST_CRED_PIN_ALT)
                .expect("OpenSession with the new PIN")
                .data
                .sess_id;
            helper_close_session(&dev2, Some(sid2), REV).expect("CloseSession");
        },
    );
}

/// `DdiOpenKeyReq` exists on the host and firmware, but firmware has no
/// handler: the session gate still answers first after NSSR.
#[test]
fn nssr_open_key() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let open_key = |dev: &Dev| {
                let req = DdiOpenKeyCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::OpenKey,
                        sess_id: Some(sid),
                        rev: REV,
                    },
                    data: DdiOpenKeyReq { key_tag: 0x5A5A },
                    ext: None,
                };
                dev.exec_op_mbor(&req, &mut None)
            };
            assert_status(open_key(dev), DdiStatus::UnsupportedCmd, "before NSSR");
            lm.cycle(dev, open_key);
            assert_status(open_key(dev), DdiStatus::UnsupportedCmd, "after recovery");
        },
    );
}
