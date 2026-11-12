// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Requires physical Uno firmware with `tsra_test_hooks` and exclusive partition access.
//!
//! These tests exercise the host-visible DDI contract independently of the
//! firmware's bulk engine. Firmware must support bulk key creation and bulk
//! data IO; unsupported bulk IO fails the test rather than skipping verification.
//!
//! Test flow:
//! 1. Establish a fresh credential and open a bulk verification session,
//!    retaining the returned session and short application IDs for bulk IO.
//! 2. Repeat each command for approved GCM, unapproved GCM, and XTS outputs.
//!    Prepare a derivation secret, RSA-wrapped AES material, or a masked source
//!    key as required by the command. XTS also needs an independent companion key.
//! 3. Create outputs until capacity is exhausted. Keep an existing output alive
//!    and delete another to make room for exactly one new output.
//! 4. Arm TriggerIoFailure and issue the command again. Expect InvalidKeyType
//!    after output creation, exercising rollback of the attempt-owned bulk key.
//! 5. Retry without resetting the device: one creation must succeed, and the next
//!    must report NotEnoughSpace. This checks reclamation without losing other keys.
//! 6. Encrypt and decrypt with both the retained and recovered outputs. For
//!    UnmaskKey, also verify that the original source key remains usable.
//!    Approved GCM decryption uses the IV returned by encryption.
//! 7. Delete output and input keys and close the verification session. Cleanup
//!    is also attempted when an assertion panics.

#[allow(clippy::unwrap_used)]
mod common;
#[path = "helper/rollback.rs"]
mod rollback;

use std::panic::AssertUnwindSafe;
use std::time::Duration;
use std::time::Instant;

use common::*;
use test_with_tracing::test;
use tsra_crypto::*;
use tsra_ddi::Ddi;
use tsra_ddi::DdiAesGcmParams;
use tsra_ddi::DdiAesXtsParams;
use tsra_ddi::DdiDev;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_types::*;

#[test]
fn test_aes_bulk_rollback() {
    ddi_dev_test(common_setup, common_cleanup, |dev, ddi, path, _| {
        check_bulk_cases(dev, ddi, path, DdiOp::AesGenerateKey);
    });
}

#[test]
fn test_hkdf_bulk_rollback() {
    ddi_dev_test(common_setup, common_cleanup, |dev, ddi, path, _| {
        check_bulk_cases(dev, ddi, path, DdiOp::HkdfDerive);
    });
}

#[test]
fn test_kbkdf_bulk_rollback() {
    ddi_dev_test(common_setup, common_cleanup, |dev, ddi, path, _| {
        check_bulk_cases(dev, ddi, path, DdiOp::KbkdfCounterHmacDerive);
    });
}

#[test]
fn test_rsa_unwrap_bulk_rollback() {
    ddi_dev_test(common_setup, common_cleanup, |dev, ddi, path, _| {
        check_bulk_cases(dev, ddi, path, DdiOp::RsaUnwrap);
    });
}

#[test]
fn test_unmask_bulk_rollback() {
    ddi_dev_test(common_setup, common_cleanup, |dev, ddi, path, _| {
        check_bulk_cases(dev, ddi, path, DdiOp::UnmaskKey);
    });
}

fn check_bulk_cases(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str, op: DdiOp) {
    assert_eq!(
        get_device_kind(dev),
        DdiDeviceKind::Physical,
        "bulk rollback requires physical firmware"
    );
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let mut bulk_dev = ddi.open_dev(path).expect("open bulk session handle");
    let (credential, public) =
        encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);
    let opened = helper_open_session(&bulk_dev, None, rev, credential, public)
        .expect("open bulk verification session");
    let session_id = opened.data.sess_id;
    let short_app_id = opened.data.short_app_id;
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        for size in [
            DdiAesKeySize::AesGcmBulk256,
            DdiAesKeySize::AesGcmBulk256Unapproved,
            DdiAesKeySize::AesXtsBulk256,
        ] {
            let kind: DdiKeyType = size.try_into().ok().expect("bulk key type");
            rollback::check_key_rollback_with_verify(
                &mut bulk_dev,
                session_id,
                |dev, keys| {
                    let companion = if kind == DdiKeyType::AesXtsBulk256 {
                        let key = helper_aes_generate(
                            dev,
                            Some(session_id),
                            rev,
                            size,
                            None,
                            bulk_properties(),
                        )
                        .expect("independent XTS companion key");
                        keys.push(key.data.key_id);
                        Some(key.data.bulk_key_id.expect("XTS companion bulk ID"))
                    } else {
                        None
                    };
                    (prepare_input(dev, session_id, op, size, keys), companion)
                },
                |dev, (input, _)| create_bulk_key(dev, session_id, op, size, kind, input),
                |(key_id, _)| key_id,
                |dev, (input, companion), retained, recovered| {
                    for (_, bulk_id) in [retained, recovered] {
                        assert_bulk_key(dev, session_id, short_app_id, kind, bulk_id, *companion);
                    }
                    if let Some(bulk_id) = input.source_bulk_id {
                        assert_bulk_key(dev, session_id, short_app_id, kind, bulk_id, *companion);
                    }
                },
            );
        }
    }));
    let closed = helper_close_session(&bulk_dev, Some(session_id), rev);
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
    closed.expect("close bulk verification session");
}

fn bulk_properties() -> DdiKeyProperties {
    helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App)
}

struct BulkInput {
    key_id: u16,
    blob: MborByteArray<3072>,
    source_bulk_id: Option<u16>,
}

fn prepare_input(
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    op: DdiOp,
    size: DdiAesKeySize,
    keys: &mut Vec<u16>,
) -> BulkInput {
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let empty = MborByteArray::from_slice(&[]).expect("empty input");
    let mut source_bulk_id = None;
    let (key_id, blob) = match op {
        DdiOp::AesGenerateKey => (0, empty),
        DdiOp::HkdfDerive | DdiOp::KbkdfCounterHmacDerive => {
            (rollback::kdf_input(dev, session_id, keys), empty)
        }
        DdiOp::UnmaskKey => {
            let original =
                helper_aes_generate(dev, Some(session_id), rev, size, None, bulk_properties())
                    .expect("generate masked bulk input");
            keys.push(original.data.key_id);
            source_bulk_id = Some(original.data.bulk_key_id.expect("source bulk ID"));
            (original.data.key_id, original.data.masked_key)
        }
        DdiOp::RsaUnwrap => {
            let deadline = Instant::now() + Duration::from_secs(120);
            let unwrapping = loop {
                match helper_get_unwrapping_key(dev, Some(session_id), rev) {
                    Ok(resp) => break resp.data,
                    Err(DdiError::DdiStatus(DdiStatus::PendingKeyGeneration))
                        if Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(err) => panic!("Unwrapping key unavailable: {err:?}"),
                }
            };
            let public = RsaPublicKey::from_bytes(unwrapping.pub_key.der.as_slice())
                .expect("unwrapping public key");
            let mut wrapper = RsaAesKeyWrap::new(HashAlgo::sha256(), 32);
            let wrapped = Encrypter::encrypt_vec(&mut wrapper, &public, &[0x73; 32])
                .expect("wrap bulk AES material");
            (
                unwrapping.key_id,
                MborByteArray::from_slice(&wrapped).expect("wrapped key"),
            )
        }
        _ => panic!("unsupported bulk rollback operation"),
    };
    BulkInput {
        key_id,
        blob,
        source_bulk_id,
    }
}

fn create_bulk_key(
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    op: DdiOp,
    size: DdiAesKeySize,
    kind: DdiKeyType,
    input: &BulkInput,
) -> Result<(u16, u16), DdiError> {
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let (key_id, bulk_id) = match op {
        DdiOp::AesGenerateKey => {
            let resp =
                helper_aes_generate(dev, Some(session_id), rev, size, None, bulk_properties())?;
            (resp.data.key_id, resp.data.bulk_key_id)
        }
        DdiOp::HkdfDerive => {
            let resp = helper_hkdf_derive(
                dev,
                Some(session_id),
                rev,
                input.key_id,
                DdiHashAlgorithm::Sha256,
                None,
                None,
                kind,
                None,
                bulk_properties(),
                None,
            )?;
            (resp.data.key_id, resp.data.bulk_key_id)
        }
        DdiOp::KbkdfCounterHmacDerive => {
            let resp = helper_kbkdf_derive(
                dev,
                Some(session_id),
                rev,
                input.key_id,
                DdiHashAlgorithm::Sha256,
                None,
                Some(MborByteArray::from_slice(&[1]).expect("KDF context")),
                kind,
                None,
                bulk_properties(),
                None,
            )?;
            (resp.data.key_id, resp.data.bulk_key_id)
        }
        DdiOp::UnmaskKey => {
            let resp = helper_unmask_key(dev, Some(session_id), rev, input.blob)?;
            (resp.data.key_id, resp.data.bulk_key_id)
        }
        DdiOp::RsaUnwrap => {
            let class = match kind {
                DdiKeyType::AesGcmBulk256 => DdiKeyClass::AesGcmBulk,
                DdiKeyType::AesGcmBulk256Unapproved => DdiKeyClass::AesGcmBulkUnapproved,
                DdiKeyType::AesXtsBulk256 => DdiKeyClass::AesXtsBulk,
                _ => panic!("unsupported bulk key type"),
            };
            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                rev,
                input.key_id,
                input.blob,
                class,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                bulk_properties(),
            )?;
            (resp.data.key_id, resp.data.bulk_key_id)
        }
        _ => panic!("unsupported bulk rollback operation"),
    };
    Ok((key_id, bulk_id.expect("bulk output must have a bulk ID")))
}

fn assert_bulk_key(
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    short_app_id: u8,
    kind: DdiKeyType,
    bulk_id: u16,
    companion: Option<u16>,
) {
    let plaintext = vec![0x42; 512];
    if kind == DdiKeyType::AesXtsBulk256 {
        let params = DdiAesXtsParams {
            key_id1: u32::from(bulk_id),
            key_id2: u32::from(companion.expect("independent XTS companion")),
            data_unit_len: plaintext.len(),
            session_id,
            short_app_id,
            tweak: [0x17; 16],
        };
        let encrypted = dev
            .exec_op_fp_xts(DdiAesOp::Encrypt, params.clone(), plaintext.clone())
            .expect("bulk XTS key must encrypt");
        assert_ne!(encrypted.data, plaintext);
        let decrypted = dev
            .exec_op_fp_xts(DdiAesOp::Decrypt, params, encrypted.data)
            .expect("bulk XTS key must decrypt");
        assert_eq!(decrypted.data, plaintext);
    } else {
        let mut params = DdiAesGcmParams {
            key_id: u32::from(bulk_id),
            iv: [0x17; 12],
            aad: Some(vec![0x31; 32]),
            tag: None,
            session_id,
            short_app_id,
        };
        let encrypted = dev
            .exec_op_fp_gcm(DdiAesOp::Encrypt, params.clone(), plaintext.clone())
            .expect("bulk GCM key must encrypt");
        assert_ne!(encrypted.data, plaintext);
        params.tag = Some(encrypted.tag.expect("GCM authentication tag"));
        if kind == DdiKeyType::AesGcmBulk256 {
            params.iv = encrypted.iv.expect("device-generated approved GCM IV");
        }
        let decrypted = dev
            .exec_op_fp_gcm(DdiAesOp::Decrypt, params, encrypted.data)
            .expect("bulk GCM key must decrypt");
        assert_eq!(decrypted.data, plaintext);
    }
}
