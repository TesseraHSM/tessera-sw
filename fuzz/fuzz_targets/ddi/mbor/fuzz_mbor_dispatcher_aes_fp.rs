// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../mbor_common.rs"]
mod common;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_cred_encrypt::DeviceCredKey;
use tsra_ddi::DdiAesGcmParams;
use tsra_ddi::DdiAesXtsParams;
use tsra_ddi::DdiDev;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_test_helpers::*;
use tsra_ddi_mbor_types::DdiAesKeySize;
use tsra_ddi_mbor_types::DdiAesOp;
use tsra_ddi_mbor_types::DdiApiRev;
use tsra_ddi_mbor_types::DdiKeyAvailability;
use tsra_ddi_mbor_types::DdiKeyUsage;

/// A small enum to differentiate between dispatching an AES-GCM request and an
/// AES-XTS request.
#[derive(Debug, Arbitrary, Clone)]
enum FuzzAesType {
    AesGcm,
    AesXts,
}

#[derive(Debug, Arbitrary, Clone)]
enum FuzzAesMode {
    Encrypt,
    Decrypt,
}

// Keep the legacy simulator field order for existing fuzz corpora.
#[derive(Debug, Arbitrary, Clone)]
struct FuzzAesGcmRequest {
    key_id: u32,
    iv: [u8; 12],
    tag: Option<[u8; 16]>,
    session_id: u16,
    short_app_id: u8,
    aad: Option<Vec<u8>>,
}

#[derive(Debug, Arbitrary, Clone)]
struct FuzzAesXtsRequest {
    data_unit_len: usize,
    key_id1: u32,
    key_id2: u32,
    tweak: [u8; 16],
    session_id: u16,
    short_app_id: u8,
}

/// A struct containing several fields to adjust the manner in which this fuzz
/// target executes.
#[derive(Debug, Arbitrary, Clone)]
struct FuzzInput {
    /// Tells the test which type of AES fast-path operation to dispatch (GCM or
    /// XTS).
    aes_type: FuzzAesType,

    /// Tells the test which AES mode to submit for the GCM/XTS request.
    /// (Encrypt or decrypt)
    aes_mode: FuzzAesMode,

    /// Randomized AES-GCM request data.
    gcm_request: FuzzAesGcmRequest,

    /// Randomized AES-XTS request data.
    xts_request: FuzzAesXtsRequest,

    /// Source buffers concatenated for the DDI fast-path slice operation.
    source_buffers: Vec<Vec<u8>>,

    /// Destination buffers concatenated for the DDI fast-path slice operation.
    destination_buffers: Vec<Vec<u8>>,

    /// Use owned session and bulk-key IDs with valid buffer lengths.
    use_valid_key: bool,
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(|dev| {
        common::helper_common_establish_credential(
            dev,
            common::TEST_CRED_ID,
            common::TEST_CRED_PIN,
        );
        let rev = Some(DdiApiRev { major: 1, minor: 0 });
        let encryption_key = helper_get_session_encryption_key(dev, None, rev)
            .expect("Failed to get session encryption key");
        let key = DeviceCredKey::new(&encryption_key.data.pub_key, encryption_key.data.nonce)
            .expect("Invalid session encryption key");
        let (key, public_key) = key
            .generate_ephemeral_encryption_key()
            .expect("Failed to generate session encryption key");
        let credential = key
            .encrypt_session_credential(
                common::TEST_CRED_ID,
                common::TEST_CRED_PIN,
                [3; 48],
                encryption_key.data.nonce,
            )
            .expect("Failed to encrypt session credential");
        let session = helper_open_session(dev, None, rev, credential, public_key)
            .expect("Failed to open session");
        let session_id = session.data.sess_id;
        let short_app_id = session.data.short_app_id;
        let mut keys = Vec::new();
        let mut generate_key = |key_size| {
            let response = helper_aes_generate(
                dev,
                Some(session_id),
                rev,
                key_size,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            )
            .expect("Failed to generate bulk AES key");
            keys.push(response.data.key_id);
            u32::from(response.data.bulk_key_id.expect("Missing bulk AES key ID"))
        };

        let mut source: Vec<u8> = input.source_buffers.into_iter().flatten().collect();
        let mut destination: Vec<u8> = input.destination_buffers.into_iter().flatten().collect();
        let mode = match input.aes_mode {
            FuzzAesMode::Encrypt => DdiAesOp::Encrypt,
            FuzzAesMode::Decrypt => DdiAesOp::Decrypt,
        };
        let mut fips_approved = false;

        let result = match input.aes_type {
            FuzzAesType::AesGcm => {
                let mut request = input.gcm_request;
                if input.use_valid_key {
                    request.key_id = generate_key(DdiAesKeySize::AesGcmBulk256Unapproved);
                    request.session_id = session_id;
                    request.short_app_id = short_app_id;
                    if let Some(aad) = &mut request.aad {
                        aad.truncate(32);
                    }
                    // Bulk submissions allow 16 KiB including the aligned AAD.
                    source.resize(source.len().clamp(1, 16384 - 32), 0);
                    destination.resize(source.len(), 0);
                    if matches!(mode, DdiAesOp::Decrypt) {
                        request.tag = Some(request.tag.unwrap_or_default());
                    }
                }
                let mut tag = None;
                let mut iv = None;
                dev.exec_op_fp_gcm_slice(
                    mode,
                    DdiAesGcmParams {
                        key_id: request.key_id,
                        iv: request.iv,
                        aad: request.aad,
                        tag: request.tag,
                        session_id: request.session_id,
                        short_app_id: request.short_app_id,
                    },
                    &source,
                    &mut destination,
                    &mut tag,
                    &mut iv,
                    &mut fips_approved,
                )
            }
            FuzzAesType::AesXts => {
                let mut request = input.xts_request;
                if input.use_valid_key {
                    request.key_id1 = generate_key(DdiAesKeySize::AesXtsBulk256);
                    request.key_id2 = generate_key(DdiAesKeySize::AesXtsBulk256);
                    request.session_id = session_id;
                    request.short_app_id = short_app_id;
                    let len = source.len().clamp(16, 16384) / 16 * 16;
                    source.resize(len, 0);
                    destination.resize(len, 0);
                    request.data_unit_len = len;
                }
                dev.exec_op_fp_xts_slice(
                    mode,
                    DdiAesXtsParams {
                        data_unit_len: request.data_unit_len,
                        key_id1: request.key_id1,
                        key_id2: request.key_id2,
                        tweak: request.tweak,
                        session_id: request.session_id,
                        short_app_id: request.short_app_id,
                    },
                    &source,
                    &mut destination,
                    &mut fips_approved,
                )
            }
        };
        if let Err(
            err @ (DdiError::DriverError(_) | DdiError::IoError(_) | DdiError::DdiError(_)),
        ) = &result
        {
            panic!("Crash Detected: {err:?}");
        }
        if input.use_valid_key
            && (matches!(input.aes_type, FuzzAesType::AesXts) || matches!(mode, DdiAesOp::Encrypt))
        {
            assert_eq!(
                result.expect("Valid bulk AES request failed"),
                source.len(),
                "Bulk AES output length must match input"
            );
        }
        for key_id in keys {
            helper_delete_key(dev, Some(session_id), rev, key_id)
                .expect("Failed to delete bulk AES key");
        }
        common::cleanup_with_session(dev, Some(session_id));
    });
});
