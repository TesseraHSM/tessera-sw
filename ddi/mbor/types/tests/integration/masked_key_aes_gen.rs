// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use test_with_tracing::test;
use tsra_ddi::*;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_types::*;

use super::common::*;

const RAW_MSG: [u8; 512] = [1u8; 512];

#[test]
fn test_masked_key_aes_128_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_masked_key_aes_gen(dev, session_id, DdiAesKeySize::Aes128);
        },
    );
}

#[test]
fn test_masked_key_aes_192_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_masked_key_aes_gen(dev, session_id, DdiAesKeySize::Aes192);
        },
    );
}

#[test]
fn test_masked_key_aes_256_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_masked_key_aes_gen(dev, session_id, DdiAesKeySize::Aes256);
        },
    );
}

fn test_masked_key_aes_gen(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_size: DdiAesKeySize,
) {
    // Generate a key
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

    let resp = helper_aes_generate(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_size,
        Some(1),
        key_props,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    let key_id = resp.data.key_id;
    let masked_key = resp.data.masked_key;

    assert!(verify_iv_not_default_from_masked_key(masked_key.as_slice()).unwrap_or(false));

    assert!(verify_masked_key_attributes(
        masked_key.as_slice(),
        MaskedKeyAttributes::ENCRYPT | MaskedKeyAttributes::DECRYPT | MaskedKeyAttributes::LOCAL
    ));

    // Encrypt the plain text with the key
    let iv = MborByteArray::new([0x8; 16], 16).expect("failed to create byte array");

    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        DdiAesOp::Encrypt,
        MborByteArray::from_slice(&RAW_MSG).expect("failed to create byte array"),
        iv,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    assert_eq!(resp.data.msg.len(), RAW_MSG.len());
    assert_ne!(RAW_MSG, resp.data.msg.as_slice());

    let encrypted_msg = resp.data.msg.as_slice().to_vec();

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        false,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (new_key_id, _, _) = resp.unwrap();

    // Decrypt the plain text
    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        new_key_id,
        DdiAesOp::Decrypt,
        MborByteArray::from_slice(encrypted_msg.as_slice()).expect("failed to create byte array"),
        iv,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    // Verify the plain text
    assert_eq!(resp.data.msg.as_slice(), RAW_MSG);
    assert_eq!(resp.data.msg.len(), RAW_MSG.len());
}

// Create session key, delete the key
// Unmask the key, should still be session key
#[test]
fn test_unmask_session_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session);

            // Create a session key
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;

            let key_id = data.key_id;

            let masked_key = data.masked_key;
            assert!(!masked_key.is_empty());

            // Delete the original key
            {
                let resp = helper_delete_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Import/unmask the key
            let key_id = {
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    masked_key,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let data = resp.unwrap().data;
                data.key_id
            };

            // Check if this key is session key
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            // Should fail
            assert!(resp.is_err());

            // Close session and reopen
            let session_id = {
                let resp = helper_close_session(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);

                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                resp.data.sess_id
            };

            // Check if the session key still exists
            // By using it to encrypt
            {
                let raw_msg = [1u8; 512];
                let msg_len = raw_msg.len();
                let mut msg = [0u8; 1024];
                msg[..msg_len].clone_from_slice(&raw_msg);

                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                    DdiAesOp::Encrypt,
                    MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                    MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_err(), "resp {:?}", resp);
            }
        },
    );
}

// Create named key, delete the key
// Unmask the key, should still be named key
#[cfg(not(feature = "emu"))]
#[test]
fn test_unmask_named_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            const KEY_TAG: u16 = 0x1234;
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            // Create a named key
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                Some(KEY_TAG),
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;

            let key_id = data.key_id;

            let masked_key = data.masked_key;
            assert!(!masked_key.is_empty());

            // Delete the key
            {
                let resp = helper_delete_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Close session and open session with new seed
            let session_id = {
                let resp = helper_close_session(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);

                let new_session_seed = [42u8; 48];
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    new_session_seed,
                );

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                resp.data.sess_id
            };

            // Import/unmask the key
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            // Check if this key is named key
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            // Should pass
            assert!(resp.is_ok());

            // Key should still be there
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            // Should pass
            assert!(resp.is_ok());
        },
    );
}

// Create session key
// Confirm unmasking into different session fails
#[test]
fn test_unmask_session_key_different_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session);

            // Create a session key
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;

            let key_id = data.key_id;

            let masked_key = data.masked_key;
            assert!(!masked_key.is_empty());

            // Delete the original key
            {
                let resp = helper_delete_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Close session and open session with new seed
            let session_id = {
                let resp = helper_close_session(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);

                let new_session_seed = [42u8; 48];
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    new_session_seed,
                );

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                resp.data.sess_id
            };

            // Import/unmask the key; should fail
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );
            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

/// Helper: generate a bulk key, extract and compare attributes after unmask.
///
/// 1. Generate an AES bulk key with the given size, availability, and optional key tag.
/// 2. Extract metadata/attributes from the original masked key blob.
/// 3. Delete the original key.
/// 4. Unmask the key from the masked blob.
/// 5. Extract metadata/attributes from the unmasked key's masked blob.
/// 6. Assert that attributes, raw attribute blob, and metadata fields match exactly.
fn unmask_bulk_key_and_verify_attributes(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    aes_key_size: DdiAesKeySize,
    availability: DdiKeyAvailability,
    key_tag: Option<u16>,
) {
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, availability);

    let resp = helper_aes_generate(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        aes_key_size,
        key_tag,
        key_props,
    );
    assert!(resp.is_ok(), "Failed to generate key: {:?}", resp);
    let data = resp.unwrap().data;

    let key_id = data.key_id;
    let original_masked_key = data.masked_key;
    assert!(!original_masked_key.is_empty());

    // Extract metadata from original masked key
    let original_metadata = extract_metadata_from_masked_key(original_masked_key.as_slice())
        .expect("Failed to extract metadata from original masked key");
    let original_attrs = MaskedKeyAttributes::try_from(&original_metadata.key_attributes)
        .expect("Failed to parse original attributes");

    // Delete the original key
    let resp = helper_delete_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
    );
    assert!(resp.is_ok(), "Failed to delete key: {:?}", resp);

    // Unmask the key
    let resp = helper_unmask_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        original_masked_key,
    );
    assert!(resp.is_ok(), "Failed to unmask key: {:?}", resp);
    let unmasked_data = resp.unwrap().data;

    // Extract metadata from unmasked key's masked blob
    let unmasked_masked_key = unmasked_data.masked_key;
    assert!(!unmasked_masked_key.is_empty());
    let unmasked_metadata = extract_metadata_from_masked_key(unmasked_masked_key.as_slice())
        .expect("Failed to extract metadata from unmasked masked key");
    let unmasked_attrs = MaskedKeyAttributes::try_from(&unmasked_metadata.key_attributes)
        .expect("Failed to parse unmasked attributes");

    // Exact attribute equality — catches any dropped flags
    assert_eq!(
        original_attrs, unmasked_attrs,
        "Key attributes mismatch after unmask: original {:?} != unmasked {:?}",
        original_attrs, unmasked_attrs
    );

    // Raw 32-byte attribute blob comparison
    assert_eq!(
        original_metadata.key_attributes.blob, unmasked_metadata.key_attributes.blob,
        "Raw attribute blob mismatch after unmask"
    );

    // Verify metadata fields are preserved
    assert_eq!(
        original_metadata.key_type, unmasked_metadata.key_type,
        "key_type mismatch after unmask"
    );
    assert_eq!(
        original_metadata.key_length, unmasked_metadata.key_length,
        "key_length mismatch after unmask"
    );
    assert_eq!(
        original_metadata.key_tag, unmasked_metadata.key_tag,
        "key_tag mismatch after unmask"
    );

    // Clean up the unmasked key
    let resp = helper_delete_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        unmasked_data.key_id,
    );
    assert!(resp.is_ok(), "Failed to delete unmasked key: {:?}", resp);
}

// Generate an AES XTS Bulk 256 App key, unmask it, and verify all attributes are preserved.
#[test]
fn test_unmask_xts_bulk_key_preserves_attributes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            unmask_bulk_key_and_verify_attributes(
                dev,
                session_id,
                DdiAesKeySize::AesXtsBulk256,
                DdiKeyAvailability::App,
                Some(0x5001),
            );
        },
    );
}

// Generate an AES XTS Bulk 256 Session key, unmask it, and verify all attributes
// (including the SESSION flag) are preserved.
#[test]
fn test_unmask_xts_bulk_session_key_preserves_attributes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            unmask_bulk_key_and_verify_attributes(
                dev,
                session_id,
                DdiAesKeySize::AesXtsBulk256,
                DdiKeyAvailability::Session,
                None,
            );
        },
    );
}

// Generate an AES GCM Bulk 256 App key, unmask it, and verify all attributes are preserved.
#[test]
fn test_unmask_gcm_bulk_key_preserves_attributes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            unmask_bulk_key_and_verify_attributes(
                dev,
                session_id,
                DdiAesKeySize::AesGcmBulk256,
                DdiKeyAvailability::App,
                Some(0x5002),
            );
        },
    );
}

// Generate an AES GCM Bulk 256 Session key, unmask it, and verify all attributes
// (including the SESSION flag) are preserved.
#[test]
fn test_unmask_gcm_bulk_session_key_preserves_attributes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            unmask_bulk_key_and_verify_attributes(
                dev,
                session_id,
                DdiAesKeySize::AesGcmBulk256,
                DdiKeyAvailability::Session,
                None,
            );
        },
    );
}
