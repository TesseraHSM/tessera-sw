// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Requires Uno firmware with `tsra_test_hooks` and exclusive partition access.

#[allow(clippy::unwrap_used)]
mod common;
#[path = "helper/rollback.rs"]
mod rollback;

use std::time::Duration;
use std::time::Instant;

use common::*;
use test_with_tracing::test;
use tsra_crypto::*;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_types::*;

#[test]
fn test_rsa_unwrap_with_rollback_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });
            rollback::check_key_rollback(
                dev,
                session_id,
                |dev, _keys| {
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
                        .expect("wrap AES-256 key");
                    // The DDI pre-encode hook handles the RSA ciphertext byte order.
                    (
                        unwrapping.key_id,
                        MborByteArray::from_slice(&wrapped).expect("wrapped key"),
                    )
                },
                |dev, (key_id, wrapped)| {
                    helper_rsa_unwrap(
                        dev,
                        Some(session_id),
                        rev,
                        *key_id,
                        *wrapped,
                        DdiKeyClass::Aes,
                        DdiRsaCryptoPadding::Oaep,
                        DdiHashAlgorithm::Sha256,
                        None,
                        helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
                    )
                    .map(|resp| resp.data.key_id)
                },
            );
        },
    );
}
