// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR rows for the session-less credential / identity opcodes.

#![cfg(test)]

use test_with_tracing::test;

use super::*;
use crate::integration::attest_key::helper_get_cert_chain;

#[test]
fn nssr_get_api_rev() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let _lm = Lm::new(dev, ddi, path);
            let before = helper_get_api_rev(dev, None, None).expect("GetApiRev").data;
            nssr(dev);
            let after = helper_get_api_rev(dev, None, None)
                .expect("GetApiRev after NSSR")
                .data;
            assert_eq!((after.min, after.max), (before.min, before.max));
        },
    );
}

#[test]
fn nssr_get_device_info() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let _lm = Lm::new(dev, ddi, path);
            let info = |dev: &Dev| {
                let data = helper_get_device_info(dev, None, REV)
                    .expect("GetDeviceInfo")
                    .data;
                (data.kind, data.tables, data.fips_approved)
            };
            let before = info(dev);
            nssr(dev);
            assert_eq!(info(dev), before);
        },
    );
}

#[test]
fn nssr_get_cert_chain_info() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let _lm = Lm::new(dev, ddi, path);
            let (count, thumbprint) = helper_get_cert_chain_info_data(dev);
            nssr(dev);
            let after = helper_get_cert_chain_info_data(dev);
            assert_eq!(after.0, count, "the chain length survives NSSR");
            assert_ne!(
                after.1, thumbprint,
                "the regenerated leaf changes the thumbprint"
            );
            assert_eq!(
                helper_get_cert_chain_info_data(dev),
                after,
                "stable after NSSR"
            );
        },
    );
}

#[test]
fn nssr_get_certificate() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let _lm = Lm::new(dev, ddi, path);
            let before = helper_get_cert_chain(dev);
            let identity = helper_get_partition_id_pub_key(dev);
            nssr(dev);
            let after = helper_get_cert_chain(dev);
            let leaf = after.len() - 1;
            assert_eq!(after.len(), before.len());
            assert_eq!(after[..leaf], before[..leaf], "device certs survive NSSR");
            assert_ne!(after[leaf], before[leaf], "the partition leaf is reissued");
            assert_ne!(
                helper_get_partition_id_pub_key(dev),
                identity,
                "part_enable regenerates the partition identity key"
            );
            assert!(helper_verify_cert_chain(&after).is_ok());
        },
    );
}

#[test]
fn nssr_get_establish_cred_encryption_key() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            // A fresh partition: the tunnel key is not consumed yet.
            common_cleanup(dev, ddi, path, None);
            let get = |dev: &Dev| helper_get_establish_cred_encryption_key(dev, None, REV);
            let before = get(dev).expect("GetEstablishCredEncryptionKey").data;
            nssr(dev);
            let after = get(dev)
                .expect("GetEstablishCredEncryptionKey after NSSR")
                .data;
            assert_ne!(after.pub_key, before.pub_key, "new tunnel key");
            assert_ne!(after.nonce, before.nonce, "new nonce");

            // EstablishCredential consumes the tunnel key; NSSR re-arms it.
            helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN)
                .expect("EstablishCredential");
            assert_status(get(dev), DdiStatus::KeyNotFound, "consumed tunnel key");
            nssr(dev);
            get(dev).expect("NSSR re-arms the tunnel key");
        },
    );
}

#[test]
fn nssr_establish_credential() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let stale_endorsement = helper_get_pota_endorsement(dev);
            nssr(dev);

            let establish = |dev: &Dev, (signature, pota_pub_key): &(Vec<u8>, Vec<u8>)| {
                let (credential, pub_key) =
                    encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);
                helper_establish_credential(
                    dev,
                    None,
                    REV,
                    credential,
                    pub_key,
                    lm.0.masked_bk3,
                    lm.0.partition_bmk,
                    empty(),
                    MborByteArray::from_slice(signature).expect("POTA signature"),
                    DdiDerPublicKey {
                        der: MborByteArray::from_slice(pota_pub_key).expect("POTA public key"),
                        key_kind: DdiKeyType::Ecc384Public,
                    },
                )
            };
            // The POTA endorsement covers the identity key NSSR replaced.
            assert_status(
                establish(dev, &stale_endorsement),
                DdiStatus::EccVerifyFailed,
                "endorsement of the pre-NSSR identity",
            );
            let resp = establish(dev, &helper_get_pota_endorsement(dev))
                .expect("EstablishCredential with a fresh endorsement");
            assert!(!resp.data.bmk.is_empty());
            lm.reopen(dev)
                .expect("the restored credential reopens the migrated session");
        },
    );
}

#[test]
fn nssr_get_session_encryption_key() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let get = |dev: &Dev| helper_get_session_encryption_key(dev, None, REV);
            let before = get(dev).expect("GetSessionEncryptionKey").data;
            nssr(dev);
            assert_status(
                get(dev),
                DdiStatus::CredentialsNotEstablished,
                "before re-establishing the credential",
            );
            lm.reestablish_credential(dev);
            let after = get(dev)
                .expect("GetSessionEncryptionKey after recovery")
                .data;
            assert_ne!(after.pub_key, before.pub_key, "new session-encryption key");
            assert_ne!(after.nonce, before.nonce, "new nonce");
        },
    );
}
