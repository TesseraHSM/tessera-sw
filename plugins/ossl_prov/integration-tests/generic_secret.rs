// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wrapped-import fixtures for provider KBKDF tests. The provider initializes
//! the partition first; this helper opens the same application without resetting it.

use std::path::Path;

use tsra_api::*;

pub fn write_fixture(id_hex: &str, pin_hex: &str, key_bytes: u32, path: &Path) {
    let revision = HsmApiRev { major: 1, minor: 0 };
    let partitions = HsmPartitionManager::partition_info_list();
    let info = partitions
        .iter()
        .find(|info| {
            info.api_rev_range
                .is_some_and(|range| range.min() <= revision && revision <= range.max())
        })
        .expect("Provider fixture needs an MBOR partition");
    let partition = HsmPartitionManager::open_partition(&info.path, revision)
        .expect("Open provider fixture partition");
    let credentials = HsmCredentials {
        id: credential_bytes(id_hex),
        pin: credential_bytes(pin_hex),
    };
    let session = partition
        .open_session(revision, &credentials, None)
        .expect("Open provider fixture session");
    let private_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("RSA unwrapping properties");
    let public_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("RSA wrapping properties");
    let (private, public) = HsmKeyManager::generate_key_pair(
        &session,
        &mut HsmRsaKeyUnwrappingKeyGenAlgo::default(),
        private_props,
        public_props,
    )
    .expect("Get fixture unwrapping key");
    let material: Vec<u8> = (0..key_bytes).map(|i| i as u8).collect();
    let wrapped = HsmEncrypter::encrypt_vec(
        &mut HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32),
        &public,
        &material,
    )
    .expect("Wrap generic-secret fixture");
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::GenericSecret)
        .bits(key_bytes * 8)
        .can_derive(true)
        .build()
        .expect("Generic-secret fixture properties");
    let key = HsmKeyManager::unwrap_key(
        &mut HsmGenericSecretKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256),
        &private,
        &wrapped,
        props,
    )
    .expect("Import generic-secret fixture");
    std::fs::write(
        path,
        key.masked_key_vec().expect("Masked generic-secret fixture"),
    )
    .expect("Write generic-secret fixture");
    HsmKeyManager::delete_key(key).expect("Delete resident fixture key");
}

fn credential_bytes(hex: &str) -> [u8; 16] {
    assert_eq!(
        hex.len(),
        32,
        "Fixture credentials must contain 32 hex digits"
    );
    let mut bytes = [0; 16];
    for (out, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *out = u8::from_str_radix(std::str::from_utf8(pair).expect("Hex credential"), 16)
            .expect("Hex credential");
    }
    bytes
}
