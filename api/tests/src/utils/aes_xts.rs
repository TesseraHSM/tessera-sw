// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for building AES-XTS wrapped key-pair blobs in tests.

use tsra_api::*;

/// On-wire header for the AES-XTS key-pair blob:
/// `magic(u64 LE) || version(u16 LE) || key1_len(u16 LE) || key2_len(u16 LE) || reserved(u16 LE)`.
fn build_xts_wrapped_blob_header(key1_len: u16, key2_len: u16) -> [u8; 16] {
    // Keep tests agnostic to the internal Rust header struct.
    const WRAP_BLOB_MAGIC: u64 = 0x5354_582D_4152_5354;
    const WRAP_BLOB_VERSION: u16 = 1;

    let mut hdr = [0u8; 16];
    hdr[0..8].copy_from_slice(&WRAP_BLOB_MAGIC.to_le_bytes());
    hdr[8..10].copy_from_slice(&WRAP_BLOB_VERSION.to_le_bytes());
    hdr[10..12].copy_from_slice(&key1_len.to_le_bytes());
    hdr[12..14].copy_from_slice(&key2_len.to_le_bytes());
    // reserved already zero
    hdr
}

/// Build a wrapped AES-XTS key blob from two plaintext AES-256 halves.
///
/// MBOR sessions use the key-pair format (`header || wrap(K1) || wrap(K2)`).
/// Ex (TBOR) sessions hold XTS as one `AesXts512` key, so the blob is a
/// single RSA-AES wrap of `K1 || K2` (PKCS#11 `CKK_AES_XTS`).
pub(crate) fn build_xts_wrapped_blob(
    wrapping_pub_key: &HsmRsaPublicKey,
    hash: HsmHashAlgo,
    key1_plain: &[u8],
    key2_plain: &[u8],
) -> Vec<u8> {
    if crate::utils::session::api_rev_at_least(1, 1) {
        let key_plain = [key1_plain, key2_plain].concat();
        // AES-256 KEK; the KEK size is independent of the wrapped key size.
        let mut wrap_algo = HsmRsaAesWrapAlgo::new(hash, 32);
        return HsmEncrypter::encrypt_vec(&mut wrap_algo, wrapping_pub_key, &key_plain)
            .expect("Failed to wrap XTS key");
    }

    let mut wrap_algo_1 = HsmRsaAesWrapAlgo::new(hash, key1_plain.len());
    let key1_wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo_1, wrapping_pub_key, key1_plain)
        .expect("Failed to wrap XTS key1");

    let mut wrap_algo_2 = HsmRsaAesWrapAlgo::new(hash, key2_plain.len());
    let key2_wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo_2, wrapping_pub_key, key2_plain)
        .expect("Failed to wrap XTS key2");

    let key1_len = u16::try_from(key1_wrapped.len()).unwrap();
    let key2_len = u16::try_from(key2_wrapped.len()).unwrap();
    let header = build_xts_wrapped_blob_header(key1_len, key2_len);

    let mut blob = Vec::with_capacity(header.len() + key1_wrapped.len() + key2_wrapped.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&key1_wrapped);
    blob.extend_from_slice(&key2_wrapped);
    blob
}
