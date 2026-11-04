// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn test_aes192_kwp_vector1() {
    let key = hex::decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8").unwrap();
    let pt = hex::decode("c37b7e6492584340bed12207808941155068f738").unwrap();
    let ct =
        hex::decode("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a").unwrap();

    // Encryption
    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut kwp = AesKeyWrapPadAlgo::default();
    let actual_ct = Encrypter::encrypt_vec(&mut kwp, &aes_key, &pt).expect("Encryption failed");
    assert_eq!(actual_ct, ct);

    // Decryption
    let actual_pt = Decrypter::decrypt_vec(&mut kwp, &aes_key, &ct).expect("Decryption failed");
    assert_eq!(actual_pt, pt);
}

#[test]
fn test_aes192_kwp_vector2() {
    let key = hex::decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8").unwrap();
    let pt = hex::decode("466f7250617369").unwrap();
    let ct = hex::decode("afbeb0f07dfbf5419200f2ccb50bb24f").unwrap();

    // Encryption
    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut kwp = AesKeyWrapPadAlgo::default();
    let actual_ct = Encrypter::encrypt_vec(&mut kwp, &aes_key, &pt).expect("Encryption failed");
    assert_eq!(actual_ct, ct);

    // Single-semiblock path: query and exact-size output buffer.
    assert_eq!(kwp.encrypt(&aes_key, &pt, None), Ok(ct.len()));
    let mut exact = vec![0u8; ct.len()];
    assert_eq!(kwp.encrypt(&aes_key, &pt, Some(&mut exact)), Ok(ct.len()));
    assert_eq!(exact, ct);

    // Decryption
    let actual_pt = Decrypter::decrypt_vec(&mut kwp, &aes_key, &ct).expect("Decryption failed");
    assert_eq!(actual_pt, pt);
}

#[test]
fn test_aes192_kwp_exactly_eight_bytes() {
    let key = hex::decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8").unwrap();
    let pt = hex::decode("0001020304050607").unwrap();
    // OpenSSL AES-192-ECB over the RFC 5649 AIV followed by the plaintext.
    let ct = hex::decode("ebc0330864fe681ead53d839b34b9c66").unwrap();
    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut kwp = AesKeyWrapPadAlgo::default();

    assert_eq!(kwp.encrypt(&aes_key, &pt, None), Ok(ct.len()));
    let mut exact = vec![0u8; ct.len()];
    assert_eq!(kwp.encrypt(&aes_key, &pt, Some(&mut exact)), Ok(ct.len()));
    assert_eq!(exact, ct);
    let actual_pt = Decrypter::decrypt_vec(&mut kwp, &aes_key, &exact).expect("Decryption failed");
    assert_eq!(actual_pt, pt);
}
