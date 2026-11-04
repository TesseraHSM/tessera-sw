// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::ofb_tests_helper::OfbTestVectorFailure;
use super::ofb_tests_helper::assert_ofb_vector_success;
use super::ofb_tests_helper::test_single_shot_decrypt;
use super::ofb_tests_helper::test_single_shot_encrypt;
use super::ofb_tests_helper::test_streaming_decrypt;
use super::ofb_tests_helper::test_streaming_encrypt;
use crate::testvectors::aes::AES_OFB_128_SBOX_TEST_VECTORS;
use crate::testvectors::aes::AES_OFB_192_SBOX_TEST_VECTORS;
use crate::testvectors::aes::AES_OFB_256_SBOX_TEST_VECTORS;
use crate::testvectors::aes::AesOfbTestVector;

const STREAMING_CHUNK_LENS: [usize; 6] = [1, 3, 7, 9, 5, 19];

fn check_sbox_vector_one_shot(vector: &AesOfbTestVector) -> Result<(), OfbTestVectorFailure> {
    let (input, expected) = if vector.encrypt {
        (vector.plaintext, vector.ciphertext)
    } else {
        (vector.ciphertext, vector.plaintext)
    };

    let output = if vector.encrypt {
        test_single_shot_encrypt(vector.key, vector.iv, input)
    } else {
        test_single_shot_decrypt(vector.key, vector.iv, input)
    }
    .map_err(|e| OfbTestVectorFailure::Crypto {
        id: vector.test_count_id,
        encrypt: vector.encrypt,
        source: e,
    })?;

    if output.as_slice() != expected {
        return Err(OfbTestVectorFailure::Mismatch {
            id: vector.test_count_id,
            encrypt: vector.encrypt,
            key: vector.key,
            iv: vector.iv,
            input,
            expected,
            actual: output,
        });
    }

    Ok(())
}

fn check_sbox_vector_streaming(vector: &AesOfbTestVector) -> Result<(), OfbTestVectorFailure> {
    let (input, expected) = if vector.encrypt {
        (vector.plaintext, vector.ciphertext)
    } else {
        (vector.ciphertext, vector.plaintext)
    };

    let output = if vector.encrypt {
        test_streaming_encrypt(vector.key, vector.iv, input, &STREAMING_CHUNK_LENS)
    } else {
        test_streaming_decrypt(vector.key, vector.iv, input, &STREAMING_CHUNK_LENS)
    }
    .map_err(|e| OfbTestVectorFailure::Crypto {
        id: vector.test_count_id,
        encrypt: vector.encrypt,
        source: e,
    })?;

    if output.as_slice() != expected {
        return Err(OfbTestVectorFailure::Mismatch {
            id: vector.test_count_id,
            encrypt: vector.encrypt,
            key: vector.key,
            iv: vector.iv,
            input,
            expected,
            actual: output,
        });
    }

    Ok(())
}

#[test]
fn test_aes_128_nist_sbox_vectors() {
    for vector in AES_OFB_128_SBOX_TEST_VECTORS.iter() {
        assert_ofb_vector_success(
            "AES-128 OFB NIST S-box (one-shot)",
            "AES-128 OFB S-box (one-shot) mismatch!",
            check_sbox_vector_one_shot(vector),
        );
    }
}

#[test]
fn test_aes_192_nist_sbox_vectors() {
    for vector in AES_OFB_192_SBOX_TEST_VECTORS.iter() {
        assert_ofb_vector_success(
            "AES-192 OFB NIST S-box (one-shot)",
            "AES-192 OFB S-box (one-shot) mismatch!",
            check_sbox_vector_one_shot(vector),
        );
    }
}

#[test]
fn test_aes_256_nist_sbox_vectors() {
    for vector in AES_OFB_256_SBOX_TEST_VECTORS.iter() {
        assert_ofb_vector_success(
            "AES-256 OFB NIST S-box (one-shot)",
            "AES-256 OFB S-box (one-shot) mismatch!",
            check_sbox_vector_one_shot(vector),
        );
    }
}

#[test]
fn test_aes_128_nist_sbox_vectors_streaming() {
    for vector in AES_OFB_128_SBOX_TEST_VECTORS.iter() {
        assert_ofb_vector_success(
            "AES-128 OFB NIST S-box (streaming)",
            "AES-128 OFB NIST S-box (streaming) mismatch!",
            check_sbox_vector_streaming(vector),
        );
    }
}

#[test]
fn test_aes_192_nist_sbox_vectors_streaming() {
    for vector in AES_OFB_192_SBOX_TEST_VECTORS.iter() {
        assert_ofb_vector_success(
            "AES-192 OFB NIST S-box (streaming)",
            "AES-192 OFB NIST S-box (streaming) mismatch!",
            check_sbox_vector_streaming(vector),
        );
    }
}

#[test]
fn test_aes_256_nist_sbox_vectors_streaming() {
    for vector in AES_OFB_256_SBOX_TEST_VECTORS.iter() {
        assert_ofb_vector_success(
            "AES-256 OFB NIST S-box (streaming)",
            "AES-256 OFB NIST S-box (streaming) mismatch!",
            check_sbox_vector_streaming(vector),
        );
    }
}
