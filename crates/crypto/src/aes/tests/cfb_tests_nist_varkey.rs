// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::cfb_tests_helper::CfbTestVectorFailure;
use super::cfb_tests_helper::assert_cfb_vector_success;
use super::cfb_tests_helper::test_single_shot_decrypt;
use super::cfb_tests_helper::test_single_shot_encrypt;
use super::cfb_tests_helper::test_streaming_decrypt;
use super::cfb_tests_helper::test_streaming_encrypt;
use crate::testvectors::aes::AES_CFB_128_VAR_KEY_TEST_VECTORS;
use crate::testvectors::aes::AES_CFB_192_VAR_KEY_TEST_VECTORS;
use crate::testvectors::aes::AES_CFB_256_VAR_KEY_TEST_VECTORS;
use crate::testvectors::aes::AesCfbTestVector;

const STREAMING_CHUNK_LENS: [usize; 6] = [1, 3, 7, 11, 2, 19];

fn check_var_key_vector_one_shot(vector: &AesCfbTestVector) -> Result<(), CfbTestVectorFailure> {
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
    .map_err(|e| CfbTestVectorFailure::Crypto {
        id: vector.test_count_id,
        encrypt: vector.encrypt,
        source: e,
    })?;

    if output.as_slice() != expected {
        return Err(CfbTestVectorFailure::Mismatch {
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

fn check_var_key_vector_streaming(vector: &AesCfbTestVector) -> Result<(), CfbTestVectorFailure> {
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
    .map_err(|e| CfbTestVectorFailure::Crypto {
        id: vector.test_count_id,
        encrypt: vector.encrypt,
        source: e,
    })?;

    if output.as_slice() != expected {
        return Err(CfbTestVectorFailure::Mismatch {
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

// Variable Key tests
#[test]
fn test_aes_128_nist_var_key_vectors() {
    for vector in AES_CFB_128_VAR_KEY_TEST_VECTORS.iter() {
        assert_cfb_vector_success(
            "AES-128 CFB NIST VarKey (one-shot)",
            "AES-128 CFB VarKey (one-shot) mismatch!",
            check_var_key_vector_one_shot(vector),
        );
    }
}

#[test]
fn test_aes_192_nist_var_key_vectors() {
    for vector in AES_CFB_192_VAR_KEY_TEST_VECTORS.iter() {
        assert_cfb_vector_success(
            "AES-192 CFB NIST VarKey (one-shot)",
            "AES-192 CFB VarKey (one-shot) mismatch!",
            check_var_key_vector_one_shot(vector),
        );
    }
}

#[test]
fn test_aes_256_nist_var_key_vectors() {
    for vector in AES_CFB_256_VAR_KEY_TEST_VECTORS.iter() {
        assert_cfb_vector_success(
            "AES-256 CFB NIST VarKey (one-shot)",
            "AES-256 CFB VarKey (one-shot) mismatch!",
            check_var_key_vector_one_shot(vector),
        );
    }
}

#[test]
fn test_aes_128_nist_var_key_vectors_streaming() {
    for vector in AES_CFB_128_VAR_KEY_TEST_VECTORS.iter() {
        assert_cfb_vector_success(
            "AES-128 CFB NIST VarKey (streaming)",
            "AES-128 CFB NIST VarKey (streaming) mismatch!",
            check_var_key_vector_streaming(vector),
        );
    }
}

#[test]
fn test_aes_192_nist_var_key_vectors_streaming() {
    for vector in AES_CFB_192_VAR_KEY_TEST_VECTORS.iter() {
        assert_cfb_vector_success(
            "AES-192 CFB NIST VarKey (streaming)",
            "AES-192 CFB NIST VarKey (streaming) mismatch!",
            check_var_key_vector_streaming(vector),
        );
    }
}

#[test]
fn test_aes_256_nist_var_key_vectors_streaming() {
    for vector in AES_CFB_256_VAR_KEY_TEST_VECTORS.iter() {
        assert_cfb_vector_success(
            "AES-256 CFB NIST VarKey (streaming)",
            "AES-256 CFB NIST VarKey (streaming) mismatch!",
            check_var_key_vector_streaming(vector),
        );
    }
}
