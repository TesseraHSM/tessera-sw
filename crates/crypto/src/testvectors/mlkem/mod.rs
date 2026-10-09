// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NIST ACVP known-answer vectors for ML-KEM (FIPS 203).
//!
//! Derived from the published NIST ACVP files.

mod mlkem_decap_test_vectors;
mod mlkem_encap_test_vectors;
mod mlkem_keycheck_test_vectors;
mod mlkem_keygen_test_vectors;

pub use mlkem_decap_test_vectors::MLKEM_DECAP_TEST_VECTORS;
pub use mlkem_encap_test_vectors::MLKEM_ENCAP_TEST_VECTORS;
pub use mlkem_keycheck_test_vectors::MLKEM_KEYCHECK_TEST_VECTORS;
pub use mlkem_keygen_test_vectors::MLKEM_KEYGEN_TEST_VECTORS;

/// An ACVP `keyGen` vector: a seed and the key pair it must expand to.
#[derive(Debug, Clone)]
pub struct MlKemKeyGenTestVector {
    /// - `param_set`: Parameter set, one of 512, 768 or 1024.
    pub param_set: u16,
    /// - `seed`: The 64-byte FIPS 203 `d ‖ z` key-generation seed.
    pub seed: &'static [u8],
    /// - `pub_key`: The encapsulation key generated from `seed`.
    pub pub_key: &'static [u8],
    /// - `sec_key`: The expanded decapsulation key generated from `seed`.
    pub sec_key: &'static [u8],
}

/// An ACVP encapsulation vector: the outputs this message must produce.
#[derive(Debug, Clone)]
pub struct MlKemEncapTestVector {
    /// - `param_set`: Parameter set, one of 512, 768 or 1024.
    pub param_set: u16,
    /// - `pub_key`: The encapsulation key to encapsulate to.
    pub pub_key: &'static [u8],
    /// - `m`: The 32-byte encapsulation message.
    pub m: &'static [u8],
    /// - `ciphertext`: The expected ciphertext.
    pub ciphertext: &'static [u8],
    /// - `shared_secret`: The expected shared secret.
    pub shared_secret: &'static [u8],
}

/// An ACVP decapsulation vector: the secret this ciphertext must yield.
///
/// The modified-ciphertext cases are *not* errors. FIPS 203 rejects
/// implicitly, so `shared_secret` is the pseudo-random implicit-rejection
/// value, which decapsulation must reproduce exactly.
#[derive(Debug, Clone)]
pub struct MlKemDecapTestVector {
    /// - `param_set`: Parameter set, one of 512, 768 or 1024.
    pub param_set: u16,
    /// - `sec_key`: The expanded decapsulation key.
    pub sec_key: &'static [u8],
    /// - `ciphertext`: The ciphertext to decapsulate.
    pub ciphertext: &'static [u8],
    /// - `shared_secret`: The expected secret, implicit-rejection or not.
    pub shared_secret: &'static [u8],
    /// - `reason`: NIST's description of the case, for failure messages.
    pub reason: &'static str,
}

/// An ACVP key-check vector: a key that must be accepted or rejected.
#[derive(Debug, Clone)]
pub struct MlKemKeyCheckTestVector {
    /// - `param_set`: Parameter set, one of 512, 768 or 1024.
    pub param_set: u16,
    /// - `is_encapsulation_key`: Whether `key` is the public or private half.
    pub is_encapsulation_key: bool,
    /// - `key`: The key bytes to validate.
    pub key: &'static [u8],
    /// - `expected_valid`: Whether the key must be accepted.
    pub expected_valid: bool,
    /// - `reason`: NIST's description of the case, for failure messages.
    pub reason: &'static str,
}
