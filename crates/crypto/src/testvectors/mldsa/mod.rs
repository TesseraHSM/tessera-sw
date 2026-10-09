// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NIST ACVP known-answer vectors for ML-DSA (FIPS 204).
//!
//! Only the *external* interface in *pure* mode is represented, which is what
//! [`crate::MlDsaAlgo`] implements. The vectors are derived from the published
//! NIST ACVP files.

mod mldsa_keygen_test_vectors;
mod mldsa_siggen_test_vectors;
mod mldsa_sigver_short_msg_test_vectors;
mod mldsa_sigver_test_vectors;

pub use mldsa_keygen_test_vectors::MLDSA_KEYGEN_TEST_VECTORS;
pub use mldsa_siggen_test_vectors::MLDSA_SIGGEN_TEST_VECTORS;
pub use mldsa_sigver_short_msg_test_vectors::MLDSA_SIGVER_SHORT_MSG_TEST_VECTORS;
pub use mldsa_sigver_test_vectors::MLDSA_SIGVER_TEST_VECTORS;

/// An ACVP `keyGen` vector: a seed and the key pair it must expand to.
#[derive(Debug, Clone)]
pub struct MlDsaKeyGenTestVector {
    /// - `param_set`: Parameter set, one of 44, 65 or 87.
    pub param_set: u16,
    /// - `seed`: The 32-byte FIPS 204 `xi` key-generation seed.
    pub seed: &'static [u8],
    /// - `pub_key`: The encoded verifying key generated from `seed`.
    pub pub_key: &'static [u8],
    /// - `sec_key`: The expanded signing key generated from `seed`.
    pub sec_key: &'static [u8],
}

/// An ACVP `sigGen` vector: the signature these inputs must produce.
///
/// Signing is deterministic in `rnd`, so the expected signature is exact.
/// Deterministic groups carry no randomness of their own; FIPS 204 defines
/// that mode as `rnd = 0^32`, which is what `rnd` holds for them.
#[derive(Debug, Clone)]
pub struct MlDsaSigGenTestVector {
    /// - `param_set`: Parameter set, one of 44, 65 or 87.
    pub param_set: u16,
    /// - `deterministic`: Whether the ACVP group was the deterministic one.
    pub deterministic: bool,
    /// - `sec_key`: The expanded signing key.
    pub sec_key: &'static [u8],
    /// - `msg`: The message to sign.
    pub msg: &'static [u8],
    /// - `ctx`: The context string to bind into the signature.
    pub ctx: &'static [u8],
    /// - `rnd`: The 32-byte per-signature randomness.
    pub rnd: &'static [u8],
    /// - `sig`: The expected signature.
    pub sig: &'static [u8],
}

/// An ACVP `sigVer` vector: a signature that must be accepted or rejected.
#[derive(Debug, Clone)]
pub struct MlDsaSigVerTestVector {
    /// - `param_set`: Parameter set, one of 44, 65 or 87.
    pub param_set: u16,
    /// - `pub_key`: The encoded verifying key.
    pub pub_key: &'static [u8],
    /// - `msg`: The message the signature is over.
    pub msg: &'static [u8],
    /// - `ctx`: The context string bound into the signature.
    pub ctx: &'static [u8],
    /// - `sig`: The signature to check.
    pub sig: &'static [u8],
    /// - `expected_pass`: Whether verification must succeed.
    pub expected_pass: bool,
    /// - `reason`: NIST's description of the case, for failure messages.
    pub reason: &'static str,
}
