// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod sha1_long_msg_test_vectors;
mod sha1_monte_test_vectors;
mod sha1_short_msg_test_vectors;
mod sha256_long_msg_test_vectors;
mod sha256_monte_test_vectors;
mod sha256_short_msg_test_vectors;
mod sha384_long_msg_test_vectors;
mod sha384_monte_test_vectors;
mod sha384_short_msg_test_vectors;
mod sha3_256_long_msg_test_vectors;
mod sha3_256_monte_test_vectors;
mod sha3_256_short_msg_test_vectors;
mod sha3_384_long_msg_test_vectors;
mod sha3_384_monte_test_vectors;
mod sha3_384_short_msg_test_vectors;
mod sha3_512_long_msg_test_vectors;
mod sha3_512_monte_test_vectors;
mod sha3_512_short_msg_test_vectors;
mod sha512_long_msg_test_vectors;
mod sha512_monte_test_vectors;
mod sha512_short_msg_test_vectors;
mod shake128_long_msg_test_vectors;
mod shake128_monte_test_vectors;
mod shake128_short_msg_test_vectors;
mod shake128_variable_out_test_vectors;
mod shake256_long_msg_test_vectors;
mod shake256_monte_test_vectors;
mod shake256_short_msg_test_vectors;
mod shake256_variable_out_test_vectors;

pub use sha1_long_msg_test_vectors::SHA1_LONG_MSG_TEST_VECTORS;
pub use sha1_monte_test_vectors::SHA1_MONTE_TEST_VECTORS;
pub use sha1_short_msg_test_vectors::SHA1_SHORT_MSG_TEST_VECTORS;
pub use sha3_256_long_msg_test_vectors::SHA3_256_LONG_MSG_TEST_VECTORS;
pub use sha3_256_monte_test_vectors::SHA3_256_MONTE_TEST_VECTORS;
pub use sha3_256_short_msg_test_vectors::SHA3_256_SHORT_MSG_TEST_VECTORS;
pub use sha3_384_long_msg_test_vectors::SHA3_384_LONG_MSG_TEST_VECTORS;
pub use sha3_384_monte_test_vectors::SHA3_384_MONTE_TEST_VECTORS;
pub use sha3_384_short_msg_test_vectors::SHA3_384_SHORT_MSG_TEST_VECTORS;
pub use sha3_512_long_msg_test_vectors::SHA3_512_LONG_MSG_TEST_VECTORS;
pub use sha3_512_monte_test_vectors::SHA3_512_MONTE_TEST_VECTORS;
pub use sha3_512_short_msg_test_vectors::SHA3_512_SHORT_MSG_TEST_VECTORS;
pub use sha256_long_msg_test_vectors::SHA256_LONG_MSG_TEST_VECTORS;
pub use sha256_monte_test_vectors::SHA256_MONTE_TEST_VECTORS;
pub use sha256_short_msg_test_vectors::SHA256_SHORT_MSG_TEST_VECTORS;
pub use sha384_long_msg_test_vectors::SHA384_LONG_MSG_TEST_VECTORS;
pub use sha384_monte_test_vectors::SHA384_MONTE_TEST_VECTORS;
pub use sha384_short_msg_test_vectors::SHA384_SHORT_MSG_TEST_VECTORS;
pub use sha512_long_msg_test_vectors::SHA512_LONG_MSG_TEST_VECTORS;
pub use sha512_monte_test_vectors::SHA512_MONTE_TEST_VECTORS;
pub use sha512_short_msg_test_vectors::SHA512_SHORT_MSG_TEST_VECTORS;
pub use shake128_long_msg_test_vectors::SHAKE128_LONG_MSG_TEST_VECTORS;
pub use shake128_monte_test_vectors::SHAKE128_MONTE_TEST_VECTORS;
pub use shake128_short_msg_test_vectors::SHAKE128_SHORT_MSG_TEST_VECTORS;
pub use shake128_variable_out_test_vectors::SHAKE128_VARIABLE_OUT_TEST_VECTORS;
pub use shake256_long_msg_test_vectors::SHAKE256_LONG_MSG_TEST_VECTORS;
pub use shake256_monte_test_vectors::SHAKE256_MONTE_TEST_VECTORS;
pub use shake256_short_msg_test_vectors::SHAKE256_SHORT_MSG_TEST_VECTORS;
pub use shake256_variable_out_test_vectors::SHAKE256_VARIABLE_OUT_TEST_VECTORS;

/// SHA NIST Test vector struct
pub struct ShaTestVector {
    pub msg_len_bytes: u32,
    pub msg: &'static [u8],
    pub md_len_bytes: u32,
    pub md: &'static [u8],
}

// SHA NIST Test vector for monte carlo tests
pub struct ShaMonteTestVector {
    pub expected_digest_len_bytes: usize,
    pub seed: &'static [u8],
    pub expected_digests: [&'static [u8]; 100],
}

/// SHAKE NIST Monte Carlo test vector (SHA3VS section 6.3.3), whose output
/// length varies between iterations within `min..=max_output_len_bytes`.
pub struct ShakeMonteTestVector {
    pub min_output_len_bytes: usize,
    pub max_output_len_bytes: usize,
    pub msg: &'static [u8],
    pub expected_outputs: [&'static [u8]; 100],
}
