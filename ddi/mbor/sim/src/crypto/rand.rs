// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Module for Rand.

use tsra_crypto::Rng;

use crate::errors::TesseraError;

///  RNG operation.
///
/// # Arguments
/// * `buf` - The buffer to be filled with cryptographically strong pseudo-random bytes.
///
/// # Returns
/// * Ok(()) - If the operation is successful.
///
/// # Errors
/// * `TesseraError::RngError` - If the RNG operation fails.
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), TesseraError> {
    Rng::rand_bytes(buf).map_err(|e| {
        tracing::error!(?e, "Random number generation failed");
        TesseraError::RngError
    })
}
