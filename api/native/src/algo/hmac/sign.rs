// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_api::*;

use crate::HANDLE_TABLE;
use crate::TsraBuffer;
use crate::TsraHandle;
use crate::TsraStatus;
use crate::handle_table::HandleType;
use crate::utils::validate_output_buffer;

/// Computes an HMAC signature for the given data
///
/// Single-shot operation that signs data using HMAC with the specified key.
///
/// # Arguments
/// * `key_handle` - Handle to the HMAC key
/// * `data` - Input data to sign
/// * `output` - Output buffer for the HMAC signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(TsraStatus)` - On failure (e.g., invalid key, buffer too small)
pub(crate) fn hmac_sign(
    key_handle: TsraHandle,
    input: &[u8],
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    // Get the key from handle
    let key = &HsmHmacKey::try_from(key_handle)?;

    // Create HMAC algorithm
    let mut algo = HsmHmacAlgo::new();

    // Determine required size
    let required_size = HsmSigner::sign(&mut algo, key, input, None)?;

    // Validate and get output buffer
    let output_data = validate_output_buffer(output, required_size)?;

    // Perform actual signing
    let sig_len = HsmSigner::sign(&mut algo, key, input, Some(output_data))?;

    // Update output buffer length
    output.len = sig_len as u32;

    Ok(())
}

/// Verifies an HMAC signature for the given data
///
/// Single-shot operation that verifies an HMAC signature matches the provided data.
///
/// # Arguments
/// * `key_handle` - Handle to the HMAC key
/// * `data` - Input data to verify
/// * `signature` - Expected HMAC signature to verify against
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(TsraStatus)` - On failure (e.g., invalid key, invalid signature format)
pub(crate) fn hmac_verify(
    key_handle: TsraHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, TsraStatus> {
    // Get the key from handle
    let key = &HsmHmacKey::try_from(key_handle)?;

    // Create HMAC algorithm
    let mut algo = HsmHmacAlgo::new();

    // Verify the signature
    Ok(HsmVerifier::verify(&mut algo, key, data, sig)?)
}

/// Initializes a streaming HMAC signing operation
///
/// Creates a context for incrementally computing an HMAC signature.
/// Use with `hmac_sign_update` and `hmac_sign_finish`.
///
/// # Arguments
/// * `key_handle` - Handle to the HMAC key
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the signing context
/// * `Err(TsraStatus)` - On failure (e.g., invalid key)
pub(crate) fn hmac_sign_init(key_handle: TsraHandle) -> Result<TsraHandle, TsraStatus> {
    // Get the key from handle
    let key = HsmHmacKey::try_from(key_handle)?;

    // Create the HMAC algorithm
    let algo = HsmHmacAlgo::new();

    // Initialize the streaming signing context
    let ctx = HsmSigner::sign_init(algo, key)?;

    // Allocate a handle for the context and return it
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::HmacSignCtx, Box::new(ctx));

    Ok(ctx_handle)
}

/// Updates a streaming HMAC signing operation with additional data
///
/// Processes a chunk of data in an incremental HMAC signature computation.
///
/// # Arguments
/// * `ctx_handle` - Handle to the signing context
/// * `data` - Data chunk to include in the signature
///
/// # Returns
/// * `Ok(())` - On success
/// * `Err(TsraStatus)` - On failure (e.g., invalid context)
pub(crate) fn hmac_sign_update(ctx_handle: TsraHandle, data: &[u8]) -> Result<(), TsraStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmHmacSignContext = HANDLE_TABLE.as_mut(ctx_handle, HandleType::HmacSignCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

/// Finishes a streaming HMAC signing operation
///
/// Completes the HMAC signature computation and returns the final signature.
///
/// # Arguments
/// * `ctx_handle` - Handle to the signing context
/// * `output` - Output buffer for the HMAC signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(TsraStatus)` - On failure (e.g., buffer too small)
pub(crate) fn hmac_sign_finish(
    ctx_handle: TsraHandle,
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    // Get a reference to determine the required signature size
    let ctx: &mut HsmHmacSignContext = HANDLE_TABLE.as_mut(ctx_handle, HandleType::HmacSignCtx)?;
    let required_size = ctx.finish(None)?;

    // Check if output buffer is large enough
    let output_data = validate_output_buffer(output, required_size)?;

    // Perform the final signing operation
    let sig_len = ctx.finish(Some(output_data))?;

    // Update the output buffer length with actual signature length
    output.len = sig_len as u32;

    Ok(())
}

/// Initializes a streaming HMAC verification operation
///
/// Creates a context for incrementally verifying an HMAC signature.
/// Use with `hmac_verify_update` and `hmac_verify_finish`.
///
/// # Arguments
/// * `key_handle` - Handle to the HMAC key
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the verification context
/// * `Err(TsraStatus)` - On failure (e.g., invalid key)
pub(crate) fn hmac_verify_init(key_handle: TsraHandle) -> Result<TsraHandle, TsraStatus> {
    // Get the key from handle
    let key = HsmHmacKey::try_from(key_handle)?;

    // Create the HMAC algorithm
    let algo = HsmHmacAlgo::new();

    // Initialize the streaming verification context
    let ctx = HsmVerifier::verify_init(algo, key)?;

    // Allocate a handle for the context and return it
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::HmacVerifyCtx, Box::new(ctx));

    Ok(ctx_handle)
}

/// Updates a streaming HMAC verification operation with additional data
///
/// Processes a chunk of data in an incremental HMAC signature verification.
///
/// # Arguments
/// * `ctx_handle` - Handle to the verification context
/// * `data` - Data chunk to include in the verification
///
/// # Returns
/// * `Ok(())` - On success
/// * `Err(TsraStatus)` - On failure (e.g., invalid context)
pub(crate) fn hmac_verify_update(ctx_handle: TsraHandle, data: &[u8]) -> Result<(), TsraStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmHmacVerifyContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::HmacVerifyCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;
    Ok(())
}

/// Finishes a streaming HMAC verification operation
///
/// Completes the HMAC verification and checks if the signature matches.
///
/// # Arguments
/// * `ctx_handle` - Handle to the verification context
/// * `signature` - Expected HMAC signature to verify against
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(TsraStatus)` - On failure
pub(crate) fn hmac_verify_finish(
    ctx_handle: TsraHandle,
    signature: &[u8],
) -> Result<bool, TsraStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmHmacVerifyContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::HmacVerifyCtx)?;

    // Perform the final verification operation
    let is_valid = ctx.finish(signature)?;

    Ok(is_valid)
}
