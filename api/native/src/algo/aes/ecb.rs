// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_api::*;

use super::*;
use crate::HANDLE_TABLE;
use crate::TsraBuffer;
use crate::TsraHandle;
use crate::TsraStatus;
use crate::handle_table::HandleType;
use crate::utils::validate_algo_params_absent;
use crate::utils::validate_output_buffer;

/// AES ECB encryption context
pub(crate) struct AesEcbEncryptContext {
    context: HsmAesEcbEncryptContext,
}

impl AesEcbEncryptContext {
    /// Update the context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, TsraStatus> {
        Ok(self.context.update(input, output)?)
    }

    /// Finish the context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, TsraStatus> {
        Ok(self.context.finish(output)?)
    }
}

/// AES ECB decryption context
pub(crate) struct AesEcbDecryptContext {
    context: HsmAesEcbDecryptContext,
}

impl AesEcbDecryptContext {
    /// Update the context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, TsraStatus> {
        Ok(self.context.update(input, output)?)
    }

    /// Finish the context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, TsraStatus> {
        Ok(self.context.finish(output)?)
    }
}

/// Encrypt data using AES ECB
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES ECB)
/// * `key_handle` - Handle to the AES key
/// * `plain_text` - Input buffer
/// * `cipher_text` - Output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(TsraStatus)` on failure
pub(crate) fn aes_ecb_encrypt(
    algo: &mut TsraAlgo,
    key_handle: TsraHandle,
    plain_text: &[u8],
    cipher_text: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    if algo.id != TsraAlgoId::AesEcb {
        Err(TsraStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    validate_algo_params_absent(algo)?;
    let mut aes_algo = HsmAesEcbAlgo;

    // Query required output length first
    let required_len = HsmEncrypter::encrypt(&mut aes_algo, key, plain_text, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(cipher_text, required_len)?;

    // Perform the operation
    let written = HsmEncrypter::encrypt(&mut aes_algo, key, plain_text, Some(output_buf))?;

    // Update output buffer length with actual bytes written
    cipher_text.len = written as u32;

    Ok(())
}

/// Decrypt data using AES ECB
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES ECB)
/// * `key_handle` - Handle to the AES key
/// * `cipher_text` - Input buffer
/// * `plain_text` - Output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(TsraStatus)` on failure
pub(crate) fn aes_ecb_decrypt(
    algo: &mut TsraAlgo,
    key_handle: TsraHandle,
    cipher_text: &[u8],
    plain_text: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    if algo.id != TsraAlgoId::AesEcb {
        Err(TsraStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    validate_algo_params_absent(algo)?;
    let mut aes_algo = HsmAesEcbAlgo;

    // Query required output length first
    let required_len = HsmDecrypter::decrypt(&mut aes_algo, key, cipher_text, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(plain_text, required_len)?;

    // Perform the operation
    let written = HsmDecrypter::decrypt(&mut aes_algo, key, cipher_text, Some(output_buf))?;

    // Update output buffer length with actual bytes written
    plain_text.len = written as u32;

    Ok(())
}

/// Initialize AES ECB encryption
///
/// Creates a encryption context that can process data incrementally.
/// The context should be used with update and finish operations.
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES ECB)
/// * `key_handle` - Handle to the AES key
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the encryption context for subsequent operations
/// * `Err(TsraStatus)` - On failure
pub(crate) fn aes_ecb_encrypt_init(
    algo: &mut TsraAlgo,
    key_handle: TsraHandle,
) -> Result<TsraHandle, TsraStatus> {
    if algo.id != TsraAlgoId::AesEcb {
        Err(TsraStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    validate_algo_params_absent(algo)?;
    let encrypt_context = HsmAesEcbAlgo.encrypt_init(key.clone())?;
    let context = AesEcbEncryptContext {
        context: encrypt_context,
    };

    // Store context in handle table and return handle
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesEcbEncryptCtx, Box::new(context));

    Ok(ctx_handle)
}

/// Initialize AES ECB decryption
///
/// Creates a decryption context that can process data incrementally.
/// The context should be used with update and finish operations.
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES ECB)
/// * `key_handle` - Handle to the AES key
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the decryption context for subsequent operations
/// * `Err(TsraStatus)` - On failure
pub(crate) fn aes_ecb_decrypt_init(
    algo: &mut TsraAlgo,
    key_handle: TsraHandle,
) -> Result<TsraHandle, TsraStatus> {
    if algo.id != TsraAlgoId::AesEcb {
        Err(TsraStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    validate_algo_params_absent(algo)?;
    let decrypt_context = HsmAesEcbAlgo.decrypt_init(key.clone())?;
    let context = AesEcbDecryptContext {
        context: decrypt_context,
    };

    // Store context in handle table and return handle
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesEcbDecryptCtx, Box::new(context));

    Ok(ctx_handle)
}

/// Update AES ECB encryption with additional data
///
/// Processes a chunk of input in a encryption operation. Complete blocks are
/// output; a trailing partial block is buffered until the next update or
/// finish. This function follows the two-phase pattern: first query the
/// required buffer size, then perform the actual operation if the buffer is
/// sufficient.
///
/// # Arguments
/// * `ctx_handle` - Handle to the encryption context
/// * `input` - Reference to input buffer
/// * `output` - Mutable reference to output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(TsraStatus)` on failure
pub(crate) fn aes_ecb_encrypt_update(
    ctx_handle: TsraHandle,
    input: &TsraBuffer,
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    // Get the context from handle table
    let ctx: &mut AesEcbEncryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesEcbEncryptCtx)?;

    // Get input data slice
    let input_slice: &[u8] = input.try_into()?;

    // Query required output length first
    let required_len = ctx.update(input_slice, None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the update operation
    let bytes_written = ctx.update(input_slice, Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Update AES ECB decryption with additional data
///
/// Processes a chunk of input in a decryption operation. Complete blocks are
/// output; a trailing partial block is buffered until the next update or
/// finish. This function follows the two-phase pattern: first query the
/// required buffer size, then perform the actual operation if the buffer is
/// sufficient.
///
/// # Arguments
/// * `ctx_handle` - Handle to the decryption context
/// * `input` - Reference to input buffer
/// * `output` - Mutable reference to output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(TsraStatus)` on failure
pub(crate) fn aes_ecb_decrypt_update(
    ctx_handle: TsraHandle,
    input: &TsraBuffer,
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    // Get the context from handle table
    let ctx: &mut AesEcbDecryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesEcbDecryptCtx)?;

    // Get input data slice
    let input_slice: &[u8] = input.try_into()?;

    // Query required output length first
    let required_len = ctx.update(input_slice, None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the update operation
    let bytes_written = ctx.update(input_slice, Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Finish AES ECB encryption
///
/// Completes the encryption operation and processes any remaining data.
///
/// # Arguments
/// * `ctx_handle` - Handle to the encryption context
/// * `output` - Mutable reference to output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(TsraStatus)` on failure
pub(crate) fn aes_ecb_encrypt_finish(
    ctx_handle: TsraHandle,
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    // Get the context from handle table
    let ctx: &mut AesEcbEncryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesEcbEncryptCtx)?;

    // Query required output length first
    let required_len = ctx.finish(None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the finish operation
    let bytes_written = ctx.finish(Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}

/// Finish AES ECB decryption
///
/// Completes the decryption operation and processes any remaining data.
///
/// # Arguments
/// * `ctx_handle` - Handle to the decryption context
/// * `output` - Mutable reference to output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(TsraStatus)` on failure
pub(crate) fn aes_ecb_decrypt_finish(
    ctx_handle: TsraHandle,
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    // Get the context from handle table
    let ctx: &mut AesEcbDecryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesEcbDecryptCtx)?;

    // Query required output length first
    let required_len = ctx.finish(None)?;

    // Prepare output buffer and get slice
    let output_slice = validate_output_buffer(output, required_len)?;

    // Perform the finish operation
    let bytes_written = ctx.finish(Some(output_slice))?;

    // Update output buffer length with actual bytes written
    output.len = bytes_written as u32;

    Ok(())
}
