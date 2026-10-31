// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_api::*;

use super::*;
use crate::HANDLE_TABLE;
use crate::TsraBuffer;
use crate::TsraHandle;
use crate::TsraStatus;
use crate::handle_table::HandleType;
use crate::utils::validate_and_cast_algo_params_mut;
use crate::utils::validate_output_buffer;

/// AES CFB (128-bit segment) parameters.
///
/// On return, `iv` holds the last full ciphertext block (unchanged if no full
/// block was produced).
///
/// Continuing a message by passing the returned `iv` to a later single-shot
/// call is only correct when every call except the last processes a multiple of
/// 16 bytes; otherwise keystream bytes are reused. To process a message in
/// arbitrary-length chunks, use a single streaming context (`tsra_crypt_*_init`
/// / `_update` / `_finish`) instead.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TsraAlgoAesCfbParams {
    /// IV
    pub iv: [u8; 16],
}

impl<'a> TryFrom<&'a mut TsraAlgo> for &'a mut TsraAlgoAesCfbParams {
    type Error = TsraStatus;

    /// Extracts a mutable reference to CFB parameters from the algorithm specification.
    ///
    /// # Safety
    /// The caller must ensure that `algo.params` points to valid `TsraAlgoAesCfbParams` data
    /// when the algorithm ID is CFB.
    #[allow(unsafe_code)]
    fn try_from(algo: &'a mut TsraAlgo) -> Result<Self, Self::Error> {
        validate_and_cast_algo_params_mut::<TsraAlgoAesCfbParams>(algo)
    }
}

/// AES CFB (128-bit segment) encryption context
pub(crate) struct AesCfbEncryptContext {
    context: HsmAesCfbEncryptContext,
    params: *mut TsraAlgoAesCfbParams,
}

impl AesCfbEncryptContext {
    /// Create a new encryption context
    fn new(ctx: HsmAesCfbEncryptContext, params: &mut TsraAlgoAesCfbParams) -> Self {
        Self {
            context: ctx,
            params: params as *mut TsraAlgoAesCfbParams,
        }
    }

    /// Update the context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, TsraStatus> {
        let bytes_written = self.context.update(input, output)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Finish the context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, TsraStatus> {
        let bytes_written = self.context.finish(output)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Update the IV in the caller's parameters
    fn update_iv(&mut self) -> Result<(), TsraStatus> {
        let params = crate::utils::deref_mut_ptr(self.params)?;
        params.iv.copy_from_slice(self.context.algo().iv());
        Ok(())
    }
}

/// AES CFB (128-bit segment) decryption context
pub(crate) struct AesCfbDecryptContext {
    context: HsmAesCfbDecryptContext,
    params: *mut TsraAlgoAesCfbParams,
}

impl AesCfbDecryptContext {
    /// Create a new decryption context
    fn new(ctx: HsmAesCfbDecryptContext, params: &mut TsraAlgoAesCfbParams) -> Self {
        Self {
            context: ctx,
            params: params as *mut TsraAlgoAesCfbParams,
        }
    }

    /// Update the context with input data
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, TsraStatus> {
        let bytes_written = self.context.update(input, output)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Finish the context
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, TsraStatus> {
        let bytes_written = self.context.finish(output)?;
        self.update_iv()?;
        Ok(bytes_written)
    }

    /// Update the IV in the caller's parameters
    fn update_iv(&mut self) -> Result<(), TsraStatus> {
        let params = crate::utils::deref_mut_ptr(self.params)?;
        params.iv.copy_from_slice(self.context.algo().iv());
        Ok(())
    }
}

/// Encrypt data using AES CFB (128-bit segment)
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CFB (128-bit segment))
/// * `key_handle` - Handle to the AES key
/// * `plain_text` - Input buffer
/// * `cipher_text` - Output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(TsraStatus)` on failure
pub(crate) fn aes_cfb_encrypt(
    algo: &mut TsraAlgo,
    key_handle: TsraHandle,
    plain_text: &[u8],
    cipher_text: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    if algo.id != TsraAlgoId::AesCfb {
        Err(TsraStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    let params: &mut TsraAlgoAesCfbParams = algo.try_into()?;
    let mut aes_algo = HsmAesCfbAlgo::new(params.iv.to_vec())?;

    // Query required output length first
    let required_len = HsmEncrypter::encrypt(&mut aes_algo, key, plain_text, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(cipher_text, required_len)?;

    // Perform the operation
    let written = HsmEncrypter::encrypt(&mut aes_algo, key, plain_text, Some(output_buf))?;

    // Update output buffer length with actual bytes written
    cipher_text.len = written as u32;

    // Update the IV
    params.iv.copy_from_slice(aes_algo.iv());

    Ok(())
}

/// Decrypt data using AES CFB (128-bit segment)
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CFB (128-bit segment))
/// * `key_handle` - Handle to the AES key
/// * `cipher_text` - Input buffer
/// * `plain_text` - Output buffer
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(TsraStatus)` on failure
pub(crate) fn aes_cfb_decrypt(
    algo: &mut TsraAlgo,
    key_handle: TsraHandle,
    cipher_text: &[u8],
    plain_text: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    if algo.id != TsraAlgoId::AesCfb {
        Err(TsraStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    let params: &mut TsraAlgoAesCfbParams = algo.try_into()?;
    let mut aes_algo = HsmAesCfbAlgo::new(params.iv.to_vec())?;

    // Query required output length first
    let required_len = HsmDecrypter::decrypt(&mut aes_algo, key, cipher_text, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(plain_text, required_len)?;

    // Perform the operation
    let written = HsmDecrypter::decrypt(&mut aes_algo, key, cipher_text, Some(output_buf))?;

    // Update output buffer length with actual bytes written
    plain_text.len = written as u32;

    // Update the IV
    params.iv.copy_from_slice(aes_algo.iv());

    Ok(())
}

/// Initialize AES CFB (128-bit segment) encryption
///
/// Creates a encryption context that can process data incrementally.
/// The context should be used with update and finish operations.
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CFB (128-bit segment))
/// * `key_handle` - Handle to the AES key
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the encryption context for subsequent operations
/// * `Err(TsraStatus)` - On failure
pub(crate) fn aes_cfb_encrypt_init(
    algo: &mut TsraAlgo,
    key_handle: TsraHandle,
) -> Result<TsraHandle, TsraStatus> {
    if algo.id != TsraAlgoId::AesCfb {
        Err(TsraStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    let params: &mut TsraAlgoAesCfbParams = algo.try_into()?;
    let aes_algo = HsmAesCfbAlgo::new(params.iv.to_vec())?;

    // Initialize context
    let encrypt_context = aes_algo.encrypt_init(key.clone())?;
    let context = AesCfbEncryptContext::new(encrypt_context, params);

    // Store context in handle table and return handle
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesCfbEncryptCtx, Box::new(context));

    Ok(ctx_handle)
}

/// Initialize AES CFB (128-bit segment) decryption
///
/// Creates a decryption context that can process data incrementally.
/// The context should be used with update and finish operations.
///
/// # Arguments
/// * `algo` - Algorithm specification (must be AES CFB (128-bit segment))
/// * `key_handle` - Handle to the AES key
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the decryption context for subsequent operations
/// * `Err(TsraStatus)` - On failure
pub(crate) fn aes_cfb_decrypt_init(
    algo: &mut TsraAlgo,
    key_handle: TsraHandle,
) -> Result<TsraHandle, TsraStatus> {
    if algo.id != TsraAlgoId::AesCfb {
        Err(TsraStatus::UnsupportedAlgorithm)?;
    }

    // Get the AES key from handle table
    let key = &HsmAesKey::try_from(key_handle)?;

    let params: &mut TsraAlgoAesCfbParams = algo.try_into()?;
    let aes_algo = HsmAesCfbAlgo::new(params.iv.to_vec())?;

    // Initialize context
    let decrypt_context = aes_algo.decrypt_init(key.clone())?;
    let context = AesCfbDecryptContext::new(decrypt_context, params);

    // Store context in handle table and return handle
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::AesCfbDecryptCtx, Box::new(context));

    Ok(ctx_handle)
}

/// Update AES CFB (128-bit segment) encryption with additional data
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
pub(crate) fn aes_cfb_encrypt_update(
    ctx_handle: TsraHandle,
    input: &TsraBuffer,
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    // Get the context from handle table
    let ctx: &mut AesCfbEncryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCfbEncryptCtx)?;

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

/// Update AES CFB (128-bit segment) decryption with additional data
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
pub(crate) fn aes_cfb_decrypt_update(
    ctx_handle: TsraHandle,
    input: &TsraBuffer,
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    // Get the context from handle table
    let ctx: &mut AesCfbDecryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCfbDecryptCtx)?;

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

/// Finish AES CFB (128-bit segment) encryption
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
pub(crate) fn aes_cfb_encrypt_finish(
    ctx_handle: TsraHandle,
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    // Get the context from handle table
    let ctx: &mut AesCfbEncryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCfbEncryptCtx)?;

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

/// Finish AES CFB (128-bit segment) decryption
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
pub(crate) fn aes_cfb_decrypt_finish(
    ctx_handle: TsraHandle,
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    // Get the context from handle table
    let ctx: &mut AesCfbDecryptContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCfbDecryptCtx)?;

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
