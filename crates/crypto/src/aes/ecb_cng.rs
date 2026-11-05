// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-ECB implementation using Windows CNG (Cryptography Next Generation) API.
//!
//! This module provides AES encryption and decryption in Electronic Codebook (ECB) mode
//! using the Windows CNG cryptographic provider. ECB mode operates on fixed-size blocks
//! independently without chaining or initialization vectors.
//!
//! # Features
//!
//! - **Native Windows integration**: Uses the platform's built-in cryptographic providers
//! - **Hardware acceleration**: Automatically leverages AES-NI when available
//! - **FIPS compliance**: Can operate in FIPS 140-2 validated mode when properly configured
//! - **No padding**: Requires input to be a multiple of the AES block size (16 bytes)
//! - **Stateless operation**: No initialization vector or state management required
//!
//! # Security Considerations
//!
//! **WARNING**: ECB mode is generally not recommended for most cryptographic use cases
//! as it does not provide semantic security. Identical plaintext blocks will produce
//! identical ciphertext blocks, which can leak information about the plaintext structure.
//!
//! ECB mode should only be used in specific scenarios where its limitations are
//! acceptable, such as:
//! - Encrypting random or unique data where patterns are not a concern
//! - As a building block for other cryptographic constructions
//! - Single-block encryption where block patterns cannot emerge
//!
//! For most applications, prefer CBC, GCM, or other authenticated encryption modes.
//!
//! # Platform
//!
//! This implementation is Windows-specific and requires the Windows CNG subsystem.
//! Key material is managed securely by the Windows kernel.

use windows::Win32::Security::Cryptography::*;

use super::*;

/// CNG-based AES-ECB cipher implementation.
///
/// This structure provides AES encryption and decryption operations in Electronic Codebook
/// (ECB) mode using the Windows Cryptography Next Generation (CNG) API. It supports all
/// standard AES key sizes: 128, 192, and 256 bits.
///
/// # Characteristics
///
/// - **Stateless**: No internal state or initialization vector required
/// - **No padding**: Input must be a multiple of 16 bytes (AES block size)
/// - **Deterministic**: Same plaintext always produces same ciphertext with same key
/// - **Parallelizable**: Each block can be processed independently
///
/// # Thread Safety
///
/// This structure is thread-safe and can be shared across threads. However, the
/// mutable reference in operations prevents concurrent use of the same instance.
///
/// # Security Warning
///
/// ECB mode does not provide semantic security. Use only when:
/// - Data is random and lacks patterns
/// - Each block is unique (e.g., encrypting distinct keys)
/// - As a primitive in higher-level constructions
///
/// For general-purpose encryption, use CBC or GCM modes instead.
#[derive(Default)]
pub struct CngAesEcbAlgo {}

impl CngAesEcbAlgo {
    /// Performs encryption using Windows CNG BCryptEncrypt API.
    ///
    /// This internal method wraps the low-level Windows CNG encryption operation,
    /// handling buffer size queries and actual encryption uniformly. No initialization
    /// vector is used (ECB mode characteristic), and no padding is applied.
    ///
    /// # Arguments
    ///
    /// * `key_handle` - Windows CNG key handle for ECB mode operations
    /// * `input` - Input plaintext data to encrypt (must be a multiple of 16 bytes)
    /// * `output` - Optional output buffer for ciphertext; if `None`, returns required size
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to output buffer, or required size if `output` is `None`
    /// * `Err(CryptoError::AesEncryptError)` - If the encryption operation fails
    ///
    /// # Errors
    ///
    /// Returns `AesEncryptError` if:
    /// - Input length is not a multiple of 16 bytes
    /// - Output buffer is too small (when provided)
    /// - Windows CNG encryption operation fails
    ///
    /// # Safety
    ///
    /// Uses unsafe Windows CNG API calls. The function ensures:
    /// - Proper error handling and status checking
    /// - No undefined behavior from buffer operations
    /// - Valid handle usage with CNG subsystem
    #[allow(unsafe_code)]
    fn bcrypt_encrypt(
        key_handle: BCRYPT_KEY_HANDLE,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut out_len = 0u32;
        // SAFETY: Calling Windows CNG BCryptEncrypt API
        // - key_handle is a valid BCRYPT_KEY_HANDLE for ECB mode
        // - input slice is valid for the duration of this call
        // - output buffer (if provided) is valid and properly sized
        // - No IV parameter (None) as ECB doesn't use initialization vectors
        // - No padding flags set (BCRYPT_FLAGS(0))
        let status = unsafe {
            BCryptEncrypt(
                key_handle,
                Some(input),
                None,
                None, // No IV for ECB mode
                output,
                &mut out_len,
                BCRYPT_FLAGS(0),
            )
        };
        status.ok().map_err(|_| CryptoError::AesEncryptError)?;
        Ok(out_len as usize)
    }

    /// Performs decryption using Windows CNG BCryptDecrypt API.
    ///
    /// This internal method wraps the low-level Windows CNG decryption operation,
    /// handling buffer size queries and actual decryption uniformly. No initialization
    /// vector is used (ECB mode characteristic), and no padding removal is performed.
    ///
    /// # Arguments
    ///
    /// * `key_handle` - Windows CNG key handle for ECB mode operations
    /// * `input` - Input ciphertext data to decrypt (must be a multiple of 16 bytes)
    /// * `output` - Optional output buffer for plaintext; if `None`, returns required size
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to output buffer, or required size if `output` is `None`
    /// * `Err(CryptoError::AesDecryptError)` - If the decryption operation fails
    ///
    /// # Errors
    ///
    /// Returns `AesDecryptError` if:
    /// - Input length is not a multiple of 16 bytes
    /// - Output buffer is too small (when provided)
    /// - Windows CNG decryption operation fails
    ///
    /// # Safety
    ///
    /// Uses unsafe Windows CNG API calls. The function ensures:
    /// - Proper error handling and status checking
    /// - No undefined behavior from buffer operations
    /// - Valid handle usage with CNG subsystem
    #[allow(unsafe_code)]
    fn bcrypt_decrypt(
        key_handle: BCRYPT_KEY_HANDLE,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut out_len = 0u32;
        // SAFETY: Calling Windows CNG BCryptDecrypt API
        // - key_handle is a valid BCRYPT_KEY_HANDLE for ECB mode
        // - input slice is valid for the duration of this call
        // - output buffer (if provided) is valid and properly sized
        // - No IV parameter (None) as ECB doesn't use initialization vectors
        // - No padding flags set (BCRYPT_FLAGS(0))
        let status = unsafe {
            BCryptDecrypt(
                key_handle,
                Some(input),
                None,
                None, // No IV for ECB mode
                output,
                &mut out_len,
                BCRYPT_FLAGS(0),
            )
        };
        status.ok().map_err(|_| CryptoError::AesDecryptError)?;
        Ok(out_len as usize)
    }
}

/// Implementation of the `EncryptOp` trait for AES-ECB encryption.
///
/// Provides single-operation encryption using AES in ECB mode. The implementation
/// delegates to the internal `bcrypt_encrypt` method after extracting the ECB key handle.
impl EncryptOp for CngAesEcbAlgo {
    type Key = AesKey;

    /// Encrypts data using AES-ECB mode with Windows CNG.
    ///
    /// Performs stateless block cipher encryption where each 16-byte block is
    /// encrypted independently. The input must be a multiple of the AES block size.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for encryption (supports 128, 192, or 256-bit keys)
    /// * `input` - The plaintext data to encrypt (must be a multiple of 16 bytes)
    /// * `output` - Optional output buffer for the ciphertext.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to the output buffer, or required buffer size if `output` is `None`
    /// * `Err(CryptoError)` - If the encryption operation fails
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if:
    /// * `AesEncryptError` - The input length is not a multiple of the AES block size (16 bytes)
    /// * `AesEncryptError` - The output buffer is too small
    /// * `AesEncryptError` - The underlying CNG operation fails
    ///
    /// # Security
    ///
    /// Identical plaintext blocks will produce identical ciphertext blocks with the same key.
    /// This property can leak information about data patterns.
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        Self::bcrypt_encrypt(key.ecb_handle(), input, output)
    }
}

/// Implementation of the `DecryptOp` trait for AES-ECB decryption.
///
/// Provides single-operation decryption using AES in ECB mode. The implementation
/// delegates to the internal `bcrypt_decrypt` method after extracting the ECB key handle.
impl DecryptOp for CngAesEcbAlgo {
    type Key = AesKey;

    /// Decrypts data using AES-ECB mode with Windows CNG.
    ///
    /// Performs stateless block cipher decryption where each 16-byte block is
    /// decrypted independently. The input must be a multiple of the AES block size.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for decryption (must match the key used for encryption)
    /// * `input` - The ciphertext data to decrypt (must be a multiple of 16 bytes)
    /// * `output` - Optional output buffer for the plaintext.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to the output buffer, or required buffer size if `output` is `None`
    /// * `Err(CryptoError)` - If the decryption operation fails
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if:
    /// * `AesDecryptError` - The input length is not a multiple of the AES block size (16 bytes)
    /// * `AesDecryptError` - The output buffer is too small
    /// * `AesDecryptError` - The underlying CNG operation fails
    ///
    /// # Security
    ///
    /// This operation does not authenticate the ciphertext. Data corruption or tampering
    /// will result in garbled plaintext rather than a clear error.
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        Self::bcrypt_decrypt(key.ecb_handle(), input, output)
    }
}

/// AES block size in bytes.
const BLOCK_SIZE: usize = 16;

/// Validates and processes whole AES blocks with the CNG ECB handle.
fn ecb_blocks(
    key: &AesKey,
    encrypt: bool,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    if !input.len().is_multiple_of(BLOCK_SIZE) {
        return Err(CryptoError::AesInvalidInputSize);
    }
    if output.len() < input.len() {
        return Err(CryptoError::AesBufferTooSmall);
    }
    if input.is_empty() {
        return Ok(0);
    }
    let output = &mut output[..input.len()];
    if encrypt {
        CngAesEcbAlgo::bcrypt_encrypt(key.ecb_handle(), input, Some(output))
    } else {
        CngAesEcbAlgo::bcrypt_decrypt(key.ecb_handle(), input, Some(output))
    }
}

impl<'a> EncryptStreamingOp<'a> for CngAesEcbAlgo {
    type Key = AesKey;
    type Context = CngAesEcbEncryptContext;

    /// Initializes a streaming AES-ECB encryption context.
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        Ok(CngAesEcbEncryptContext {
            algo: self,
            key,
            block: AesBlock::default(),
        })
    }
}

/// Streaming context for AES-ECB encryption operations.
///
/// Created by [`CngAesEcbAlgo`]'s `encrypt_init`. Data is buffered into whole
/// 16-byte blocks; [`EncryptOpContext::finish`] fails with
/// [`CryptoError::AesInvalidInputSize`] if the total input is not block aligned.
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct CngAesEcbEncryptContext {
    algo: CngAesEcbAlgo,
    key: AesKey,
    block: AesBlock,
}

impl<'a> EncryptOpContext<'a> for CngAesEcbEncryptContext {
    type Algo = CngAesEcbAlgo;

    /// Processes a chunk of input, emitting all complete blocks except the last.
    ///
    /// Returns the number of bytes written, or the required size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesEncryptError` - CNG operation fails
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.update_len(input);
        };
        if output.len() < self.block.update_len(input)? {
            return Err(CryptoError::AesBufferTooSmall);
        }
        let mut offset = 0;
        let key = &self.key;
        self.block.update(input, |data| {
            let count = ecb_blocks(key, true, data, &mut output[offset..])?;
            offset += count;
            Ok(count)
        })
    }

    /// Processes the remaining buffered data.
    ///
    /// Returns the number of bytes written, or the maximum required size if
    /// `output` is `None`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::AesInvalidInputSize` - Total input is not a multiple of 16 bytes
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesEncryptError` - CNG operation fails
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.final_len();
        };
        let key = &self.key;
        self.block
            .r#final(|data| ecb_blocks(key, true, data, output))
    }

    /// Returns a reference to the underlying algorithm.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying algorithm.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying algorithm.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

impl<'a> DecryptStreamingOp<'a> for CngAesEcbAlgo {
    type Key = AesKey;
    type Context = CngAesEcbDecryptContext;

    /// Initializes a streaming AES-ECB decryption context.
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        Ok(CngAesEcbDecryptContext {
            algo: self,
            key,
            block: AesBlock::default(),
        })
    }
}

/// Streaming context for AES-ECB decryption operations.
///
/// Created by [`CngAesEcbAlgo`]'s `decrypt_init`. Data is buffered into whole
/// 16-byte blocks; [`DecryptOpContext::finish`] fails with
/// [`CryptoError::AesInvalidInputSize`] if the total input is not block aligned.
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct CngAesEcbDecryptContext {
    algo: CngAesEcbAlgo,
    key: AesKey,
    block: AesBlock,
}

impl<'a> DecryptOpContext<'a> for CngAesEcbDecryptContext {
    type Algo = CngAesEcbAlgo;

    /// Processes a chunk of input, emitting all complete blocks except the last.
    ///
    /// Returns the number of bytes written, or the required size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesDecryptError` - CNG operation fails
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.update_len(input);
        };
        if output.len() < self.block.update_len(input)? {
            return Err(CryptoError::AesBufferTooSmall);
        }
        let mut offset = 0;
        let key = &self.key;
        self.block.update(input, |data| {
            let count = ecb_blocks(key, false, data, &mut output[offset..])?;
            offset += count;
            Ok(count)
        })
    }

    /// Processes the remaining buffered data.
    ///
    /// Returns the number of bytes written, or the maximum required size if
    /// `output` is `None`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::AesInvalidInputSize` - Total input is not a multiple of 16 bytes
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesDecryptError` - CNG operation fails
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.final_len();
        };
        let key = &self.key;
        self.block
            .r#final(|data| ecb_blocks(key, false, data, output))
    }

    /// Returns a reference to the underlying algorithm.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying algorithm.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying algorithm.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}
