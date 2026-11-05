// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based AES-ECB encryption/decryption implementation.
//!
//! This module provides AES-ECB (Electronic Codebook) mode encryption using OpenSSL.
//! ECB is a block cipher mode that encrypts each block of plaintext independently.
//!
//! # Security Warning
//!
//! ECB mode is NOT recommended for most cryptographic applications because identical
//! plaintext blocks produce identical ciphertext blocks, which can leak information
//! about the plaintext structure. Consider using CBC, GCM, or other authenticated
//! encryption modes instead.
//!
//! # Block Size Requirement
//!
//! Input data must be a multiple of the AES block size (16 bytes). No padding is applied.

use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

use super::*;

/// OpenSSL AES-ECB encryption/decryption operation.
///
/// This structure provides AES-ECB mode encryption and decryption using OpenSSL.
/// It supports AES with 128, 192, and 256-bit keys.
///
/// # Security Considerations
///
/// ECB mode encrypts each block independently, which means:
/// - Identical plaintext blocks produce identical ciphertext blocks
/// - Patterns in the plaintext are preserved in the ciphertext
/// - No protection against block reordering or replay attacks
///
/// Use ECB mode only when:
/// - Processing random data with no patterns
/// - Encrypting single blocks
/// - Implementing higher-level protocols that handle security concerns
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync`.

#[derive(Default)]
pub struct OsslAesEcbAlgo;

impl OsslAesEcbAlgo {
    /// Returns the appropriate OpenSSL cipher based on key size.
    ///
    /// This internal method maps key sizes to their corresponding AES-ECB cipher variants.
    ///
    /// # Arguments
    ///
    /// * `key_size` - Size of the key in bytes (16 for AES-128, 24 for AES-192, 32 for AES-256)
    ///
    /// # Returns
    ///
    /// The corresponding OpenSSL `Cipher` for AES-ECB with the specified key size.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesInvalidKeySize` if the key size is not 16, 24, or 32 bytes.
    fn cipher(key_size: usize) -> Result<Cipher, CryptoError> {
        let name = match key_size {
            16 => "AES-128-ECB",
            24 => "AES-192-ECB",
            32 => "AES-256-ECB",
            _ => return Err(CryptoError::AesInvalidKeySize),
        };
        Cipher::fetch(Some(crate::libctx::crypto_libctx()), name, None)
            .map_err(|_| CryptoError::AesError)
    }
}

impl EncryptOp for OsslAesEcbAlgo {
    type Key = AesKey;

    /// Performs AES-ECB encryption in a single operation.
    ///
    /// Encrypts the input data using AES-ECB mode. The input must be a multiple of
    /// the AES block size (16 bytes). No padding is applied.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (16, 24, or 32 bytes for AES-128/192/256)
    /// * `input` - Input plaintext data to encrypt (must be multiple of 16 bytes)
    /// * `output` - Optional output buffer for ciphertext. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to output, or required buffer size if output is `None`
    /// * `Err(CryptoError)` - If encryption fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::AesInvalidKeySize` - Key size is not 16, 24, or 32 bytes
    /// - `CryptoError::AesInvalidInputSize` - Input length is not a multiple of 16 bytes
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesError` - Failed to initialize OpenSSL crypter
    /// - `CryptoError::AesEncryptError` - Encryption operation failed
    #[allow(unsafe_code)]
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, super::CryptoError> {
        let key_bytes = key.bytes();
        let cipher = Self::cipher(key_bytes.len())?;

        if !input.len().is_multiple_of(cipher.block_size()) {
            return Err(CryptoError::AesInvalidInputSize);
        }

        let len = input.len() + cipher.block_size();
        let count = if let Some(output) = output {
            // Validate output buffer size
            if output.len() < len {
                return Err(CryptoError::AesBufferTooSmall);
            }
            let mut ctx = CipherCtx::new().map_err(|_| CryptoError::AesEncryptError)?;
            ctx.set_padding(false);
            ctx.encrypt_init(Some(&cipher), Some(key_bytes), None)
                .map_err(|_| CryptoError::AesEncryptError)?;
            let mut count = ctx
                .cipher_update(input, Some(output))
                .map_err(|_| CryptoError::AesEncryptError)?;
            count += ctx
                .cipher_final(&mut output[count..])
                .map_err(|_| CryptoError::AesEncryptError)?;
            debug_assert!(count == input.len());
            count
        } else {
            len
        };

        Ok(count)
    }
}

impl DecryptOp for OsslAesEcbAlgo {
    type Key = AesKey;

    /// Performs AES-ECB decryption in a single operation.
    ///
    /// Decrypts the input ciphertext using AES-ECB mode. The input must be a multiple of
    /// the AES block size (16 bytes). No padding is applied.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (16, 24, or 32 bytes for AES-128/192/256)
    /// * `input` - Input ciphertext data to decrypt (must be multiple of 16 bytes)
    /// * `output` - Optional output buffer for plaintext. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to output, or required buffer size if output is `None`
    /// * `Err(CryptoError)` - If decryption fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::AesInvalidKeySize` - Key size is not 16, 24, or 32 bytes
    /// - `CryptoError::AesInvalidInputSize` - Input length is not a multiple of 16 bytes
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesError` - Failed to initialize OpenSSL crypter
    /// - `CryptoError::AesDecryptError` - Decryption operation failed
    #[allow(unsafe_code)]
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, super::CryptoError> {
        let key_bytes = key.bytes();
        let cipher = Self::cipher(key_bytes.len())?;

        if !input.len().is_multiple_of(cipher.block_size()) {
            return Err(CryptoError::AesInvalidInputSize);
        }

        let len = input.len() + cipher.block_size();

        let count = if let Some(output) = output {
            // Validate output buffer size
            if output.len() < len {
                return Err(CryptoError::AesBufferTooSmall);
            }

            let mut ctx = CipherCtx::new().map_err(|_| CryptoError::AesDecryptError)?;
            ctx.decrypt_init(Some(&cipher), Some(key_bytes), None)
                .map_err(|_| CryptoError::AesDecryptError)?;
            ctx.set_padding(false);
            let mut count = ctx
                .cipher_update(input, Some(output))
                .map_err(|_| CryptoError::AesDecryptError)?;
            count += ctx
                .cipher_final(&mut output[count..])
                .map_err(|_| CryptoError::AesDecryptError)?;
            debug_assert!(count == input.len());
            count
        } else {
            len
        };

        Ok(count)
    }
}

/// AES block size in bytes.
const BLOCK_SIZE: usize = 16;

/// Runs whole AES blocks through an initialized, unpadded ECB context.
///
/// Each block goes through a stack scratch buffer so callers only need an
/// output buffer as large as `input` (OpenSSL itself requires one extra block).
fn ecb_update_blocks(
    ctx: &mut CipherCtx,
    input: &[u8],
    output: &mut [u8],
    encrypt: bool,
) -> Result<usize, CryptoError> {
    let err = || {
        if encrypt {
            CryptoError::AesEncryptError
        } else {
            CryptoError::AesDecryptError
        }
    };
    if !input.len().is_multiple_of(BLOCK_SIZE) {
        return Err(CryptoError::AesInvalidInputSize);
    }
    if output.len() < input.len() {
        return Err(CryptoError::AesBufferTooSmall);
    }
    let mut scratch = [0u8; 2 * BLOCK_SIZE];
    for (inb, outb) in input
        .chunks_exact(BLOCK_SIZE)
        .zip(output.chunks_exact_mut(BLOCK_SIZE))
    {
        let count = ctx
            .cipher_update(inb, Some(&mut scratch))
            .map_err(|_| err())?;
        if count != BLOCK_SIZE {
            return Err(err());
        }
        outb.copy_from_slice(&scratch[..BLOCK_SIZE]);
    }
    scratch.fill(0);
    Ok(input.len())
}

/// Finalizes an unpadded ECB context with the remaining buffered block(s).
fn ecb_final_blocks(
    ctx: &mut CipherCtx,
    input: &[u8],
    output: &mut [u8],
    encrypt: bool,
) -> Result<usize, CryptoError> {
    let count = ecb_update_blocks(ctx, input, output, encrypt)?;
    let err = || {
        if encrypt {
            CryptoError::AesEncryptError
        } else {
            CryptoError::AesDecryptError
        }
    };
    let mut scratch = [0u8; BLOCK_SIZE];
    if ctx.cipher_final(&mut scratch).map_err(|_| err())? != 0 {
        return Err(err());
    }
    Ok(count)
}

impl OsslAesEcbAlgo {
    /// Creates an initialized, unpadded OpenSSL ECB context.
    fn init_ctx(key: &AesKey, encrypt: bool) -> Result<CipherCtx, CryptoError> {
        let key_bytes = key.bytes();
        let cipher = Self::cipher(key_bytes.len())?;
        let mut ctx = CipherCtx::new().map_err(|_| CryptoError::AesError)?;
        if encrypt {
            ctx.encrypt_init(Some(&cipher), Some(key_bytes), None)
        } else {
            ctx.decrypt_init(Some(&cipher), Some(key_bytes), None)
        }
        .map_err(|_| CryptoError::AesError)?;
        // Disable padding after init: OpenSSL 1.1 resets it during init.
        ctx.set_padding(false);
        Ok(ctx)
    }
}

impl<'a> EncryptStreamingOp<'a> for OsslAesEcbAlgo {
    type Key = AesKey;
    type Context = OsslAesEcbEncryptContext;

    /// Initializes a streaming AES-ECB encryption context.
    ///
    /// # Errors
    ///
    /// - `CryptoError::AesInvalidKeySize` - Key size is not 16, 24, or 32 bytes
    /// - `CryptoError::AesError` - OpenSSL context initialization fails
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let ctx = Self::init_ctx(&key, true)?;
        Ok(OsslAesEcbEncryptContext {
            algo: self,
            ctx,
            block: AesBlock::default(),
        })
    }
}

/// Streaming context for AES-ECB encryption operations.
///
/// Created by [`OsslAesEcbAlgo`]'s `encrypt_init`. Data is buffered into whole
/// 16-byte blocks; [`EncryptOpContext::finish`] fails with
/// [`CryptoError::AesInvalidInputSize`] if the total input is not block aligned.
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct OsslAesEcbEncryptContext {
    algo: OsslAesEcbAlgo,
    ctx: CipherCtx,
    block: AesBlock,
}

impl<'a> EncryptOpContext<'a> for OsslAesEcbEncryptContext {
    type Algo = OsslAesEcbAlgo;

    /// Processes a chunk of input, emitting all complete blocks except the last.
    ///
    /// Returns the number of bytes written, or the required size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesEncryptError` - OpenSSL operation fails
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.update_len(input);
        };
        if output.len() < self.block.update_len(input)? {
            return Err(CryptoError::AesBufferTooSmall);
        }
        let mut offset = 0;
        let ctx = &mut self.ctx;
        self.block.update(input, |data| {
            let count = ecb_update_blocks(ctx, data, &mut output[offset..], true)?;
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
    /// - `CryptoError::AesEncryptError` - OpenSSL operation fails
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.final_len();
        };
        let ctx = &mut self.ctx;
        self.block
            .r#final(|data| ecb_final_blocks(ctx, data, output, true))
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

impl<'a> DecryptStreamingOp<'a> for OsslAesEcbAlgo {
    type Key = AesKey;
    type Context = OsslAesEcbDecryptContext;

    /// Initializes a streaming AES-ECB decryption context.
    ///
    /// # Errors
    ///
    /// - `CryptoError::AesInvalidKeySize` - Key size is not 16, 24, or 32 bytes
    /// - `CryptoError::AesError` - OpenSSL context initialization fails
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let ctx = Self::init_ctx(&key, false)?;
        Ok(OsslAesEcbDecryptContext {
            algo: self,
            ctx,
            block: AesBlock::default(),
        })
    }
}

/// Streaming context for AES-ECB decryption operations.
///
/// Created by [`OsslAesEcbAlgo`]'s `decrypt_init`. Data is buffered into whole
/// 16-byte blocks; [`DecryptOpContext::finish`] fails with
/// [`CryptoError::AesInvalidInputSize`] if the total input is not block aligned.
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct OsslAesEcbDecryptContext {
    algo: OsslAesEcbAlgo,
    ctx: CipherCtx,
    block: AesBlock,
}

impl<'a> DecryptOpContext<'a> for OsslAesEcbDecryptContext {
    type Algo = OsslAesEcbAlgo;

    /// Processes a chunk of input, emitting all complete blocks except the last.
    ///
    /// Returns the number of bytes written, or the required size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesDecryptError` - OpenSSL operation fails
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.update_len(input);
        };
        if output.len() < self.block.update_len(input)? {
            return Err(CryptoError::AesBufferTooSmall);
        }
        let mut offset = 0;
        let ctx = &mut self.ctx;
        self.block.update(input, |data| {
            let count = ecb_update_blocks(ctx, data, &mut output[offset..], false)?;
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
    /// - `CryptoError::AesDecryptError` - OpenSSL operation fails
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return self.block.final_len();
        };
        let ctx = &mut self.ctx;
        self.block
            .r#final(|data| ecb_final_blocks(ctx, data, output, false))
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
