// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-ECB encryption and decryption operations.
//!
//! This module provides AES-ECB (Electronic Codebook) mode encryption and
//! decryption operations for HSM keys. The mode is only available on
//! extended (TBOR) sessions; other sessions fail with
//! [`HsmError::UnsupportedAlgorithm`].
//!
//! # Security
//!
//! ECB encrypts each block independently, so identical plaintext blocks
//! produce identical ciphertext blocks. Prefer an authenticated mode unless a
//! protocol specifically requires ECB.

use super::*;

/// An algorithm implementation for AES-ECB encryption and decryption.
///
/// This struct provides both single-shot and streaming encryption and
/// decryption using AES in ECB mode. Input must be a non-empty multiple of
/// the AES block size (16 bytes); no padding is applied. It implements the
/// [`HsmEncryptOp`], [`HsmEncryptStreamingOp`], [`HsmDecryptOp`], and
/// [`HsmDecryptStreamingOp`] traits for HSM operations.
#[derive(Debug, Default, Clone)]
pub struct HsmAesEcbAlgo;

impl HsmAesEcbAlgo {
    /// AES block size in bytes.
    const BLOCK_SIZE: usize = 16;

    /// Validates the input length for a single-shot operation.
    fn check_len(input: &[u8]) -> HsmResult<usize> {
        if input.is_empty() || !input.len().is_multiple_of(Self::BLOCK_SIZE) {
            return Err(HsmError::InvalidArgument);
        }
        Ok(input.len())
    }
}

impl HsmEncryptOp for HsmAesEcbAlgo {
    /// The AES key type used for encryption.
    type Key = HsmAesKey;

    /// The error type for encryption operations.
    type Error = HsmError;

    /// Encrypts data using AES-ECB mode in a single operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for encryption
    /// * `plaintext` - The input data (must be a non-empty multiple of 16 bytes)
    /// * `ciphertext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes written (equal to the input length),
    ///   or the required buffer size if `ciphertext` is `None`
    /// * `Err(HsmError::InvalidKey)` - If the key cannot encrypt
    /// * `Err(HsmError::InvalidArgument)` - If `plaintext` is empty or not block-aligned
    /// * `Err(HsmError::BufferTooSmall)` - If the output buffer is too small
    /// * `Err(HsmError::UnsupportedAlgorithm)` - If the session is not an extended session
    fn encrypt(
        &mut self,
        key: &Self::Key,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        if !key.props().can_encrypt() {
            Err(HsmError::InvalidKey)?;
        }
        ddi::aes_mode_ensure_supported(key)?;

        let expected_len = Self::check_len(plaintext)?;
        let Some(ciphertext) = ciphertext else {
            return Ok(expected_len);
        };
        if ciphertext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }
        if plaintext.is_empty() {
            return Ok(0);
        }
        ddi::aes_mode_encrypt(
            key,
            ddi::AesMode::Ecb,
            &mut [],
            plaintext,
            &mut ciphertext[..expected_len],
        )
    }
}

impl HsmEncryptStreamingOp for HsmAesEcbAlgo {
    /// The AES key type used for encryption.
    type Key = HsmAesKey;

    /// The error type for encryption operations.
    type Error = HsmError;

    /// The context type for streaming encryption.
    type Context = HsmAesEcbEncryptContext;

    /// Initializes a streaming AES-ECB encryption operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for encryption
    ///
    /// # Returns
    ///
    /// * `Ok(HsmAesEcbEncryptContext)` - An initialized encryption context
    /// * `Err(HsmError::InvalidKey)` - If the key cannot encrypt
    /// * `Err(HsmError::UnsupportedAlgorithm)` - If the session is not an extended session
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        if !key.props().can_encrypt() {
            Err(HsmError::InvalidKey)?;
        }
        ddi::aes_mode_ensure_supported(&key)?;

        Ok(HsmAesEcbEncryptContext {
            algo: self,
            key,
            block: AesEcbBlock::default(),
            can_update: true,
        })
    }
}

/// A context for streaming AES-ECB encryption operations.
///
/// Complete 16-byte blocks are sent to the HSM by `update`; a trailing partial
/// block is buffered until the next `update` or `finish`.
pub struct HsmAesEcbEncryptContext {
    /// The AES-ECB algorithm.
    algo: HsmAesEcbAlgo,

    /// The AES key being used for encryption.
    key: HsmAesKey,

    /// Internal buffer for a trailing partial block.
    block: AesEcbBlock,

    /// Cleared once `finish` succeeds, to prevent further use.
    can_update: bool,
}

impl HsmEncryptContext for HsmAesEcbEncryptContext {
    /// The AES-ECB algorithm for this encryption context.
    type Algo = HsmAesEcbAlgo;

    /// Encrypts a chunk of input in the streaming operation.
    ///
    /// Only complete blocks are processed and output; a trailing partial block
    /// is buffered.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The input data chunk
    /// * `ciphertext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written, or required buffer size if `ciphertext` is `None`
    /// * `Err(HsmError::InvalidContextState)` - If `finish` has already succeeded
    /// * `Err(HsmError::BufferTooSmall)` - If the output buffer is too small
    fn update(
        &mut self,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        if !self.can_update {
            return Err(HsmError::InvalidContextState);
        }
        let expected_len = self.block.update_len(plaintext);
        let Some(ciphertext) = ciphertext else {
            return Ok(expected_len);
        };
        if ciphertext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }
        self.block.update(plaintext, |input: &[u8]| {
            ddi::aes_mode_encrypt(
                &self.key,
                ddi::AesMode::Ecb,
                &mut [],
                input,
                &mut ciphertext[..input.len()],
            )
        })
    }

    /// Finalizes the streaming encryption operation.
    ///
    /// ECB has no partial-block handling: any buffered bytes mean the total
    /// input was not block-aligned and the operation fails.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(0)` - ECB never produces output on finish
    /// * `Err(HsmError::InvalidContextState)` - If `finish` has already succeeded
    /// * `Err(HsmError::InvalidArgument)` - If the total input was not block-aligned
    fn finish(
        &mut self,
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        if !self.can_update {
            return Err(HsmError::InvalidContextState);
        }
        if !self.block.is_empty() {
            return Err(HsmError::InvalidArgument);
        }
        if ciphertext.is_some() {
            self.can_update = false;
        }
        Ok(0)
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

impl HsmDecryptOp for HsmAesEcbAlgo {
    /// The AES key type used for decryption.
    type Key = HsmAesKey;

    /// The error type for decryption operations.
    type Error = HsmError;

    /// Decrypts data using AES-ECB mode in a single operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for decryption
    /// * `ciphertext` - The input data (must be a non-empty multiple of 16 bytes)
    /// * `plaintext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes written (equal to the input length),
    ///   or the required buffer size if `plaintext` is `None`
    /// * `Err(HsmError::InvalidKey)` - If the key cannot decrypt
    /// * `Err(HsmError::InvalidArgument)` - If `ciphertext` is empty or not block-aligned
    /// * `Err(HsmError::BufferTooSmall)` - If the output buffer is too small
    /// * `Err(HsmError::UnsupportedAlgorithm)` - If the session is not an extended session
    fn decrypt(
        &mut self,
        key: &Self::Key,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        if !key.props().can_decrypt() {
            Err(HsmError::InvalidKey)?;
        }
        ddi::aes_mode_ensure_supported(key)?;

        let expected_len = Self::check_len(ciphertext)?;
        let Some(plaintext) = plaintext else {
            return Ok(expected_len);
        };
        if plaintext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }
        if ciphertext.is_empty() {
            return Ok(0);
        }
        ddi::aes_mode_decrypt(
            key,
            ddi::AesMode::Ecb,
            &mut [],
            ciphertext,
            &mut plaintext[..expected_len],
        )
    }
}

impl HsmDecryptStreamingOp for HsmAesEcbAlgo {
    /// The AES key type used for decryption.
    type Key = HsmAesKey;

    /// The error type for decryption operations.
    type Error = HsmError;

    /// The context type for streaming decryption.
    type Context = HsmAesEcbDecryptContext;

    /// Initializes a streaming AES-ECB decryption operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for decryption
    ///
    /// # Returns
    ///
    /// * `Ok(HsmAesEcbDecryptContext)` - An initialized decryption context
    /// * `Err(HsmError::InvalidKey)` - If the key cannot decrypt
    /// * `Err(HsmError::UnsupportedAlgorithm)` - If the session is not an extended session
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        if !key.props().can_decrypt() {
            Err(HsmError::InvalidKey)?;
        }
        ddi::aes_mode_ensure_supported(&key)?;

        Ok(HsmAesEcbDecryptContext {
            algo: self,
            key,
            block: AesEcbBlock::default(),
            can_update: true,
        })
    }
}

/// A context for streaming AES-ECB decryption operations.
///
/// Complete 16-byte blocks are sent to the HSM by `update`; a trailing partial
/// block is buffered until the next `update` or `finish`.
pub struct HsmAesEcbDecryptContext {
    /// The AES-ECB algorithm.
    algo: HsmAesEcbAlgo,

    /// The AES key being used for decryption.
    key: HsmAesKey,

    /// Internal buffer for a trailing partial block.
    block: AesEcbBlock,

    /// Cleared once `finish` succeeds, to prevent further use.
    can_update: bool,
}

impl HsmDecryptContext for HsmAesEcbDecryptContext {
    /// The AES-ECB algorithm for this decryption context.
    type Algo = HsmAesEcbAlgo;

    /// Decrypts a chunk of input in the streaming operation.
    ///
    /// Only complete blocks are processed and output; a trailing partial block
    /// is buffered.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The input data chunk
    /// * `plaintext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written, or required buffer size if `plaintext` is `None`
    /// * `Err(HsmError::InvalidContextState)` - If `finish` has already succeeded
    /// * `Err(HsmError::BufferTooSmall)` - If the output buffer is too small
    fn update(
        &mut self,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        if !self.can_update {
            return Err(HsmError::InvalidContextState);
        }
        let expected_len = self.block.update_len(ciphertext);
        let Some(plaintext) = plaintext else {
            return Ok(expected_len);
        };
        if plaintext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }
        self.block.update(ciphertext, |input: &[u8]| {
            ddi::aes_mode_decrypt(
                &self.key,
                ddi::AesMode::Ecb,
                &mut [],
                input,
                &mut plaintext[..input.len()],
            )
        })
    }

    /// Finalizes the streaming decryption operation.
    ///
    /// ECB has no partial-block handling: any buffered bytes mean the total
    /// input was not block-aligned and the operation fails.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(0)` - ECB never produces output on finish
    /// * `Err(HsmError::InvalidContextState)` - If `finish` has already succeeded
    /// * `Err(HsmError::InvalidArgument)` - If the total input was not block-aligned
    fn finish(
        &mut self,
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        if !self.can_update {
            return Err(HsmError::InvalidContextState);
        }
        if !self.block.is_empty() {
            return Err(HsmError::InvalidArgument);
        }
        if plaintext.is_some() {
            self.can_update = false;
        }
        Ok(0)
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

/// Buffers a trailing partial AES block between AES-ECB streaming updates.
///
/// Only whole blocks are sent to the HSM before `finish` so the chaining IV
/// stays valid across requests.
#[derive(Default)]
struct AesEcbBlock {
    /// Buffered bytes; always fewer than [`Self::BLOCK_SIZE`].
    buf: Vec<u8>,
}

impl AesEcbBlock {
    /// AES block size in bytes.
    const BLOCK_SIZE: usize = 16;

    /// Returns the number of bytes `update` would output for `input`.
    fn update_len(&self, input: &[u8]) -> usize {
        (self.buf.len() + input.len()) / Self::BLOCK_SIZE * Self::BLOCK_SIZE
    }

    /// Runs `op` over all complete blocks formed by the buffer and `input`,
    /// then buffers the remaining partial block.
    ///
    /// The buffer is only updated if `op` succeeds.
    fn update<F>(&mut self, input: &[u8], op: F) -> HsmResult<usize>
    where
        F: FnOnce(&[u8]) -> HsmResult<usize>,
    {
        let whole = self.update_len(input);
        if whole == 0 {
            self.buf.extend_from_slice(input);
            return Ok(0);
        }
        let take = whole - self.buf.len();
        let written = if self.buf.is_empty() {
            op(&input[..take])?
        } else {
            let mut data = Vec::with_capacity(whole);
            data.extend_from_slice(&self.buf);
            data.extend_from_slice(&input[..take]);
            op(&data)?
        };
        self.buf.clear();
        self.buf.extend_from_slice(&input[take..]);
        Ok(written)
    }

    /// Returns `true` if no partial block is buffered.
    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}
