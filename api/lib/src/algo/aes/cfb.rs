// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-CFB (128-bit segment) encryption and decryption operations.
//!
//! This module provides AES-CFB (128-bit segment) (Cipher Feedback with a 128-bit segment) mode encryption and
//! decryption operations for HSM keys. The mode is only available on
//! extended (TBOR) sessions; other sessions fail with
//! [`HsmError::UnsupportedAlgorithm`].
//!
//! CFB is a stream mode: input of any length is accepted and output is the
//! same length as input. After each operation [`HsmAesCfbAlgo::iv`] returns
//! the chaining IV, which is the last complete ciphertext block, or the input IV if no complete block was processed. Continuing a message from that IV
//! is only valid if every preceding operation processed a multiple of 16
//! bytes.

use super::*;

/// An algorithm implementation for AES-CFB (128-bit segment) encryption and decryption.
///
/// This struct provides both single-shot and streaming encryption and
/// decryption using AES in CFB mode. It implements the [`HsmEncryptOp`],
/// [`HsmEncryptStreamingOp`], [`HsmDecryptOp`], and [`HsmDecryptStreamingOp`]
/// traits for HSM operations.
#[derive(Debug, Clone)]
pub struct HsmAesCfbAlgo {
    /// The initialization vector, updated after each operation to support
    /// chaining. Always exactly 16 bytes.
    iv: Vec<u8>,
}

impl HsmAesCfbAlgo {
    /// Size of the initialization vector (IV) in bytes.
    const IV_SIZE: usize = 16;

    /// Creates a new AES-CFB (128-bit segment) algorithm instance.
    ///
    /// # Arguments
    ///
    /// * `iv` - The initialization vector (must be exactly 16 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - A configured AES-CFB (128-bit segment) algorithm instance
    /// * `Err(HsmError::InvalidArgument)` - If the IV is not exactly 16 bytes
    pub fn new(iv: Vec<u8>) -> HsmResult<Self> {
        if iv.len() != Self::IV_SIZE {
            return Err(HsmError::InvalidArgument);
        }
        Ok(Self { iv })
    }

    /// Returns the current chaining IV.
    ///
    /// After an operation this is the last complete ciphertext block, or the input IV if no complete block was processed.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Validates the input length for a single-shot operation.
    fn check_len(input: &[u8]) -> HsmResult<usize> {
        Ok(input.len())
    }
}

impl HsmEncryptOp for HsmAesCfbAlgo {
    /// The AES key type used for encryption.
    type Key = HsmAesKey;

    /// The error type for encryption operations.
    type Error = HsmError;

    /// Encrypts data using AES-CFB (128-bit segment) mode in a single operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for encryption
    /// * `plaintext` - The input data (may be any length)
    /// * `ciphertext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes written (equal to the input length),
    ///   or the required buffer size if `ciphertext` is `None`
    /// * `Err(HsmError::InvalidKey)` - If the key cannot encrypt
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
            ddi::AesMode::Cfb,
            &mut self.iv,
            plaintext,
            &mut ciphertext[..expected_len],
        )
    }
}

impl HsmEncryptStreamingOp for HsmAesCfbAlgo {
    /// The AES key type used for encryption.
    type Key = HsmAesKey;

    /// The error type for encryption operations.
    type Error = HsmError;

    /// The context type for streaming encryption.
    type Context = HsmAesCfbEncryptContext;

    /// Initializes a streaming AES-CFB (128-bit segment) encryption operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for encryption
    ///
    /// # Returns
    ///
    /// * `Ok(HsmAesCfbEncryptContext)` - An initialized encryption context
    /// * `Err(HsmError::InvalidKey)` - If the key cannot encrypt
    /// * `Err(HsmError::UnsupportedAlgorithm)` - If the session is not an extended session
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        if !key.props().can_encrypt() {
            Err(HsmError::InvalidKey)?;
        }
        ddi::aes_mode_ensure_supported(&key)?;

        Ok(HsmAesCfbEncryptContext {
            algo: self,
            key,
            block: AesCfbBlock::default(),
            can_update: true,
        })
    }
}

/// A context for streaming AES-CFB (128-bit segment) encryption operations.
///
/// Complete 16-byte blocks are sent to the HSM by `update`; a trailing partial
/// block is buffered until the next `update` or `finish`.
pub struct HsmAesCfbEncryptContext {
    /// The AES-CFB (128-bit segment) algorithm, including the chaining IV.
    algo: HsmAesCfbAlgo,

    /// The AES key being used for encryption.
    key: HsmAesKey,

    /// Internal buffer for a trailing partial block.
    block: AesCfbBlock,

    /// Cleared once `finish` succeeds, to prevent further use.
    can_update: bool,
}

impl HsmEncryptContext for HsmAesCfbEncryptContext {
    /// The AES-CFB (128-bit segment) algorithm for this encryption context.
    type Algo = HsmAesCfbAlgo;

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
                ddi::AesMode::Cfb,
                &mut self.algo.iv,
                input,
                &mut ciphertext[..input.len()],
            )
        })
    }

    /// Finalizes the streaming encryption operation.
    ///
    /// Processes the buffered partial block, if any.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written, or required buffer size if `ciphertext` is `None`
    /// * `Err(HsmError::InvalidContextState)` - If `finish` has already succeeded
    /// * `Err(HsmError::BufferTooSmall)` - If the output buffer is too small
    fn finish(
        &mut self,
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        if !self.can_update {
            return Err(HsmError::InvalidContextState);
        }
        let expected_len = self.block.finish_len();
        let Some(ciphertext) = ciphertext else {
            return Ok(expected_len);
        };
        if ciphertext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }
        let len = self.block.finish(|input: &[u8]| {
            ddi::aes_mode_encrypt(
                &self.key,
                ddi::AesMode::Cfb,
                &mut self.algo.iv,
                input,
                &mut ciphertext[..input.len()],
            )
        })?;
        self.can_update = false;
        Ok(len)
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

impl HsmDecryptOp for HsmAesCfbAlgo {
    /// The AES key type used for decryption.
    type Key = HsmAesKey;

    /// The error type for decryption operations.
    type Error = HsmError;

    /// Decrypts data using AES-CFB (128-bit segment) mode in a single operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for decryption
    /// * `ciphertext` - The input data (may be any length)
    /// * `plaintext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes written (equal to the input length),
    ///   or the required buffer size if `plaintext` is `None`
    /// * `Err(HsmError::InvalidKey)` - If the key cannot decrypt
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
            ddi::AesMode::Cfb,
            &mut self.iv,
            ciphertext,
            &mut plaintext[..expected_len],
        )
    }
}

impl HsmDecryptStreamingOp for HsmAesCfbAlgo {
    /// The AES key type used for decryption.
    type Key = HsmAesKey;

    /// The error type for decryption operations.
    type Error = HsmError;

    /// The context type for streaming decryption.
    type Context = HsmAesCfbDecryptContext;

    /// Initializes a streaming AES-CFB (128-bit segment) decryption operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for decryption
    ///
    /// # Returns
    ///
    /// * `Ok(HsmAesCfbDecryptContext)` - An initialized decryption context
    /// * `Err(HsmError::InvalidKey)` - If the key cannot decrypt
    /// * `Err(HsmError::UnsupportedAlgorithm)` - If the session is not an extended session
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        if !key.props().can_decrypt() {
            Err(HsmError::InvalidKey)?;
        }
        ddi::aes_mode_ensure_supported(&key)?;

        Ok(HsmAesCfbDecryptContext {
            algo: self,
            key,
            block: AesCfbBlock::default(),
            can_update: true,
        })
    }
}

/// A context for streaming AES-CFB (128-bit segment) decryption operations.
///
/// Complete 16-byte blocks are sent to the HSM by `update`; a trailing partial
/// block is buffered until the next `update` or `finish`.
pub struct HsmAesCfbDecryptContext {
    /// The AES-CFB (128-bit segment) algorithm, including the chaining IV.
    algo: HsmAesCfbAlgo,

    /// The AES key being used for decryption.
    key: HsmAesKey,

    /// Internal buffer for a trailing partial block.
    block: AesCfbBlock,

    /// Cleared once `finish` succeeds, to prevent further use.
    can_update: bool,
}

impl HsmDecryptContext for HsmAesCfbDecryptContext {
    /// The AES-CFB (128-bit segment) algorithm for this decryption context.
    type Algo = HsmAesCfbAlgo;

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
                ddi::AesMode::Cfb,
                &mut self.algo.iv,
                input,
                &mut plaintext[..input.len()],
            )
        })
    }

    /// Finalizes the streaming decryption operation.
    ///
    /// Processes the buffered partial block, if any.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written, or required buffer size if `plaintext` is `None`
    /// * `Err(HsmError::InvalidContextState)` - If `finish` has already succeeded
    /// * `Err(HsmError::BufferTooSmall)` - If the output buffer is too small
    fn finish(
        &mut self,
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        if !self.can_update {
            return Err(HsmError::InvalidContextState);
        }
        let expected_len = self.block.finish_len();
        let Some(plaintext) = plaintext else {
            return Ok(expected_len);
        };
        if plaintext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }
        let len = self.block.finish(|input: &[u8]| {
            ddi::aes_mode_decrypt(
                &self.key,
                ddi::AesMode::Cfb,
                &mut self.algo.iv,
                input,
                &mut plaintext[..input.len()],
            )
        })?;
        self.can_update = false;
        Ok(len)
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

/// Buffers a trailing partial AES block between AES-CFB (128-bit segment) streaming updates.
///
/// Only whole blocks are sent to the HSM before `finish` so the chaining IV
/// stays valid across requests.
#[derive(Default)]
struct AesCfbBlock {
    /// Buffered bytes; always fewer than [`Self::BLOCK_SIZE`].
    buf: Vec<u8>,
}

impl AesCfbBlock {
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

    /// Returns the number of bytes `finish` would output.
    fn finish_len(&self) -> usize {
        self.buf.len()
    }

    /// Runs `op` over the buffered partial block, if any.
    fn finish<F>(&mut self, op: F) -> HsmResult<usize>
    where
        F: FnOnce(&[u8]) -> HsmResult<usize>,
    {
        if self.buf.is_empty() {
            return Ok(0);
        }
        let written = op(&self.buf)?;
        self.buf.clear();
        Ok(written)
    }
}
