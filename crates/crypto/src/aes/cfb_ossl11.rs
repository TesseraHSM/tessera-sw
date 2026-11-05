// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based AES-CFB-128 encryption/decryption implementation.
//!
//! Cipher Feedback (CFB-128, NIST SP 800-38A) turns AES into a self-synchronizing
//! stream cipher: each 128-bit segment of plaintext is XORed with the encryption of
//! the previous ciphertext block (the IV for the first block). Input of any length
//! is accepted and the output is always the same length as the input.
//!
//! # IV chaining
//!
//! After each single-shot operation, or when a streaming context finishes, the
//! algorithm's IV is replaced with the last complete ciphertext block, or the input IV if no complete block
//! was processed. Consecutive operations therefore
//! continue the same stream, provided every operation except the last processes a
//! multiple of 16 bytes.
//!
//! # Security Considerations
//!
//! - Never reuse the same key-IV pair for different plaintexts
//! - This mode does not provide authentication; consider AES-GCM for new applications

use openssl::cipher::*;
use openssl::cipher_ctx::*;

use super::*;

/// AES block size in bytes.
const BLOCK_SIZE: usize = 16;

/// Validates the IV and returns it as a block.
///
/// # Errors
///
/// Returns `CryptoError::AesInvalidIVSize` if `iv` is not 16 bytes.
fn validate_iv(iv: &[u8]) -> Result<[u8; BLOCK_SIZE], CryptoError> {
    iv.try_into().map_err(|_| CryptoError::AesInvalidIVSize)
}

/// Validates that `output`, when present, can hold `len` bytes.
///
/// # Errors
///
/// Returns `CryptoError::AesBufferTooSmall` if the output buffer is too small.
fn check_output(len: usize, output: &Option<&mut [u8]>) -> Result<(), CryptoError> {
    match output {
        Some(out) if out.len() < len => Err(CryptoError::AesBufferTooSmall),
        _ => Ok(()),
    }
}

/// OpenSSL-based AES-CFB-128 encryption/decryption operation.
///
/// Supports AES-128, AES-192 and AES-256 keys in single-shot and streaming form.
pub struct OsslAesCfbAlgo {
    /// Initialization vector (16 bytes); advanced after each operation.
    iv: Vec<u8>,
}

impl OsslAesCfbAlgo {
    /// Creates a new AES-CFB-128 operation.
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector. Must be exactly 16 bytes; the length is
    ///   validated when the operation runs.
    pub fn new(iv: &[u8]) -> Self {
        Self { iv: iv.to_vec() }
    }

    /// Returns the current IV (the chaining value after the last operation).
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Returns the OpenSSL cipher for the given key size.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesInvalidKeySize` if the key size is not 16, 24, or 32 bytes.
    fn cipher(key_size: usize) -> Result<&'static CipherRef, CryptoError> {
        match key_size {
            16 => Ok(Cipher::aes_128_cfb128()),
            24 => Ok(Cipher::aes_192_cfb128()),
            32 => Ok(Cipher::aes_256_cfb128()),
            _ => Err(CryptoError::AesInvalidKeySize),
        }
    }

    /// Runs a single-shot operation and advances the IV.
    fn crypt(
        &mut self,
        key: &AesKey,
        encrypt: bool,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut stream = OsslAesCfbStream::new(&self.iv, key, encrypt)?;
        let Some(output) = output else {
            return Ok(input.len());
        };
        let mut count = stream.update(key, input, Some(&mut *output))?;
        count += stream.finish(&mut output[count..])?;
        self.iv = stream.iv(key)?.to_vec();
        Ok(count)
    }
}

/// Implements single-operation encryption for AES-CFB-128.
impl EncryptOp for OsslAesCfbAlgo {
    type Key = AesKey;

    /// Performs AES-CFB-128 encryption in a single operation.
    ///
    /// # Returns
    ///
    /// The number of bytes written (always `input.len()`), or the required
    /// buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::AesInvalidIVSize` - The IV is not 16 bytes
    /// - `CryptoError::AesInvalidKeySize` - The key is not 16, 24 or 32 bytes
    /// - `CryptoError::AesBufferTooSmall` - The output buffer is too small
    /// - `CryptoError::AesEncryptError` - The backend operation failed
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        self.crypt(key, true, input, output)
    }
}

/// Implements single-operation decryption for AES-CFB-128.
impl DecryptOp for OsslAesCfbAlgo {
    type Key = AesKey;

    /// Performs AES-CFB-128 decryption in a single operation.
    ///
    /// # Returns
    ///
    /// The number of bytes written (always `input.len()`), or the required
    /// buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// - `CryptoError::AesInvalidIVSize` - The IV is not 16 bytes
    /// - `CryptoError::AesInvalidKeySize` - The key is not 16, 24 or 32 bytes
    /// - `CryptoError::AesBufferTooSmall` - The output buffer is too small
    /// - `CryptoError::AesDecryptError` - The backend operation failed
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        self.crypt(key, false, input, output)
    }
}

/// Implements streaming encryption for AES-CFB-128.
impl<'a> EncryptStreamingOp<'a> for OsslAesCfbAlgo {
    type Key = AesKey;
    type Context = OsslAesCfbEncryptContext;

    /// Initializes a streaming AES-CFB-128 encryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = OsslAesCfbStream::new(&self.iv, &key, true)?;
        Ok(OsslAesCfbEncryptContext {
            algo: self,
            key,
            stream,
        })
    }
}

/// Streaming context for AES-CFB-128 encryption operations.
///
/// Output is produced for every input byte, so `update` always writes
/// `input.len()` bytes and `finish` writes none. The algorithm's IV is advanced
/// by `finish`.
pub struct OsslAesCfbEncryptContext {
    algo: OsslAesCfbAlgo,
    key: AesKey,
    stream: OsslAesCfbStream,
}

impl<'a> EncryptOpContext<'a> for OsslAesCfbEncryptContext {
    type Algo = OsslAesCfbAlgo;

    /// Encrypts a chunk of data of any length.
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        self.stream.update(&self.key, input, output)
    }

    /// Finishes the operation and advances the algorithm's IV.
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return Ok(0);
        };
        let count = self.stream.finish(output)?;
        self.algo.iv = self.stream.iv(&self.key)?.to_vec();
        Ok(count)
    }

    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

/// Implements streaming decryption for AES-CFB-128.
impl<'a> DecryptStreamingOp<'a> for OsslAesCfbAlgo {
    type Key = AesKey;
    type Context = OsslAesCfbDecryptContext;

    /// Initializes a streaming AES-CFB-128 decryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = OsslAesCfbStream::new(&self.iv, &key, false)?;
        Ok(OsslAesCfbDecryptContext {
            algo: self,
            key,
            stream,
        })
    }
}

/// Streaming context for AES-CFB-128 decryption operations.
///
/// Output is produced for every input byte, so `update` always writes
/// `input.len()` bytes and `finish` writes none. The algorithm's IV is advanced
/// by `finish`.
pub struct OsslAesCfbDecryptContext {
    algo: OsslAesCfbAlgo,
    key: AesKey,
    stream: OsslAesCfbStream,
}

impl<'a> DecryptOpContext<'a> for OsslAesCfbDecryptContext {
    type Algo = OsslAesCfbAlgo;

    /// Decrypts a chunk of data of any length.
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        self.stream.update(&self.key, input, output)
    }

    /// Finishes the operation and advances the algorithm's IV.
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let Some(output) = output else {
            return Ok(0);
        };
        let count = self.stream.finish(output)?;
        self.algo.iv = self.stream.iv(&self.key)?.to_vec();
        Ok(count)
    }

    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

/// OpenSSL cipher context plus the IV-chaining state shared by the single-shot
/// and streaming paths.
struct OsslAesCfbStream {
    ctx: CipherCtx,
    encrypt: bool,
    feedback: CfbFeedback,
}

impl OsslAesCfbStream {
    fn new(iv: &[u8], key: &AesKey, encrypt: bool) -> Result<Self, CryptoError> {
        let iv = validate_iv(iv)?;
        let key_bytes = key.bytes();
        let cipher = OsslAesCfbAlgo::cipher(key_bytes.len())?;
        let mut ctx = CipherCtx::new().map_err(|_| CryptoError::AesError)?;
        if encrypt {
            ctx.encrypt_init(Some(cipher), Some(key_bytes), Some(&iv))
        } else {
            ctx.decrypt_init(Some(cipher), Some(key_bytes), Some(&iv))
        }
        .map_err(|_| CryptoError::AesError)?;
        Ok(Self {
            ctx,
            encrypt,
            feedback: CfbFeedback::new(iv),
        })
    }

    fn error(&self) -> CryptoError {
        if self.encrypt {
            CryptoError::AesEncryptError
        } else {
            CryptoError::AesDecryptError
        }
    }

    fn update(
        &mut self,
        _key: &AesKey,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        check_output(input.len(), &output)?;
        let Some(output) = output else {
            return Ok(input.len());
        };
        let count = self
            .ctx
            .cipher_update(input, Some(&mut output[..input.len()]))
            .map_err(|_| self.error())?;
        if count != input.len() {
            return Err(self.error());
        }
        self.feedback.absorb(if self.encrypt {
            &output[..count]
        } else {
            input
        });
        Ok(count)
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<usize, CryptoError> {
        self.ctx.cipher_final(output).map_err(|_| self.error())
    }

    fn iv(&self, _key: &AesKey) -> Result<[u8; BLOCK_SIZE], CryptoError> {
        Ok(self.feedback.register())
    }
}

/// Tracks the CFB-128 feedback register: the last complete ciphertext block, or
/// the IV if no complete block has been processed.
struct CfbFeedback {
    reg: [u8; BLOCK_SIZE],
    blk: [u8; BLOCK_SIZE],
    pos: usize,
}

impl CfbFeedback {
    fn new(iv: [u8; BLOCK_SIZE]) -> Self {
        Self {
            reg: iv,
            blk: [0u8; BLOCK_SIZE],
            pos: 0,
        }
    }

    /// Records ciphertext bytes in stream order.
    fn absorb(&mut self, ciphertext: &[u8]) {
        for &byte in ciphertext {
            self.blk[self.pos] = byte;
            self.pos += 1;
            if self.pos == BLOCK_SIZE {
                self.reg = self.blk;
                self.pos = 0;
            }
        }
    }

    fn register(&self) -> [u8; BLOCK_SIZE] {
        self.reg
    }
}
