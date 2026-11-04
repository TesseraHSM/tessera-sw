// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based AES-CTR encryption/decryption implementation.
//!
//! Counter mode (CTR, NIST SP 800-38A) turns AES into a synchronous stream cipher:
//! the keystream is the encryption of successive counter blocks and is XORed with
//! the data. The IV is the initial counter block, treated as a 128-bit big-endian
//! integer that wraps on overflow. Encryption and decryption are the same
//! operation. Input of any length is accepted and the output is always the same
//! length as the input.
//!
//! # IV chaining
//!
//! After each single-shot operation, or when a streaming context finishes, the
//! algorithm's IV is replaced with the next unused counter block (`iv + ceil(len / 16)`). Consecutive operations therefore
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

/// OpenSSL-based AES-CTR encryption/decryption operation.
///
/// Supports AES-128, AES-192 and AES-256 keys in single-shot and streaming form.
pub struct OsslAesCtrAlgo {
    /// Initialization vector (16 bytes); advanced after each operation.
    iv: Vec<u8>,
}

impl OsslAesCtrAlgo {
    /// Creates a new AES-CTR operation.
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
            16 => Ok(Cipher::aes_128_ctr()),
            24 => Ok(Cipher::aes_192_ctr()),
            32 => Ok(Cipher::aes_256_ctr()),
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
        let mut stream = OsslAesCtrStream::new(&self.iv, key, encrypt)?;
        let Some(output) = output else {
            return Ok(input.len());
        };
        let mut count = stream.update(key, input, Some(&mut *output))?;
        count += stream.finish(&mut output[count..])?;
        self.iv = stream.iv(key)?.to_vec();
        Ok(count)
    }
}

/// Implements single-operation encryption for AES-CTR.
impl EncryptOp for OsslAesCtrAlgo {
    type Key = AesKey;

    /// Performs AES-CTR encryption in a single operation.
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

/// Implements single-operation decryption for AES-CTR.
impl DecryptOp for OsslAesCtrAlgo {
    type Key = AesKey;

    /// Performs AES-CTR decryption in a single operation.
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

/// Implements streaming encryption for AES-CTR.
impl<'a> EncryptStreamingOp<'a> for OsslAesCtrAlgo {
    type Key = AesKey;
    type Context = OsslAesCtrEncryptContext;

    /// Initializes a streaming AES-CTR encryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = OsslAesCtrStream::new(&self.iv, &key, true)?;
        Ok(OsslAesCtrEncryptContext {
            algo: self,
            key,
            stream,
        })
    }
}

/// Streaming context for AES-CTR encryption operations.
///
/// Output is produced for every input byte, so `update` always writes
/// `input.len()` bytes and `finish` writes none. The algorithm's IV is advanced
/// by `finish`.
pub struct OsslAesCtrEncryptContext {
    algo: OsslAesCtrAlgo,
    key: AesKey,
    stream: OsslAesCtrStream,
}

impl<'a> EncryptOpContext<'a> for OsslAesCtrEncryptContext {
    type Algo = OsslAesCtrAlgo;

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

/// Implements streaming decryption for AES-CTR.
impl<'a> DecryptStreamingOp<'a> for OsslAesCtrAlgo {
    type Key = AesKey;
    type Context = OsslAesCtrDecryptContext;

    /// Initializes a streaming AES-CTR decryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = OsslAesCtrStream::new(&self.iv, &key, false)?;
        Ok(OsslAesCtrDecryptContext {
            algo: self,
            key,
            stream,
        })
    }
}

/// Streaming context for AES-CTR decryption operations.
///
/// Output is produced for every input byte, so `update` always writes
/// `input.len()` bytes and `finish` writes none. The algorithm's IV is advanced
/// by `finish`.
pub struct OsslAesCtrDecryptContext {
    algo: OsslAesCtrAlgo,
    key: AesKey,
    stream: OsslAesCtrStream,
}

impl<'a> DecryptOpContext<'a> for OsslAesCtrDecryptContext {
    type Algo = OsslAesCtrAlgo;

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
struct OsslAesCtrStream {
    ctx: CipherCtx,
    encrypt: bool,
    counter: CtrCounter,
}

impl OsslAesCtrStream {
    fn new(iv: &[u8], key: &AesKey, encrypt: bool) -> Result<Self, CryptoError> {
        let iv = validate_iv(iv)?;
        let key_bytes = key.bytes();
        let cipher = OsslAesCtrAlgo::cipher(key_bytes.len())?;
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
            counter: CtrCounter::new(iv),
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
        self.counter.absorb(count);
        Ok(count)
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<usize, CryptoError> {
        self.ctx.cipher_final(output).map_err(|_| self.error())
    }

    fn iv(&self, _key: &AesKey) -> Result<[u8; BLOCK_SIZE], CryptoError> {
        Ok(self.counter.counter())
    }
}

/// Tracks the CTR counter block: a 128-bit big-endian integer that wraps on
/// overflow and advances once per keystream block started.
struct CtrCounter {
    ctr: u128,
    pos: usize,
}

impl CtrCounter {
    fn new(iv: [u8; BLOCK_SIZE]) -> Self {
        Self {
            ctr: u128::from_be_bytes(iv),
            pos: 0,
        }
    }

    /// Records that `len` more bytes were processed.
    fn absorb(&mut self, len: usize) {
        let avail = if self.pos == 0 {
            0
        } else {
            BLOCK_SIZE - self.pos
        };
        if len <= avail {
            self.pos = (self.pos + len) % BLOCK_SIZE;
            return;
        }
        let rest = len - avail;
        self.ctr = self.ctr.wrapping_add(rest.div_ceil(BLOCK_SIZE) as u128);
        self.pos = rest % BLOCK_SIZE;
    }

    /// Returns the next unused counter block.
    fn counter(&self) -> [u8; BLOCK_SIZE] {
        self.ctr.to_be_bytes()
    }
}
