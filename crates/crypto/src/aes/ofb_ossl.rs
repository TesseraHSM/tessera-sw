// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based AES-OFB encryption/decryption implementation.
//!
//! Output Feedback (OFB, NIST SP 800-38A) turns AES into a synchronous stream
//! cipher: the keystream is produced by repeatedly encrypting the IV and is XORed
//! with the data. Encryption and decryption are the same operation. Input of any
//! length is accepted and the output is always the same length as the input.
//!
//! # IV chaining
//!
//! After each single-shot operation, or when a streaming context finishes, the
//! algorithm's IV is replaced with the last keystream block generated, or the input IV if no data was
//! processed. Consecutive operations therefore
//! continue the same stream, provided every operation except the last processes a
//! multiple of 16 bytes.
//!
//! # Security Considerations
//!
//! - Never reuse the same key-IV pair for different plaintexts
//! - This mode does not provide authentication; consider AES-GCM for new applications

use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

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

/// Applies the AES forward cipher to `input` (a multiple of 16 bytes) with AES-ECB.
fn ecb_encrypt_blocks(key: &AesKey, input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut algo = AesEcbAlgo::default();
    // OpenSSL requires one spare block of output space.
    let mut out = vec![0u8; input.len() + BLOCK_SIZE];
    let len = Encrypter::encrypt(&mut algo, key, input, Some(&mut out))?;
    if len != input.len() {
        return Err(CryptoError::AesEncryptError);
    }
    out.truncate(len);
    Ok(out)
}

/// Applies the AES forward cipher to a single block.
fn ecb_encrypt_block(
    key: &AesKey,
    block: &[u8; BLOCK_SIZE],
) -> Result<[u8; BLOCK_SIZE], CryptoError> {
    ecb_encrypt_blocks(key, block)?
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::AesEncryptError)
}

/// OpenSSL-based AES-OFB encryption/decryption operation.
///
/// Supports AES-128, AES-192 and AES-256 keys in single-shot and streaming form.
pub struct OsslAesOfbAlgo {
    /// Initialization vector (16 bytes); advanced after each operation.
    iv: Vec<u8>,
}

impl OsslAesOfbAlgo {
    /// Creates a new AES-OFB operation.
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
    /// The cipher is fetched from the crate-private libctx (default-provider-only)
    /// so it never resolves to a third-party provider. See [`crate::libctx`].
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesInvalidKeySize` if the key size is not 16, 24, or 32 bytes.
    fn cipher(key_size: usize) -> Result<Cipher, CryptoError> {
        let name = match key_size {
            16 => "AES-128-OFB",
            24 => "AES-192-OFB",
            32 => "AES-256-OFB",
            _ => return Err(CryptoError::AesInvalidKeySize),
        };
        Cipher::fetch(Some(crate::libctx::crypto_libctx()), name, None)
            .map_err(|_| CryptoError::AesError)
    }

    /// Runs a single-shot operation and advances the IV.
    fn crypt(
        &mut self,
        key: &AesKey,
        encrypt: bool,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut stream = OsslAesOfbStream::new(&self.iv, key, encrypt)?;
        let Some(output) = output else {
            return Ok(input.len());
        };
        let mut count = stream.update(key, input, Some(&mut *output))?;
        count += stream.finish(&mut output[count..])?;
        self.iv = stream.iv(key)?.to_vec();
        Ok(count)
    }
}

/// Implements single-operation encryption for AES-OFB.
impl EncryptOp for OsslAesOfbAlgo {
    type Key = AesKey;

    /// Performs AES-OFB encryption in a single operation.
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

/// Implements single-operation decryption for AES-OFB.
impl DecryptOp for OsslAesOfbAlgo {
    type Key = AesKey;

    /// Performs AES-OFB decryption in a single operation.
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

/// Implements streaming encryption for AES-OFB.
impl<'a> EncryptStreamingOp<'a> for OsslAesOfbAlgo {
    type Key = AesKey;
    type Context = OsslAesOfbEncryptContext;

    /// Initializes a streaming AES-OFB encryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = OsslAesOfbStream::new(&self.iv, &key, true)?;
        Ok(OsslAesOfbEncryptContext {
            algo: self,
            key,
            stream,
        })
    }
}

/// Streaming context for AES-OFB encryption operations.
///
/// Output is produced for every input byte, so `update` always writes
/// `input.len()` bytes and `finish` writes none. The algorithm's IV is advanced
/// by `finish`.
pub struct OsslAesOfbEncryptContext {
    algo: OsslAesOfbAlgo,
    key: AesKey,
    stream: OsslAesOfbStream,
}

impl<'a> EncryptOpContext<'a> for OsslAesOfbEncryptContext {
    type Algo = OsslAesOfbAlgo;

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

/// Implements streaming decryption for AES-OFB.
impl<'a> DecryptStreamingOp<'a> for OsslAesOfbAlgo {
    type Key = AesKey;
    type Context = OsslAesOfbDecryptContext;

    /// Initializes a streaming AES-OFB decryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = OsslAesOfbStream::new(&self.iv, &key, false)?;
        Ok(OsslAesOfbDecryptContext {
            algo: self,
            key,
            stream,
        })
    }
}

/// Streaming context for AES-OFB decryption operations.
///
/// Output is produced for every input byte, so `update` always writes
/// `input.len()` bytes and `finish` writes none. The algorithm's IV is advanced
/// by `finish`.
pub struct OsslAesOfbDecryptContext {
    algo: OsslAesOfbAlgo,
    key: AesKey,
    stream: OsslAesOfbStream,
}

impl<'a> DecryptOpContext<'a> for OsslAesOfbDecryptContext {
    type Algo = OsslAesOfbAlgo;

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
struct OsslAesOfbStream {
    ctx: CipherCtx,
    encrypt: bool,
    feedback: OfbFeedback,
}

impl OsslAesOfbStream {
    fn new(iv: &[u8], key: &AesKey, encrypt: bool) -> Result<Self, CryptoError> {
        let iv = validate_iv(iv)?;
        let key_bytes = key.bytes();
        let cipher = OsslAesOfbAlgo::cipher(key_bytes.len())?;
        let mut ctx = CipherCtx::new().map_err(|_| CryptoError::AesError)?;
        if encrypt {
            ctx.encrypt_init(Some(&cipher), Some(key_bytes), Some(&iv))
        } else {
            ctx.decrypt_init(Some(&cipher), Some(key_bytes), Some(&iv))
        }
        .map_err(|_| CryptoError::AesError)?;
        Ok(Self {
            ctx,
            encrypt,
            feedback: OfbFeedback::new(iv),
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
        self.feedback.absorb(input, &output[..count]);
        Ok(count)
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<usize, CryptoError> {
        self.ctx.cipher_final(output).map_err(|_| self.error())
    }

    fn iv(&self, key: &AesKey) -> Result<[u8; BLOCK_SIZE], CryptoError> {
        self.feedback.register(key)
    }
}

/// Tracks the OFB output register: the last keystream block generated.
struct OfbFeedback {
    reg: [u8; BLOCK_SIZE],
    blk: [u8; BLOCK_SIZE],
    pos: usize,
}

impl OfbFeedback {
    fn new(iv: [u8; BLOCK_SIZE]) -> Self {
        Self {
            reg: iv,
            blk: [0u8; BLOCK_SIZE],
            pos: 0,
        }
    }

    /// Records the keystream recovered from matching input and output bytes.
    fn absorb(&mut self, input: &[u8], output: &[u8]) {
        for (i, o) in input.iter().zip(output) {
            self.blk[self.pos] = i ^ o;
            self.pos += 1;
            if self.pos == BLOCK_SIZE {
                self.reg = self.blk;
                self.pos = 0;
            }
        }
    }

    /// Returns the last keystream block. A partially consumed block is only
    /// partly visible in the data, so it is regenerated from the previous one.
    fn register(&self, key: &AesKey) -> Result<[u8; BLOCK_SIZE], CryptoError> {
        if self.pos == 0 {
            Ok(self.reg)
        } else {
            ecb_encrypt_block(key, &self.reg)
        }
    }
}
