// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG AES-OFB encryption/decryption implementation.
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

/// Windows CNG AES-OFB encryption/decryption operation.
///
/// Supports AES-128, AES-192 and AES-256 keys in single-shot and streaming form.
pub struct CngAesOfbAlgo {
    /// Initialization vector (16 bytes); advanced after each operation.
    iv: Vec<u8>,
}

impl CngAesOfbAlgo {
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

    /// Runs a single-shot operation and advances the IV.
    fn crypt(
        &mut self,
        key: &AesKey,
        encrypt: bool,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut stream = CngAesOfbStream::new(&self.iv, key, encrypt)?;
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
impl EncryptOp for CngAesOfbAlgo {
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
impl DecryptOp for CngAesOfbAlgo {
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
impl<'a> EncryptStreamingOp<'a> for CngAesOfbAlgo {
    type Key = AesKey;
    type Context = CngAesOfbEncryptContext;

    /// Initializes a streaming AES-OFB encryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = CngAesOfbStream::new(&self.iv, &key, true)?;
        Ok(CngAesOfbEncryptContext {
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
pub struct CngAesOfbEncryptContext {
    algo: CngAesOfbAlgo,
    key: AesKey,
    stream: CngAesOfbStream,
}

impl<'a> EncryptOpContext<'a> for CngAesOfbEncryptContext {
    type Algo = CngAesOfbAlgo;

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
impl<'a> DecryptStreamingOp<'a> for CngAesOfbAlgo {
    type Key = AesKey;
    type Context = CngAesOfbDecryptContext;

    /// Initializes a streaming AES-OFB decryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = CngAesOfbStream::new(&self.iv, &key, false)?;
        Ok(CngAesOfbDecryptContext {
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
pub struct CngAesOfbDecryptContext {
    algo: CngAesOfbAlgo,
    key: AesKey,
    stream: CngAesOfbStream,
}

impl<'a> DecryptOpContext<'a> for CngAesOfbDecryptContext {
    type Algo = CngAesOfbAlgo;

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

/// Software OFB keystream over the CNG AES-ECB key handle.
struct CngAesOfbStream {
    /// Last keystream block generated (the IV before the first block).
    reg: [u8; BLOCK_SIZE],
    /// Bytes of `reg` already used; 0 means a new block is needed.
    pos: usize,
}

impl CngAesOfbStream {
    fn new(iv: &[u8], _key: &AesKey, _encrypt: bool) -> Result<Self, CryptoError> {
        Ok(Self {
            reg: validate_iv(iv)?,
            pos: 0,
        })
    }

    fn update(
        &mut self,
        key: &AesKey,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        check_output(input.len(), &output)?;
        let Some(output) = output else {
            return Ok(input.len());
        };
        // Each keystream block is the encryption of the previous one.
        for (o, d) in output.iter_mut().zip(input) {
            if self.pos == 0 {
                self.reg = ecb_encrypt_block(key, &self.reg)?;
            }
            *o = d ^ self.reg[self.pos];
            self.pos = (self.pos + 1) % BLOCK_SIZE;
        }
        Ok(input.len())
    }

    fn finish(&mut self, _output: &mut [u8]) -> Result<usize, CryptoError> {
        Ok(0)
    }

    fn iv(&self, _key: &AesKey) -> Result<[u8; BLOCK_SIZE], CryptoError> {
        Ok(self.reg)
    }
}
