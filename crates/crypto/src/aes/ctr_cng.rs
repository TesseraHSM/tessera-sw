// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG AES-CTR encryption/decryption implementation.
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

/// Windows CNG AES-CTR encryption/decryption operation.
///
/// Supports AES-128, AES-192 and AES-256 keys in single-shot and streaming form.
pub struct CngAesCtrAlgo {
    /// Initialization vector (16 bytes); advanced after each operation.
    iv: Vec<u8>,
}

impl CngAesCtrAlgo {
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

    /// Runs a single-shot operation and advances the IV.
    fn crypt(
        &mut self,
        key: &AesKey,
        encrypt: bool,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut stream = CngAesCtrStream::new(&self.iv, key, encrypt)?;
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
impl EncryptOp for CngAesCtrAlgo {
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
impl DecryptOp for CngAesCtrAlgo {
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
impl<'a> EncryptStreamingOp<'a> for CngAesCtrAlgo {
    type Key = AesKey;
    type Context = CngAesCtrEncryptContext;

    /// Initializes a streaming AES-CTR encryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = CngAesCtrStream::new(&self.iv, &key, true)?;
        Ok(CngAesCtrEncryptContext {
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
pub struct CngAesCtrEncryptContext {
    algo: CngAesCtrAlgo,
    key: AesKey,
    stream: CngAesCtrStream,
}

impl<'a> EncryptOpContext<'a> for CngAesCtrEncryptContext {
    type Algo = CngAesCtrAlgo;

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
impl<'a> DecryptStreamingOp<'a> for CngAesCtrAlgo {
    type Key = AesKey;
    type Context = CngAesCtrDecryptContext;

    /// Initializes a streaming AES-CTR decryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = CngAesCtrStream::new(&self.iv, &key, false)?;
        Ok(CngAesCtrDecryptContext {
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
pub struct CngAesCtrDecryptContext {
    algo: CngAesCtrAlgo,
    key: AesKey,
    stream: CngAesCtrStream,
}

impl<'a> DecryptOpContext<'a> for CngAesCtrDecryptContext {
    type Algo = CngAesCtrAlgo;

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

/// Software CTR keystream over the CNG AES-ECB key handle.
struct CngAesCtrStream {
    ctr: u128,
    ks: [u8; BLOCK_SIZE],
    /// Bytes of `ks` already used; 0 means a new block is needed.
    pos: usize,
}

impl CngAesCtrStream {
    fn new(iv: &[u8], _key: &AesKey, _encrypt: bool) -> Result<Self, CryptoError> {
        Ok(Self {
            ctr: u128::from_be_bytes(validate_iv(iv)?),
            ks: [0u8; BLOCK_SIZE],
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
        // Use the rest of a partially consumed keystream block first.
        let mut i = 0;
        while self.pos != 0 && i < input.len() {
            output[i] = input[i] ^ self.ks[self.pos];
            self.pos = (self.pos + 1) % BLOCK_SIZE;
            i += 1;
        }
        let rest = &input[i..];
        if rest.is_empty() {
            return Ok(input.len());
        }
        // Counters are independent, so the keystream is produced in one ECB call.
        let blocks = rest.len().div_ceil(BLOCK_SIZE);
        let mut counters = Vec::with_capacity(blocks * BLOCK_SIZE);
        for _ in 0..blocks {
            counters.extend_from_slice(&self.ctr.to_be_bytes());
            self.ctr = self.ctr.wrapping_add(1);
        }
        let ks = ecb_encrypt_blocks(key, &counters)?;
        for ((o, d), k) in output[i..input.len()].iter_mut().zip(rest).zip(&ks) {
            *o = d ^ k;
        }
        let tail = rest.len() % BLOCK_SIZE;
        if tail != 0 {
            self.ks.copy_from_slice(&ks[ks.len() - BLOCK_SIZE..]);
            self.pos = tail;
        }
        Ok(input.len())
    }

    fn finish(&mut self, _output: &mut [u8]) -> Result<usize, CryptoError> {
        Ok(0)
    }

    fn iv(&self, _key: &AesKey) -> Result<[u8; BLOCK_SIZE], CryptoError> {
        Ok(self.ctr.to_be_bytes())
    }
}
