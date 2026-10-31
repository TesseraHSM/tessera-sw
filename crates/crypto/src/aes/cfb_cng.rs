// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG AES-CFB-128 encryption/decryption implementation.
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

use windows::Win32::Security::Cryptography::*;

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

/// Windows CNG AES-CFB-128 encryption/decryption operation.
///
/// Supports AES-128, AES-192 and AES-256 keys in single-shot and streaming form.
pub struct CngAesCfbAlgo {
    /// Initialization vector (16 bytes); advanced after each operation.
    iv: Vec<u8>,
}

impl CngAesCfbAlgo {
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

    /// Runs a single-shot operation and advances the IV.
    fn crypt(
        &mut self,
        key: &AesKey,
        encrypt: bool,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut stream = CngAesCfbStream::new(&self.iv, key, encrypt)?;
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
impl EncryptOp for CngAesCfbAlgo {
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
impl DecryptOp for CngAesCfbAlgo {
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
impl<'a> EncryptStreamingOp<'a> for CngAesCfbAlgo {
    type Key = AesKey;
    type Context = CngAesCfbEncryptContext;

    /// Initializes a streaming AES-CFB-128 encryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = CngAesCfbStream::new(&self.iv, &key, true)?;
        Ok(CngAesCfbEncryptContext {
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
pub struct CngAesCfbEncryptContext {
    algo: CngAesCfbAlgo,
    key: AesKey,
    stream: CngAesCfbStream,
}

impl<'a> EncryptOpContext<'a> for CngAesCfbEncryptContext {
    type Algo = CngAesCfbAlgo;

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
impl<'a> DecryptStreamingOp<'a> for CngAesCfbAlgo {
    type Key = AesKey;
    type Context = CngAesCfbDecryptContext;

    /// Initializes a streaming AES-CFB-128 decryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or IV size is invalid or the backend fails
    /// to initialize.
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let stream = CngAesCfbStream::new(&self.iv, &key, false)?;
        Ok(CngAesCfbDecryptContext {
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
pub struct CngAesCfbDecryptContext {
    algo: CngAesCfbAlgo,
    key: AesKey,
    stream: CngAesCfbStream,
}

impl<'a> DecryptOpContext<'a> for CngAesCfbDecryptContext {
    type Algo = CngAesCfbAlgo;

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

/// CNG AES-CFB-128 state.
///
/// Block-aligned runs use the native CNG CFB key handle; partial segments are
/// handled in software over the AES-ECB key handle.
struct CngAesCfbStream {
    encrypt: bool,
    /// Feedback register: the last complete ciphertext block, or the IV.
    reg: [u8; BLOCK_SIZE],
    /// Keystream for the current partial segment.
    ks: [u8; BLOCK_SIZE],
    /// Ciphertext of the current partial segment.
    blk: [u8; BLOCK_SIZE],
    /// Bytes of the current segment already processed.
    pos: usize,
}

impl CngAesCfbStream {
    fn new(iv: &[u8], key: &AesKey, encrypt: bool) -> Result<Self, CryptoError> {
        let reg = validate_iv(iv)?;
        Self::set_segment_size(key.cfb_handle())?;
        Ok(Self {
            encrypt,
            reg,
            ks: [0u8; BLOCK_SIZE],
            blk: [0u8; BLOCK_SIZE],
            pos: 0,
        })
    }

    fn error(&self) -> CryptoError {
        if self.encrypt {
            CryptoError::AesEncryptError
        } else {
            CryptoError::AesDecryptError
        }
    }

    /// Selects CFB-128 (CNG defaults to an 8-bit segment).
    #[allow(unsafe_code)]
    fn set_segment_size(key_handle: BCRYPT_KEY_HANDLE) -> Result<(), CryptoError> {
        let len = (BLOCK_SIZE as u32).to_ne_bytes();
        // SAFETY: key_handle is a valid CNG key handle owned by the AES key and
        // `len` is a valid DWORD buffer for the message block length property.
        let status =
            unsafe { BCryptSetProperty(key_handle.into(), BCRYPT_MESSAGE_BLOCK_LENGTH, &len, 0) };
        status.ok().map_err(|_| CryptoError::AesError)
    }

    /// Processes block-aligned data with the native CNG CFB-128 handle.
    #[allow(unsafe_code)]
    fn bcrypt_cfb(
        &mut self,
        key: &AesKey,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let mut iv = self.reg;
        let mut out_len = 0u32;
        // SAFETY: the key handle is valid for the lifetime of `key`, and the
        // input, IV and output slices are valid for the duration of the call.
        let status = unsafe {
            if self.encrypt {
                BCryptEncrypt(
                    key.cfb_handle(),
                    Some(input),
                    None,
                    Some(&mut iv),
                    Some(output),
                    &mut out_len,
                    BCRYPT_FLAGS(0),
                )
            } else {
                BCryptDecrypt(
                    key.cfb_handle(),
                    Some(input),
                    None,
                    Some(&mut iv),
                    Some(output),
                    &mut out_len,
                    BCRYPT_FLAGS(0),
                )
            }
        };
        status.ok().map_err(|_| self.error())?;
        if out_len as usize != input.len() {
            return Err(self.error());
        }
        Ok(())
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
        let mut i = 0;
        while i < input.len() {
            let remaining = input.len() - i;
            if self.pos == 0 && remaining >= BLOCK_SIZE {
                let end = i + remaining / BLOCK_SIZE * BLOCK_SIZE;
                self.bcrypt_cfb(key, &input[i..end], &mut output[i..end])?;
                let ct = if self.encrypt {
                    &output[..end]
                } else {
                    &input[..end]
                };
                self.reg.copy_from_slice(&ct[end - BLOCK_SIZE..]);
                i = end;
                continue;
            }
            if self.pos == 0 {
                self.ks = ecb_encrypt_block(key, &self.reg)?;
            }
            output[i] = input[i] ^ self.ks[self.pos];
            self.blk[self.pos] = if self.encrypt { output[i] } else { input[i] };
            self.pos += 1;
            if self.pos == BLOCK_SIZE {
                self.reg = self.blk;
                self.pos = 0;
            }
            i += 1;
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
