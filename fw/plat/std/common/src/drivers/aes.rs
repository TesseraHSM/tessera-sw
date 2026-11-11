// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std AES driver — performs AES operations via OpenSSL.
//!
//! Takes raw key bytes and offloads AES encryption/decryption to the
//! [`WorkerPool`]. Exposes an async API that mirrors hardware AES engine
//! peripherals which yield while the engine processes data.
//!
//! ## Supported modes
//!
//! | Mode | Padding | IV required |
//! |------|---------|-------------|
//! | CBC  | None    | Yes (16 B)  |
//! | ECB  | None    | No          |
//! | CFB  | None    | Yes (16 B)  |
//! | OFB  | None    | Yes (16 B)  |
//! | CTR  | None    | Yes (16 B)  |
//!
//! ## Key sizes
//!
//! | Key length | Algorithm |
//! |------------|-----------|
//! | 16 bytes   | AES-128   |
//! | 24 bytes   | AES-192   |
//! | 32 bytes   | AES-256   |
//!
//! ## Thread model
//!
//! All methods copy inputs to owned buffers internally, dispatch the
//! OpenSSL cipher operation on the tokio worker pool, then write
//! results directly into the caller's `&mut [u8]` output buffers.

use tsra_crypto::AesCbcAlgo;
use tsra_crypto::AesCfbAlgo;
use tsra_crypto::AesCtrAlgo;
use tsra_crypto::AesEcbAlgo;
use tsra_crypto::AesGcmAlgo;
use tsra_crypto::AesKey;
use tsra_crypto::AesKeyWrapAlgo;
use tsra_crypto::AesKeyWrapPadAlgo;
use tsra_crypto::AesOfbAlgo;
use tsra_crypto::CryptoError;
use tsra_crypto::DecryptOp;
use tsra_crypto::EncryptOp;
use tsra_crypto::ImportableKey;
use tsra_crypto::Rng;
use tsra_fw_hsm_pal_traits::*;
use zeroize::Zeroizing;

use crate::worker::WorkerPool;

/// Std AES driver — software AES via OpenSSL with async worker dispatch.
///
/// Created once during PAL initialization and shared across all IO tasks.
pub struct StdAes {
    pool: WorkerPool,
}

impl StdAes {
    /// Create a new AES driver backed by the given worker pool.
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    /// Generate a random AES key asynchronously.
    ///
    /// # Parameters
    /// - `key` — Output buffer filled with random key material. Length
    ///   determines key size (16/24/32 bytes).
    ///
    /// # Errors
    /// Returns [`HsmError::AesGenerateError`] if the RNG fails.
    pub async fn gen_key(&self, key: &mut [u8]) -> HsmResult<()> {
        let len = key.len();
        let bytes = self
            .pool
            .submit_with_result(async move {
                let mut buf = vec![0u8; len];
                Rng::rand_bytes(&mut buf).map_err(|_| HsmError::AesGenerateError)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;
        key.copy_from_slice(&bytes);
        Ok(())
    }

    /// AES-CBC encrypt or decrypt asynchronously.
    ///
    /// No PKCS#7 padding — input must be block-aligned (multiple of 16).
    ///
    /// # Parameters
    /// - `key` — Raw AES key bytes (16, 24, or 32 bytes).
    /// - `encrypt` — `true` for encryption, `false` for decryption.
    /// - `iv` — 16-byte IV. Updated in-place to the last ciphertext
    ///   block after the operation (for CBC chaining).
    /// - `input` — Source data (must be block-aligned).
    /// - `output` — Destination buffer (must be ≥ `input.len()` bytes).
    ///
    /// # Errors
    /// - [`HsmError::AesEncryptFailed`] / [`HsmError::AesDecryptFailed`]
    /// - [`HsmError::AesInvalidKeyLength`]
    pub async fn cbc_enc_dec(
        &self,
        key: &[u8],
        encrypt: bool,
        iv: &mut [u8],
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        // `Zeroizing` scrubs this transient heap copy of the plaintext key
        // when the worker closure drops it.
        let key_owned = Zeroizing::new(key.to_vec());
        let iv_owned = iv.to_vec();
        let input_owned = input.to_vec();
        let input_len = input.len();

        let (result_data, updated_iv) = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&key_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesCbcAlgo::with_no_padding(&iv_owned);
                let mut buf = vec![0u8; input_len + 16];

                if encrypt {
                    let written = algo
                        .encrypt(&aes_key, &input_owned, Some(&mut buf))
                        .map_err(|_| HsmError::AesEncryptFailed)?;
                    buf.truncate(written);
                } else {
                    let written = algo
                        .decrypt(&aes_key, &input_owned, Some(&mut buf))
                        .map_err(|_| HsmError::AesDecryptFailed)?;
                    buf.truncate(written);
                }

                let new_iv = algo.iv().to_vec();
                Ok::<_, HsmError>((buf, new_iv))
            })
            .await?;

        output[..result_data.len()].copy_from_slice(&result_data);
        iv[..updated_iv.len()].copy_from_slice(&updated_iv);
        Ok(())
    }

    /// AES encrypt or decrypt in any [`HsmAesMode`] asynchronously.
    ///
    /// # Parameters
    /// - `key` — Raw AES key bytes (16, 24, or 32 bytes).
    /// - `encrypt` — `true` for encryption, `false` for decryption.
    /// - `mode` — Confidentiality mode.
    /// - `iv` — `mode.iv_len()` bytes of IV (empty for ECB).
    /// - `input` — Source data; block-aligned for ECB/CBC.
    ///
    /// # Returns
    /// The transformed data and the chaining IV (empty for ECB).
    ///
    /// # Errors
    /// - [`HsmError::AesEncryptFailed`] / [`HsmError::AesDecryptFailed`]
    /// - [`HsmError::AesInvalidKeyLength`]
    pub async fn enc_dec(
        &self,
        key: &[u8],
        encrypt: bool,
        mode: HsmAesMode,
        iv: &[u8],
        input: &[u8],
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        fn run<A>(
            algo: &mut A,
            key: &AesKey,
            encrypt: bool,
            input: &[u8],
        ) -> Result<Vec<u8>, CryptoError>
        where
            A: EncryptOp<Key = AesKey> + DecryptOp<Key = AesKey>,
        {
            // Block-mode backends require one spare block of output space.
            let mut buf = vec![0u8; input.len() + 16];
            let written = if encrypt {
                algo.encrypt(key, input, Some(&mut buf))?
            } else {
                algo.decrypt(key, input, Some(&mut buf))?
            };
            buf.truncate(written);
            Ok(buf)
        }

        let key_owned = Zeroizing::new(key.to_vec());
        let iv_owned = iv.to_vec();
        let input_owned = input.to_vec();

        self.pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&key_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let result = match mode {
                    HsmAesMode::Cbc => {
                        let mut algo = AesCbcAlgo::with_no_padding(&iv_owned);
                        run(&mut algo, &aes_key, encrypt, &input_owned)
                            .map(|data| (data, algo.iv().to_vec()))
                    }
                    HsmAesMode::Ecb => {
                        run(&mut AesEcbAlgo::default(), &aes_key, encrypt, &input_owned)
                            .map(|data| (data, Vec::new()))
                    }
                    HsmAesMode::Cfb => {
                        let mut algo = AesCfbAlgo::new(&iv_owned);
                        run(&mut algo, &aes_key, encrypt, &input_owned)
                            .map(|data| (data, algo.iv().to_vec()))
                    }
                    HsmAesMode::Ofb => {
                        let mut algo = AesOfbAlgo::new(&iv_owned);
                        run(&mut algo, &aes_key, encrypt, &input_owned)
                            .map(|data| (data, algo.iv().to_vec()))
                    }
                    HsmAesMode::Ctr => {
                        let mut algo = AesCtrAlgo::new(&iv_owned);
                        run(&mut algo, &aes_key, encrypt, &input_owned)
                            .map(|data| (data, algo.iv().to_vec()))
                    }
                };
                result.map_err(|_| {
                    if encrypt {
                        HsmError::AesEncryptFailed
                    } else {
                        HsmError::AesDecryptFailed
                    }
                })
            })
            .await
    }

    /// AES-ECB encrypt or decrypt asynchronously.
    ///
    /// No padding — input must be block-aligned (multiple of 16).
    ///
    /// # Parameters
    /// - `key` — Raw AES key bytes (16, 24, or 32 bytes).
    /// - `encrypt` — `true` for encryption, `false` for decryption.
    /// - `input` — Source data (must be block-aligned).
    /// - `output` — Destination buffer (must be ≥ `input.len()` bytes).
    ///
    /// # Errors
    /// - [`HsmError::AesEncryptFailed`] / [`HsmError::AesDecryptFailed`]
    /// - [`HsmError::AesInvalidKeyLength`]
    pub async fn ecb_enc_dec(
        &self,
        key: &[u8],
        encrypt: bool,
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        let key_owned = Zeroizing::new(key.to_vec());
        let input_owned = input.to_vec();
        let input_len = input.len();

        let result_data = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&key_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesEcbAlgo::default();
                let mut buf = vec![0u8; input_len + 16];

                if encrypt {
                    let written = algo
                        .encrypt(&aes_key, &input_owned, Some(&mut buf))
                        .map_err(|_| HsmError::AesEncryptFailed)?;
                    buf.truncate(written);
                } else {
                    let written = algo
                        .decrypt(&aes_key, &input_owned, Some(&mut buf))
                        .map_err(|_| HsmError::AesDecryptFailed)?;
                    buf.truncate(written);
                }

                Ok::<_, HsmError>(buf)
            })
            .await?;

        output[..result_data.len()].copy_from_slice(&result_data);
        Ok(())
    }

    /// AES-256-GCM encrypt asynchronously.
    ///
    /// # Parameters
    /// - `key` — Raw AES-256 key bytes (must be exactly 32 bytes).
    /// - `iv` — 12-byte nonce.
    /// - `aad` — Optional additional authenticated data.
    /// - `plaintext` — Source data (any length).
    /// - `ciphertext` — Destination buffer (must be ≥ `plaintext.len()`).
    /// - `tag` — Output buffer for the 16-byte authentication tag.
    pub async fn gcm_encrypt(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad: Option<&[u8]>,
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> HsmResult<()> {
        if key.len() != 32 {
            return Err(HsmError::AesInvalidKeyLength);
        }

        let key_owned = Zeroizing::new(key.to_vec());
        let iv_owned = *iv;
        let aad_owned = aad.map(|a| a.to_vec());
        let pt_owned = plaintext.to_vec();
        let pt_len = plaintext.len();

        let (result_data, result_tag) = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&key_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesGcmAlgo::for_encrypt(&iv_owned, aad_owned.as_deref())
                    .map_err(|_| HsmError::AesEncryptFailed)?;
                let mut buf = vec![0u8; pt_len];
                algo.encrypt(&aes_key, &pt_owned, Some(&mut buf))
                    .map_err(|_| HsmError::AesEncryptFailed)?;
                let tag_out: [u8; 16] = algo
                    .tag()
                    .try_into()
                    .map_err(|_| HsmError::AesEncryptFailed)?;
                Ok::<_, HsmError>((buf, tag_out))
            })
            .await?;

        ciphertext[..result_data.len()].copy_from_slice(&result_data);
        tag.copy_from_slice(&result_tag);
        Ok(())
    }

    /// AES-256-GCM decrypt asynchronously.
    ///
    /// # Parameters
    /// - `key` — Raw AES-256 key bytes (must be exactly 32 bytes).
    /// - `iv` — 12-byte nonce used during encryption.
    /// - `aad` — Optional additional authenticated data.
    /// - `tag` — The 16-byte authentication tag.
    /// - `ciphertext` — Source data (any length).
    /// - `plaintext` — Destination buffer (must be ≥ `ciphertext.len()`).
    pub async fn gcm_decrypt(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad: Option<&[u8]>,
        tag: &[u8; 16],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> HsmResult<()> {
        if key.len() != 32 {
            return Err(HsmError::AesInvalidKeyLength);
        }

        let key_owned = Zeroizing::new(key.to_vec());
        let iv_owned = *iv;
        let aad_owned = aad.map(|a| a.to_vec());
        let tag_owned = *tag;
        let ct_owned = ciphertext.to_vec();
        let ct_len = ciphertext.len();

        let result_data = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&key_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesGcmAlgo::for_decrypt(&iv_owned, &tag_owned, aad_owned.as_deref())
                    .map_err(|_| HsmError::AesDecryptFailed)?;
                let mut buf = vec![0u8; ct_len];
                algo.decrypt(&aes_key, &ct_owned, Some(&mut buf))
                    .map_err(|_| HsmError::AesGcmDecryptTagDoesNotMatch)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;

        plaintext[..result_data.len()].copy_from_slice(&result_data);
        Ok(())
    }

    /// AES-KW (RFC 3394) wrap asynchronously.
    ///
    /// Wraps `input` with the key-encryption key `kek` using
    /// [`AesKeyWrapAlgo`] with the default `0xA6A6…` IV.
    ///
    /// # Parameters
    /// - `kek` — key-encryption key (16, 24, or 32 bytes).
    /// - `input` — plaintext key material (`16..=`[`HSM_AES_KW_MAX_DATA_LEN`] bytes, a
    ///   multiple of 8).
    /// - `output` — destination; must hold at least `input.len() + 8`
    ///   bytes. `None` only validates and returns the wrapped length.
    ///
    /// # Returns
    /// - `Ok(input.len() + 8)` — the wrapped length.
    ///
    /// # Errors
    /// - [`HsmError::AesInvalidKeyLength`] — `kek` is not a valid AES
    ///   key length.
    /// - [`HsmError::InvalidArg`] — `input`/`output` size-constraint
    ///   violation.
    /// - [`HsmError::AesEncryptFailed`] — the wrapping operation failed.
    pub async fn kw_wrap(
        &self,
        kek: &[u8],
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        if input.len() < 16
            || !input.len().is_multiple_of(8)
            || input.len() > HSM_AES_KW_MAX_DATA_LEN
        {
            return Err(HsmError::InvalidArg);
        }
        let wrapped_len = input.len() + 8;
        if !matches!(kek.len(), 16 | 24 | 32) {
            return Err(HsmError::AesInvalidKeyLength);
        }
        let Some(output) = output else {
            return Ok(wrapped_len);
        };
        if output.len() < wrapped_len {
            return Err(HsmError::InvalidArg);
        }

        let kek_owned = Zeroizing::new(kek.to_vec());
        let input_owned = Zeroizing::new(input.to_vec());

        let result = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&kek_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesKeyWrapAlgo::with_default_iv();
                let mut buf = Zeroizing::new(vec![0u8; wrapped_len]);
                let written = algo
                    .encrypt(&aes_key, &input_owned, Some(&mut buf))
                    .map_err(|_| HsmError::AesEncryptFailed)?;
                buf.truncate(written);
                Ok::<_, HsmError>(buf)
            })
            .await?;

        output[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }

    /// AES-KW (RFC 3394) unwrap asynchronously.
    ///
    /// Unwraps `input` with the key-encryption key `kek`, verifying the
    /// default `0xA6A6…` IV.
    ///
    /// # Parameters
    /// - `kek` — key-encryption key (16, 24, or 32 bytes).
    /// - `input` — wrapped key material (`24..=`[`HSM_AES_KW_MAX_DATA_LEN`]` + 8` bytes,
    ///   a multiple of 8).
    /// - `output` — destination; must hold at least `input.len() - 8`
    ///   bytes. `None` only validates and returns the unwrapped length.
    ///
    /// # Returns
    /// - `Ok(input.len() - 8)` — the unwrapped length.
    ///
    /// # Errors
    /// - [`HsmError::AesInvalidKeyLength`] — `kek` is not a valid AES
    ///   key length.
    /// - [`HsmError::InvalidArg`] — `input`/`output` size-constraint
    ///   violation.
    /// - [`HsmError::AesUnwrapFailed`] — IV integrity check failed.
    pub async fn kw_unwrap(
        &self,
        kek: &[u8],
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        if input.len() < 24
            || !input.len().is_multiple_of(8)
            || input.len() > HSM_AES_KW_MAX_DATA_LEN + 8
        {
            return Err(HsmError::InvalidArg);
        }
        let unwrapped_len = input.len() - 8;
        if !matches!(kek.len(), 16 | 24 | 32) {
            return Err(HsmError::AesInvalidKeyLength);
        }
        let Some(output) = output else {
            return Ok(unwrapped_len);
        };
        if output.len() < unwrapped_len {
            return Err(HsmError::InvalidArg);
        }

        let kek_owned = Zeroizing::new(kek.to_vec());
        let input_owned = input.to_vec();

        let result = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&kek_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesKeyWrapAlgo::with_default_iv();
                let mut buf = Zeroizing::new(vec![0u8; unwrapped_len]);
                // Size is pre-validated above, so a failure here is an IV
                // integrity failure.
                algo.decrypt(&aes_key, &input_owned, Some(&mut buf))
                    .map_err(|_| HsmError::AesUnwrapFailed)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;

        output[..unwrapped_len].copy_from_slice(&result);
        Ok(unwrapped_len)
    }

    /// AES-KWP (RFC 5649) wrap asynchronously.
    ///
    /// Wraps `input` with the key-encryption key `kek` using
    /// [`AesKeyWrapPadAlgo`] (the same `tsra_crypto` primitive as
    /// [`kwp_unwrap`](Self::kwp_unwrap)) and writes the wrapped output.
    /// Byte-oriented — no endianness conversion.
    ///
    /// # Parameters
    /// - `kek` — key-encryption key (16, 24, or 32 bytes).
    /// - `input` — plaintext key material (`1..=`[`HSM_AES_KW_MAX_DATA_LEN`] bytes, any
    ///   length).
    /// - `output` — destination; must hold at least
    ///   `round_up_8(input.len()) + 8` bytes. `None` only validates and
    ///   returns the wrapped length.
    ///
    /// # Returns
    /// - `Ok(round_up_8(input.len()) + 8)` — the wrapped length.
    ///
    /// # Errors
    /// - [`HsmError::AesInvalidKeyLength`] — `kek` is not a valid AES
    ///   key length.
    /// - [`HsmError::InvalidArg`] — `input`/`output` size-constraint
    ///   violation (`input` must be `1..=HSM_AES_KW_MAX_DATA_LEN`; `output` must hold at
    ///   least `round_up_8(input.len()) + 8` bytes).
    /// - [`HsmError::AesEncryptFailed`] — the wrapping operation failed.
    pub async fn kwp_wrap(
        &self,
        kek: &[u8],
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        // RFC 5649 size constraints (per the `aes_kwp_wrap` trait
        // contract): the plaintext is 1..=HSM_AES_KW_MAX_DATA_LEN bytes and the output holds
        // at least `round_up_8(input.len()) + 8` bytes.  Violations are
        // `InvalidArg`, matching the hardware PAL.
        if input.is_empty() || input.len() > HSM_AES_KW_MAX_DATA_LEN {
            return Err(HsmError::InvalidArg);
        }
        let wrapped_len = input.len().next_multiple_of(8) + 8;
        if !matches!(kek.len(), 16 | 24 | 32) {
            return Err(HsmError::AesInvalidKeyLength);
        }
        let Some(output) = output else {
            return Ok(wrapped_len);
        };
        if output.len() < wrapped_len {
            return Err(HsmError::InvalidArg);
        }

        let kek_owned = kek.to_vec();
        let input_owned = input.to_vec();

        let result = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&kek_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesKeyWrapPadAlgo::default();
                let mut buf = vec![0u8; wrapped_len];
                let written = algo
                    .encrypt(&aes_key, &input_owned, Some(&mut buf))
                    .map_err(|_| HsmError::AesEncryptFailed)?;
                buf.truncate(written);
                Ok::<_, HsmError>(buf)
            })
            .await?;

        output[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }

    /// AES-KWP (RFC 5649) unwrap asynchronously.
    ///
    /// Unwraps `input` with the key-encryption key `kek`, verifying the
    /// RFC 5649 AIV and padding, and writes the recovered key material
    /// into `output`.  Byte-oriented — no endianness conversion.
    ///
    /// # Parameters
    /// - `kek` — key-encryption key (16, 24, or 32 bytes).
    /// - `input` — wrapped key material (multiple of 8 bytes, `>= 16`).
    /// - `output` — destination for the unwrapped key material. `None`
    ///   only validates and returns the maximum unwrapped length,
    ///   `input.len() - 8`.
    ///
    /// # Returns
    /// - `Ok(len)` — unwrapped plaintext length; `output[..len]` valid.
    ///
    /// # Errors
    /// - [`HsmError::AesInvalidKeyLength`] — `kek` is not a valid AES
    ///   key length.
    /// - [`HsmError::InvalidArg`] — `input`/`output` size-constraint
    ///   violation (RFC 5649: `input` must be >= 16 bytes, a multiple of 8,
    ///   and <= `HSM_AES_KW_MAX_DATA_LEN + 8`; `output` must hold at least `input.len() - 8` bytes).
    /// - [`HsmError::AesUnwrapFailed`] — AIV/padding integrity check failed
    ///   (wrong key, tampering, or corruption).
    pub async fn kwp_unwrap(
        &self,
        kek: &[u8],
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        // RFC 5649 size constraints (per the `aes_kwp_unwrap` trait
        // contract): the wrapped input is >= 16 bytes, a multiple of 8, and
        // at most `HSM_AES_KW_MAX_DATA_LEN + 8` (the 8-aligned max plaintext
        // plus the 8-byte AIV); the output holds at least `input.len() - 8`
        // bytes.  Violations are `InvalidArg` — distinct from an integrity
        // failure — matching the hardware PAL.
        if input.len() < 16
            || !input.len().is_multiple_of(8)
            || input.len() > HSM_AES_KW_MAX_DATA_LEN + 8
        {
            return Err(HsmError::InvalidArg);
        }
        if !matches!(kek.len(), 16 | 24 | 32) {
            return Err(HsmError::AesInvalidKeyLength);
        }
        let Some(output) = output else {
            return Ok(input.len() - 8);
        };
        if output.len() < input.len() - 8 {
            return Err(HsmError::InvalidArg);
        }

        let kek_owned = kek.to_vec();
        let input_owned = input.to_vec();
        let out_len = output.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let aes_key =
                    AesKey::from_bytes(&kek_owned).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut algo = AesKeyWrapPadAlgo::default();
                let mut buf = vec![0u8; out_len];
                // Size is pre-validated above, so a failure here is an
                // AIV / padding integrity failure.
                let written = algo
                    .decrypt(&aes_key, &input_owned, Some(&mut buf))
                    .map_err(|_| HsmError::AesUnwrapFailed)?;
                buf.truncate(written);
                Ok::<_, HsmError>(buf)
            })
            .await?;

        output[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }

    /// AES-XTS encrypt or decrypt in place.
    ///
    /// IEEE 1619 XTS built on AES-ECB, since `dul` is block-aligned and
    /// needs no ciphertext stealing. `tweak` is the full 128-bit
    /// little-endian data unit number of the first `dul` bytes and
    /// increments by one per data unit.
    ///
    /// # Parameters
    /// - `key1` — data key (32 bytes).
    /// - `key2` — tweak key (32 bytes).
    /// - `encrypt` — `true` for encryption, `false` for decryption.
    /// - `tweak` — initial tweak.
    /// - `dul` — data unit length; a non-zero multiple of 16 dividing
    ///   `data.len()`.
    /// - `data` — the data, replaced by the result.
    ///
    /// # Errors
    /// - [`HsmError::AesXtsInvalidDul`] — bad `dul`.
    /// - [`HsmError::AesInvalidKeyLength`] — bad key length.
    /// - [`HsmError::AesEncryptFailed`] / [`HsmError::AesDecryptFailed`] —
    ///   AES failure (including 128-bit tweak overflow).
    pub async fn xts_crypt(
        &self,
        key1: &[u8],
        key2: &[u8],
        encrypt: bool,
        tweak: [u8; 16],
        dul: usize,
        data: &mut [u8],
    ) -> HsmResult<()> {
        if dul == 0 || !dul.is_multiple_of(16) || !data.len().is_multiple_of(dul) {
            return Err(HsmError::AesXtsInvalidDul);
        }
        if key1.len() != 32 || key2.len() != 32 {
            return Err(HsmError::AesInvalidKeyLength);
        }

        let key1 = Zeroizing::new(key1.to_vec());
        let key2 = Zeroizing::new(key2.to_vec());
        let mut buf = Zeroizing::new(data.to_vec());

        let result = self
            .pool
            .submit_with_result(async move {
                let err = if encrypt {
                    HsmError::AesEncryptFailed
                } else {
                    HsmError::AesDecryptFailed
                };
                let data_key =
                    AesKey::from_bytes(&key1).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let tweak_key =
                    AesKey::from_bytes(&key2).map_err(|_| HsmError::AesInvalidKeyLength)?;
                let mut masks = Zeroizing::new(vec![0u8; dul]);
                let mut out = Zeroizing::new(vec![0u8; dul + 16]);
                let first = u128::from_le_bytes(tweak);

                for (i, unit) in buf.chunks_mut(dul).enumerate() {
                    let unit_tweak = u128::try_from(i)
                        .ok()
                        .and_then(|i| first.checked_add(i))
                        .ok_or(err)?;
                    AesEcbAlgo::default()
                        .encrypt(&tweak_key, &unit_tweak.to_le_bytes(), Some(&mut out))
                        .map_err(|_| err)?;
                    let mut t = u128::from_le_bytes(out[..16].try_into().map_err(|_| err)?);
                    for mask in masks.chunks_exact_mut(16) {
                        mask.copy_from_slice(&t.to_le_bytes());
                        // Multiply by alpha in GF(2^128) (IEEE 1619).
                        t = (t << 1) ^ ((t >> 127) * 0x87);
                    }

                    unit.iter_mut().zip(masks.iter()).for_each(|(b, m)| *b ^= m);
                    let mut algo = AesEcbAlgo::default();
                    let n = if encrypt {
                        algo.encrypt(&data_key, unit, Some(&mut out))
                    } else {
                        algo.decrypt(&data_key, unit, Some(&mut out))
                    }
                    .map_err(|_| err)?;
                    if n != dul {
                        return Err(err);
                    }
                    unit.iter_mut()
                        .zip(out.iter().zip(masks.iter()))
                        .for_each(|(b, (o, m))| *b = o ^ m);
                }
                Ok::<_, HsmError>(buf)
            })
            .await?;

        data.copy_from_slice(&result);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;
    use tsra_crypto::AesXtsAlgo;
    use tsra_crypto::AesXtsKey;

    use super::*;

    fn make_driver() -> StdAes {
        StdAes::new(WorkerPool::new(Handle::current()))
    }

    // ── AES-XTS ─────────────────────────────────────────────────

    #[tokio::test]
    async fn xts_increments_tweak_per_unit_and_round_trips() {
        let driver = make_driver();
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let plaintext: Vec<u8> = (0..1024u32).map(|i| i as u8).collect();
        let tweak = 0xFFFF_FFFEu64;

        let mut whole = plaintext.clone();
        let t = u128::from(tweak).to_le_bytes();
        driver
            .xts_crypt(&key1, &key2, true, t, 512, &mut whole)
            .await
            .unwrap();
        assert_ne!(whole, plaintext);

        for (i, unit) in plaintext.chunks(512).enumerate() {
            let mut one = unit.to_vec();
            let t = u128::from(tweak + i as u64).to_le_bytes();
            driver
                .xts_crypt(&key1, &key2, true, t, 512, &mut one)
                .await
                .unwrap();
            assert_eq!(one, whole[i * 512..(i + 1) * 512]);
        }

        driver
            .xts_crypt(&key1, &key2, false, t, 512, &mut whole)
            .await
            .unwrap();
        assert_eq!(whole, plaintext);
    }

    #[tokio::test]
    async fn xts_rejects_bad_dul_and_uses_full_tweak() {
        let driver = make_driver();
        let k = [0x33u8; 32];
        let k2 = [0x44u8; 32];
        let mut data = vec![0u8; 64];
        for dul in [0usize, 24, 48] {
            assert_eq!(
                driver
                    .xts_crypt(&k, &k2, true, [0; 16], dul, &mut data)
                    .await,
                Err(HsmError::AesXtsInvalidDul)
            );
        }
        let mut low = [0u8; 16];
        low[0] = 7;
        let mut high = low;
        high[8] = 1;
        let mut a = data.clone();
        let mut b = data.clone();
        driver
            .xts_crypt(&k, &k2, true, low, 32, &mut a)
            .await
            .unwrap();
        driver
            .xts_crypt(&k, &k2, true, high, 32, &mut b)
            .await
            .unwrap();
        assert_ne!(a, b);

        // Low 64-bit tweaks match the reference XTS implementation.
        let mut key = k.to_vec();
        key.extend_from_slice(&k2);
        let mut expected = vec![0u8; data.len() + 16];
        let n = AesXtsAlgo::new(&low[..8], 32)
            .unwrap()
            .encrypt(
                &AesXtsKey::from_bytes(&key).unwrap(),
                &data,
                Some(&mut expected),
            )
            .unwrap();
        assert_eq!(a, expected[..n]);

        let mut max = [0xffu8; 16];
        assert_eq!(
            driver.xts_crypt(&k, &k2, true, max, 32, &mut data).await,
            Err(HsmError::AesEncryptFailed)
        );
        max[0] = 0xfe;
        let mut one_unit = vec![0u8; 32];
        driver
            .xts_crypt(&k, &k2, true, max, 32, &mut one_unit)
            .await
            .unwrap();
    }

    // ── Key generation ──────────────────────────────────────────

    #[tokio::test]
    async fn gen_key_128() {
        let driver = make_driver();
        let mut key = [0u8; 16];
        driver.gen_key(&mut key).await.unwrap();
        assert_ne!(key, [0u8; 16]);
    }

    #[tokio::test]
    async fn gen_key_192() {
        let driver = make_driver();
        let mut key = [0u8; 24];
        driver.gen_key(&mut key).await.unwrap();
        assert_ne!(key, [0u8; 24]);
    }

    #[tokio::test]
    async fn gen_key_256() {
        let driver = make_driver();
        let mut key = [0u8; 32];
        driver.gen_key(&mut key).await.unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    // ── CBC roundtrip (all key sizes) ───────────────────────────

    #[tokio::test]
    async fn cbc_roundtrip_128() {
        let driver = make_driver();
        let key = [0x42u8; 16];
        let plaintext = [0xABu8; 32];
        let orig_iv = [0u8; 16];

        let mut ct = [0u8; 32];
        let mut iv = orig_iv;
        driver
            .cbc_enc_dec(&key, true, &mut iv, &plaintext, &mut ct)
            .await
            .unwrap();
        assert_ne!(ct, plaintext);

        let mut pt = [0u8; 32];
        iv = orig_iv;
        driver
            .cbc_enc_dec(&key, false, &mut iv, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn cbc_roundtrip_192() {
        let driver = make_driver();
        let key = [0x55u8; 24];
        let plaintext = [0xCDu8; 48]; // 3 blocks
        let orig_iv = [0x01u8; 16];

        let mut ct = [0u8; 48];
        let mut iv = orig_iv;
        driver
            .cbc_enc_dec(&key, true, &mut iv, &plaintext, &mut ct)
            .await
            .unwrap();

        let mut pt = [0u8; 48];
        iv = orig_iv;
        driver
            .cbc_enc_dec(&key, false, &mut iv, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn cbc_roundtrip_256() {
        let driver = make_driver();
        let key = [0x77u8; 32];
        let plaintext = [0xEFu8; 64]; // 4 blocks
        let orig_iv = [0x02u8; 16];

        let mut ct = [0u8; 64];
        let mut iv = orig_iv;
        driver
            .cbc_enc_dec(&key, true, &mut iv, &plaintext, &mut ct)
            .await
            .unwrap();

        let mut pt = [0u8; 64];
        iv = orig_iv;
        driver
            .cbc_enc_dec(&key, false, &mut iv, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    // ── CBC NIST vectors (NIST SP 800-38A) ──────────────────────

    /// NIST SP 800-38A F.2.1 — AES-128-CBC Encrypt.
    #[tokio::test]
    async fn cbc_nist_128() {
        let driver = make_driver();
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let mut iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut ct = [0u8; 16];
        driver
            .cbc_enc_dec(&key, true, &mut iv, &pt, &mut ct)
            .await
            .unwrap();
        assert_eq!(hex::encode(ct), "7649abac8119b246cee98e9b12e9197d");
    }

    /// NIST SP 800-38A F.2.3 — AES-192-CBC Encrypt.
    #[tokio::test]
    async fn cbc_nist_192() {
        let driver = make_driver();
        let key = hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
        let mut iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut ct = [0u8; 16];
        driver
            .cbc_enc_dec(&key, true, &mut iv, &pt, &mut ct)
            .await
            .unwrap();
        assert_eq!(hex::encode(ct), "4f021db243bc633d7178183a9fa071e8");
    }

    /// NIST SP 800-38A F.2.5 — AES-256-CBC Encrypt.
    #[tokio::test]
    async fn cbc_nist_256() {
        let driver = make_driver();
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let mut iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut ct = [0u8; 16];
        driver
            .cbc_enc_dec(&key, true, &mut iv, &pt, &mut ct)
            .await
            .unwrap();
        assert_eq!(hex::encode(ct), "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
    }

    // ── ECB roundtrip (all key sizes) ───────────────────────────

    #[tokio::test]
    async fn ecb_roundtrip_128() {
        let driver = make_driver();
        let key = [0x33u8; 16];
        let plaintext = [0xAAu8; 16];
        let mut ct = [0u8; 16];
        driver
            .ecb_enc_dec(&key, true, &plaintext, &mut ct)
            .await
            .unwrap();
        let mut pt = [0u8; 16];
        driver.ecb_enc_dec(&key, false, &ct, &mut pt).await.unwrap();
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn ecb_roundtrip_192() {
        let driver = make_driver();
        let key = [0x44u8; 24];
        let plaintext = [0xBBu8; 32]; // 2 blocks
        let mut ct = [0u8; 32];
        driver
            .ecb_enc_dec(&key, true, &plaintext, &mut ct)
            .await
            .unwrap();
        let mut pt = [0u8; 32];
        driver.ecb_enc_dec(&key, false, &ct, &mut pt).await.unwrap();
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn ecb_roundtrip_256() {
        let driver = make_driver();
        let key = [0x66u8; 32];
        let plaintext = [0xCCu8; 48]; // 3 blocks
        let mut ct = [0u8; 48];
        driver
            .ecb_enc_dec(&key, true, &plaintext, &mut ct)
            .await
            .unwrap();
        let mut pt = [0u8; 48];
        driver.ecb_enc_dec(&key, false, &ct, &mut pt).await.unwrap();
        assert_eq!(pt, plaintext);
    }

    // ── ECB NIST vectors (NIST SP 800-38A) ──────────────────────

    /// NIST AESAVS ECBGFSbox128 — AES-128-ECB.
    #[tokio::test]
    async fn ecb_nist_128() {
        let driver = make_driver();
        let key = hex::decode("00000000000000000000000000000000").unwrap();
        let pt = hex::decode("f34481ec3cc627bacd5dc3fb08f273e6").unwrap();
        let mut ct = [0u8; 16];
        driver.ecb_enc_dec(&key, true, &pt, &mut ct).await.unwrap();
        assert_eq!(hex::encode(ct), "0336763e966d92595a567cc9ce537f5e");
    }

    /// NIST SP 800-38A F.1.3 — AES-192-ECB Encrypt.
    #[tokio::test]
    async fn ecb_nist_192() {
        let driver = make_driver();
        let key = hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut ct = [0u8; 16];
        driver.ecb_enc_dec(&key, true, &pt, &mut ct).await.unwrap();
        assert_eq!(hex::encode(ct), "bd334f1d6e45f25ff712a214571fa5cc");
    }

    /// NIST SP 800-38A F.1.5 — AES-256-ECB Encrypt.
    #[tokio::test]
    async fn ecb_nist_256() {
        let driver = make_driver();
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let mut ct = [0u8; 16];
        driver.ecb_enc_dec(&key, true, &pt, &mut ct).await.unwrap();
        assert_eq!(hex::encode(ct), "f3eed1bdb5d2a03c064b5a7e3db181f8");
    }

    // ── GCM roundtrip (AES-256 only) ──────────────────────────────

    #[tokio::test]
    async fn gcm_roundtrip_256() {
        let driver = make_driver();
        let key = [0x77u8; 32];
        let iv = [0x03u8; 12];
        let plaintext = [0xEFu8; 64];

        let mut ct = [0u8; 64];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, None, &plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        let mut pt = [0u8; 64];
        driver
            .gcm_decrypt(&key, &iv, None, &tag, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    // ── GCM rejects non-256-bit keys ──────────────────────────────

    #[tokio::test]
    async fn gcm_rejects_128_bit_key() {
        let driver = make_driver();
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];
        let mut ct = [0u8; 16];
        let mut tag = [0u8; 16];
        let result = driver
            .gcm_encrypt(&key, &iv, None, &[0u8; 16], &mut ct, &mut tag)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn gcm_rejects_192_bit_key() {
        let driver = make_driver();
        let key = [0x42u8; 24];
        let iv = [0x01u8; 12];
        let mut ct = [0u8; 16];
        let mut tag = [0u8; 16];
        let result = driver
            .gcm_encrypt(&key, &iv, None, &[0u8; 16], &mut ct, &mut tag)
            .await;
        assert!(result.is_err());
    }

    // ── GCM with AAD ────────────────────────────────────────────

    #[tokio::test]
    async fn gcm_roundtrip_with_aad() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x04u8; 12];
        let aad = b"authenticated header";
        let plaintext = b"secret payload data";

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, Some(aad), plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        let mut pt = vec![0u8; plaintext.len()];
        driver
            .gcm_decrypt(&key, &iv, Some(aad), &tag, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(&pt, plaintext);
    }

    #[tokio::test]
    async fn gcm_wrong_aad_fails() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x05u8; 12];
        let aad = b"correct header";
        let plaintext = b"payload";

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, Some(aad), plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        let mut pt = vec![0u8; plaintext.len()];
        let result = driver
            .gcm_decrypt(&key, &iv, Some(b"wrong header"), &tag, &ct, &mut pt)
            .await;
        assert_eq!(result.unwrap_err(), HsmError::AesGcmDecryptTagDoesNotMatch);
    }

    // ── GCM tag tamper detection ────────────────────────────────

    #[tokio::test]
    async fn gcm_tampered_tag_fails() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x06u8; 12];
        let plaintext = b"tamper test";

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, None, plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        tag[0] ^= 0xFF; // tamper
        let mut pt = vec![0u8; plaintext.len()];
        let result = driver
            .gcm_decrypt(&key, &iv, None, &tag, &ct, &mut pt)
            .await;
        assert_eq!(result.unwrap_err(), HsmError::AesGcmDecryptTagDoesNotMatch);
    }

    #[tokio::test]
    async fn gcm_tampered_ciphertext_fails() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x07u8; 12];
        let plaintext = b"tamper ct test!!";

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, None, plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        ct[0] ^= 0xFF; // tamper
        let mut pt = vec![0u8; plaintext.len()];
        let result = driver
            .gcm_decrypt(&key, &iv, None, &tag, &ct, &mut pt)
            .await;
        assert_eq!(result.unwrap_err(), HsmError::AesGcmDecryptTagDoesNotMatch);
    }

    // ── GCM empty plaintext ─────────────────────────────────────

    #[tokio::test]
    async fn gcm_empty_plaintext() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x08u8; 12];
        let aad = b"auth only, no payload";

        let mut ct = [];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, Some(aad), &[], &mut ct, &mut tag)
            .await
            .unwrap();

        let mut pt = [];
        driver
            .gcm_decrypt(&key, &iv, Some(aad), &tag, &[], &mut pt)
            .await
            .unwrap();
    }

    // ── GCM non-block-aligned data ──────────────────────────────

    #[tokio::test]
    async fn gcm_non_block_aligned() {
        let driver = make_driver();
        let key = [0x42u8; 32];
        let iv = [0x09u8; 12];
        let plaintext = b"7 bytes"; // not a multiple of 16

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, None, plaintext, &mut ct, &mut tag)
            .await
            .unwrap();

        let mut pt = vec![0u8; plaintext.len()];
        driver
            .gcm_decrypt(&key, &iv, None, &tag, &ct, &mut pt)
            .await
            .unwrap();
        assert_eq!(&pt, plaintext);
    }

    // ── GCM NIST test vector ────────────────────────────────────

    /// NIST GCM test vector — AES-256-GCM (from NIST SP 800-38D).
    /// Test Case 16: key=256, pt=256, aad=256, iv=96, tag=128.
    #[tokio::test]
    async fn gcm_nist_256() {
        let driver = make_driver();
        let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .unwrap();
        let iv_vec = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let iv: [u8; 12] = iv_vec.try_into().unwrap();
        let pt = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .unwrap();
        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();

        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; 16];
        driver
            .gcm_encrypt(&key, &iv, Some(&aad), &pt, &mut ct, &mut tag)
            .await
            .unwrap();

        let expected_ct = hex::decode(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        )
        .unwrap();
        let expected_tag = hex::decode("76fc6ece0f4e1768cddf8853bb2d551b").unwrap();

        assert_eq!(ct, expected_ct);
        assert_eq!(&tag[..], &expected_tag[..]);

        // Verify decrypt produces original plaintext
        let mut dec_pt = vec![0u8; ct.len()];
        driver
            .gcm_decrypt(&key, &iv, Some(&aad), &tag, &ct, &mut dec_pt)
            .await
            .unwrap();
        assert_eq!(dec_pt, pt);
    }

    // ── AES-KWP unwrap (RFC 5649) round-trip ────────────────────

    #[tokio::test]
    async fn kwp_unwrap_roundtrip() {
        let driver = make_driver();
        let kek = [0x42u8; 32]; // AES-256 KEK

        // Wrap a representative payload whose length is not a multiple of
        // 8 (47 bytes), so RFC 5649 pads it to the next 8-byte boundary
        // (exercising the padding / unpadding path).
        let payload: Vec<u8> = (0..47u8).collect();
        let mut wrapped = vec![0u8; payload.len() + 16];
        let wrapped_len = {
            let kek_key = AesKey::from_bytes(&kek).unwrap();
            let mut algo = AesKeyWrapPadAlgo::default();
            algo.encrypt(&kek_key, &payload, Some(&mut wrapped))
                .unwrap()
        };
        wrapped.truncate(wrapped_len);

        let mut out = vec![0u8; payload.len() + 8];
        let len = driver
            .kwp_unwrap(&kek, &wrapped, Some(&mut out))
            .await
            .unwrap();
        assert_eq!(&out[..len], &payload[..]);
    }

    #[tokio::test]
    async fn kwp_unwrap_tamper_fails() {
        let driver = make_driver();
        let kek = [0x42u8; 32];

        let payload: Vec<u8> = (0..32u8).collect();
        let mut wrapped = vec![0u8; payload.len() + 16];
        let wrapped_len = {
            let kek_key = AesKey::from_bytes(&kek).unwrap();
            let mut algo = AesKeyWrapPadAlgo::default();
            algo.encrypt(&kek_key, &payload, Some(&mut wrapped))
                .unwrap()
        };
        wrapped.truncate(wrapped_len);
        wrapped[0] ^= 0xff; // corrupt the AIV → integrity check must fail

        let mut out = vec![0u8; payload.len() + 8];
        let res = driver.kwp_unwrap(&kek, &wrapped, Some(&mut out)).await;
        assert_eq!(res.unwrap_err(), HsmError::AesUnwrapFailed);
    }

    #[tokio::test]
    async fn kwp_unwrap_rejects_bad_sizes() {
        let driver = make_driver();
        let kek = [0x42u8; 32];
        // Large enough for every case below, so only the input size fails.
        let mut out = vec![0u8; HSM_AES_KW_MAX_DATA_LEN + 16];

        // Too short (< 16 bytes).
        let short = [0u8; 8];
        assert_eq!(
            driver
                .kwp_unwrap(&kek, &short, Some(&mut out))
                .await
                .unwrap_err(),
            HsmError::InvalidArg
        );

        // Not a multiple of 8.
        let unaligned = [0u8; 20];
        assert_eq!(
            driver
                .kwp_unwrap(&kek, &unaligned, Some(&mut out))
                .await
                .unwrap_err(),
            HsmError::InvalidArg
        );

        // Larger than the maximum wrapped length.
        let oversized = vec![0u8; HSM_AES_KW_MAX_DATA_LEN + 16];
        assert_eq!(
            driver
                .kwp_unwrap(&kek, &oversized, Some(&mut out))
                .await
                .unwrap_err(),
            HsmError::InvalidArg
        );

        // Output too small (< input.len() - 8).
        let input = [0u8; 24];
        let mut tiny = vec![0u8; 8];
        assert_eq!(
            driver
                .kwp_unwrap(&kek, &input, Some(&mut tiny))
                .await
                .unwrap_err(),
            HsmError::InvalidArg
        );
    }

    // ── AES-KWP wrap (RFC 5649) round-trip ──────────────────────

    #[tokio::test]
    async fn kwp_wrap_roundtrip() {
        let driver = make_driver();
        let kek = [0x42u8; 32]; // AES-256 KEK

        // Payload length not a multiple of 8 (47 bytes), so RFC 5649 pads
        // it to the next 8-byte boundary (exercises the padding path).
        let payload: Vec<u8> = (0..47u8).collect();
        let wrapped_len = payload.len().next_multiple_of(8) + 8;

        let mut wrapped = vec![0u8; wrapped_len];
        driver
            .kwp_wrap(&kek, &payload, Some(&mut wrapped))
            .await
            .unwrap();

        // The wrap must be recoverable by the corresponding unwrap.
        let mut out = vec![0u8; payload.len() + 8];
        let len = driver
            .kwp_unwrap(&kek, &wrapped, Some(&mut out))
            .await
            .unwrap();
        assert_eq!(&out[..len], &payload[..]);
    }

    #[tokio::test]
    async fn kw_and_kwp_roundtrip_max_len() {
        let driver = make_driver();
        let kek = [0x42u8; 32];
        let payload: Vec<u8> = (0..HSM_AES_KW_MAX_DATA_LEN).map(|i| i as u8).collect();
        let mut wrapped = vec![0u8; HSM_AES_KW_MAX_DATA_LEN + 8];
        let mut out = vec![0u8; HSM_AES_KW_MAX_DATA_LEN];

        assert_eq!(
            driver.kw_wrap(&kek, &payload, Some(&mut wrapped)).await,
            Ok(wrapped.len())
        );
        assert_eq!(
            driver.kw_unwrap(&kek, &wrapped, Some(&mut out)).await,
            Ok(payload.len())
        );
        assert_eq!(out, payload);

        assert_eq!(
            driver.kwp_wrap(&kek, &payload, Some(&mut wrapped)).await,
            Ok(wrapped.len())
        );
        assert_eq!(
            driver.kwp_unwrap(&kek, &wrapped, Some(&mut out)).await,
            Ok(payload.len())
        );
        assert_eq!(out, payload);
    }

    #[tokio::test]
    async fn kwp_query_returns_lengths() {
        let driver = make_driver();
        let kek = [0x42u8; 32];
        let payload: Vec<u8> = (0..47u8).collect();

        let wrapped_len = driver.kwp_wrap(&kek, &payload, None).await.unwrap();
        assert_eq!(wrapped_len, 56);
        let mut wrapped = vec![0u8; wrapped_len];
        assert_eq!(
            driver
                .kwp_wrap(&kek, &payload, Some(&mut wrapped))
                .await
                .unwrap(),
            wrapped_len
        );

        // The unwrap query is the upper bound `input.len() - 8`; the real
        // unwrap returns the exact MLI.
        let max_len = driver.kwp_unwrap(&kek, &wrapped, None).await.unwrap();
        assert_eq!(max_len, 48);
        let mut out = vec![0u8; max_len];
        assert_eq!(
            driver
                .kwp_unwrap(&kek, &wrapped, Some(&mut out))
                .await
                .unwrap(),
            payload.len()
        );

        // Queries still validate input sizes.
        assert_eq!(
            driver.kwp_wrap(&kek, &[], None).await.unwrap_err(),
            HsmError::InvalidArg
        );
        assert_eq!(
            driver.kwp_unwrap(&kek, &[0u8; 20], None).await.unwrap_err(),
            HsmError::InvalidArg
        );
    }

    #[tokio::test]
    async fn kwp_wrap_rejects_bad_sizes() {
        let driver = make_driver();
        let kek = [0x42u8; 32];

        // Empty input.
        let mut out = vec![0u8; 32];
        assert_eq!(
            driver
                .kwp_wrap(&kek, &[], Some(&mut out))
                .await
                .unwrap_err(),
            HsmError::InvalidArg
        );

        // Larger than the maximum plaintext.
        let oversized = vec![0u8; HSM_AES_KW_MAX_DATA_LEN + 1];
        let mut big = vec![0u8; HSM_AES_KW_MAX_DATA_LEN + 1 + 16];
        assert_eq!(
            driver
                .kwp_wrap(&kek, &oversized, Some(&mut big))
                .await
                .unwrap_err(),
            HsmError::InvalidArg
        );

        // Output too small (< round_up_8(input.len()) + 8).
        let input = [0u8; 24];
        let mut tiny = vec![0u8; 24];
        assert_eq!(
            driver
                .kwp_wrap(&kek, &input, Some(&mut tiny))
                .await
                .unwrap_err(),
            HsmError::InvalidArg
        );
    }

    #[tokio::test]
    async fn kwp_wrap_rejects_bad_kek() {
        let driver = make_driver();
        let bad_kek = [0x42u8; 20]; // not a valid AES key length

        let payload = [0u8; 16];
        let mut out = vec![0u8; 32];
        assert_eq!(
            driver
                .kwp_wrap(&bad_kek, &payload, Some(&mut out))
                .await
                .unwrap_err(),
            HsmError::AesInvalidKeyLength
        );
    }

    #[tokio::test]
    async fn kw_kwp_queries_reject_bad_kek() {
        let driver = make_driver();
        let bad_kek = [0x42u8; 15];
        let data = [0u8; 16];
        let wrapped = [0u8; 24];
        for err in [
            driver.kw_wrap(&bad_kek, &data, None).await,
            driver.kw_unwrap(&bad_kek, &wrapped, None).await,
            driver.kwp_wrap(&bad_kek, &data, None).await,
            driver.kwp_unwrap(&bad_kek, &wrapped, None).await,
        ] {
            assert_eq!(err.unwrap_err(), HsmError::AesInvalidKeyLength);
        }
    }
}
