// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_api::*;

use super::*;
use crate::HANDLE_TABLE;
use crate::TsraBuffer;
use crate::TsraHandle;
use crate::TsraStatus;
use crate::handle_table::HandleType;
use crate::utils::*;

impl TryFrom<&TsraAlgo> for HsmRsaKeyUnwrappingKeyGenAlgo {
    type Error = TsraStatus;

    /// Converts a C FFI algorithm specification to HsmRsaKeyUnwrappingKeyGenAlgo.
    fn try_from(_algo: &TsraAlgo) -> Result<Self, Self::Error> {
        Ok(HsmRsaKeyUnwrappingKeyGenAlgo::default())
    }
}

/// RSA-AES Wrap algorithm parameters structure matching C API
///
/// This structure specifies the parameters for RSA-AES generic wrapping,
/// which combines RSA-OAEP encryption with AES wrapping to securely
/// transport data.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TsraAlgoRsaAesWrapParams {
    /// AES key bits
    pub aes_key_bits: u32,

    /// OAEP parameters
    pub oaep_params: *const TsraAlgoRsaPkcsOaepParams,
}

impl TsraAlgoRsaAesWrapParams {
    /// Validates RSA-AES wrap parameters at the FFI boundary.
    ///
    /// Checks that the AES key size is a supported value (128, 192, or 256 bits),
    /// dereferences the nested OAEP parameters pointer, and validates the OAEP
    /// parameters.
    pub(crate) fn validate(&self) -> Result<(), TsraStatus> {
        // Validate that the AES key size is supported (128, 192, or 256 bits)
        match self.aes_key_bits {
            128 | 192 | 256 => {}
            _ => Err(TsraStatus::InvalidArgument)?,
        }

        // Dereference and validate the nested OAEP parameters
        let oaep_params = deref_ptr(self.oaep_params)?;
        oaep_params.validate()
    }
}

impl<'a> TryFrom<&'a TsraAlgo> for &'a TsraAlgoRsaAesWrapParams {
    type Error = TsraStatus;

    #[allow(unsafe_code)]
    fn try_from(algo: &'a TsraAlgo) -> Result<Self, Self::Error> {
        let params = validate_and_cast_algo_params::<TsraAlgoRsaAesWrapParams>(algo)?;

        // Validate the parameters (including nested OAEP params)
        params.validate()?;

        Ok(params)
    }
}

impl TryFrom<&TsraAlgoRsaAesWrapParams> for HsmRsaAesWrapAlgo {
    type Error = TsraStatus;

    #[allow(unsafe_code)]
    fn try_from(params: &TsraAlgoRsaAesWrapParams) -> Result<Self, Self::Error> {
        let oaep_params = deref_ptr(params.oaep_params)?;
        let hash_algo = HsmHashAlgo::try_from(oaep_params.hash_algo_id)?;
        Ok(HsmRsaAesWrapAlgo::new(
            hash_algo,
            (params.aes_key_bits / 8) as usize,
        ))
    }
}

/// MGF1 (Mask Generation Function 1) identifier enumeration.
///
/// This enum defines the supported mask generation functions used in RSA operations,
/// particularly for OAEP padding schemes. MGF1 is based on hash functions and provides
/// deterministic mask generation for cryptographic operations.
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TsraMgf1Id {
    /// MGF1 with SHA-256 hash function
    Sha256 = 1,

    /// MGF1 with SHA-384 hash function
    Sha384 = 2,

    /// MGF1 with SHA-512 hash function
    Sha512 = 3,

    /// MGF1 with SHA-1 hash function
    Sha1 = 4,
}

/// RSA PKCS OAEP encryption/decryption parameters matching C API.
///
/// Defines parameters for OAEP (Optimal Asymmetric Encryption Padding) operations,
/// which provide secure probabilistic encryption using a hash function, mask
/// generation function (MGF1), and optional label for context binding.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TsraAlgoRsaPkcsOaepParams {
    /// Hash algorithm identifier used for OAEP padding
    pub hash_algo_id: TsraAlgoId,

    /// MGF1 mask generation function identifier.
    pub mgf1_hash_algo_id: TsraMgf1Id,

    /// Optional label for encryption context (can be null)
    pub label: *const TsraBuffer,
}

impl TsraAlgoRsaPkcsOaepParams {
    /// Validates OAEP parameters at the FFI boundary.
    ///
    /// Checks that the hash algorithm and MGF1 hash algorithm form a valid,
    /// matching pair (SHA-256/256, SHA-384/384, SHA-512/512), and that the
    /// optional label buffer pointer is well-formed.
    ///
    /// Current limitation: OAEP MGF1 is not independently propagated through
    /// all layers (native -> DDI -> device/sim). Enforce matching values at
    /// the API boundary so behavior is explicit and deterministic.
    pub(crate) fn validate(&self) -> Result<(), TsraStatus> {
        // Enforce that hash_algo_id and mgf1_hash_algo_id are a valid, matching pair.
        let hash_matches_mgf1 = matches!(
            (self.hash_algo_id, self.mgf1_hash_algo_id),
            (TsraAlgoId::Sha256, TsraMgf1Id::Sha256)
                | (TsraAlgoId::Sha384, TsraMgf1Id::Sha384)
                | (TsraAlgoId::Sha512, TsraMgf1Id::Sha512)
        );

        //reject mismatched or unsupported hash/MGF1 combinations.
        if !hash_matches_mgf1 {
            Err(TsraStatus::InvalidArgument)?;
        }

        // Validate that the label buffer pointer is well-formed (if non-null)
        buffer_to_optional_slice(self.label)?;
        Ok(())
    }
}

impl TryFrom<TsraHandle> for HsmRsaPublicKey {
    type Error = TsraStatus;

    fn try_from(handle: TsraHandle) -> Result<Self, Self::Error> {
        let key: &HsmRsaPublicKey = HANDLE_TABLE.as_ref(handle, HandleType::RsaPubKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<TsraHandle> for HsmRsaPrivateKey {
    type Error = TsraStatus;

    fn try_from(handle: TsraHandle) -> Result<Self, Self::Error> {
        let key: &HsmRsaPrivateKey = HANDLE_TABLE.as_ref(handle, HandleType::RsaPrivKey)?;
        Ok(key.clone())
    }
}

/// Generic helper function to perform RSA cryptographic operations (encrypt/decrypt)
fn perform_crypto<A, K, F>(
    crypto_algo: &mut A,
    key: &K,
    input: &[u8],
    output: &mut TsraBuffer,
    crypto_fn: F,
) -> Result<(), TsraStatus>
where
    F: Fn(&mut A, &K, &[u8], Option<&mut [u8]>) -> Result<usize, HsmError>,
{
    // Query the required output buffer size
    let required_len = crypto_fn(crypto_algo, key, input, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(output, required_len)?;

    // Perform the cryptographic operation
    let written = crypto_fn(crypto_algo, key, input, Some(output_buf))?;

    // Update output buffer length with actual bytes written
    output.len = written as u32;

    Ok(())
}

/// Encrypts data using RSA public key encryption
///
/// Encrypts plaintext using RSA with the specified padding scheme.
///
/// # Arguments
/// * `algo` - RSA encryption algorithm (PKCS#1 v1.5 or OAEP)
/// * `key_handle` - Handle to the RSA public key
/// * `plaintext` - Data to encrypt
/// * `output` - Output buffer for the ciphertext
///
/// # Returns
/// * `Ok(())` - On successful encryption
/// * `Err(TsraStatus)` - On failure (e.g., plaintext too large, buffer too small)
pub(crate) fn rsa_encrypt(
    algo: &TsraAlgo,
    key_handle: TsraHandle,
    input: &[u8],
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    let key: HsmRsaPublicKey = HsmRsaPublicKey::try_from(key_handle)?;

    match algo.id {
        TsraAlgoId::RsaPkcs => {
            let mut encrypt_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
            perform_crypto(
                &mut encrypt_algo,
                &key,
                input,
                output,
                HsmEncrypter::encrypt,
            )
        }
        TsraAlgoId::RsaPkcsOaep => {
            let params = <&TsraAlgoRsaPkcsOaepParams>::try_from(algo)?;
            let hash_algo = HsmHashAlgo::try_from(params.hash_algo_id)?;
            let mut encrypt_algo = HsmRsaEncryptAlgo::with_oaep_padding(hash_algo, None);
            perform_crypto(
                &mut encrypt_algo,
                &key,
                input,
                output,
                HsmEncrypter::encrypt,
            )
        }
        TsraAlgoId::RsaAesWrap => {
            let params = <&TsraAlgoRsaAesWrapParams>::try_from(algo)?;
            let mut wrap_algo = HsmRsaAesWrapAlgo::try_from(params)?;
            perform_crypto(&mut wrap_algo, &key, input, output, HsmEncrypter::encrypt)
        }
        _ => Err(TsraStatus::UnsupportedAlgorithm),
    }
}

/// Decrypts data using RSA private key decryption
///
/// Decrypts ciphertext using RSA with the specified padding scheme.
///
/// # Arguments
/// * `algo` - RSA decryption algorithm (PKCS#1 v1.5 or OAEP)
/// * `key_handle` - Handle to the RSA private key
/// * `ciphertext` - Data to decrypt
/// * `output` - Output buffer for the plaintext
///
/// # Returns
/// * `Ok(())` - On successful decryption
/// * `Err(TsraStatus)` - On failure (e.g., invalid ciphertext, buffer too small)
pub(crate) fn rsa_decrypt(
    algo: &TsraAlgo,
    key_handle: TsraHandle,
    input: &[u8],
    output: &mut TsraBuffer,
) -> Result<(), TsraStatus> {
    let key: HsmRsaPrivateKey = HsmRsaPrivateKey::try_from(key_handle)?;

    match algo.id {
        TsraAlgoId::RsaPkcs => {
            let mut decrypt_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
            perform_crypto(
                &mut decrypt_algo,
                &key,
                input,
                output,
                HsmDecrypter::decrypt,
            )
        }
        TsraAlgoId::RsaPkcsOaep => {
            let params = <&TsraAlgoRsaPkcsOaepParams>::try_from(algo)?;
            let hash_algo = HsmHashAlgo::try_from(params.hash_algo_id)?;
            let mut decrypt_algo = HsmRsaEncryptAlgo::with_oaep_padding(hash_algo, None);
            perform_crypto(
                &mut decrypt_algo,
                &key,
                input,
                output,
                HsmDecrypter::decrypt,
            )
        }
        _ => Err(TsraStatus::UnsupportedAlgorithm),
    }
}
