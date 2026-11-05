// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic hash function implementations.
//!
//! This module provides a unified interface for various cryptographic hash functions
//! including SHA-1, the SHA-2 family, SHA3-256/384/512 and the SHAKE128/256
//! XOFs. The implementation abstracts over platform-specific backends to
//! provide consistent APIs across different operating systems.
//!
//! # Supported Hash Functions
//!
//! - **SHA-1**: 160-bit hash (deprecated for cryptographic use, provided for compatibility)
//! - **SHA-256**: 256-bit hash from the SHA-2 family
//! - **SHA-384**: 384-bit hash from the SHA-2 family  
//! - **SHA-512**: 512-bit hash from the SHA-2 family
//! - **SHA3-256**, **SHA3-384**, **SHA3-512**: SHA-3 family (FIPS 202); on
//!   Windows, requires Windows 11 23H2 / Windows Server 2025 or later. HMAC
//!   and RSA signing reject SHA-3 with `CryptoError::HashUnsupportedAlgorithm`,
//!   as PKCS #11 defines them over SHA-1 and SHA-2 only
//! - **SHAKE128**, **SHAKE256**: SHA-3 extendable-output functions (FIPS 202)
//!   whose output length is fixed when the `HashAlgo` is created; on Windows,
//!   requires Windows 11 24H2 / Windows Server 2025 or later. SHAKE is
//!   supported for hashing only: FIPS 202 does not approve XOFs as hash
//!   functions, and PKCS #11 v3.2 defines no HMAC, KDF, RSA or ECDSA
//!   mechanism over SHAKE, so those consumers reject it with
//!   `CryptoError::HashUnsupportedAlgorithm`.
//! - **ML-DSA-MU**: the ML-DSA external-`μ` hash of a message under a public
//!   key and context string (FIPS 204), as OpenSSL's `ML-DSA-MU` digest; see
//!   [`HashAlgo::mldsa_mu`]. Being SHAKE256 underneath, it is likewise
//!   supported for hashing only.
//!
//! # Architecture
//!
//! The module provides two main operation modes:
//!
//! ## One-shot Operations
//!
//! For hashing complete data available in memory.
//!
//! ## Streaming Operations
//!
//! For processing large data or data available in chunks.
//!
//! # Platform Support
//!
//! - **Linux**: Uses OpenSSL implementations for optimal performance and security
//! - **Windows**: Platform-specific implementation (future)
//!
//! # Security Considerations
//!
//! - **SHA-1**: Cryptographically broken, use only for non-security purposes
//! - **SHA-2 family**: Currently secure for cryptographic applications
//! - All implementations use platform-optimized code when available
//! - Hardware acceleration is utilized when supported by the platform

use super::*;

#[cfg(all(target_os = "linux", ossl300))]
mod hash_ossl;

#[cfg(all(target_os = "linux", not(ossl300)))]
#[path = "hash_ossl11.rs"]
mod hash_ossl;

#[cfg(target_os = "windows")]
mod hash_cng;

define_type!(pub HashAlgo, hash_ossl::OsslHashAlgo, hash_cng::CngHashAlgo);
define_type!(pub HashAlgoContext, hash_ossl::OsslHashAlgoContext, hash_cng::CngHashAlgoContext);

/// SHAKE256 output length for ML-DSA's `tr` and `μ`.
const MLDSA_MU_OUT_LEN: core::num::NonZeroUsize = match core::num::NonZeroUsize::new(MLDSA_MU_LEN) {
    Some(len) => len,
    None => panic!("MLDSA_MU_LEN is zero"),
};

impl HashAlgo {
    /// Creates the ML-DSA external-`μ` hash (FIPS 204) for messages signed
    /// under `pub_key` and the context string `ctx`.
    ///
    /// Hashing a message `M` gives the [`MLDSA_MU_LEN`]-byte message
    /// representative that pure ML-DSA signs for it:
    ///
    /// ```text
    /// tr = SHAKE256(pk, 64)
    /// μ  = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)
    /// ```
    ///
    /// This is OpenSSL's `ML-DSA-MU` digest, whose `pub` and `context-string`
    /// parameters are taken here. The message is hashed as with any other
    /// algorithm, in one call or streamed, and the result signs and verifies
    /// with [`MlDsaAlgo::external_mu`]: a signature over it is a pure ML-DSA
    /// signature over `M` under `ctx`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsaInvalidContext`] if `ctx` is longer than
    /// [`MLDSA_CTX_MAX_LEN`] bytes, or the hashing error if `tr` cannot be
    /// computed.
    pub fn mldsa_mu(pub_key: &MlDsaPublicKey, ctx: &[u8]) -> Result<Self, CryptoError> {
        let ctx_len = u8::try_from(ctx.len()).map_err(|_| CryptoError::MlDsaInvalidContext)?;
        let mut prefix = vec![0u8; MLDSA_MU_LEN];
        Hasher::hash(
            &mut Self::shake256(MLDSA_MU_OUT_LEN),
            pub_key.as_bytes(),
            Some(&mut prefix),
        )?;
        prefix.extend_from_slice(&[0x00, ctx_len]);
        prefix.extend_from_slice(ctx);
        Ok(Self::shake256(MLDSA_MU_OUT_LEN).with_prefix(prefix))
    }

    /// Rejects the SHAKE XOFs with `CryptoError::HashUnsupportedAlgorithm`.
    ///
    /// Every consumer that uses a `HashAlgo` as a fixed-length hash (HKDF,
    /// the concatenation KDFs, RSA encryption and ECDSA) calls this before
    /// doing any work, on every backend; HMAC, KBKDF and RSA signing use the
    /// stricter [`Self::ensure_sha1_or_sha2`].
    pub(crate) fn ensure_not_xof(&self) -> Result<(), CryptoError> {
        if self.is_xof() {
            return Err(CryptoError::HashUnsupportedAlgorithm);
        }
        Ok(())
    }

    /// Rejects SHA-3 and the SHAKE XOFs with
    /// `CryptoError::HashUnsupportedAlgorithm`.
    ///
    /// PKCS #11 defines HMAC and RSA signing over SHA-1 and SHA-2 only, so
    /// those consumers (and KBKDF, which runs over HMAC) call this before
    /// doing any work, on every backend.
    pub(crate) fn ensure_sha1_or_sha2(&self) -> Result<(), CryptoError> {
        self.der_algo().map(|_| ())
    }
}

#[cfg(test)]
mod tests;
