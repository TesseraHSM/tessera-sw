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
//!   Windows, requires Windows 11 23H2 / Windows Server 2025 or later
//! - **SHAKE128**, **SHAKE256**: SHA-3 extendable-output functions (FIPS 202)
//!   whose output length is fixed when the `HashAlgo` is created; on Windows,
//!   requires Windows 11 24H2 / Windows Server 2025 or later. SHAKE is
//!   supported for hashing only: FIPS 202 does not approve XOFs as hash
//!   functions, and PKCS #11 v3.2 defines no HMAC, KDF, RSA or ECDSA
//!   mechanism over SHAKE, so those consumers reject it with
//!   `CryptoError::HashUnsupportedAlgorithm`.
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

#[cfg(target_os = "windows")]
pub(crate) use hash_cng::BCRYPT_SHA3_256_ALG_HANDLE;
#[cfg(target_os = "windows")]
pub(crate) use hash_cng::BCRYPT_SHA3_384_ALG_HANDLE;
#[cfg(target_os = "windows")]
pub(crate) use hash_cng::BCRYPT_SHA3_512_ALG_HANDLE;

define_type!(pub HashAlgo, hash_ossl::OsslHashAlgo, hash_cng::CngHashAlgo);
define_type!(pub HashAlgoContext, hash_ossl::OsslHashAlgoContext, hash_cng::CngHashAlgoContext);

impl HashAlgo {
    /// Rejects the SHAKE XOFs with `CryptoError::HashUnsupportedAlgorithm`.
    ///
    /// Every consumer that uses a `HashAlgo` as a fixed-length hash (HMAC,
    /// HKDF, KBKDF, the concatenation KDFs, RSA and ECDSA) calls this before
    /// doing any work, on every backend.
    pub(crate) fn ensure_not_xof(&self) -> Result<(), CryptoError> {
        if self.is_xof() {
            return Err(CryptoError::HashUnsupportedAlgorithm);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
