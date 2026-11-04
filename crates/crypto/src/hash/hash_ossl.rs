// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based cryptographic hash function implementations for Linux systems.
//!
//! This module provides concrete implementations of various hash algorithms using
//! the OpenSSL cryptographic library. It serves as the Linux-specific backend
//! for the platform-agnostic hash interface defined in the parent module.
//!
//! # Supported Algorithms
//!
//! - **SHA-1**: Legacy hash function (cryptographically broken)
//! - **SHA-256**: Secure 256-bit hash from SHA-2 family
//! - **SHA-384**: Secure 384-bit hash from SHA-2 family
//! - **SHA-512**: Secure 512-bit hash from SHA-2 family
//! - **SHA3-256**, **SHA3-384**, **SHA3-512**: SHA-3 family (FIPS 202)
//! - **SHAKE128**, **SHAKE256**: SHA-3 XOFs (FIPS 202) with a caller-chosen
//!   output length
//!
//! # Implementation Strategy
//!
//! The module provides the `OsslHash` type that stores the selected hash algorithm
//! and corresponding OpenSSL `MessageDigest`. Instances can be created using the
//! `new()` constructor or convenient factory methods like `sha256()`.
//!
//! # Platform Integration
//!
//! - Leverages OpenSSL's optimized hash implementations
//! - Automatically benefits from hardware acceleration (AES-NI, etc.)
//! - Uses system-provided OpenSSL for security updates
//! - Provides memory-safe Rust wrappers around OpenSSL APIs
//!
//! # Performance
//!
//! OpenSSL implementations are highly optimized and include:
//! - Assembly-optimized code paths for various architectures
//! - Hardware acceleration when available
//! - Efficient memory management
//! - Vectorized operations for large data processing

use std::num::NonZeroUsize;

use openssl::hash::*;
use openssl::md::*;
use openssl::md_ctx::MdCtx;
use openssl::nid::Nid;

use super::*;
use crate::libctx::crypto_libctx;

/// OpenSSL-based hash implementation.
///
/// This structure provides a hash implementation using OpenSSL APIs.
/// It stores the hash algorithm selection and the corresponding OpenSSL
/// `MessageDigest` for efficient hash operations.
#[derive(Clone)]
pub struct OsslHashAlgo {
    md: MessageDigest,
    /// Output length of the SHAKE XOFs; `None` for fixed-length digests.
    xof_len: Option<NonZeroUsize>,
}

impl OsslHashAlgo {
    /// Creates a new instance of the OpenSSL hash implementation.
    ///
    /// Initializes the hash implementation with the specified algorithm and
    /// obtains the corresponding OpenSSL `MessageDigest`.
    ///
    /// # Arguments
    ///
    /// * `algo` - The hash algorithm to use
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance ready to perform hash operations.
    pub fn new(md: MessageDigest) -> Self {
        Self { md, xof_len: None }
    }

    /// Creates a new SHA-1 hash instance.
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA-1 hashing.
    ///
    /// # Security Warning
    ///
    /// SHA-1 is cryptographically broken and should not be used for security-sensitive
    /// applications. Use SHA-256 or stronger algorithms instead.
    pub fn sha1() -> Self {
        Self::new(MessageDigest::sha1())
    }

    /// Creates a new SHA-256 hash instance.
    ///
    /// SHA-256 is part of the SHA-2 family and provides 256-bit hash values.
    /// It is recommended for most cryptographic applications.
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA-256 hashing.
    pub fn sha256() -> Self {
        Self::new(MessageDigest::sha256())
    }

    /// Creates a new SHA-384 hash instance.
    ///
    /// SHA-384 is part of the SHA-2 family and provides 384-bit hash values.
    /// It is a truncated version of SHA-512 and is suitable for high-security applications.
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA-384 hashing.
    pub fn sha384() -> Self {
        Self::new(MessageDigest::sha384())
    }

    /// Creates a new SHA-512 hash instance.
    ///
    /// SHA-512 is part of the SHA-2 family and provides 512-bit hash values.
    /// It is suitable for high-security applications requiring larger hash outputs.
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA-512 hashing.
    pub fn sha512() -> Self {
        Self::new(MessageDigest::sha512())
    }

    /// Creates a new SHA3-256 hash instance (FIPS 202, 256-bit hash values).
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA3-256 hashing.
    pub fn sha3_256() -> Self {
        Self::new(MessageDigest::sha3_256())
    }

    /// Creates a new SHA3-384 hash instance (FIPS 202, 384-bit hash values).
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA3-384 hashing.
    pub fn sha3_384() -> Self {
        Self::new(MessageDigest::sha3_384())
    }

    /// Creates a new SHA3-512 hash instance (FIPS 202, 512-bit hash values).
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA3-512 hashing.
    pub fn sha3_512() -> Self {
        Self::new(MessageDigest::sha3_512())
    }

    /// Creates a new SHAKE128 XOF instance (FIPS 202) that produces `len`
    /// bytes of output.
    ///
    /// SHAKE is supported for hashing only: HMAC, HKDF, KBKDF, the
    /// concatenation KDFs, RSA and ECDSA reject it with
    /// `CryptoError::HashUnsupportedAlgorithm`.
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHAKE128 hashing.
    pub fn shake128(len: NonZeroUsize) -> Self {
        Self {
            md: MessageDigest::shake_128(),
            xof_len: Some(len),
        }
    }

    /// Creates a new SHAKE256 XOF instance (FIPS 202) that produces `len`
    /// bytes of output.
    ///
    /// SHAKE is supported for hashing only: HMAC, HKDF, KBKDF, the
    /// concatenation KDFs, RSA and ECDSA reject it with
    /// `CryptoError::HashUnsupportedAlgorithm`.
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHAKE256 hashing.
    pub fn shake256(len: NonZeroUsize) -> Self {
        Self {
            md: MessageDigest::shake_256(),
            xof_len: Some(len),
        }
    }

    /// Returns the hash output size in bytes for this algorithm.
    ///
    /// This method provides the size of the hash digest produced by this
    /// hash algorithm without performing any cryptographic operations.
    ///
    /// # Returns
    ///
    /// The hash output size in bytes:
    /// - SHA-1: 20 bytes
    /// - SHA-256, SHA3-256: 32 bytes
    /// - SHA-384, SHA3-384: 48 bytes
    /// - SHA-512, SHA3-512: 64 bytes
    /// - SHAKE128, SHAKE256: the output length given at construction
    pub fn size(&self) -> usize {
        self.xof_len
            .map_or_else(|| self.md.size(), NonZeroUsize::get)
    }

    /// Returns `true` for the SHAKE extendable-output functions.
    pub(crate) fn is_xof(&self) -> bool {
        matches!(self.md.type_(), Nid::SHAKE128 | Nid::SHAKE256)
    }

    /// Returns the OpenSSL MessageDigest for this hash algorithm.
    ///
    /// # Returns
    ///
    /// The `MessageDigest` configured for this hash instance.
    pub(crate) fn message_digest(&self) -> MessageDigest {
        self.md
    }

    /// Returns a reference to the OpenSSL MdRef for this hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `MdRef` configured for this hash instance.
    pub(crate) fn md(&self) -> &MdRef {
        #[allow(clippy::unwrap_used)]
        Md::from_nid(self.message_digest().type_()).unwrap()
    }

    /// Canonical OpenSSL name used to fetch this digest from a libctx.
    ///
    /// Returns `CryptoError::HashUnsupportedAlgorithm` for any digest outside
    /// the fixed-length set (SHA-1/256/384/512, SHA3-256/384/512), including
    /// the SHAKE XOFs, so a consumer that resolves its digest by name (HMAC,
    /// RSA) can never pick up SHAKE. It returns an error instead of panicking
    /// in production code.
    pub(crate) fn md_name(&self) -> Result<&'static str, CryptoError> {
        match self.md.type_() {
            Nid::SHA1 => Ok("SHA1"),
            Nid::SHA256 => Ok("SHA256"),
            Nid::SHA384 => Ok("SHA384"),
            Nid::SHA512 => Ok("SHA512"),
            Nid::SHA3_256 => Ok("SHA3-256"),
            Nid::SHA3_384 => Ok("SHA3-384"),
            Nid::SHA3_512 => Ok("SHA3-512"),
            _ => Err(CryptoError::HashUnsupportedAlgorithm),
        }
    }

    /// Fetches this digest (or XOF) from the crate-private libctx
    /// (default-provider-only) so it never resolves to a provider (e.g. tsra)
    /// in the process default libctx. See [`crate::libctx`].
    fn fetch_md(&self) -> Result<Md, CryptoError> {
        let name = match self.md.type_() {
            Nid::SHAKE128 => "SHAKE128",
            Nid::SHAKE256 => "SHAKE256",
            _ => self.md_name()?,
        };
        Md::fetch(Some(crypto_libctx()), name, None).map_err(|_| CryptoError::HashInitError)
    }

    /// Returns the DER digest algorithm identifier for this hash algorithm.
    ///
    /// # Returns
    ///
    /// The `DerDigestAlgo` corresponding to this hash algorithm, or
    /// `CryptoError::HashUnsupportedAlgorithm` for SHA-3 and SHAKE, which
    /// have no `DigestInfo` mapping here.
    pub(crate) fn der_algo(&self) -> Result<DerDigestAlgo, CryptoError> {
        match self.md.type_() {
            Nid::SHA1 => Ok(DerDigestAlgo::Sha1),
            Nid::SHA256 => Ok(DerDigestAlgo::Sha256),
            Nid::SHA384 => Ok(DerDigestAlgo::Sha384),
            Nid::SHA512 => Ok(DerDigestAlgo::Sha512),
            _ => Err(CryptoError::HashUnsupportedAlgorithm),
        }
    }
}

/// Implementation of one-shot hash operations using OpenSSL.
///
/// This implementation provides both hash calculation and output size
/// determination through OpenSSL's optimized hash functions.
impl HashOp for OsslHashAlgo {
    /// Computes a hash using OpenSSL's optimized implementation.
    ///
    /// This method computes the digest with an `MdCtx` over an `Md` fetched from
    /// the crate-private libctx (default-provider only), so it never resolves to
    /// the tsra provider on OpenSSL 3.5 (see [`crate::libctx`]). It handles
    /// both size queries and actual hash computation based on whether an output
    /// buffer is provided.
    ///
    /// # Implementation Details
    ///
    /// - Fetches the digest from the crate-private libctx (`fetch_md`)
    /// - Validates output buffer size before computation
    /// - Runs `digest_init` / `digest_update` / `digest_final` on an `MdCtx`
    ///   (`digest_final_xof` for the SHAKE XOFs)
    /// - Returns actual hash size regardless of operation mode
    ///
    /// # Buffer Management
    ///
    /// The method ensures the output buffer is large enough before performing
    /// the hash computation, preventing buffer overflows and ensuring safe
    /// operation.
    fn hash(&mut self, data: &[u8], hash: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let size = self.size();
        if let Some(hash) = hash {
            if hash.len() < size {
                Err(CryptoError::HashBufferTooSmall)?;
            }
            let md = self.fetch_md()?;
            let mut ctx = MdCtx::new().map_err(|_| CryptoError::HashInitError)?;
            ctx.digest_init(&md)
                .map_err(|_| CryptoError::HashInitError)?;
            ctx.digest_update(data)
                .map_err(|_| CryptoError::HashUpdateError)?;
            digest_final(&mut ctx, self.is_xof(), &mut hash[..size])?;
        }
        Ok(size)
    }
}

/// Finalizes `ctx` into all of `out`: `out.len()` bytes of XOF output, or the
/// digest, which `out` must exactly fit.
fn digest_final(ctx: &mut MdCtx, xof: bool, out: &mut [u8]) -> Result<(), CryptoError> {
    let result = if xof {
        ctx.digest_final_xof(out)
    } else {
        ctx.digest_final(out).map(|_| ())
    };
    result.map_err(|_| CryptoError::HashFinishError)
}

impl HashStreamingOp for OsslHashAlgo {
    type Context = OsslHashAlgoContext;

    /// Initializes a new OpenSSL hash context for streaming operations.
    ///
    /// Fetches an `Md` for the algorithm from the crate-private libctx
    /// (default-provider only; see [`crate::libctx`]) and initialises an
    /// `MdCtx` for incremental hashing. The fetched `Md` is stored in the
    /// context (`_md`) so it stays alive for the lifetime of the `MdCtx`.
    ///
    /// # Context Initialization
    ///
    /// - Fetches the digest from the crate-private libctx (`fetch_md`)
    /// - Initialises an `MdCtx` via `digest_init`
    /// - Keeps the `Md` alive alongside the context
    /// - Handles OpenSSL initialization errors gracefully
    ///
    /// # Error Handling
    ///
    /// Returns `CryptoError::HashInitError` if OpenSSL context
    /// initialization fails, which may occur due to memory allocation
    /// failures or invalid algorithm configurations.
    fn hash_init(self) -> Result<Self::Context, CryptoError> {
        let md = self.fetch_md()?;
        let mut ctx = MdCtx::new().map_err(|_| CryptoError::HashInitError)?;
        ctx.digest_init(&md)
            .map_err(|_| CryptoError::HashInitError)?;
        Ok(OsslHashAlgoContext {
            algo: self,
            ctx,
            _md: md,
        })
    }
}

/// OpenSSL-based streaming hash context.
///
/// This structure maintains the state for streaming hash operations,
/// wrapping OpenSSL's `Hasher` and providing the necessary metadata
/// for proper operation.
///
/// # State Management
///
/// The context encapsulates:
/// - OpenSSL's internal hash state via `Hasher`
/// - Algorithm metadata via `MessageDigest`
/// - All necessary information for multi-step hash computation
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single
/// thread. OpenSSL's `Hasher` maintains internal state that could
/// be corrupted by concurrent access.
pub struct OsslHashAlgoContext {
    /// The hash algorithm instance.
    algo: OsslHashAlgo,
    /// OpenSSL digest context, fetched from the crate-private libctx.
    ctx: MdCtx,
    /// Keeps the fetched digest alive for the context's lifetime.
    _md: Md,
}

/// Implementation of streaming hash operations for OpenSSL contexts.
///
/// This implementation provides incremental hash computation through
/// OpenSSL's streaming interface, allowing efficient processing of
/// large datasets.
impl HashOpContext for OsslHashAlgoContext {
    /// The associated hash algorithm type.
    type Algo = OsslHashAlgo;

    /// Updates the hash state with new input data.
    ///
    /// This method feeds new data into OpenSSL's incremental hash
    /// computation engine. The data is processed immediately and
    /// the internal state is updated accordingly.
    ///
    /// # Implementation Details
    ///
    /// - Delegates directly to OpenSSL's `Hasher::update`
    /// - Handles OpenSSL errors and converts to `CryptoError`
    /// - Maintains hash state across multiple update calls
    /// - Optimized for processing data in chunks
    ///
    /// # Error Conditions
    ///
    /// Returns `CryptoError::HashUpdateError` if OpenSSL's update
    /// operation fails, which may indicate memory issues or
    /// corrupted context state.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.ctx
            .digest_update(data)
            .map_err(|_| CryptoError::HashUpdateError)
    }

    /// Finalizes the hash computation and produces the final result.
    ///
    /// This method completes the hash computation by calling OpenSSL's
    /// finalization process, which applies the algorithm-specific padding
    /// and produces the final hash value.
    ///
    /// # Finalization Process
    ///
    /// 1. Validates output buffer size if provided
    /// 2. Calls OpenSSL's `Hasher::finish` to complete computation
    /// 3. Copies result to output buffer if provided
    /// 4. Returns the hash size regardless of operation mode
    ///
    /// # Buffer Management
    ///
    /// The method ensures the output buffer is sufficiently large to
    /// hold the complete hash result before attempting the finalization,
    /// preventing buffer overflows.
    ///
    /// # Context Consumption
    ///
    /// This method consumes the context by taking ownership (`self`),
    /// ensuring that the context cannot be accidentally reused after
    /// finalization, which would be a programming error.
    ///
    /// # Error Handling
    ///
    /// - `CryptoError::HashBufferTooSmall`: Output buffer insufficient
    /// - `CryptoError::HashFinishError`: OpenSSL finalization failed
    fn finish(&mut self, hash: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let len = self.algo.size();
        if let Some(hash) = hash {
            if hash.len() < len {
                Err(CryptoError::HashBufferTooSmall)?;
            }

            digest_final(&mut self.ctx, self.algo.is_xof(), &mut hash[..len])?;
        }

        Ok(len)
    }

    /// Returns a reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `OsslHash` algorithm instance.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `OsslHash` algorithm instance.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// The `OsslHash` algorithm instance.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}
