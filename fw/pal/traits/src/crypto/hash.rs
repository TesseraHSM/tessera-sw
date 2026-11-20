// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic hash (digest) trait for the HSM PAL.
//!
//! Defines [`HsmHashAlgo`] and the [`HsmHash`] trait that PAL
//! implementations use to expose hardware-accelerated or software-backed hash
//! computation.
//!
//! On Cortex-M7 hardware this would typically delegate to a SHA engine
//! peripheral. On the standard (host-native) PAL it would use OpenSSL.
//!
//! **Status**: This trait is part of [`HsmCrypto`] and is implemented by PALs
//! that provide SHA digest support. Higher-level DDI commands can build on it
//! for operations such as signing and key derivation.

use core::num::NonZeroU16;

use super::*;

/// Supported hash algorithms.
///
/// Discriminants are fixed `u32` values. Platforms map them to their engine's
/// own selectors (e.g. the Uno SHA driver's `ShaMode`, which numbers the
/// algorithms differently) with a `match`, never by casting.
///
/// The SHAKE XOFs carry their output length, so [`digest_len`] is the length
/// they produce. The SHA-3 variants are not implemented yet: PALs reject them
/// with [`HsmError::UnsupportedDigestHashAlgorithm`].
///
/// [`digest_len`]: Self::digest_len
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmHashAlgo {
    /// SHA-1 (160-bit digest). **Not FIPS-approved for signing.**
    Sha1 = 2,

    /// SHA-256 (256-bit / 32-byte digest).
    Sha256 = 4,

    /// SHA-384 (384-bit / 48-byte digest).
    Sha384 = 5,

    /// SHA-512 (512-bit / 64-byte digest).
    Sha512 = 6,

    /// SHA3-256 (256-bit / 32-byte digest).
    Sha3_256 = 11,

    /// SHA3-384 (384-bit / 48-byte digest).
    Sha3_384 = 12,

    /// SHA3-512 (512-bit / 64-byte digest).
    Sha3_512 = 13,

    /// SHAKE128 extendable output (XOF), producing the given number of bytes.
    Shake128(NonZeroU16) = 14,

    /// SHAKE256 extendable output (XOF), producing the given number of bytes.
    Shake256(NonZeroU16) = 15,
}

impl HsmHashAlgo {
    /// Returns the output length in bytes: the digest length, or the
    /// requested output length of a SHAKE XOF.
    pub const fn digest_len(&self) -> usize {
        match self {
            HsmHashAlgo::Sha1 => 20,
            HsmHashAlgo::Sha256 | HsmHashAlgo::Sha3_256 => 32,
            HsmHashAlgo::Sha384 | HsmHashAlgo::Sha3_384 => 48,
            HsmHashAlgo::Sha512 | HsmHashAlgo::Sha3_512 => 64,
            HsmHashAlgo::Shake128(len) | HsmHashAlgo::Shake256(len) => len.get() as usize,
        }
    }

    /// Returns `true` for the extendable-output functions (SHAKE128 and
    /// SHAKE256).
    pub const fn is_xof(&self) -> bool {
        matches!(self, HsmHashAlgo::Shake128(_) | HsmHashAlgo::Shake256(_))
    }

    /// Block size in bytes for the algorithm; for SHA-3 and SHAKE, the
    /// sponge rate.
    pub const fn block_len(&self) -> usize {
        match self {
            HsmHashAlgo::Sha1 | HsmHashAlgo::Sha256 => 64,
            HsmHashAlgo::Sha384 | HsmHashAlgo::Sha512 => 128,
            HsmHashAlgo::Sha3_256 | HsmHashAlgo::Shake256(_) => 136,
            HsmHashAlgo::Sha3_384 => 104,
            HsmHashAlgo::Sha3_512 => 72,
            HsmHashAlgo::Shake128(_) => 168,
        }
    }

    /// Working-variable state size in bytes (intermediate hash state); for
    /// SHA-3 and SHAKE, the 200-byte Keccak-f\[1600\] state.
    pub const fn state_len(&self) -> usize {
        match self {
            HsmHashAlgo::Sha1 => 20,
            HsmHashAlgo::Sha256 => 32,
            HsmHashAlgo::Sha384 | HsmHashAlgo::Sha512 => 64,
            HsmHashAlgo::Sha3_256
            | HsmHashAlgo::Sha3_384
            | HsmHashAlgo::Sha3_512
            | HsmHashAlgo::Shake128(_)
            | HsmHashAlgo::Shake256(_) => 200,
        }
    }

    /// Algorithmic SHA state + pending-block layout size.
    ///
    /// Query [`HsmHash::hash_state_size`] for the backend's actual storage
    /// requirement: native state can need no DMA bytes, while buffered
    /// SHAKE needs more than this layout.
    pub const fn hash_state_len(&self) -> usize {
        self.state_len() + self.block_len()
    }

    /// Algorithmic HMAC layout size: state + pending block + opad block.
    ///
    /// Query [`HsmHmac::hmac_state_size`] for the backend's actual DMA storage
    /// requirement.
    pub const fn hmac_state_len(&self) -> usize {
        self.state_len() + self.block_len() * 2
    }

    /// Minimum state buffer size for [`HsmKdf::mgf1`]:
    /// `digest_len + seed_len + 4` (hash output + `seed || counter`).
    pub const fn mgf1_state_len(&self, seed_len: usize) -> usize {
        self.digest_len() + seed_len + 4
    }

    /// Minimum state buffer size for [`HsmKdf::x963_kdf`] and
    /// [`HsmKdf::sp800_56a_kdf`]:
    /// `digest_len + z_len + 4 + info_len`
    /// (hash output + `Z || counter || info` in the largest ordering).
    pub const fn concat_kdf_state_len(&self, z_len: usize, info_len: usize) -> usize {
        self.digest_len() + z_len + 4 + info_len
    }
}

/// Asynchronous SHA digest interface.
///
/// Implementations expose two complementary APIs:
///
/// - **One-shot** ([`hash`](Self::hash)) — entire message available up
///   front; submitted to the engine in a single descriptor.
/// - **Multi-step** ([`hash_begin`](Self::hash_begin) →
///   [`hash_continue`](Self::hash_continue) … →
///   [`hash_finish`](Self::hash_finish)) — message arrives in
///   fragments; intermediate state lives in caller-provided storage.
///
/// Every digest is produced in the [`HsmDigestForm`] the caller asks
/// for: the standard digest (DDI responses, KDF input, certificates) or
/// an ECC sign/verify operand in the platform's operand byte order.
pub trait HsmHash: HsmIoTypes + HsmCryptoOrder {
    /// Platform-specific multi-step hash context.
    ///
    /// Created by [`hash_begin`](Self::hash_begin) and finalized by
    /// [`hash_finish`](Self::hash_finish). Holds the intermediate
    /// SHA working state and pending bytes. The context borrows caller-provided
    /// storage for `'a`, independently of the PAL and IO lifetimes.
    /// Contexts are backend-specific objects, not serializable byte strings.
    type HashCtx<'a>
    where
        Self: 'a;

    /// Computes a SHA digest in a single call.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — hash algorithm; selects the digest length and
    ///   hardware mode.
    /// - `data` — input message; any length, including zero.
    /// - `form` — [`HsmDigestForm::Standard`] for the standard digest,
    ///   [`HsmDigestForm::Operand`] for an ECC sign/verify operand.
    /// - `digest` — `None` queries the digest length without performing
    ///   crypto or allocating scratch. `Some` must hold at least that
    ///   many bytes; only the returned prefix is written.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required digest size or bytes written.
    /// - `Err(HsmError::InvalidArg)` — `digest` shorter than
    ///   `algo.digest_len()` or `data.len()` exceeds the engine's
    ///   length limit.
    /// - `Err(HsmError)` — propagated from the SHA driver.
    async fn hash(
        &self,
        io: &Self::Io,
        algo: HsmHashAlgo,
        data: &HsmDmaBuf,
        form: HsmDigestForm,
        digest: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Hashes a raw message from an OOB SGL descriptor using bounded DMA
    /// staging, returning its digest in the requested form.
    ///
    /// The caller must keep the host buffer unchanged and accessible until
    /// command completion. The descriptor is captured once; this does not
    /// make the referenced message bytes an atomic snapshot. The digest covers
    /// the byte stream actually read by the platform transport.
    ///
    /// `expected_len` must be at most 8192 bytes. A zero-length message does
    /// not read an OOB descriptor and hashes the empty byte string. The output
    /// must hold at least `algo.digest_len()` bytes; only that prefix is
    /// written. The method validates algorithm and output capacity before
    /// reading message data.
    ///
    /// The platform validates the root descriptor and its address range.
    /// Uno submits it unchanged to GDMA, which traverses any SGL segments,
    /// gathering exactly `expected_len` bytes into a scoped DMA allocation
    /// of that size. Other platforms may stream the message in smaller chunks.
    async fn hash_oob(
        &self,
        io: &Self::Io,
        algo: HsmHashAlgo,
        expected_len: usize,
        index: usize,
        form: HsmDigestForm,
        digest: &mut HsmDmaBuf,
    ) -> HsmResult<usize>;

    /// Returns the backend's required DMA storage size for a multi-step hash.
    ///
    /// Validates algorithm support and limits without allocating or initializing
    /// a crypto operation. May return zero for native crypto backends.
    fn hash_state_size(&self, algo: HsmHashAlgo) -> HsmResult<usize>;

    /// Begins a multi-step hash in caller-provided storage.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — hash algorithm.
    /// - `state` — storage of at least [`hash_state_size`](Self::hash_state_size)
    ///   bytes, 4-byte aligned when the required size is nonzero.
    ///   Only the required prefix may be modified.
    ///
    /// # Returns
    ///
    /// - `Ok(ctx)` — initialized context ready for
    ///   [`hash_continue`](Self::hash_continue).
    /// - `Err(HsmError::UnsupportedDigestHashAlgorithm)` — the platform
    ///   cannot run `algo`.
    /// - `Err(HsmError::InvalidArg)` — storage is too short or misaligned.
    ///
    /// The caller must keep storage alive until context drop, then
    /// reclaim and scrub it according to its allocation lifetime. Dropping
    /// the context does not reclaim or scrub caller-provided storage.
    fn hash_begin<'a>(
        &self,
        io: &Self::Io,
        algo: HsmHashAlgo,
        state: &'a mut HsmDmaBuf,
    ) -> HsmResult<Self::HashCtx<'a>>
    where
        Self: 'a;

    /// Feeds bytes into the running hash.
    ///
    /// Implementations buffer a partial trailing block internally
    /// and submit full blocks to the engine as soon as they are
    /// available; callers can pass arbitrary-length fragments,
    /// including zero-length.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — context returned by
    ///   [`hash_begin`](Self::hash_begin).
    /// - `data` — bytes to append to the running hash.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::InvalidArg)` — context is no longer active or the
    ///   cumulative byte count overflows the engine's length field.
    /// - `Err(HsmError)` — propagated from the SHA driver.
    async fn hash_continue(
        &self,
        io: &Self::Io,
        ctx: &mut Self::HashCtx<'_>,
        data: &HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Queries the digest size or finalises the hash into `digest`.
    ///
    /// A query leaves the active context unchanged. Execution flushes pending
    /// bytes with SHA auto-padding. After finalization starts, the context is
    /// no longer usable, including if execution fails or is cancelled.
    /// Native resources are released on finalization or context drop.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — active context to query or finalise.
    /// - `form` — [`HsmDigestForm::Standard`] for the standard digest,
    ///   [`HsmDigestForm::Operand`] for an ECC sign/verify operand.
    /// - `digest` — `None` queries the digest size; `Some` must have at
    ///   least that capacity. Only the returned prefix is written.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required digest size or bytes written.
    /// - `Err(HsmError::InvalidArg)` — context is no longer active or the
    ///   output is too short. A short output leaves the context unchanged.
    /// - `Err(HsmError)` — propagated from the SHA driver.
    async fn hash_finish(
        &self,
        io: &Self::Io,
        ctx: &mut Self::HashCtx<'_>,
        form: HsmDigestForm,
        digest: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;
}
