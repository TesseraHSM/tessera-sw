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

    /// Minimum buffer size for a multi-step hash context: state +
    /// block.
    pub const fn hash_state_len(&self) -> usize {
        self.state_len() + self.block_len()
    }

    /// Buffer size for a multi-step HMAC context: state + block
    /// (pending) + block (opad key).
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
///   fragments; intermediate state lives in a PAL-allocated context.
///
/// All output digests can be requested in either NIST big-endian or
/// little-endian order via the `big_endian` flag, to match what the
/// next consumer (DDI response framing, KDF input, etc.) expects. The
/// little-endian form is the full byte reversal of the big-endian
/// digest.
pub trait HsmHash: HsmIoTypes {
    /// Platform-specific multi-step hash context.
    ///
    /// Created by [`hash_begin`](Self::hash_begin) and consumed by
    /// [`hash_finish`](Self::hash_finish).  Holds the intermediate
    /// SHA working state and a single block's worth of pending
    /// bytes; the underlying buffer is allocated from the
    /// [`HsmScopedAlloc`] passed to `hash_begin`, so the context's
    /// lifetime is bounded by that scope.
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
    /// - `digest` — output buffer; must be at least
    ///   [`HsmHashAlgo::digest_len`] bytes.  Only the leading
    ///   `digest_len` bytes are written.
    /// - `big_endian` — `true` for NIST big-endian output, `false`
    ///   for little-endian (the full byte reversal of the big-endian
    ///   digest, i.e. the PKA `ecc_sign` operand order).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `digest[..digest_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — `digest` shorter than
    ///   `algo.digest_len()` or `data.len()` exceeds the engine's
    ///   length limit.
    /// - `Err(HsmError)` — propagated from the SHA driver.
    async fn hash(
        &self,
        io: &Self::Io,
        algo: HsmHashAlgo,
        data: &HsmDmaBuf,
        digest: &mut HsmDmaBuf,
        big_endian: bool,
    ) -> HsmResult<()>;

    /// Begins a multi-step hash.
    ///
    /// Allocates the working state buffer from `alloc` and returns a
    /// fresh context with no bytes processed and an empty pending
    /// region.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — hash algorithm.
    /// - `alloc` — scoped allocator used to back the
    ///   [`Self::HashCtx`] state buffer; the returned context
    ///   borrows from this allocator's scope.
    ///
    /// # Returns
    ///
    /// - `Ok(ctx)` — fresh hash context ready for
    ///   [`hash_continue`](Self::hash_continue).
    /// - `Err(HsmError::UnsupportedDigestHashAlgorithm)` — the platform
    ///   cannot run `algo`.
    /// - `Err(HsmError::NotEnoughSpace)` — `alloc` cannot satisfy
    ///   the context allocation (typically
    ///   [`HsmHashAlgo::hash_state_len`] bytes; a PAL that buffers the
    ///   message for an XOF needs more).
    fn hash_begin<'a>(
        &self,
        io: &Self::Io,
        algo: HsmHashAlgo,
        alloc: &'a impl HsmScopedAlloc,
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
    /// - `Err(HsmError::InvalidArg)` — cumulative byte count
    ///   overflows the engine's length field.
    /// - `Err(HsmError)` — propagated from the SHA driver.
    async fn hash_continue(
        &self,
        io: &Self::Io,
        ctx: &mut Self::HashCtx<'_>,
        data: &HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Finalises the hash and writes the digest into `digest`.
    ///
    /// Consumes `ctx`; any pending bytes are flushed with SHA
    /// auto-padding before the final block is submitted.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — context to finalise (consumed).
    /// - `digest` — output buffer; must be at least
    ///   [`HsmHashAlgo::digest_len`] bytes.
    /// - `big_endian` — `true` for NIST big-endian output, `false`
    ///   for little-endian (the full byte reversal of the big-endian
    ///   digest, i.e. the PKA `ecc_sign` operand order).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `digest[..digest_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — `digest` is shorter than
    ///   `digest_len`.
    /// - `Err(HsmError)` — propagated from the SHA driver.
    async fn hash_finish(
        &self,
        io: &Self::Io,
        ctx: Self::HashCtx<'_>,
        digest: &mut HsmDmaBuf,
        big_endian: bool,
    ) -> HsmResult<()>;
}
