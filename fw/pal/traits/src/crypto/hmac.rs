// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC (Hash-based Message Authentication Code) trait for the HSM PAL.
//!
//! Defines the [`HsmHmac`] trait that PAL implementations use to expose
//! HMAC key generation, signing (MAC computation), and verification.
//!
//! On Cortex-M7 hardware this delegates to the SHA engine with software
//! HMAC key scheduling (RFC 2104 ipad/opad). On the standard
//! (host-native) PAL it uses OpenSSL's HMAC implementation.
//!
//! ## Key representation
//!
//! All key parameters are plain `&[u8]` byte slices containing the raw
//! HMAC key material. Each PAL implementation is responsible for parsing
//! them into whatever internal representation it needs.
//!
//! ## Output buffer convention
//!
//! MAC-producing methods accept optional output buffers, with `None` querying
//! the tag length without computing it. The MAC tag length matches
//! [`HsmHashAlgo::digest_len`] for the underlying hash. Initialization
//! instead accepts state storage sized by [`HsmHmac::hmac_state_size`].
//!
//! ## Multi-step API
//!
//! For messages that arrive in pieces, callers use
//! [`hmac_begin`](HsmHmac::hmac_begin) /
//! [`hmac_continue`](HsmHmac::hmac_continue) /
//! [`hmac_finish`](HsmHmac::hmac_finish) (or
//! [`hmac_finish_verify`](HsmHmac::hmac_finish_verify)). Initialization
//! accepts caller-provided storage sized by [`HsmHmac::hmac_state_size`].
//! The context borrows the storage, matching the hash API.

use super::*;

/// Asynchronous HMAC operations trait.
///
/// PAL implementations provide this to the core for HMAC key generation,
/// MAC computation, and MAC verification. The async signatures allow
/// hardware-backed implementations to yield while the HMAC engine
/// processes data.
///
/// Both one-shot ([`hmac_sign`](Self::hmac_sign),
/// [`hmac_verify`](Self::hmac_verify)) and multi-step
/// ([`hmac_begin`](Self::hmac_begin) / [`hmac_continue`](Self::hmac_continue)
/// / [`hmac_finish`](Self::hmac_finish)) forms are provided.
pub trait HsmHmac: HsmIoTypes {
    /// Platform-specific multi-step HMAC context.
    ///
    /// Created by [`hmac_begin`](Self::hmac_begin) and finalized by
    /// [`hmac_finish`](Self::hmac_finish) or
    /// [`hmac_finish_verify`](Self::hmac_finish_verify). Holds the
    /// intermediate SHA state, pending partial block, and the outer key
    /// (opad) needed for finalization. Borrows caller-provided storage for
    /// `'a`, independently of the IO and PAL lifetimes.
    /// Native backend objects remain typed; they are not serialized into
    /// the DMA buffer. Persistent storage must outlive individual requests.
    type HmacCtx<'a>
    where
        Self: 'a;

    /// Generate a random HMAC key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — underlying hash algorithm; informational, used by
    ///   PAL implementations that record key metadata.  The actual
    ///   key length is determined by `key_len`.
    /// - `key_len` — requested key length in bytes, independent of the
    ///   hash algorithm. Typical sizes are `algo.digest_len()`
    ///   (32 / 48 / 64 bytes for SHA-256 / 384 / 512).
    /// - `key` — `None` queries `key_len` without allocation or RNG use.
    ///   `Some` must hold at least that many bytes; only the key prefix is
    ///   filled, leaving any tail unchanged.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required key length or bytes written.
    /// - `Err(HsmError::InvalidArg)` — output is shorter than `key_len`.
    /// - `Err(HsmError)` — propagated from the CSPRNG.
    async fn hmac_gen_key(
        &self,
        io: &Self::Io,
        algo: HsmHashAlgo,
        key_len: usize,
        key: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Compute an HMAC tag (sign) in a single call.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — underlying hash algorithm.
    /// - `key` — HMAC key bytes; longer than `algo.block_len()`
    ///   triggers an internal pre-hash to `algo.digest_len()`.
    /// - `data` — message to authenticate.  Any length, including
    ///   zero.
    /// - `tag` — `None` queries the tag length without crypto or scratch
    ///   allocation. An output buffer must be at least
    ///   `algo.digest_len()` bytes.  Only the leading `digest_len`
    ///   bytes are written.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required tag length or bytes written.
    /// - `Err(HsmError::InvalidArg)` — `tag` shorter than
    ///   `algo.digest_len()`.
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation
    ///   cannot fit the HMAC state buffer.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_sign(
        &self,
        io: &Self::Io,
        algo: HsmHashAlgo,
        key: &HsmDmaBuf,
        data: &HsmDmaBuf,
        tag: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Verify an HMAC tag in a single call using constant-time
    /// comparison.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — underlying hash algorithm.
    /// - `key` — HMAC key (same key that produced the tag).
    /// - `data` — message that was authenticated.
    /// - `tag` — MAC tag to verify against.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — tag is valid.
    /// - `Ok(false)` — tag does not match (not an error).
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation
    ///   cannot fit the HMAC state buffer.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_verify(
        &self,
        io: &Self::Io,
        algo: HsmHashAlgo,
        key: &HsmDmaBuf,
        data: &HsmDmaBuf,
        tag: &HsmDmaBuf,
    ) -> HsmResult<bool>;

    /// Returns the backend's required DMA storage size for a multi-step HMAC.
    ///
    /// Validates algorithm support without allocating, conditioning a key, or
    /// initializing a crypto operation. May return zero for native backends.
    fn hmac_state_size(&self, algo: HsmHashAlgo) -> HsmResult<usize>;

    /// Begins a multi-step HMAC computation in caller-provided storage.
    ///
    /// Derives the inner (ipad) and outer (opad) keys from `key` per
    /// RFC 2104, submits the ipad block as the first SHA input, and
    /// stores the opad-keyed prefix in the returned context for use
    /// at finalisation.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — underlying hash algorithm.
    /// - `key` — HMAC key bytes; keys longer than
    ///   `algo.block_len()` are first hashed.
    /// - `state` — storage of at least [`hmac_state_size`](Self::hmac_state_size)
    ///   bytes, 4-byte aligned when the required size is nonzero.
    ///   Only the required prefix may be modified.
    ///
    /// # Returns
    ///
    /// - `Ok(ctx)` — initialized HMAC context.
    /// - `Err(HsmError::InvalidArg)` — storage is too short or misaligned.
    /// - `Err(HsmError::NotEnoughSpace)` — internal initialization
    ///   scratch cannot be allocated.
    /// - `Err(HsmError)` — SHA driver failure during the ipad
    ///   prelude.
    ///
    /// The key is not borrowed after initialization. The storage owner
    /// must reclaim and scrub backing storage on finish, abort, or session
    /// teardown. Dropping the context does not reclaim or scrub caller storage.
    async fn hmac_begin<'a>(
        &self,
        io: &Self::Io,
        algo: HsmHashAlgo,
        key: &HsmDmaBuf,
        state: &'a mut HsmDmaBuf,
    ) -> HsmResult<Self::HmacCtx<'a>>
    where
        Self: 'a;

    /// Feed arbitrary-length data into a running HMAC.
    ///
    /// May be called any number of times (including zero) between
    /// [`hmac_begin`](Self::hmac_begin) and the chosen finaliser.
    /// Implementations buffer a partial trailing block and submit
    /// full blocks to the SHA engine as soon as they accumulate.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — context returned by
    ///   [`hmac_begin`](Self::hmac_begin).
    /// - `data` — message bytes to append.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_continue(
        &self,
        io: &Self::Io,
        ctx: &mut Self::HmacCtx<'_>,
        data: &HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Finalise the inner hash, compute the outer hash, and write
    /// the resulting tag into `tag`, or query the tag length.
    ///
    /// Queries and short-output errors leave the context unchanged. Once
    /// execution starts, the context rejects updates and finalization, even
    /// if execution fails or is cancelled. Native resources are released on
    /// finalization or context drop.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — active context to query or finalise.
    /// - `tag` — `None` queries the tag length; an output buffer must be at least
    ///   `algo.digest_len()` bytes.  Only the leading `digest_len`
    ///   bytes are written.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required tag length or bytes written.
    /// - `Err(HsmError::InvalidArg)` — inactive context or `tag` too short.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_finish(
        &self,
        io: &Self::Io,
        ctx: &mut Self::HmacCtx<'_>,
        tag: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Finalise the HMAC and write the tag directly to `dest`.
    ///
    /// Identical to [`hmac_finish`](Self::hmac_finish) except the
    /// SHA hardware DMA writes the outer-hash digest straight into
    /// `dest` rather than into the context's state buffer.  This
    /// elides a `copy_from_slice` when the caller already has a
    /// destination in mind (e.g. KDF iterations).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — active context to query or finalise.
    /// - `dest` — `None` queries the full tag length without changing state.
    ///   `Some` writes up to `algo.digest_len()` bytes, truncating to the
    ///   buffer length when shorter. Any tail after the full tag is unchanged.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — full tag length in query mode or actual bytes written.
    /// - `Err(HsmError::InvalidArg)` — context is inactive.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_finish_into(
        &self,
        io: &Self::Io,
        ctx: &mut Self::HmacCtx<'_>,
        dest: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Finalise and verify the running HMAC against an expected
    /// `tag` using hardware constant-time comparison.  Consumes
    /// `ctx`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — context to finalise (consumed).
    /// - `tag` — expected MAC tag.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — tag matches.
    /// - `Ok(false)` — tag does not match (not an error).
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_finish_verify(
        &self,
        io: &Self::Io,
        ctx: Self::HmacCtx<'_>,
        tag: &HsmDmaBuf,
    ) -> HsmResult<bool>;
}
