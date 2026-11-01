// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-XTS (IEEE 1619 / NIST SP 800-38E) trait for the HSM PAL.
//!
//! The whole buffer passed to an operation is a single data unit: the
//! tweak is not incremented within a call. Only the in-place form is
//! provided; callers transform request buffers where they lie.

use super::*;

/// AES-256-XTS key length in bytes: the data key `K1` followed by the
/// tweak key `K2`, 32 bytes each.
pub const HSM_AES_XTS_KEY_LEN: usize = 64;

/// AES-XTS tweak length in bytes: the 64-bit little-endian data-unit
/// number.
pub const HSM_AES_XTS_TWEAK_LEN: usize = 8;

/// Asynchronous AES-XTS operations trait.
///
/// PAL implementations provide this to the core for AES-XTS key
/// generation, encryption and decryption. The async signatures allow
/// hardware-backed implementations to yield while the AES engine
/// processes data.
///
/// All methods take `io` as their second parameter so callers can forward
/// the operation-scoped [`HsmIo`] context through the PAL crypto stack.
pub trait HsmAesXts: HsmIoTypes {
    /// Generate a random AES-256-XTS key (`K1 || K2`).
    ///
    /// Fills `key` with random bytes and ensures `K1 != K2`, as
    /// IEEE 1619 requires distinct data and tweak keys.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — output buffer; must be exactly [`HSM_AES_XTS_KEY_LEN`]
    ///   bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `key` populated, `K1 != K2`.
    /// - `Err(HsmError::InvalidArg)` — `key.len() != 64`.
    /// - `Err(HsmError)` — propagated from the CSPRNG.
    async fn aes_xts_gen_key(&self, io: &Self::Io, key: &mut [u8]) -> HsmResult<()>;

    /// AES-256-XTS encrypt or decrypt host-to-host over raw SGL
    /// descriptors.
    ///
    /// The AES engine reads `len` bytes (`len / dul` data units) from the
    /// host buffer described by `src` and writes the result (same length)
    /// to the host buffer described by `dst`; nothing is staged in HSM
    /// memory.  The tweak of the first data unit is `tweak`; it increments
    /// by one per subsequent data unit.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope; selects the host
    ///   interface).
    /// - `op` — [`HsmAesOp::Encrypt`] or [`HsmAesOp::Decrypt`].
    /// - `key` — XTS key, exactly [`HSM_AES_XTS_KEY_LEN`] bytes
    ///   (`K1[32] || K2[32]`) with `K1 != K2`.
    /// - `tweak` — exactly [`HSM_AES_XTS_TWEAK_LEN`] bytes: the
    ///   little-endian number of the first data unit.
    /// - `len` — total length: a non-zero multiple of `dul`.
    /// - `dul` — data-unit length: at least 16 and a multiple of 16.
    /// - `src` — raw 16-byte NVMe SGL descriptor of the host input.
    /// - `dst` — raw 16-byte NVMe SGL descriptor of the host output.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — result written to `dst`.
    /// - `Err(HsmError::InvalidArg)` — key or tweak length violation,
    ///   `K1 == K2`, or a descriptor does not describe `len` bytes.
    /// - `Err(HsmError::AesXtsInvalidBufferSize)` — `len` / `dul`
    ///   violation, or `tweak + len / dul` (the tweak after the last data
    ///   unit) would overflow 64 bits.
    /// - `Err(HsmError)` — AES / DMA failure.
    #[allow(clippy::too_many_arguments)]
    async fn aes_xts_enc_dec_sgl(
        &self,
        io: &Self::Io,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        tweak: &HsmDmaBuf,
        len: usize,
        dul: usize,
        src: &[u8; 16],
        dst: &[u8; 16],
    ) -> HsmResult<()>;
}
