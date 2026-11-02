// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-XTS (IEEE 1619 / NIST SP 800-38E) trait for the HSM PAL.
//!
//! AES-XTS support is currently disabled. The data unit length selector
//! and trait entry points are retained here, commented out, for future
//! re-enablement.

use super::*;

// ── AES-XTS data unit length ──────────────────────────────────────
// /// XTS data unit length.
// ///
// /// Controls how the hardware segments the input into data units and
// /// increments the tweak between them. The input length must be a
// /// multiple of the selected data unit length.
// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub enum XtsDataUnitLen {
//     /// Entire input is a single data unit.
//     Full,
//
//     /// 512-byte blocks.
//     Block512,
//
//     /// 4096-byte blocks.
//     Block4K,
//
//     /// 8192-byte blocks.
//     Block8K,
// }

/// Asynchronous AES-XTS operations trait.
///
/// PAL implementations provide this to the core for AES-XTS encryption
/// and decryption. The async signatures allow hardware-backed
/// implementations to yield while the AES engine processes data.
///
/// All methods take `io` as their second parameter so callers can forward
/// the operation-scoped [`HsmIo`] context through the PAL crypto stack.
pub trait HsmAesXts: HsmIoTypes {
    // ── AES-XTS (IEEE 1619 / NIST SP 800-38E) ─────────────────────
    //
    // /// Generate a random AES-256-XTS key (`K1 || K2`).
    // ///
    // /// Fills `key` with 64 random bytes and ensures `K1 ≠ K2` (XTS
    // /// requires distinct halves; the standard prohibits a tweak
    // /// degenerate case).
    // ///
    // /// # Parameters
    // ///
    // /// - `io` — caller's I/O context (per-IO scope).
    // /// - `key` — output buffer; must be exactly 64 bytes.
    // ///
    // /// # Returns
    // ///
    // /// - `Ok(())` — `key` populated, `K1 ≠ K2`.
    // /// - `Err(HsmError::InvalidArg)` — `key.len() != 64`.
    // /// - `Err(HsmError)` — propagated from the CSPRNG.
    // async fn aes_xts_gen_key(&self, io: &Self::Io, key: &mut [u8]) -> HsmResult<()>;
    //
    // /// AES-XTS encrypt with separate input / output buffers
    // /// (IEEE 1619 / NIST SP 800-38E).
    // ///
    // /// # Parameters
    // ///
    // /// - `io` — caller's I/O context (per-IO scope).
    // /// - `key` — XTS key, exactly 64 bytes (`K1[32] || K2[32]`).
    // /// - `tweak` — 8-byte tweak (typically a little-endian sector
    // ///   number).
    // /// - `dul` — data-unit length selector; controls how the
    // ///   tweak is incremented.
    // /// - `input` — plaintext.  Must be ≥ 16 bytes, a multiple of
    // ///   16, and a multiple of `dul.bytes()` when `dul` is not
    // ///   [`XtsDataUnitLen::Full`].
    // /// - `output` — destination; must be at least
    // ///   `input.len()` bytes.
    // ///
    // /// # Returns
    // ///
    // /// - `Ok(())` — `output[..input.len()]` populated.
    // /// - `Err(HsmError::InvalidArg)` — size or alignment
    // ///   violation, or `K1 == K2`.
    // /// - `Err(HsmError)` — AES driver failure.
    // async fn aes_xts_encrypt(
    //     &self,
    //     io: &Self::Io,
    //     key: &HsmDmaBuf,
    //     tweak: &HsmDmaBuf,
    //     dul: XtsDataUnitLen,
    //     input: &HsmDmaBuf,
    //     output: &mut HsmDmaBuf,
    // ) -> HsmResult<()>;
    //
    // /// AES-XTS decrypt with separate input / output buffers.
    // ///
    // /// Parameter and return semantics match
    // /// [`aes_xts_encrypt`](Self::aes_xts_encrypt) with the
    // /// direction reversed; `input` is ciphertext and `output`
    // /// receives plaintext.
    // async fn aes_xts_decrypt(
    //     &self,
    //     io: &Self::Io,
    //     key: &HsmDmaBuf,
    //     tweak: &HsmDmaBuf,
    //     dul: XtsDataUnitLen,
    //     input: &HsmDmaBuf,
    //     output: &mut HsmDmaBuf,
    // ) -> HsmResult<()>;
    //
    // /// AES-XTS encrypt in-place.
    // ///
    // /// # Parameters
    // ///
    // /// - `io` — caller's I/O context (per-IO scope).
    // /// - `key` — XTS key, exactly 64 bytes (`K1[32] || K2[32]`).
    // /// - `tweak` — 8-byte tweak.
    // /// - `dul` — data-unit length selector.
    // /// - `data` — plaintext on entry, ciphertext on return; must
    // ///   be ≥ 16 bytes, a multiple of 16, and a multiple of
    // ///   `dul.bytes()` when `dul` is not [`XtsDataUnitLen::Full`].
    // ///
    // /// # Returns
    // ///
    // /// - `Ok(())` — `data` overwritten with ciphertext.
    // /// - `Err(HsmError::InvalidArg)` — size or alignment
    // ///   violation, or `K1 == K2`.
    // /// - `Err(HsmError)` — AES driver failure.
    // async fn aes_xts_encrypt_in_place(
    //     &self,
    //     io: &Self::Io,
    //     key: &HsmDmaBuf,
    //     tweak: &HsmDmaBuf,
    //     dul: XtsDataUnitLen,
    //     data: &mut HsmDmaBuf,
    // ) -> HsmResult<()>;
    //
    // /// AES-XTS decrypt in-place.
    // ///
    // /// Parameter and return semantics match
    // /// [`aes_xts_encrypt_in_place`](Self::aes_xts_encrypt_in_place)
    // /// with the direction reversed; `data` holds ciphertext on
    // /// entry and plaintext on return.
    // async fn aes_xts_decrypt_in_place(
    //     &self,
    //     io: &Self::Io,
    //     key: &HsmDmaBuf,
    //     tweak: &HsmDmaBuf,
    //     dul: XtsDataUnitLen,
    //     data: &mut HsmDmaBuf,
    // ) -> HsmResult<()>;
}
