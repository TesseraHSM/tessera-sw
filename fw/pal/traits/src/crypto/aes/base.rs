// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES key generation and confidentiality-mode trait for the HSM PAL.
//!
//! Defines the [`HsmAes`] trait that PAL implementations use to expose
//! AES key generation, the generic multi-mode
//! [`aes_enc_dec`](HsmAes::aes_enc_dec) operation
//! (CBC / ECB / CFB-128 / OFB / CTR) and the legacy ECB/CBC entry points.
//!
//! ## Generic encrypt / decrypt layout
//!
//! The generic operation follows the tiger `AesOp` buffer layout:
//!
//! | Buffer   | Layout                                           |
//! |----------|--------------------------------------------------|
//! | `input`  | `[IV (mode.iv_len() bytes) \| data]`             |
//! | `output` | `[data (same length) \| IV out (mode.iv_len())]` |
//!
//! The output IV is the chaining value for a follow-up call:
//!
//! | Mode | IV out                                                  |
//! |------|---------------------------------------------------------|
//! | CBC  | last ciphertext block                                   |
//! | ECB  | none (no IV)                                            |
//! | CFB  | last complete ciphertext block (input IV if none)       |
//! | OFB  | last keystream block                                    |
//! | CTR  | next counter block (`IV + ceil(len / 16)`, 128-bit BE)  |
//!
//! Chaining is only meaningful when every call except the last processes a
//! multiple of 16 bytes.
//!
//! ## Encrypt / decrypt unification
//!
//! CBC and ECB methods take an [`HsmAesOp`] selector instead of having
//! separate `_encrypt` / `_decrypt` methods. This reduces trait
//! surface while keeping the operation direction explicit at the call
//! site.

use super::*;

/// AES encrypt/decrypt operation selector.
///
/// Discriminants match the tiger CPT `minor_opcode` bit 0.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmAesOp {
    /// Encrypt the input.
    Encrypt = 0,

    /// Decrypt the input.
    Decrypt = 1,
}

/// AES confidentiality mode for
/// [`aes_enc_dec`](HsmAes::aes_enc_dec).
///
/// Discriminants match tiger `AesMode` / CPT `param1[3:0]`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmAesMode {
    /// Cipher block chaining; data must be a multiple of 16 bytes.
    Cbc = 0,

    /// Electronic codebook; no IV, data must be a multiple of 16 bytes.
    Ecb = 1,

    /// 128-bit cipher feedback; any data length.
    Cfb = 2,

    /// Output feedback; any data length.
    Ofb = 3,

    /// Counter mode with a 128-bit big-endian counter; any data length.
    Ctr = 4,
}

impl HsmAesMode {
    /// AES block size in bytes.
    pub const BLOCK_SIZE: usize = 16;

    /// Length of the IV carried in the input and output buffers.
    pub const fn iv_len(self) -> usize {
        match self {
            Self::Ecb => 0,
            _ => Self::BLOCK_SIZE,
        }
    }

    /// Whether the data length must be a multiple of [`Self::BLOCK_SIZE`].
    pub const fn is_block_mode(self) -> bool {
        matches!(self, Self::Cbc | Self::Ecb)
    }

    /// Returns the data length carried in an `[IV | data]` input of
    /// `input_len` bytes, or `None` if the length is invalid for this mode.
    pub const fn data_len(self, input_len: usize) -> Option<usize> {
        let Some(len) = input_len.checked_sub(self.iv_len()) else {
            return None;
        };
        if self.is_block_mode() && len % Self::BLOCK_SIZE != 0 {
            return None;
        }
        Some(len)
    }
}

/// Asynchronous AES operations trait.
///
/// PAL implementations provide this to the core for AES key generation
/// and block cipher operations. The async signatures allow hardware-backed
/// implementations to yield while the AES engine processes data.
///
/// All methods take `io` as their second parameter so callers can forward
/// the operation-scoped [`HsmIo`] context through the PAL crypto stack.
pub trait HsmAes: HsmIoTypes {
    /// Generate a random AES key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — output buffer; entirely filled with random bytes.
    ///   Buffer length determines key size: 16 / 24 / 32 bytes for
    ///   AES-128 / 192 / 256 respectively.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `key` populated.
    /// - `Err(HsmError::InvalidArg)` — `key.len()` is not 16, 24, or 32.
    /// - `Err(HsmError)` — propagated from the CSPRNG.
    async fn aes_gen_key(&self, io: &Self::Io, key: &mut [u8]) -> HsmResult<()>;

    /// Generic AES encrypt or decrypt in any [`HsmAesMode`].
    ///
    /// See the [module docs](self) for the buffer layout and IV-out
    /// semantics.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `op` — [`HsmAesOp::Encrypt`] or [`HsmAesOp::Decrypt`].
    /// - `mode` — confidentiality mode.
    /// - `key` — AES key (16 / 24 / 32 bytes).
    /// - `input` — `[IV | data]`; see [`HsmAesMode::data_len`].
    /// - `output` — receives `[data | IV out]`; must be at least
    ///   `input.len()` bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output[..input.len()]` populated.
    /// - `Err(HsmError::InvalidArg)` — key, IV, alignment or buffer-size
    ///   violation; `output` is not modified.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_enc_dec(
        &self,
        io: &Self::Io,
        op: HsmAesOp,
        mode: HsmAesMode,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// In-place variant of
    /// [`aes_enc_dec`](Self::aes_enc_dec).
    ///
    /// `buf` holds `[IV | data]` on entry and `[data | IV out]` on return,
    /// so a request buffer can be turned into a response without a second
    /// allocation.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `buf` overwritten with the result.
    /// - `Err(HsmError::InvalidArg)` — key, IV or alignment violation;
    ///   `buf` is not modified.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_enc_dec_in_place(
        &self,
        io: &Self::Io,
        op: HsmAesOp,
        mode: HsmAesMode,
        key: &HsmDmaBuf,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// AES-CBC encrypt or decrypt with separate input / output buffers.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `op` — [`HsmAesOp::Encrypt`] or [`HsmAesOp::Decrypt`].
    /// - `key` — AES key (16 / 24 / 32 bytes).
    /// - `input` — source bytes; length must be a multiple of 16.
    /// - `iv_in` — 16-byte IV used for this request.
    /// - `output` — destination; must be at least `input.len()` bytes.
    /// - `iv_out` — optional destination for the updated chaining IV.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output[..input.len()]` populated and `iv_out`
    ///   updated when provided.
    /// - `Err(HsmError::InvalidArg)` — buffer-size or alignment
    ///   violation.
    /// - `Err(HsmError)` — AES driver failure.
    #[allow(clippy::too_many_arguments)]
    async fn aes_cbc_enc_dec(
        &self,
        io: &Self::Io,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        iv_in: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
        iv_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<()>;

    /// AES-CBC encrypt or decrypt in-place.
    ///
    /// Identical to [`aes_cbc_enc_dec`](Self::aes_cbc_enc_dec) but the
    /// transform is applied to a single buffer.  This avoids a second
    /// allocation and is the natural shape for hardware engines that
    /// operate directly on DMA buffers.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `op` — [`HsmAesOp::Encrypt`] or [`HsmAesOp::Decrypt`].
    /// - `key` — AES key (16 / 24 / 32 bytes).
    /// - `data` — input on entry, output on return; length must
    ///   be a multiple of 16.
    /// - `iv_in` — 16-byte IV used for this request.
    /// - `iv_out` — optional destination for the updated chaining IV.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `data` overwritten with the result and `iv_out`
    ///   updated when provided.
    /// - `Err(HsmError::InvalidArg)` — buffer-size or alignment
    ///   violation.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_cbc_enc_dec_in_place(
        &self,
        io: &Self::Io,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
        iv_in: &HsmDmaBuf,
        iv_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<()>;

    /// AES-ECB encrypt or decrypt with separate input / output
    /// buffers.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `op` — [`HsmAesOp::Encrypt`] or [`HsmAesOp::Decrypt`].
    /// - `key` — AES key (16 / 24 / 32 bytes).
    /// - `input` — source block(s); length must be a multiple of
    ///   16.
    /// - `output` — destination; must be at least `input.len()`
    ///   bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output[..input.len()]` populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size or alignment
    ///   violation.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_ecb_enc_dec(
        &self,
        io: &Self::Io,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// AES-ECB encrypt or decrypt in-place.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `op` — [`HsmAesOp::Encrypt`] or [`HsmAesOp::Decrypt`].
    /// - `key` — AES key (16 / 24 / 32 bytes).
    /// - `data` — input on entry, output on return; length must
    ///   be a multiple of 16.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `data` overwritten with the result.
    /// - `Err(HsmError::InvalidArg)` — buffer-size or alignment
    ///   violation.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_ecb_enc_dec_in_place(
        &self,
        io: &Self::Io,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()>;
}
