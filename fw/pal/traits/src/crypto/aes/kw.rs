// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES Key Wrap (RFC 3394) and Key Wrap with Padding (RFC 5649) trait
//! for the HSM PAL.

use super::*;

/// Asynchronous AES key wrap operations trait.
///
/// PAL implementations provide this to the core for AES-KW and AES-KWP
/// key wrapping and unwrapping. The async signatures allow
/// hardware-backed implementations to yield while the AES engine
/// processes data.
///
/// All methods take `io` as their second parameter so callers can forward
/// the operation-scoped [`HsmIo`] context through the PAL crypto stack.
pub trait HsmAesKw: HsmIoTypes {
    // ── AES Key Wrap (RFC 3394) ────────────────────────────────────

    /// AES Key Wrap (RFC 3394) — wrap key data.
    ///
    /// Wraps `input` under the KEK `key`.  The output prepends the
    /// 8-byte default integrity check value
    /// `0xA6A6A6A6A6A6A6A6` to the wrapped semiblocks.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `input` — plaintext key material.  Must be ≥ 16 bytes,
    ///   a multiple of 8, and at most 3072 bytes.
    /// - `output` — destination; must be at least
    ///   `input.len() + 8` bytes. Pass `None` to validate the inputs
    ///   and query the output length without wrapping.
    ///
    /// # Returns
    ///
    /// - `Ok(input.len() + 8)` — the wrapped length; when `output` is
    ///   `Some`, `output[..input.len() + 8]` is populated.
    /// - `Err(HsmError::InvalidArg)` — size or alignment
    ///   constraints violated.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kw_wrap(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// AES Key Wrap (RFC 3394) — wrap key data in place.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `buf` — `[reserved (8) | plaintext]`.  The plaintext
    ///   (`buf[8..]`) must satisfy the [`Self::aes_kw_wrap`] input
    ///   constraints; the first 8 bytes are overwritten.
    ///
    /// # Returns
    ///
    /// - `Ok(buf.len())` — `buf` holds the wrapped key.
    /// - `Err(HsmError::InvalidArg)` — size or alignment
    ///   constraints violated.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kw_wrap_in_place(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<usize>;

    /// AES Key Wrap (RFC 3394) — unwrap key data.
    ///
    /// Unwraps `input` under the KEK `key` and verifies the
    /// integrity check value matches the default `0xA6A6…`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `input` — wrapped key data.  Must be ≥ 24 bytes,
    ///   a multiple of 8, and at most 3080 bytes.
    /// - `output` — destination; must be at least
    ///   `input.len() - 8` bytes. Pass `None` to validate the inputs
    ///   and query the output length without unwrapping.
    ///
    /// # Returns
    ///
    /// - `Ok(input.len() - 8)` — the unwrapped length; when `output`
    ///   is `Some`, `output[..input.len() - 8]` is populated.
    /// - `Err(HsmError::InvalidArg)` — size or alignment
    ///   constraints violated.
    /// - `Err(HsmError::AesUnwrapFailed)` — IV mismatch (wrong
    ///   key or tampered ciphertext).
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kw_unwrap(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// AES Key Wrap (RFC 3394) — unwrap key data in place.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `buf` — wrapped key data satisfying the
    ///   [`Self::aes_kw_unwrap`] input constraints.
    ///
    /// # Returns
    ///
    /// - `Ok(buf.len() - 8)` — `buf[..buf.len() - 8]` holds the
    ///   unwrapped key; the trailing 8 bytes are unspecified.
    /// - `Err(HsmError::InvalidArg)` — size or alignment
    ///   constraints violated.
    /// - `Err(HsmError::AesUnwrapFailed)` — IV mismatch (wrong
    ///   key or tampered ciphertext).
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kw_unwrap_in_place(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<usize>;

    // ── AES Key Wrap with Padding (RFC 5649) ───────────────────────

    /// AES Key Wrap with Padding (RFC 5649) — wrap key data of any
    /// length.
    ///
    /// Pads `input` to an 8-byte boundary and uses an Alternative
    /// Initial Value (AIV) that encodes the plaintext length.
    /// Padded payloads of one semiblock use a single AES-ECB pass;
    /// longer payloads delegate to AES-KW with the AIV.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `input` — plaintext (1..=3072 bytes, any alignment).
    /// - `output` — destination; must be at least
    ///   `round_up_8(input.len()) + 8` bytes. Pass `None` to validate
    ///   the inputs and query the output length without wrapping.
    ///
    /// # Returns
    ///
    /// - `Ok(round_up_8(input.len()) + 8)` — the wrapped length; when
    ///   `output` is `Some`, that prefix of `output` is populated.
    /// - `Err(HsmError::InvalidArg)` — size constraints violated.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kwp_wrap(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// AES Key Wrap with Padding (RFC 5649) — wrap key data in place.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `data_len` — plaintext length (1..=3072).
    /// - `buf` — `[reserved (8) | plaintext (data_len) | pad room]`;
    ///   must be at least `round_up_8(data_len) + 8` bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(round_up_8(data_len) + 8)` — that prefix of `buf` holds
    ///   the wrapped key.
    /// - `Err(HsmError::InvalidArg)` — size constraints violated.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kwp_wrap_in_place(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        data_len: usize,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<usize>;

    /// AES Key Wrap with Padding (RFC 5649) — unwrap key data.
    ///
    /// Verifies the AIV (constant prefix + Message Length
    /// Indicator) and that all trailing pad bytes are zero.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `input` — wrapped key data.  Must be ≥ 16 bytes, a
    ///   multiple of 8, and at most 3080 bytes.
    /// - `output` — destination; must be at least
    ///   `input.len() - 8` bytes. Pass `None` to validate the inputs
    ///   and query the maximum output length without unwrapping.
    ///
    /// # Returns
    ///
    /// - With `output = None`: `Ok(input.len() - 8)`, an upper bound on
    ///   the plaintext length (the exact length is only known after
    ///   the AIV is decrypted).
    /// - With `output = Some`: `Ok(mli)` — the recovered plaintext
    ///   length (the MLI from the AIV); `output[..mli]` is valid
    ///   plaintext.
    /// - `Err(HsmError::InvalidArg)` — size constraints violated.
    /// - `Err(HsmError::AesUnwrapFailed)` — AIV mismatch or
    ///   non-zero pad bytes.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kwp_unwrap(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// AES Key Wrap with Padding (RFC 5649) — unwrap key data in place.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `buf` — wrapped key data satisfying the
    ///   [`Self::aes_kwp_unwrap`] input constraints.
    ///
    /// # Returns
    ///
    /// - `Ok(mli)` — the recovered plaintext length; `buf[..mli]` is
    ///   valid plaintext and the remaining bytes are unspecified.
    /// - `Err(HsmError::InvalidArg)` — size constraints violated.
    /// - `Err(HsmError::AesUnwrapFailed)` — AIV mismatch or
    ///   non-zero pad bytes.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kwp_unwrap_in_place(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<usize>;
}
