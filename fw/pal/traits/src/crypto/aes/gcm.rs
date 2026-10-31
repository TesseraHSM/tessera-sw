// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-GCM authenticated encryption trait for the HSM PAL.

use super::*;

/// Asynchronous AES-GCM operations trait.
///
/// PAL implementations provide this to the core for AES-GCM
/// authenticated encryption and decryption. The async signatures allow
/// hardware-backed implementations to yield while the AES engine
/// processes data.
///
/// All methods take `io` as their second parameter so callers can forward
/// the operation-scoped [`HsmIo`] context through the PAL crypto stack.
pub trait HsmAesGcm: HsmIoTypes {
    /// AES-GCM encrypt with separate input/output buffers.
    ///
    /// Encrypts the text portion of `plaintext` using AES-GCM and writes
    /// the result to `ciphertext` and the authentication tag to `tag`.
    /// Data does not need to be 16-byte-aligned — the PAL handles
    /// alignment and tag correction internally.
    ///
    /// # Buffer layout
    ///
    /// Both `plaintext` and `ciphertext` use the layout
    /// `[padded_AAD | text]`, where `padded_AAD` is the AAD region
    /// prepared according to the `pad_aad` GHASH-alignment convention:
    ///
    /// | `aad_len % 32` | Layout |
    /// |----------------|--------|
    /// | `== 0` | `[AAD]` — no padding |
    /// | `1..=16` | `[zeros(16) \| AAD \| zeros(32 - 16 - rem)]` — prepend 16 zero bytes, AAD left-justified after, trail-pad to next 32 |
    /// | `17..=31` | `[AAD \| zeros(32 - rem)]` — AAD left-justified, trail-pad to next 32 |
    ///
    /// The total padded AAD region is always `round_up_32(aad_len)` bytes.
    /// When `aad_len` is `0`, no AAD region is present and `data` contains
    /// only the text.
    ///
    /// The prepend-zeros rule ensures the leading GHASH block is all zeros
    /// (transparent to the GHASH accumulator), so the AAD content occupies
    /// the same GHASH-block positions as standard GCM. This allows the
    /// PAL to correct the hardware tag with a simple length-field fixup.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce. Must be unique per encryption
    ///   with the same key.
    /// - `aad_len` — **Unpadded** AAD length in bytes. The padded AAD
    ///   region in the buffer is `round_up_32(aad_len)` bytes.
    /// - `plaintext` — `[padded_AAD | plaintext_bytes]`.
    /// - `ciphertext` — Destination. Must be at least `plaintext.len()`.
    /// - `tag` — Output buffer for the 16-byte authentication tag.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `ciphertext[..plaintext.len()]` populated, `tag`
    ///   set.
    /// - `Err(HsmError::InvalidArg)` — buffer-size violation, IV not
    ///   12 bytes, or AAD layout malformed.
    /// - `Err(HsmError)` — AES driver failure.
    #[allow(clippy::too_many_arguments)]
    async fn gcm_encrypt(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        plaintext: &HsmDmaBuf,
        ciphertext: &mut HsmDmaBuf,
        tag: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// AES-GCM encrypt in-place.
    ///
    /// Reads plaintext from and writes ciphertext to the same `data`
    /// buffer. The authentication tag is written to `tag`. This avoids
    /// an extra buffer allocation and is the natural model for hardware
    /// engines that operate directly on DMA buffers.
    ///
    /// # Buffer layout
    ///
    /// `data` uses the layout `[padded_AAD | text]`. See
    /// [`gcm_encrypt`](Self::gcm_encrypt) for the full `pad_aad`
    /// convention. The padded AAD region occupies the first
    /// `round_up_32(aad_len)` bytes; the remaining bytes are plaintext
    /// (overwritten with ciphertext on return).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce. Must be unique per encryption
    ///   with the same key.
    /// - `aad_len` — **Unpadded** AAD length in bytes.
    /// - `data` — `[padded_AAD | plaintext]`; the text portion is
    ///   overwritten with ciphertext.
    /// - `tag` — Output buffer for the 16-byte authentication tag.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `data` text portion overwritten, `tag` set.
    /// - `Err(HsmError::InvalidArg)` — buffer-size violation, IV not
    ///   12 bytes, or AAD layout malformed.
    /// - `Err(HsmError)` — AES driver failure.
    async fn gcm_encrypt_in_place(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        data: &mut HsmDmaBuf,
        tag: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// AES-GCM decrypt with separate input/output buffers.
    ///
    /// Decrypts the text portion of `ciphertext` using AES-GCM and writes
    /// the result to `plaintext`. Verifies the authentication tag before
    /// returning.
    ///
    /// # Buffer layout
    ///
    /// Both `ciphertext` and `plaintext` use the layout
    /// `[padded_AAD | text]`. See [`gcm_encrypt`](Self::gcm_encrypt) for
    /// the full `pad_aad` convention.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce used during encryption.
    /// - `aad_len` — **Unpadded** AAD length in bytes. Must match the
    ///   value supplied during encryption.
    /// - `tag` — The 16-byte authentication tag from encryption.
    /// - `ciphertext` — `[padded_AAD | ciphertext_bytes]`.
    /// - `plaintext` — Destination. Must be at least `ciphertext.len()`.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — tag verified and `plaintext[..ciphertext.len()]`
    ///   populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size violation or AAD
    ///   layout malformed.
    /// - `Err(HsmError::AesGcmTagMismatch)` — authentication tag
    ///   does not match.
    /// - `Err(HsmError)` — AES driver failure.
    #[allow(clippy::too_many_arguments)]
    async fn gcm_decrypt(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        tag: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        plaintext: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// AES-GCM decrypt in-place.
    ///
    /// Reads ciphertext from and writes plaintext to the same `data`
    /// buffer. Verifies the authentication tag before returning. This
    /// avoids an extra buffer allocation and is the natural model for
    /// hardware engines that operate directly on DMA buffers.
    ///
    /// # Buffer layout
    ///
    /// `data` uses the layout `[padded_AAD | text]`. See
    /// [`gcm_encrypt`](Self::gcm_encrypt) for the full `pad_aad`
    /// convention. The padded AAD region occupies the first
    /// `round_up_32(aad_len)` bytes; the remaining bytes are ciphertext
    /// (overwritten with plaintext on return).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce used during encryption.
    /// - `aad_len` — **Unpadded** AAD length in bytes. Must match the
    ///   value supplied during encryption.
    /// - `tag` — The 16-byte authentication tag from encryption.
    /// - `data` — `[padded_AAD | ciphertext]`; the text portion is
    ///   overwritten with plaintext.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — tag verified, `data` text portion overwritten
    ///   with plaintext.
    /// - `Err(HsmError::InvalidArg)` — buffer-size violation or AAD
    ///   layout malformed.
    /// - `Err(HsmError::AesGcmTagMismatch)` — authentication tag
    ///   does not match (`data` is left in an unspecified state).
    /// - `Err(HsmError)` — AES driver failure.
    async fn gcm_decrypt_in_place(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        tag: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()>;
}
