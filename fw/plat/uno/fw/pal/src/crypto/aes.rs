// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES (ECB, CBC, CFB, OFB, CTR, GCM, and KW/KWP) trait implementations
//! for the Uno PAL.
//!
//! This module is organized as follows:
//!
//! 1. Constants and module-level helpers.
//! 2. Private `impl UnoHsmPal` — internal AES driver wrappers.
//! 3. `impl HsmAes` / `HsmAesGcm` / `HsmAesKw` / `HsmAesXts` for
//!    `UnoHsmPal` — the public trait surfaces.

#![allow(clippy::unused_async)]

use core::slice;

use tsra_fw_hsm_pal_traits::HsmAes;
use tsra_fw_hsm_pal_traits::HsmAesGcm;
use tsra_fw_hsm_pal_traits::HsmAesKw;
use tsra_fw_hsm_pal_traits::HsmAesMode;
use tsra_fw_hsm_pal_traits::HsmAesOp;
use tsra_fw_hsm_pal_traits::HsmAesXts;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_uno_drivers_aes::AesMode;
use tsra_fw_uno_drivers_aes::AesOp as DriverAesOp;
use tsra_fw_uno_drivers_aes::AesRequest;

use super::gcm::GCM_IV_LEN;
use super::gcm::GCM_TAG_LEN;
use crate::UnoHsmIo;
use crate::UnoHsmPal;

// =============================================================================
// Constants
// =============================================================================

/// AES block size in bytes (128 bits / 16 bytes).
///
/// All AES modes implemented here (ECB, CBC) require message lengths that
/// are a whole multiple of this value. Re-exported `pub(super)` so
/// Public so downstream PAL extension crates can re-use it for block math.
pub const AES_BLOCK_SIZE: usize = 16;

// =============================================================================
// Module-level helpers
// =============================================================================

/// Map the PAL AES direction selector to the AES driver enum.
#[inline]
fn aes_op(op: HsmAesOp) -> DriverAesOp {
    match op {
        HsmAesOp::Encrypt => DriverAesOp::Encrypt,
        HsmAesOp::Decrypt => DriverAesOp::Decrypt,
    }
}

/// Validate that a buffer pair is acceptable for an AES-ECB / AES-CBC
/// operation.
///
/// # Parameters
/// * `input` — source buffer. Must be non-empty and a whole multiple of
///   [`AES_BLOCK_SIZE`].
/// * `output_len` — length of the destination buffer in bytes. Must be at
///   least `input.len()`.
///
/// # Returns
/// * `Ok(())` when all length constraints are satisfied.
///
/// # Errors
/// * [`HsmError::InvalidArg`] if `input` is empty, not a multiple of
///   [`AES_BLOCK_SIZE`], or the destination is shorter than the source.
fn require_block_multiple(input: &[u8], output_len: usize) -> HsmResult<()> {
    if input.is_empty() || !input.len().is_multiple_of(AES_BLOCK_SIZE) || output_len < input.len() {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Map the PAL generic AES mode to the AES driver (hardware) mode.
#[inline]
fn hw_mode(mode: HsmAesMode) -> AesMode {
    match mode {
        HsmAesMode::Cbc => AesMode::Cbc,
        HsmAesMode::Ecb => AesMode::Ecb,
        HsmAesMode::Cfb => AesMode::Cfb,
        HsmAesMode::Ofb => AesMode::Ofb,
        HsmAesMode::Ctr => AesMode::Ctr,
    }
}

/// Validates a generic-mode `[IV | data]` buffer of `len` bytes and returns
/// `(iv_len, data_len)`.
fn generic_lens(mode: HsmAesMode, key_len: usize, len: usize) -> HsmResult<(usize, usize)> {
    if !matches!(key_len, 16 | 24 | 32) {
        return Err(HsmError::InvalidArg);
    }
    let data_len = mode.data_len(len).ok_or(HsmError::InvalidArg)?;
    Ok((mode.iv_len(), data_len))
}

/// Copies one AES block out of `buf` starting at `offset`.
#[inline]
fn block_at(buf: &[u8], offset: usize) -> [u8; AES_BLOCK_SIZE] {
    let mut block = [0u8; AES_BLOCK_SIZE];
    block.copy_from_slice(&buf[offset..offset + AES_BLOCK_SIZE]);
    block
}

#[inline]
fn require_cbc_iv(iv: &[u8]) -> HsmResult<()> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Build an immutable slice that aliases the same memory as some other
/// `&mut [u8]` borrow held by the caller.
///
/// Used to feed both the source and the destination of an in-place hardware
/// submission. The hardware engines exposed through this PAL read each input
/// chunk from `src` before writing
/// the corresponding output chunk to `dst`, which makes the aliased borrow
/// sound for the lifetime of the submission.
///
/// Takes raw `(ptr, len)` rather than a `&mut [u8]` so the caller can keep
/// its own mutable borrow on the same buffer alive across the call site.
///
/// # Type parameters
/// * `'a` — lifetime of the returned slice. Inferred at the call site to
///   match whichever borrow keeps the underlying memory live.
///
/// # Parameters
/// * `ptr` — start address of the buffer.
/// * `len` — length in bytes of the buffer at `ptr`.
///
/// # Returns
/// * `&'a [u8]` of length `len` that aliases the memory at `ptr`.
///
/// # Safety
///
/// The caller must ensure that:
/// * `ptr` points to `len` valid bytes for the duration of `'a`;
/// * the resulting slice is only handed to a hardware path that reads
///   before it writes the corresponding output bytes; and
/// * no Rust code observes the aliased slice while the underlying buffer
///   is being mutated.
#[inline]
pub(super) unsafe fn alias_immutable<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    // Safety: forwarded to the caller — see the function-level docs.
    unsafe { slice::from_raw_parts(ptr, len) }
}

// =============================================================================
// AES driver wrappers
// =============================================================================

impl UnoHsmPal {
    /// Issue a single AES request through the AES driver and await its
    /// completion.
    ///
    /// `iv = Some(_)` selects CBC-style chaining (and is updated in-place by
    /// the driver after each block). `iv = None` selects ECB-style operation.
    ///
    /// Public so downstream PAL extension crates can use it for tag-correction
    /// pre-computation (single AES-ECB block encrypts).
    ///
    /// # Parameters
    /// * `mode` — [`AesMode::Cbc`] or [`AesMode::Ecb`].
    /// * `op` — [`DriverAesOp::Encrypt`] or [`DriverAesOp::Decrypt`].
    /// * `key` — AES key. Must be 16, 24, or 32 bytes (AES-128/192/256);
    ///   the AES driver itself enforces this.
    /// * `iv` — Optional 16-byte IV. Required for CBC, must be `None` for
    ///   ECB. When provided it is updated in-place to the last
    ///   ciphertext/plaintext block so callers can chain across submissions.
    /// * `message` — Source buffer. Length must be a whole multiple of
    ///   [`AES_BLOCK_SIZE`].
    /// * `result` — Destination buffer. Must be at least `message.len()`
    ///   bytes long.
    ///
    /// # Returns
    /// * `Ok(())` on a successful submission and completion. The decrypted
    ///   or encrypted bytes are written to `result`.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the AES driver (queue full, key
    ///   length, IV length, hardware fault, etc.).
    pub async fn aes_run(
        &self,
        mode: AesMode,
        op: DriverAesOp,
        key: &HsmDmaBuf,
        iv: Option<&mut HsmDmaBuf>,
        message: &HsmDmaBuf,
        result: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let update_iv = iv.is_some();
        self.aes
            .encrypt_decrypt(AesRequest {
                mode,
                op,
                key,
                iv,
                update_iv,
                message: Some(message),
                result,
            })
            .await
    }

    /// In-place AES-ECB / AES-CBC over a multi-block buffer.
    ///
    /// The AES engine accepts the full buffer in a single DMA submission and
    /// processes blocks sequentially, reading block N before writing block N.
    /// That ordering makes it sound for the message and result regions to
    /// alias the same memory, avoiding any per-block ping-pong loop.
    ///
    /// # Parameters
    /// * `mode` — [`AesMode::Cbc`] or [`AesMode::Ecb`].
    /// * `op` — [`HsmAesOp::Encrypt`] or [`HsmAesOp::Decrypt`].
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `iv` — Optional 16-byte IV (required for CBC, `None` for ECB).
    ///   Updated in-place when present.
    /// * `data` — Buffer holding the plaintext on input; overwritten with
    ///   the corresponding ciphertext (or vice versa) on completion. Length
    ///   must be a whole multiple of [`AES_BLOCK_SIZE`].
    ///
    /// # Returns
    /// * `Ok(())` on a successful submission and completion. `data` now
    ///   contains the transformed bytes.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by [`Self::aes_run`].
    async fn aes_run_in_place(
        &self,
        mode: AesMode,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        iv: Option<&mut HsmDmaBuf>,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let (ptr, len) = (data.as_ptr(), data.len());
        // Safety: AES reads block N before writing block N (see method docs).
        // The aliased slice covers `data`, which is DMA-resident, so branding
        // it as a `HsmDmaBuf` is sound.
        let message = unsafe { HsmDmaBuf::from_raw(alias_immutable(ptr, len)) };
        self.aes_run(mode, aes_op(op), key, iv, message, data).await
    }

    /// In-place generic AES over `buf` = `[IV | data]` → `[data | IV out]`.
    ///
    /// The data is staged in a zero-padded block-multiple work buffer, so
    /// partial final blocks in CFB/OFB/CTR only affect discarded bytes. The
    /// IV out is derived in software from the staged input and output
    /// blocks rather than relying on hardware IV write-back, which is only
    /// defined for CBC. CTR assumes the engine increments the full 128-bit
    /// big-endian counter block.
    async fn aes_generic_in_place(
        &self,
        io: &UnoHsmIo,
        op: HsmAesOp,
        mode: HsmAesMode,
        key: &HsmDmaBuf,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let (iv_len, data_len) = generic_lens(mode, key.len(), buf.len())?;
        if data_len == 0 {
            // `[IV]` → `[IV]`: every mode leaves the chaining value unchanged.
            return Ok(());
        }
        let padded = data_len.next_multiple_of(AES_BLOCK_SIZE);
        let full = data_len - data_len % AES_BLOCK_SIZE;

        self.alloc_scoped_async(io, async |scope| {
            let work = scope.dma_alloc(padded)?;
            work[..data_len].copy_from_slice(&buf[iv_len..]);
            work[data_len..].fill(0);
            let mut iv_in = [0u8; AES_BLOCK_SIZE];
            iv_in[..iv_len].copy_from_slice(&buf[..iv_len]);
            let iv = match iv_len {
                0 => None,
                _ => {
                    let iv = scope.dma_alloc(AES_BLOCK_SIZE)?;
                    iv.copy_from_slice(&iv_in);
                    Some(iv)
                }
            };
            let last_in = block_at(work, padded - AES_BLOCK_SIZE);
            let last_full_in = match full {
                0 => iv_in,
                _ => block_at(work, full - AES_BLOCK_SIZE),
            };

            self.aes
                .encrypt_decrypt(AesRequest {
                    mode: hw_mode(mode),
                    op: aes_op(op),
                    key,
                    iv,
                    update_iv: false,
                    message: None,
                    result: work,
                })
                .await?;

            let last_out = block_at(work, padded - AES_BLOCK_SIZE);
            let iv_out = match (mode, op) {
                (HsmAesMode::Ecb, _) => [0u8; AES_BLOCK_SIZE],
                (HsmAesMode::Cbc, HsmAesOp::Encrypt) => last_out,
                (HsmAesMode::Cbc, HsmAesOp::Decrypt) => last_in,
                (HsmAesMode::Cfb, _) if full == 0 => iv_in,
                (HsmAesMode::Cfb, HsmAesOp::Encrypt) => block_at(work, full - AES_BLOCK_SIZE),
                (HsmAesMode::Cfb, HsmAesOp::Decrypt) => last_full_in,
                (HsmAesMode::Ofb, _) => {
                    // Zero padding makes the padded output block the raw
                    // keystream XOR the padded input block.
                    let mut ks = last_out;
                    ks.iter_mut().zip(&last_in).for_each(|(k, i)| *k ^= i);
                    ks
                }
                (HsmAesMode::Ctr, _) => {
                    let blocks = (padded / AES_BLOCK_SIZE) as u128;
                    u128::from_be_bytes(iv_in)
                        .wrapping_add(blocks)
                        .to_be_bytes()
                }
            };

            buf[..data_len].copy_from_slice(&work[..data_len]);
            buf[data_len..].copy_from_slice(&iv_out[..iv_len]);
            Ok::<(), HsmError>(())
        })
        .await
    }
}

// =============================================================================
// AES trait impls
// =============================================================================
//
// The primary contract for each method (intended semantics, parameter
// shapes, panic conditions) is documented on the AES traits themselves.
// The implementation notes below describe only the Uno-specific
// validation and the building blocks each method delegates to.

impl HsmAes for UnoHsmPal {
    /// Generate a random AES key by filling `key` from the on-chip
    /// hardware RNG.
    ///
    /// The key size is taken from `key.len()`: 16 / 24 / 32 bytes for
    /// AES-128 / 192 / 256 respectively. Any other length is rejected
    /// before touching the RNG.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] — `key.len()` is not 16, 24, or 32.
    /// * Any [`HsmError`] surfaced by the RNG driver.
    async fn aes_gen_key(&self, io: &UnoHsmIo, key: &mut [u8]) -> HsmResult<()> {
        match key.len() {
            16 | 24 | 32 => {}
            _ => return Err(HsmError::InvalidArg),
        }
        self.rng_fill_bytes(io, key)
    }

    /// Validates lengths before touching `output`, copies `input` into
    /// `output` and runs [`Self::aes_generic_in_place`] on it.
    async fn aes_enc_dec(
        &self,
        io: &UnoHsmIo,
        op: HsmAesOp,
        mode: HsmAesMode,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        generic_lens(mode, key.len(), input.len())?;
        if output.len() < input.len() {
            return Err(HsmError::InvalidArg);
        }
        let output = &mut output[..input.len()];
        output.copy_from_slice(input);
        self.aes_generic_in_place(io, op, mode, key, output).await
    }

    /// See [`Self::aes_generic_in_place`].
    async fn aes_enc_dec_in_place(
        &self,
        io: &UnoHsmIo,
        op: HsmAesOp,
        mode: HsmAesMode,
        key: &HsmDmaBuf,
        buf: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.aes_generic_in_place(io, op, mode, key, buf).await
    }

    /// Validates `iv_in` / `iv_out` lengths and that `input` / `output`
    /// satisfy [`require_block_multiple`], then dispatches a single CBC
    /// submission via [`Self::aes_run`].
    async fn aes_cbc_enc_dec(
        &self,
        io: &UnoHsmIo,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        iv_in: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
        mut iv_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<()> {
        require_cbc_iv(iv_in)?;
        if let Some(iv_out) = iv_out.as_deref() {
            require_cbc_iv(iv_out)?;
        }
        require_block_multiple(input, output.len())?;

        self.alloc_scoped_async(io, async |scope| {
            let iv_work = scope.dma_alloc(AES_BLOCK_SIZE)?;
            iv_work.copy_from_slice(iv_in);
            self.aes_run(AesMode::Cbc, aes_op(op), key, Some(iv_work), input, output)
                .await?;

            if let Some(iv_out) = iv_out.take() {
                iv_out.copy_from_slice(iv_work);
            }
            Ok::<(), HsmError>(())
        })
        .await
    }

    /// Validates `iv_in` / `iv_out` lengths and that `data` is a whole
    /// number of blocks, then dispatches a single in-place CBC submission
    /// via [`Self::aes_run_in_place`].
    async fn aes_cbc_enc_dec_in_place(
        &self,
        io: &UnoHsmIo,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
        iv_in: &HsmDmaBuf,
        mut iv_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<()> {
        require_cbc_iv(iv_in)?;
        if let Some(iv_out) = iv_out.as_deref() {
            require_cbc_iv(iv_out)?;
        }
        require_block_multiple(data, data.len())?;

        self.alloc_scoped_async(io, async |scope| {
            let iv_work = scope.dma_alloc(AES_BLOCK_SIZE)?;
            iv_work.copy_from_slice(iv_in);
            self.aes_run_in_place(AesMode::Cbc, op, key, Some(iv_work), data)
                .await?;

            if let Some(iv_out) = iv_out.take() {
                iv_out.copy_from_slice(iv_work);
            }
            Ok::<(), HsmError>(())
        })
        .await
    }

    /// Validates that `input` / `output` satisfy [`require_block_multiple`],
    /// then dispatches a single ECB submission via [`Self::aes_run`].
    async fn aes_ecb_enc_dec(
        &self,
        _io: &UnoHsmIo,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        require_block_multiple(input, output.len())?;
        self.aes_run(AesMode::Ecb, aes_op(op), key, None, input, output)
            .await
    }

    /// Validates that `data` is a whole number of blocks, then dispatches a
    /// single in-place ECB submission via [`Self::aes_run_in_place`].
    async fn aes_ecb_enc_dec_in_place(
        &self,
        _io: &UnoHsmIo,
        op: HsmAesOp,
        key: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        require_block_multiple(data, data.len())?;
        self.aes_run_in_place(AesMode::Ecb, op, key, None, data)
            .await
    }
}

impl HsmAesGcm for UnoHsmPal {
    /// AES-GCM encrypt using AES-CTR plus software GHASH.
    #[allow(clippy::too_many_arguments)]
    async fn gcm_encrypt(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        plaintext: &HsmDmaBuf,
        ciphertext: &mut HsmDmaBuf,
        tag: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        if iv.len() != GCM_IV_LEN || tag.len() != GCM_TAG_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.gcm_encrypt_impl(io, key, iv, aad_len, plaintext, ciphertext, tag)
            .await
    }

    /// AES-GCM encrypt in-place using AES-CTR plus software GHASH.
    async fn gcm_encrypt_in_place(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        data: &mut HsmDmaBuf,
        tag: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        if iv.len() != GCM_IV_LEN || tag.len() != GCM_TAG_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.gcm_encrypt_in_place_impl(io, key, iv, aad_len, data, tag)
            .await
    }

    /// AES-GCM decrypt using AES-CTR plus software GHASH.
    #[allow(clippy::too_many_arguments)]
    async fn gcm_decrypt(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        tag: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        plaintext: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        if iv.len() != GCM_IV_LEN || tag.len() != GCM_TAG_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.gcm_decrypt_impl(io, key, iv, aad_len, tag, ciphertext, plaintext)
            .await
    }

    /// AES-GCM decrypt in-place using AES-CTR plus software GHASH.
    async fn gcm_decrypt_in_place(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        iv: &HsmDmaBuf,
        aad_len: usize,
        tag: &HsmDmaBuf,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        if iv.len() != GCM_IV_LEN || tag.len() != GCM_TAG_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.gcm_decrypt_in_place_impl(io, key, iv, aad_len, tag, data)
            .await
    }
}

impl HsmAesKw for UnoHsmPal {
    // ── AES Key Wrap (RFC 3394) / Key Wrap with Padding (RFC 5649) ──

    /// AES-KW wrap (RFC 3394 §2.2.1).
    ///
    /// Delegates to [`UnoHsmPal::kw_wrap_impl`] in the [`super::kw`]
    /// module — see that method for the full algorithm description and
    /// async batching strategy.
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `input` — plaintext to wrap. Must be at least 16 bytes, a
    ///   whole multiple of 8, and at most 3 KiB.
    /// * `output` — destination buffer. Must be at least
    ///   `input.len() + 8` bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success. `output[..input.len() + 8]` contains the
    ///   wrapped key.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if a length constraint is violated.
    /// * Any [`HsmError`] surfaced by the AES driver.
    async fn aes_kw_wrap(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.kw_wrap_impl(io, key, input, output).await
    }

    /// AES-KW unwrap (RFC 3394 §2.2.2).
    ///
    /// Delegates to [`UnoHsmPal::kw_unwrap_impl`] in the [`super::kw`]
    /// module.
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `input` — wrapped ciphertext. Must be at least 24 bytes, a
    ///   whole multiple of 8, and at most `3 KiB + 8` bytes.
    /// * `output` — destination buffer. Must be at least
    ///   `input.len() - 8` bytes.
    ///
    /// # Returns
    /// * `Ok(())` on a verified unwrap. `output[..input.len() - 8]`
    ///   contains the recovered key.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if a length constraint is violated.
    /// * [`HsmError::AesUnwrapFailed`] if the recovered IV does not
    ///   match the RFC 3394 default value (authentication failure).
    /// * Any [`HsmError`] surfaced by the AES driver.
    async fn aes_kw_unwrap(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.kw_unwrap_impl(io, key, input, output).await
    }

    /// AES-KWP wrap (RFC 5649 §4.1).
    ///
    /// Delegates to [`UnoHsmPal::kwp_wrap_impl`] in the [`super::kw`]
    /// module. Accepts inputs of any non-zero length up to 3 KiB by
    /// zero-padding to the next 8-byte boundary and prefixing an
    /// Alternative Initial Value.
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `input` — plaintext to wrap (1–3 KiB, any length).
    /// * `output` — destination buffer. Must be at least
    ///   `next_multiple_of(input.len(), 8) + 8` bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if a length constraint is violated.
    /// * Any [`HsmError`] surfaced by the AES driver.
    async fn aes_kwp_wrap(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.kwp_wrap_impl(io, key, input, output).await
    }

    /// AES-KWP unwrap (RFC 5649 §4.2).
    ///
    /// Delegates to [`UnoHsmPal::kwp_unwrap_impl`] in the
    /// [`super::kw`] module. Verifies the AIV and recovers the
    /// original message length from its embedded MLI field.
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `input` — wrapped ciphertext. Must be at least 16 bytes, a
    ///   whole multiple of 8, and at most `3 KiB + 8` bytes.
    /// * `output` — destination buffer. Must be at least the recovered
    ///   `mli` bytes (and at least `input.len() - 8` bytes for inputs
    ///   larger than one AES block).
    ///
    /// # Returns
    /// * `Ok(mli)` — the recovered message length. `output[..mli]`
    ///   contains the unwrapped plaintext.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if a length constraint is violated.
    /// * [`HsmError::AesUnwrapFailed`] if the AIV does not validate.
    /// * Any [`HsmError`] surfaced by the AES driver.
    async fn aes_kwp_unwrap(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        input: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<usize> {
        self.kwp_unwrap_impl(io, key, input, output).await
    }
}

// AES-XTS support is currently disabled.
impl HsmAesXts for UnoHsmPal {}
