// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-XTS (IEEE 1619) for the Uno PAL, host-to-host over raw SGLs.
//!
//! Runs on the CP AES core in both build configurations: the BCP's XTS
//! data-unit size is fixed by the FP bulk path, so it cannot serve the
//! caller-chosen DUL of the HSM command. XTS is built from AES-ECB:
//!
//! * `T₀ = AES_K2(tweak + i)` per data unit `i` (128-bit little-endian).
//! * `C_j = AES_K1(P_j ⊕ T_j) ⊕ T_j`, with `T_{j+1} = T_j · α` in GF(2¹²⁸).
//!
//! Data is streamed through the per-IO DMA slot in [`XTS_CHUNK`]-byte
//! pieces with one ECB submission per piece; the tweak carries across
//! pieces of the same data unit.

use tsra_fw_hsm_pal_traits::HSM_AES_XTS_KEY_LEN;
use tsra_fw_hsm_pal_traits::HSM_AES_XTS_TWEAK_LEN;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_uno_drivers_aes::AesMode;
use tsra_fw_uno_drivers_aes::AesOp;

use super::aes::AES_BLOCK_SIZE;
use crate::UnoHsmIo;
use crate::UnoHsmPal;
use crate::gdma::HostSgl;

/// Bytes moved per GDMA/ECB round trip. Two buffers of this size live
/// in the per-IO DMA slot at once.
const XTS_CHUNK: usize = 2048;

/// Half of an XTS key: one AES-256 key.
const XTS_HALF_KEY_LEN: usize = HSM_AES_XTS_KEY_LEN / 2;

/// Multiply a tweak by α in GF(2¹²⁸) (IEEE 1619 little-endian convention).
#[inline]
fn mul_alpha(t: u128) -> u128 {
    (t << 1) ^ ((t >> 127) * 0x87)
}

/// XOR the tweak sequence starting at `t` into `buf` (whole blocks) and
/// return the tweak that follows the last block.
fn xor_tweaks(buf: &mut [u8], mut t: u128) -> u128 {
    for block in buf.as_chunks_mut::<AES_BLOCK_SIZE>().0 {
        for (b, m) in block.iter_mut().zip(t.to_le_bytes()) {
            *b ^= m;
        }
        t = mul_alpha(t);
    }
    t
}

impl UnoHsmPal {
    /// Fill `key` with a random AES-256-XTS key whose halves differ.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `key` is not [`HSM_AES_XTS_KEY_LEN`].
    /// * Any RNG error.
    pub(super) fn xts_gen_key_impl(&self, io: &UnoHsmIo, key: &mut [u8]) -> HsmResult<()> {
        if key.len() != HSM_AES_XTS_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        let (k1, k2) = key.split_at_mut(XTS_HALF_KEY_LEN);
        self.rng_fill_bytes(io, k1)?;
        loop {
            self.rng_fill_bytes(io, k2)?;
            if k1 != k2 {
                return Ok(());
            }
        }
    }

    /// AES-256-XTS encrypt/decrypt `len` bytes from host SGL `src` to
    /// host SGL `dst`, in data units of `dul` bytes.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] for a bad key/tweak length, equal key
    ///   halves, or a malformed SGL.
    /// * [`HsmError::AesXtsInvalidBufferSize`] if `dul` is not a non-zero
    ///   multiple of 16, `len` is not a non-zero multiple of `dul`, or the
    ///   last data-unit number exceeds 64 bits.
    /// * Any GDMA or AES driver error.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn xts_enc_dec_sgl_impl(
        &self,
        io: &UnoHsmIo,
        op: AesOp,
        key: &HsmDmaBuf,
        tweak: &HsmDmaBuf,
        len: usize,
        dul: usize,
        src: &[u8; 16],
        dst: &[u8; 16],
    ) -> HsmResult<()> {
        if key.len() != HSM_AES_XTS_KEY_LEN || tweak.len() != HSM_AES_XTS_TWEAK_LEN {
            return Err(HsmError::InvalidArg);
        }
        if key[..XTS_HALF_KEY_LEN] == key[XTS_HALF_KEY_LEN..] {
            return Err(HsmError::InvalidArg);
        }
        if dul < AES_BLOCK_SIZE || !dul.is_multiple_of(AES_BLOCK_SIZE) {
            return Err(HsmError::AesXtsInvalidBufferSize);
        }
        if len == 0 || !len.is_multiple_of(dul) {
            return Err(HsmError::AesXtsInvalidBufferSize);
        }
        let mut t = [0u8; 16];
        t[..HSM_AES_XTS_TWEAK_LEN].copy_from_slice(tweak);
        let first = u128::from_le_bytes(t);
        let units = len / dul;
        // The tweak after the last unit must still fit in 64 bits.
        if first + units as u128 > u128::from(u64::MAX) {
            return Err(HsmError::AesXtsInvalidBufferSize);
        }

        let mut rd = HostSgl::new(src, len)?;
        let mut wr = HostSgl::new(dst, len)?;

        self.alloc_scoped_async(io, async |scope| {
            let k1 = scope.dma_alloc(XTS_HALF_KEY_LEN)?;
            k1.copy_from_slice(&key[..XTS_HALF_KEY_LEN]);
            let k2 = scope.dma_alloc(XTS_HALF_KEY_LEN)?;
            k2.copy_from_slice(&key[XTS_HALF_KEY_LEN..]);
            let tw_in = scope.dma_alloc(AES_BLOCK_SIZE)?;
            let tw_out = scope.dma_alloc(AES_BLOCK_SIZE)?;
            let desc = scope.dma_alloc(AES_BLOCK_SIZE)?;
            let buf = scope.dma_alloc(XTS_CHUNK)?;
            let out = scope.dma_alloc(XTS_CHUNK)?;

            let result = async {
                for i in 0..units {
                    tw_in.copy_from_slice(&(first + i as u128).to_le_bytes());
                    self.aes_run(AesMode::Ecb, AesOp::Encrypt, k2, None, tw_in, tw_out)
                        .await?;
                    let mut t = [0u8; 16];
                    t.copy_from_slice(tw_out);
                    let mut tw = u128::from_le_bytes(t);

                    let mut done = 0;
                    while done < dul {
                        let n = core::cmp::min(XTS_CHUNK, dul - done);
                        rd.read_into(self, io, desc, &mut buf[..n]).await?;
                        xor_tweaks(&mut buf[..n], tw);
                        self.aes_run(AesMode::Ecb, op, k1, None, &buf[..n], &mut out[..n])
                            .await?;
                        tw = xor_tweaks(&mut out[..n], tw);
                        wr.write_from(self, io, desc, &out[..n]).await?;
                        done += n;
                    }
                }
                Ok(())
            }
            .await;

            k1.fill(0);
            k2.fill(0);
            buf.fill(0);
            out.fill(0);
            result
        })
        .await
    }
}
