// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-XTS tweak schedule (IEEE 1619) for the Uno PAL's streamed XTS.
//!
//! The PAL streams each data unit in [`XTS_CHUNK`]-byte pieces; the tweak
//! returned by [`xor_tweaks`] for one piece seeds the next piece of the
//! same data unit.

use crate::AES_BLOCK_SIZE;

/// Bytes moved per GDMA/ECB round trip. Two buffers of this size live
/// in the per-IO DMA slot at once.
pub const XTS_CHUNK: usize = 2048;

/// Multiply a tweak by α in GF(2¹²⁸) (IEEE 1619 little-endian convention).
#[inline]
pub fn mul_alpha(t: u128) -> u128 {
    (t << 1) ^ ((t >> 127) * 0x87)
}

/// XOR the tweak sequence starting at `t` into `buf` (whole blocks) and
/// return the tweak that follows the last block.
pub fn xor_tweaks(buf: &mut [u8], mut t: u128) -> u128 {
    for block in buf.as_chunks_mut::<AES_BLOCK_SIZE>().0 {
        for (b, m) in block.iter_mut().zip(t.to_le_bytes()) {
            *b ^= m;
        }
        t = mul_alpha(t);
    }
    t
}
