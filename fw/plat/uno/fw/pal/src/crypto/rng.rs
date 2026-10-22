// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmRng`] implementation for the Uno PAL.
//!
//! Delegates to the synchronous [`RngDriver`] which polls the on-chip
//! TRNG peripheral for 32 bits at a time and demultiplexes them into
//! the destination buffer.
//!
//! [`RngDriver`]: tsra_fw_uno_drivers_rng::RngDriver

use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;

use crate::UnoHsmPal;

impl HsmRng for UnoHsmPal {
    /// Fill `buf` with hardware-generated random bytes.
    ///
    /// # Parameters
    /// * `io` — PAL I/O handle for platform-mediated operations.
    /// * `buf` — destination buffer; every byte is overwritten.
    ///
    /// # Returns
    /// * `Ok(())` on success. `buf` contains `buf.len()` random bytes.
    ///
    /// # Errors
    /// * Any [`HsmError`](tsra_fw_hsm_pal_traits::HsmError) surfaced by
    ///   the RNG driver (e.g. hardware fault).
    fn rng_fill_bytes(&self, _io: &impl HsmIo, buf: &mut [u8]) -> HsmResult<()> {
        // SAFETY: The RNG driver only writes through the CPU; this borrow is not used for DMA.
        let dma = unsafe { DmaBuf::from_raw_mut(buf) };
        self.rng.fill_bytes(dma)
    }
}
