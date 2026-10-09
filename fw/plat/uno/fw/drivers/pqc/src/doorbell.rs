// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM-side INTC doorbell to the fastpath cores.
//!
//! Rings an FP core to tell it a request is waiting in its mailbox.  The
//! doorbell carries no meaning beyond "look now" — the request and its
//! answer both live in PSRAM.
//!
//! Deliberately not routed through the IPC driver: that driver's `wake()`
//! runs from the PAL's interrupt poll and clears every pending bit in the
//! HSM's block, which would race away anything this path tried to observe
//! there.  Completion is detected from the mailbox instead, so only the
//! outbound ring is needed here.
//!
//! Descriptors 2–7 carry HSM↔FP traffic, two per core: the HSM rings
//! `2 + 2n` and FP core `n` replies on `3 + 2n`.

use core::ptr::write_volatile;

use crate::types::EngineId;

/// Base of the INTC block.
const INTC_BASE: usize = 0xB000_6000;

/// Doorbell descriptor value registers.
const DESC: usize = INTC_BASE + 0x110;

/// Ring `engine`'s request descriptor with `value`.
pub fn ring(engine: EngineId, value: u32) {
    // The request block and operand slot are Normal memory, and this write
    // is to a Device-mapped peripheral; without a barrier the doorbell can
    // reach the core before the work it announces.
    crate::mailbox::dsb();

    // SAFETY: as above; writes one descriptor value register.
    unsafe {
        write_volatile(
            (DESC + engine.outbound_desc() as usize * 4) as *mut u32,
            value,
        );
    }
}
