// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal INTC doorbell handling for the fastpath cores.
//!
//! Enough to prove the HSM↔FP doorbell path works in both directions,
//! without pulling the full IPC driver onto FP.
//!
//! # Why polled
//!
//! The HSM side drives its IPC driver from the PAL, which polls the NVIC
//! and calls `wake()` on whichever driver owns the pending IRQ.  FP has no
//! PAL and no interrupt plumbing, so wiring the same driver here would mean
//! porting that machinery too.
//!
//! Polling the pending register from an Embassy task instead costs a few
//! milliseconds of latency on a PQC operation measured in milliseconds, and
//! keeps this step small enough to debug on a core with no console.  It can
//! become interrupt-driven later without changing the protocol.
//!
//! # Descriptors
//!
//! The INTC has six interrupt blocks — one per CPU, `CP0, CP1, FP0, FP1,
//! FP2, HSP` = 0..5 — and 32 doorbell descriptors.  A CPU rings another by
//! writing that descriptor's register; every CPU that has enabled the
//! descriptor in its own block then sees the bit set in its pending
//! register.
//!
//! Descriptors 2–7 carry HSM↔FP traffic, two per core.  Core `n` listens
//! on `2 + 2n` and replies on `3 + 2n`, matching the mapping the HSM-side
//! PQC driver uses.

use core::ptr::read_volatile;
use core::ptr::write_volatile;

/// Base of the INTC block.
const INTC_BASE: usize = 0xB000_6000;

/// Write 1 to bit N to clear descriptor N's pending status.
const PEND_CLR: usize = INTC_BASE;

/// Reads as the set of descriptors currently pending for a block.
const PEND_SET: usize = INTC_BASE + 0x18;

/// Write 1 to bit N to let descriptor N raise this block's interrupt.
const ENABLE_SET: usize = INTC_BASE + 0x78;

/// Doorbell descriptor value registers.
const DESC: usize = INTC_BASE + 0x110;

/// INTC block index of FP core 0.  Blocks run `CP0, CP1, FP0, FP1, FP2,
/// HSP` = 0..5.
const FP0_INTC_BLOCK: usize = 2;

/// First descriptor reserved for HSM↔FP traffic.
const FIRST_FP_DESC: usize = 2;

/// This core's INTC block index.
fn block(core_id: u8) -> usize {
    FP0_INTC_BLOCK + core_id as usize
}

/// Descriptor this core listens on for requests from the HSM.
pub fn request_desc(core_id: u8) -> usize {
    FIRST_FP_DESC + core_id as usize * 2
}

/// Descriptor this core rings to answer the HSM.
pub fn response_desc(core_id: u8) -> usize {
    request_desc(core_id) + 1
}

/// Allow this core's request descriptor to raise its pending bit.
pub fn init(core_id: u8) {
    // SAFETY: INTC is a device register block at a fixed address, reachable
    // from every CPU including FP — the legacy fastpath drove the same
    // registers. Writes are volatile and to this core's own block only.
    unsafe {
        // Clear stale pending first: descriptors carry traffic from before
        // this core booted, and a leftover bit would read as an arrival.
        write_volatile((PEND_CLR + block(core_id) * 4) as *mut u32, 0xFFFF_FFFF);
        let enable = (ENABLE_SET + block(core_id) * 4) as *mut u32;
        write_volatile(enable, 1u32 << request_desc(core_id));
    }
}

/// Take a pending request doorbell, if one has arrived.
///
/// Clears the pending bit so the next ring is distinguishable from this
/// one, and returns the value the HSM left in the descriptor.
pub fn take_request(core_id: u8) -> Option<u32> {
    let desc = request_desc(core_id);

    // SAFETY: as above.
    unsafe {
        let pending = read_volatile((PEND_SET + block(core_id) * 4) as *const u32);
        if pending & (1u32 << desc) == 0 {
            return None;
        }

        let value = read_volatile((DESC + desc * 4) as *const u32);
        write_volatile((PEND_CLR + block(core_id) * 4) as *mut u32, 1u32 << desc);
        Some(value)
    }
}

/// Ring the HSM, leaving `value` in this core's response descriptor.
pub fn ring_response(core_id: u8, value: u32) {
    // SAFETY: as above.
    unsafe {
        write_volatile((DESC + response_desc(core_id) * 4) as *mut u32, value);
    }
}
