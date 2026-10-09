// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM-side view of the FP shared status block.
//!
//! Bring-up instrumentation for the FP↔HSM shared memory path.  The FP
//! cores have no console, so this is how they report: each publishes a
//! small block in GSRAM that the HSM reads back and logs over UART.
//!
//! The layout mirrors `shared_status.rs` in the FP firmware
//! (`fw/plat/uno/pqc/app/src/`) and the two must be kept in step.
//!
//! ```text
//! 0xA3E0_0C80  +0x00  u32  HSM -> FP sentinel
//!              +0x10  ---- FP0 block ----
//!                     +0x00 u32  magic "FPOK"
//!                     +0x04 u32  core id
//!                     +0x08 u32  counter (increments while the core lives)
//!                     +0x0C u32  echo of the sentinel this core last read
//!                     +0x10 u32  CLIDR  (cache levels implemented)
//!                     +0x14 u32  CCR    (bit 16 DC, bit 17 IC enable)
//!              +0x30  ---- FP1 block ----
//!              +0x50  ---- FP2 block ----
//! ```
//!
//! Reading it answers four questions at once: whether an FP core can write
//! memory the HSM can see (magic and counter present), whether it can read
//! memory the HSM wrote (echo matches the sentinel), whether the post-link
//! identity stamp landed correctly (block `n` reports id `n`), and whether
//! the FP cores have caches at all (`CLIDR`) — which decides whether the
//! shared window needs non-cacheable MPU attributes.

use core::ptr::read_volatile;
use core::ptr::write_volatile;

use crate::types::ENGINES;

/// Base of the shared status block in the global SoC map.
///
/// **PSRAM, not GSRAM.**  GSRAM was the obvious choice — it is where the
/// HSM's DMA scratch lives, so operands would need no copy — but an FP core
/// faults on it, both at its global address and at the `0xE046_0000`
/// aperture the legacy FP memory map names.  That map defines a GSRAM base
/// and then never uses it anywhere, which fits: FP appears never to have
/// been able to reach GSRAM.
///
/// PSRAM is reachable from both sides: the legacy fastpath used it
/// routinely, and the legacy CP firmware maps it at `0xA3E0_0000` (32 KB).
/// An FP core addresses this same block core-locally as `0x0001_7C00`.
///
/// Sits just after the mailboxes and before FP0's operand slot; the tail of
/// PSRAM this used to occupy is now covered by FP2's slot.
const BLOCK_BASE: usize = 0xA3E0_0C80;

/// Offset of the first per-core block.
const CORE_BLOCK_OFFSET: usize = 0x10;

/// Size of one core's block.
const CORE_BLOCK_SIZE: usize = 0x20;

/// Value an FP core writes to claim its block: ASCII "FPOK".
pub const FP_STATUS_MAGIC: u32 = 0x464F_4B50;

/// One core's published status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FpStatus {
    /// Should be [`FP_STATUS_MAGIC`] if the core has published anything.
    pub magic: u32,

    /// Core id as the core itself understands it.
    pub core_id: u32,

    /// Increments while the core is alive.
    pub counter: u32,

    /// Sentinel value the core last read from the HSM.
    pub echo: u32,

    /// The core's Cache Level ID Register.  Zero means no caches are
    /// fitted, so cacheability attributes on the shared window are inert.
    pub clidr: u32,

    /// The core's Configuration and Control Register; bit 16 `DC` and bit
    /// 17 `IC` report whether the caches are enabled.
    pub ccr: u32,

    /// Value of the last doorbell request the core observed.
    pub doorbell_req: u32,

    /// How many doorbells the core has answered.
    pub doorbell_count: u32,
}

impl FpStatus {
    /// Whether this block looks like a live FP core reporting the expected
    /// identity and echoing `sentinel`.
    pub fn is_healthy(&self, expected_id: usize, sentinel: u32) -> bool {
        self.magic == FP_STATUS_MAGIC
            && self.core_id as usize == expected_id
            && self.echo == sentinel
    }
}

/// Leave `value` for the FP cores to echo back.
pub fn write_sentinel(value: u32) {
    // SAFETY: a reserved word in the GSRAM aperture (see the layout above),
    // outside every region the linker knows about, so nothing aliases it.
    // Volatile because the FP cores observe the write.
    unsafe { write_volatile(BLOCK_BASE as *mut u32, value) };
}

/// Read one core's published status.
pub fn read_status(core: usize) -> FpStatus {
    let block = (BLOCK_BASE + CORE_BLOCK_OFFSET + core * CORE_BLOCK_SIZE) as *const u32;

    // SAFETY: as above; `core` is bounded by the caller to `ENGINES`, which
    // keeps the read inside the reserved block.
    unsafe {
        FpStatus {
            magic: read_volatile(block),
            core_id: read_volatile(block.add(1)),
            counter: read_volatile(block.add(2)),
            echo: read_volatile(block.add(3)),
            clidr: read_volatile(block.add(4)),
            ccr: read_volatile(block.add(5)),
            doorbell_req: read_volatile(block.add(6)),
            doorbell_count: read_volatile(block.add(7)),
        }
    }
}

/// Read every core's published status.
pub fn read_all() -> [FpStatus; ENGINES] {
    core::array::from_fn(read_status)
}
